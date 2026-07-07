"""Butler firewall backend — UFW only.

Butler управляет доступом к сервисам через UFW (Uncomplicated Firewall).

Стратегия применения правил — ИНКРЕМЕНТАЛЬНАЯ и ИДЕМПОТЕНТНАЯ:

  * Butler НИКОГДА не вызывает `ufw reset` и не выполняет `ufw disable/enable`
    во время применения правил. Это защищает от двух проблем прошлого прода:
      1. `ufw reset` на Astra Linux стирает /etc/sudoers.d/ → потеря sudo NOPASSWD.
      2. reset/disable рвёт активные соединения, включая текущую SSH-сессию.

  * Все правила Butler помечаются комментарием `butler` (ufw ... comment 'butler').
    При каждом apply Butler удаляет ТОЛЬКО свои прежние правила (по комментарию),
    затем добавляет актуальный набор. Чужие правила не трогаются.

  * SSH (порт 22) и порт веб-панели Butler защищаются отдельным `allow` и
    НИКОГДА не удаляются и не перекрываются deny-правилами.

Публичный API (используется routes.py):
    build_rules()                -> (rules_text, mode, skipped_list)
    write_generated_rules_file() -> generated_file_path
    apply_firewall_rules()       -> (generated_file, target_file_or_None, backup_file_or_None)
    reset_firewall_rules()       -> (target_file_or_None, backup_file_or_None)
"""

from __future__ import annotations

import ipaddress
import os
import re
import shutil
import subprocess
from datetime import datetime
from pathlib import Path

from flask import current_app

from .db import get_db, get_setting, parse_ports_raw

# Полный путь к ufw обязателен для совпадения с NOPASSWD в sudoers (Astra Linux).
_UFW = shutil.which('ufw') or '/usr/sbin/ufw'

# Комментарий-маркер, которым Butler помечает все свои правила.
BUTLER_TAG = 'butler'

# Порт SSH — защищаем всегда, никогда не закрываем (удалённые серверы).
SSH_PORT = 22


def _ufw_cmd(*args) -> list:
    """Собрать команду ufw с sudo -n.

    Сервис Butler работает под обычным пользователем, а ufw требует root.
    sudoers.sh выдаёт этому пользователю NOPASSWD на ufw, поэтому вызываем
    через `sudo -n` (без пароля, без запроса tty). Если процесс уже root —
    sudo просто выполнит команду напрямую без лишних вопросов.
    """
    return ['sudo', '-n', _UFW, *args]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_butler_port() -> int:
    """Порт, на котором слушает веб-панель Butler. Дефолт 5050, берётся из конфига/env."""
    try:
        return int(current_app.config.get('BUTLER_PORT',
                                           os.environ.get('BUTLER_PORT', 5050)))
    except (TypeError, ValueError):
        return 5050


def _protected_ports() -> set:
    """Порты, которые Butler никогда не блокирует и не перекрывает deny."""
    return {SSH_PORT, _get_butler_port()}


def run_command(command, error_prefix, timeout=15):
    """Выполнить команду, поднять RuntimeError при ненулевом коде возврата."""
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        raise RuntimeError(f'{error_prefix}\nКоманда превысила timeout ({timeout}s).')
    if result.returncode != 0:
        raise RuntimeError(f'{error_prefix}\n' + (result.stderr.strip() or result.stdout.strip()))
    return result


def _try_command(command, timeout=15):
    """Выполнить команду, вернуть (ok: bool, output: str). Не поднимает исключение."""
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return False, f'timeout ({timeout}s)'
    if result.returncode != 0:
        return False, (result.stderr.strip() or result.stdout.strip())
    return True, result.stdout


def _collect_ips(rows):
    """Разобрать строки БД в список нормализованных IP/подсетей (v4 и v6).

    Возвращает (ip_list, invalid_list). Поддерживаются и IPv4, и IPv6.
    """
    result = []
    invalid = []
    for row in rows:
        raw = row['ip_address'].strip()
        try:
            net = ipaddress.ip_network(raw, strict=False)
            # /32 (v4) и /128 (v6) — представляем как одиночный адрес.
            if net.prefixlen == net.max_prefixlen:
                result.append(str(net.network_address))
            else:
                result.append(str(net))
        except ValueError:
            invalid.append(raw)
    return result, invalid


# ---------------------------------------------------------------------------
# Правила: сборка списка UFW-команд из БД
# ---------------------------------------------------------------------------

def _iter_service_specs():
    """Итератор по (port:int, proto:str in {'tcp','udp'}) для всех сервисов."""
    db = get_db()
    services = db.execute(
        'SELECT port, ports_raw, protocol FROM services ORDER BY port'
    ).fetchall()
    protected = _protected_ports()
    for row in services:
        proto = (row['protocol'] or 'tcp').lower().strip()
        ports_raw = row['ports_raw'] or str(row['port'])
        expanded = parse_ports_raw(ports_raw) or [row['port']]
        protos = ['tcp', 'udp'] if proto == 'both' else [proto if proto in ('tcp', 'udp') else 'tcp']
        for port in sorted(set(expanded)):
            if port in protected:
                # SSH и порт панели никогда не трогаем сервисными правилами.
                continue
            for use_proto in protos:
                yield port, use_proto


def _rule_commands():
    """Построить список UFW-команд (списки argv) для применения из текущей БД.

    Все правила снабжаются `comment 'butler'` для последующей идемпотентной чистки.
    Возвращает (commands: list[list[str]], mode: str, skipped: list[str]).
    """
    mode = get_setting('firewall_mode', 'whitelist')
    db = get_db()

    whitelist_rows = db.execute(
        'SELECT ip_address FROM whitelist_entries WHERE enabled = 1 ORDER BY ip_address'
    ).fetchall()
    blacklist_rows = db.execute(
        'SELECT ip_address FROM blacklist_entries WHERE enabled = 1 ORDER BY ip_address'
    ).fetchall()

    whitelist_ips, wl_invalid = _collect_ips(whitelist_rows)
    blacklist_ips, bl_invalid = _collect_ips(blacklist_rows)
    skipped = wl_invalid + bl_invalid

    commands = []
    for port, proto in _iter_service_specs():
        if mode == 'whitelist':
            for ip in whitelist_ips:
                commands.append(
                    _ufw_cmd('allow', 'from', ip, 'to', 'any', 'port', str(port),
                             'proto', proto, 'comment', BUTLER_TAG)
                )
            commands.append(_ufw_cmd('deny', f'{port}/{proto}', 'comment', BUTLER_TAG))
        else:  # blacklist
            for ip in blacklist_ips:
                commands.append(
                    _ufw_cmd('deny', 'from', ip, 'to', 'any', 'port', str(port),
                             'proto', proto, 'comment', BUTLER_TAG)
                )
            commands.append(_ufw_cmd('allow', f'{port}/{proto}', 'comment', BUTLER_TAG))

    return commands, mode, skipped


def build_rules() -> tuple[str, str, list]:
    """Вернуть (человекочитаемый предпросмотр команд, mode, skipped_ips)."""
    commands, mode, skipped = _rule_commands()
    butler_port = _get_butler_port()

    lines = [f'# Butler UFW rules  (режим: {mode})']
    if skipped:
        lines.append('# Пропущены некорректные адреса: ' + ', '.join(skipped))
    lines.append('')
    lines.append('# --- защищённые порты (никогда не блокируются) ---')
    lines.append(f'ufw allow {SSH_PORT}/tcp                    # SSH')
    lines.append(f'ufw allow {butler_port}/tcp                  # Butler web UI')
    lines.append('')
    lines.append('# --- правила сервисов (помечены comment \'butler\') ---')
    if not commands:
        lines.append('# (нет сервисов или списков — правил не будет)')
    for cmd in commands:
        # cmd = ['sudo','-n', _UFW, ...]; печатаем читаемо как "ufw ..."
        lines.append('ufw ' + ' '.join(cmd[3:]))
    return '\n'.join(lines) + '\n', mode, skipped


def _generated_dir() -> Path:
    d = Path('generated')
    d.mkdir(exist_ok=True)
    return d


def write_generated_rules_file() -> Path:
    """Сохранить предпросмотр UFW-команд в файл generated/butler-ufw.sh."""
    generated_file = _generated_dir() / 'butler-ufw.sh'
    rules, _, _ = build_rules()
    generated_file.write_text('#!/usr/bin/env bash\n# Автоген Butler — предпросмотр. Butler применяет правила сам.\n' + rules,
                              encoding='utf-8')
    try:
        generated_file.chmod(0o755)
    except OSError:
        pass
    return generated_file


# ---------------------------------------------------------------------------
# Идемпотентная чистка прежних правил Butler (по комментарию)
# ---------------------------------------------------------------------------

def _list_butler_rule_numbers() -> list[int]:
    """Вернуть номера правил UFW, помеченных комментарием butler, по убыванию.

    Удалять правила нужно от большего номера к меньшему, иначе нумерация
    сдвигается после каждого удаления.
    """
    ok, out = _try_command(_ufw_cmd('status', 'numbered'))
    if not ok:
        return []
    numbers = []
    for line in out.splitlines():
        # Формат строки: "[ 5] 8011/tcp   DENY IN   Anywhere   # butler"
        if f'# {BUTLER_TAG}' not in line:
            continue
        m = re.match(r'\s*\[\s*(\d+)\s*\]', line)
        if m:
            numbers.append(int(m.group(1)))
    return sorted(numbers, reverse=True)


def _delete_butler_rules() -> int:
    """Удалить все правила с комментарием butler. Вернуть число удалённых."""
    deleted = 0
    # Перечитываем нумерацию после каждого удаления, чтобы не промахнуться.
    while True:
        numbers = _list_butler_rule_numbers()
        if not numbers:
            break
        num = numbers[0]  # самый большой номер
        ok, _out = _try_command(_ufw_cmd('--force', 'delete', str(num)))
        if not ok:
            break
        deleted += 1
        # Предохранитель от бесконечного цикла.
        if deleted > 10000:
            break
    return deleted


def _ensure_enabled_and_protected() -> None:
    """Гарантировать безопасные дефолты: UFW включён, SSH + порт Butler разрешены,
    глобальная политика — deny incoming / allow outgoing.

    ВАЖНО: не используем reset/disable. Порядок критичен для защиты от self-lockout:
      1. СНАЧАЛА явно allow на SSH (22) и порт панели — до смены default policy.
      2. ЗАТЕМ default deny incoming / allow outgoing (чтобы whitelist без сервисов
         реально закрывал остальное, а не оставлял всё открытым).
      3. ПОСЛЕ этого enable, если UFW был неактивен.

    `ufw allow` и `ufw default` идемпотентны — повторный вызов ничего не ломает.
    """
    butler_port = _get_butler_port()

    # Шаг 1. Разрешаем SSH и порт Butler ДО смены политики и включения —
    # защита от self-lockout. Правила без тега butler, чтобы чистка их не снесла.
    run_command(_ufw_cmd('allow', f'{SSH_PORT}/tcp'),
                'Не удалось разрешить SSH (22/tcp):')
    run_command(_ufw_cmd('allow', f'{butler_port}/tcp'),
                f'Не удалось защитить порт Butler ({butler_port}/tcp):')

    # Шаг 2. Безопасные дефолтные политики. Даже при пустом списке сервисов
    # входящий трафик будет закрыт (кроме явно разрешённых 22 и порта панели).
    run_command(_ufw_cmd('default', 'deny', 'incoming'),
                'Не удалось задать default deny incoming:')
    run_command(_ufw_cmd('default', 'allow', 'outgoing'),
                'Не удалось задать default allow outgoing:')

    # Шаг 3. Включаем UFW, если он ещё не активен. --force не задаёт вопросов.
    ok, out = _try_command(_ufw_cmd('status'))
    if ok and 'Status: active' not in out:
        run_command(_ufw_cmd('--force', 'enable'),
                    'Не удалось включить UFW:')


# ---------------------------------------------------------------------------
# Публичный API — apply / reset
# ---------------------------------------------------------------------------

def apply_firewall_rules() -> tuple[Path, None, None]:
    """Идемпотентно применить правила Butler через UFW.

    Порядок:
      1. Гарантировать, что SSH и порт Butler разрешены, UFW включён.
      2. Удалить прежние правила Butler (по comment 'butler').
      3. Добавить актуальный набор правил из БД.

    Не вызывает reset/disable → sudoers и активные соединения не страдают.
    Возвращает (generated_file, None, None) для совместимости сигнатуры с routes.
    """
    generated_file = write_generated_rules_file()

    # Шаг 1 — защита критичных портов и активация.
    _ensure_enabled_and_protected()

    # Шаг 2 — снять прежние правила Butler.
    _delete_butler_rules()

    # Шаг 3 — применить актуальные правила.
    commands, _mode, _skipped = _rule_commands()
    for cmd in commands:
        run_command(cmd, f'Не удалось применить правило: {" ".join(cmd[1:])}')

    return generated_file, None, None


def reset_firewall_rules() -> tuple[None, None]:
    """Убрать ТОЛЬКО правила Butler, не трогая остальную конфигурацию UFW.

    Не вызывает `ufw reset` (который стирает sudoers и рвёт соединения).
    SSH и порт Butler остаются разрешёнными. Возвращает (None, None).
    """
    # Гарантируем, что критичные порты открыты (на случай если их не было).
    _ensure_enabled_and_protected()
    # Удаляем только помеченные Butler правила.
    _delete_butler_rules()
    return None, None
