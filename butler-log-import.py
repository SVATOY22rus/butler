#!/usr/bin/env python3
"""
Butler — автосбор попыток подключений из journald.

Читает kernel-лог через journalctl начиная с последней
обработанной записи (метка хранится в state-файле).
Фильтрует строки по портам из таблицы сервисов Butler.

Запускается systemd-таймером каждые 5 минут.

Использование:
    python3 butler-log-import.py [--db PATH] [--state PATH] [--lines N]
"""

import argparse
import ipaddress
import re
import sqlite3
import subprocess
import sys
from datetime import datetime
from pathlib import Path


DEFAULT_DB    = Path(__file__).parent / 'instance' / 'butler.sqlite3'
DEFAULT_STATE = Path(__file__).parent / 'instance' / 'log-import.state'
DEFAULT_LINES = 10000   # сколько строк journald читать за раз


def parse_args():
    p = argparse.ArgumentParser(description='Butler log importer')
    p.add_argument('--db',    default=str(DEFAULT_DB),    help='Путь к SQLite БД')
    p.add_argument('--state', default=str(DEFAULT_STATE), help='Файл состояния (cursor)')
    p.add_argument('--lines', default=DEFAULT_LINES, type=int, help='Строк из journald')
    return p.parse_args()


def read_cursor(state_path: Path) -> str | None:
    """Прочитать сохранённый cursor journald."""
    try:
        return state_path.read_text().strip() or None
    except FileNotFoundError:
        return None


def write_cursor(state_path: Path, cursor: str):
    state_path.parent.mkdir(parents=True, exist_ok=True)
    state_path.write_text(cursor)


def fetch_journal_lines(cursor: str | None, lines: int) -> tuple[list[str], str | None]:
    """
    Получить строки kernel-лога из journald.
    Возвращает (список строк, новый cursor).
    """
    cmd = [
        'journalctl', '-k', '--no-pager',
        '-n', str(lines),
        '--output=short-precise',
    ]
    if cursor:
        cmd += ['--after-cursor', cursor]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    except Exception as exc:
        print(f'[butler-log-import] ошибка journalctl: {exc}', file=sys.stderr)
        return [], None

    lines_out = result.stdout.splitlines()

    # Получить новый cursor (последняя запись)
    new_cursor = None
    try:
        cur_result = subprocess.run(
            ['journalctl', '-k', '--no-pager', '-n', '1', '--output=export'],
            capture_output=True, text=True, timeout=10
        )
        for line in cur_result.stdout.splitlines():
            if line.startswith('__CURSOR='):
                new_cursor = line.split('=', 1)[1]
                break
    except Exception:
        pass

    return lines_out, new_cursor


RE_SRC = re.compile(r'SRC=(\S+)')
RE_DPT = re.compile(r'DPT=(\d+)')


def parse_line(line: str) -> dict | None:
    m_src = RE_SRC.search(line)
    m_dpt = RE_DPT.search(line)
    if not (m_src and m_dpt):
        return None
    ip_raw = m_src.group(1)
    port   = int(m_dpt.group(1))
    try:
        ip = str(ipaddress.ip_address(ip_raw))
    except ValueError:
        return None
    return {'ip': ip, 'port': port}


def run(db_path: str, state_path: Path, max_lines: int):
    cursor = read_cursor(state_path)

    log_lines, new_cursor = fetch_journal_lines(cursor, max_lines)
    if not log_lines:
        print('[butler-log-import] нет новых строк')
        return

    con = sqlite3.connect(db_path)
    con.row_factory = sqlite3.Row

    # Загрузим порты сервисов для фильтрации
    known_ports = {
        row['port']: row['name']
        for row in con.execute('SELECT port, name FROM services').fetchall()
    }

    added = updated = skipped = 0

    for line in log_lines:
        parsed = parse_line(line)
        if parsed is None:
            continue

        ip   = parsed['ip']
        port = parsed['port']

        # Фильтр: только порты наших сервисов
        if port not in known_ports:
            skipped += 1
            continue

        service_name = known_ports[port]

        existing = con.execute(
            'SELECT id FROM attempts WHERE ip_address = ? AND port = ?',
            (ip, port)
        ).fetchone()

        if existing:
            con.execute(
                'UPDATE attempts SET attempts_count = attempts_count + 1, last_seen = ? WHERE id = ?',
                (datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'), existing['id'])
            )
            updated += 1
        else:
            con.execute(
                'INSERT INTO attempts (ip_address, service_name, port, status) VALUES (?, ?, ?, ?)',
                (ip, service_name, port, 'new')
            )
            added += 1

    con.commit()
    con.close()

    if new_cursor:
        write_cursor(state_path, new_cursor)

    print(
        f'[butler-log-import] добавлено: {added}, обновлено: {updated}, '
        f'пропущено (не наш порт): {skipped}'
    )


if __name__ == '__main__':
    args = parse_args()
    run(args.db, Path(args.state), args.lines)
