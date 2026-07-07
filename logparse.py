"""Разбор строк лога брандмауэра.

Общий модуль без зависимостей от Flask и пакета app — импортируется
как из веб-приложения (app/routes.py), так и из standalone-скрипта
butler-log-import.py (запускается systemd-таймером системным python,
где Flask может быть недоступен).
"""

import ipaddress
import re

RE_SRC = re.compile(r'SRC=(\S+)')
RE_DPT = re.compile(r'DPT=(\d+)')
RE_TS = re.compile(r'^(\w{3}\s+\d+\s+\d+:\d+:\d+)')
# UFW пишет события с префиксом [UFW BLOCK]/[UFW ALLOW]/[UFW LIMIT]/[UFW AUDIT].
RE_UFW = re.compile(r'kernel:.*\[UFW\s+(?:BLOCK|ALLOW|LIMIT|AUDIT)\]')
# Legacy-совместимость: прежний Butler-бэкенд помечал пакеты префиксом BUTLER.
RE_BUTLER = re.compile(r'kernel:.*BUTLER\b')


def parse_log_line(line):
    """Разобрать одну строку kernel-лога брандмауэра.

    Распознаётся формат UFW (`[UFW BLOCK/ALLOW/LIMIT/AUDIT]`), а также
    legacy-префикс BUTLER для обратной совместимости.

    Возвращает dict {ip, port, ts_raw} или None, если строка не является
    распознанным событием брандмауэра.
    """
    if not (RE_UFW.search(line) or RE_BUTLER.search(line)):
        return None

    m_src = RE_SRC.search(line)
    m_dpt = RE_DPT.search(line)
    if not (m_src and m_dpt):
        return None

    m_ts = RE_TS.search(line)
    try:
        ip = str(ipaddress.ip_address(m_src.group(1)))
    except ValueError:
        return None
    return {'ip': ip, 'port': int(m_dpt.group(1)), 'ts_raw': m_ts.group(1) if m_ts else None}
