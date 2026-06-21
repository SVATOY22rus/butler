"""Butler firewall backend abstraction.

Supported backends:
  - 'nftables'  (default, existing behaviour)
  - 'ufw'       (new, per customer requirements)

All public functions used by routes.py:
  apply_firewall_rules()  -> (generated_file, target_file, backup_file)
  reset_firewall_rules()  -> (target_file, backup_file)
  build_rules()           -> (rules_str, mode, skipped_list)
  write_generated_rules_file() -> generated_file_path
"""

from __future__ import annotations

import ipaddress
import os
import shutil
import subprocess
from datetime import datetime
from pathlib import Path

from flask import current_app

from .db import get_db, get_setting, parse_ports_raw

# Full path required for sudoers NOPASSWD match on Astra Linux
_UFW = shutil.which('ufw') or '/usr/sbin/ufw'

# ---------------------------------------------------------------------------
# Helpers shared by both backends
# ---------------------------------------------------------------------------

def _get_backend() -> str:
    return current_app.config.get('BUTLER_BACKEND', 'nftables').lower()


def _get_butler_port() -> int:
    """Return the port Butler web UI is listening on (default 5050)."""
    return int(current_app.config.get('BUTLER_PORT', os.environ.get('BUTLER_PORT', 5050)))


def run_command(command, error_prefix, timeout=10):
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError(f'{error_prefix}\nКоманда превысила timeout ({timeout}s).')

    if result.returncode != 0:
        raise RuntimeError(
            f'{error_prefix}\n' + (result.stderr.strip() or result.stdout.strip())
        )
    return result


def _collect_ipv4(rows):
    result_v4 = []
    skipped_v6 = []
    for row in rows:
        raw = row['ip_address'].strip()
        try:
            net = ipaddress.ip_network(raw, strict=False)
            if net.version == 4:
                result_v4.append(
                    str(net.network_address) if net.prefixlen == 32 else str(net)
                )
            else:
                skipped_v6.append(raw)
        except ValueError:
            skipped_v6.append(raw)
    return result_v4, skipped_v6


def _backup_file(target_file: Path) -> Path | None:
    backup_dir = Path('generated/backups')
    backup_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime('%Y%m%d-%H%M%S')
    backup_file = backup_dir / f'butler-target-backup-{timestamp}.bak'

    exists = subprocess.run(
        ['sudo', '-n', '/usr/bin/test', '-f', str(target_file)],
        capture_output=True, text=True, timeout=5
    )
    if exists.returncode != 0:
        return None

    read = run_command(
        ['sudo', '-n', '/usr/bin/cat', str(target_file)],
        'Не удалось прочитать target-файл для backup:'
    )
    backup_file.write_text(read.stdout, encoding='utf-8')
    return backup_file


def _generated_dir() -> Path:
    d = Path('generated')
    d.mkdir(exist_ok=True)
    return d


# ---------------------------------------------------------------------------
# Public API — routes to correct backend
# ---------------------------------------------------------------------------

def build_rules() -> tuple[str, str, list]:
    """Return (rules_text, mode, skipped_ips)."""
    if _get_backend() == 'ufw':
        return _ufw_build_rules()
    return _nft_build_rules()


def write_generated_rules_file() -> Path:
    """Write generated rules to disk and return the path."""
    if _get_backend() == 'ufw':
        return _ufw_write_rules_file()
    return _nft_write_rules_file()


def apply_firewall_rules() -> tuple[Path, Path | None, Path | None]:
    """Apply rules. Returns (generated_file, target_file_or_None, backup_file_or_None)."""
    if _get_backend() == 'ufw':
        return _ufw_apply()
    return _nft_apply()


def reset_firewall_rules() -> tuple[Path | None, Path | None]:
    """Reset Butler rules. Returns (target_file_or_None, backup_file_or_None)."""
    if _get_backend() == 'ufw':
        return _ufw_reset()
    return _nft_reset()


# ---------------------------------------------------------------------------
# nftables backend (original logic, unchanged)
# ---------------------------------------------------------------------------

def _nft_get_paths():
    generated_dir = _generated_dir()
    generated_file = generated_dir / 'butler.nft'
    target_file = Path(current_app.config.get('BUTLER_FIREWALL_TARGET', '/etc/nftables.d/butler.nft'))
    nftables_conf = Path(current_app.config.get('BUTLER_NFTABLES_CONF', '/etc/nftables.conf'))
    return generated_dir, generated_file, target_file, nftables_conf


def _nft_proto_rules(proto, set_name, mode):
    lines = []
    if mode == 'whitelist':
        lines.append(f'        ip saddr @web_whitelist_v4 {proto} dport @{set_name} accept')
        lines.append(f'        {proto} dport @{set_name} log prefix "BUTLER "')
        lines.append(f'        {proto} dport @{set_name} drop')
    else:
        lines.append(f'        ip saddr @web_blacklist_v4 {proto} dport @{set_name} log prefix "BUTLER "')
        lines.append(f'        ip saddr @web_blacklist_v4 {proto} dport @{set_name} drop')
        lines.append(f'        {proto} dport @{set_name} accept')
    return '\n'.join(lines)


def _nft_build_rules() -> tuple[str, str, list]:
    db = get_db()
    mode = get_setting('firewall_mode', 'whitelist')

    services = db.execute('SELECT port, ports_raw, protocol FROM services ORDER BY port').fetchall()
    whitelist_rows = db.execute('SELECT ip_address FROM whitelist_entries WHERE enabled = 1 ORDER BY ip_address').fetchall()
    blacklist_rows = db.execute('SELECT ip_address FROM blacklist_entries WHERE enabled = 1 ORDER BY ip_address').fetchall()

    tcp_ports: set = set()
    udp_ports: set = set()
    for row in services:
        proto = (row['protocol'] or 'tcp').lower().strip()
        ports_raw = row['ports_raw'] or str(row['port'])
        expanded = parse_ports_raw(ports_raw) or [row['port']]
        if proto in ('tcp', 'both'):
            tcp_ports.update(expanded)
        if proto in ('udp', 'both'):
            udp_ports.update(expanded)

    tcp_list = [str(p) for p in sorted(tcp_ports)]
    udp_list = [str(p) for p in sorted(udp_ports)]

    whitelist_v4, wl_skipped = _collect_ipv4(whitelist_rows)
    blacklist_v4, bl_skipped = _collect_ipv4(blacklist_rows)

    tcp_text = ', '.join(tcp_list) if tcp_list else ''
    udp_text = ', '.join(udp_list) if udp_list else ''
    whitelist_text = ', '.join(whitelist_v4) if whitelist_v4 else ''
    blacklist_text = ', '.join(blacklist_v4) if blacklist_v4 else ''

    skipped_comment = ''
    all_skipped = wl_skipped + bl_skipped
    if all_skipped:
        skipped_comment = '    # IPv6 (не поддерживается в этом наборе): ' + ', '.join(all_skipped) + '\n'

    chain_parts = [
        '        iif lo accept',
        '        ct state established,related accept',
        '',
        f'        # Режим: {"только белый список" if mode == "whitelist" else "только чёрный список"}',
        '        # SSH не трогаем',
        '        tcp dport 22 accept',
    ]
    if tcp_list:
        chain_parts.append('')
        chain_parts.append('        # TCP-сервисы')
        chain_parts.append(_nft_proto_rules('tcp', 'web_tcp_ports', mode))
    if udp_list:
        chain_parts.append('')
        chain_parts.append('        # UDP-сервисы')
        chain_parts.append(_nft_proto_rules('udp', 'web_udp_ports', mode))

    chain_rules = '\n'.join(chain_parts)

    def _set_block(name, type_, extra, elements):
        lines = [f'    set {name} {{', f'        type {type_}']
        if extra:
            lines.append(f'        {extra}')
        if elements:
            lines.append(f'        elements = {{ {elements} }}')
        lines.append('    }')
        return '\n'.join(lines)

    set_tcp = _set_block('web_tcp_ports',    'inet_service', '',               tcp_text)
    set_udp = _set_block('web_udp_ports',    'inet_service', '',               udp_text)
    set_wl  = _set_block('web_whitelist_v4', 'ipv4_addr',    'flags interval', whitelist_text)
    set_bl  = _set_block('web_blacklist_v4', 'ipv4_addr',    'flags interval', blacklist_text)

    rules = f"""# Режим Butler: {mode}
{skipped_comment}table inet butler {{
{set_tcp}

{set_udp}

{set_wl}

{set_bl}

    chain input {{
        type filter hook input priority filter; policy accept;
{chain_rules}
    }}
}}
"""
    return rules, mode, all_skipped


def _nft_write_rules_file() -> Path:
    _, generated_file, _, _ = _nft_get_paths()
    rules, _, _ = _nft_build_rules()
    generated_file.write_text(rules, encoding='utf-8')
    return generated_file


def _nft_apply() -> tuple[Path, Path, Path | None]:
    _, generated_file, target_file, nftables_conf = _nft_get_paths()
    _nft_write_rules_file()
    backup_file = _backup_file(target_file)

    run_command(['sudo', '-n', '/usr/bin/mkdir', '-p', str(target_file.parent)],
                'Не удалось создать каталог для target-файла:')
    run_command(['sudo', '-n', '/usr/bin/install', '-m', '0644', str(generated_file), str(target_file)],
                'Не удалось установить target-файл:')
    run_command(['sudo', '-n', 'nft', '-c', '-f', str(nftables_conf)],
                'Проверка nftables-конфига не прошла:')
    run_command(['sudo', '-n', 'nft', '-f', str(nftables_conf)],
                'Не удалось применить правила:')
    return generated_file, target_file, backup_file


def _nft_reset() -> tuple[Path, Path | None]:
    _, generated_file, target_file, nftables_conf = _nft_get_paths()
    backup_file = _backup_file(target_file)

    empty = """table inet butler {
    set web_tcp_ports {
        type inet_service
    }

    set web_udp_ports {
        type inet_service
    }

    set web_whitelist_v4 {
        type ipv4_addr
        flags interval
    }

    set web_blacklist_v4 {
        type ipv4_addr
        flags interval
    }

    chain input {
        type filter hook input priority filter; policy accept;

        iif lo accept
        ct state established,related accept

        # Butler reset state: no managed ports
    }
}
"""
    generated_file.write_text(empty, encoding='utf-8')
    run_command(['sudo', '-n', '/usr/bin/mkdir', '-p', str(target_file.parent)],
                'Не удалось создать каталог для target-файла:')
    run_command(['sudo', '-n', '/usr/bin/install', '-m', '0644', str(generated_file), str(target_file)],
                'Не удалось установить reset target-файл:')
    run_command(['sudo', '-n', 'nft', '-c', '-f', str(nftables_conf)],
                'Проверка reset-конфига не прошла:')
    run_command(['sudo', '-n', 'nft', '-f', str(nftables_conf)],
                'Не удалось сбросить Butler-правила:')
    return target_file, backup_file


# ---------------------------------------------------------------------------
# UFW backend (new)
# ---------------------------------------------------------------------------

def _ufw_build_rules() -> tuple[str, str, list]:
    """Build a human-readable summary of UFW commands Butler would apply."""
    db = get_db()
    mode = get_setting('firewall_mode', 'whitelist')
    butler_port = _get_butler_port()

    services = db.execute('SELECT port, ports_raw, protocol FROM services ORDER BY port').fetchall()
    whitelist_rows = db.execute('SELECT ip_address FROM whitelist_entries WHERE enabled = 1 ORDER BY ip_address').fetchall()
    blacklist_rows = db.execute('SELECT ip_address FROM blacklist_entries WHERE enabled = 1 ORDER BY ip_address').fetchall()

    whitelist_v4, wl_skipped = _collect_ipv4(whitelist_rows)
    blacklist_v4, bl_skipped = _collect_ipv4(blacklist_rows)
    all_skipped = wl_skipped + bl_skipped

    lines = [f'# Butler UFW rules  (mode: {mode})']
    if all_skipped:
        lines.append('# IPv6 skipped: ' + ', '.join(all_skipped))
    lines.append('')
    lines.append('# --- protected system ports (never blocked) ---')
    lines.append('ufw allow 22/tcp')
    lines.append(f'ufw allow {butler_port}/tcp  # Butler web UI')
    lines.append('')

    if mode == 'whitelist':
        lines.append('# --- whitelist: allow only listed IPs to managed ports, deny rest ---')
        for row in services:
            proto = (row['protocol'] or 'tcp').lower()
            ports_raw = row['ports_raw'] or str(row['port'])
            expanded = parse_ports_raw(ports_raw) or [row['port']]
            for port in sorted(set(expanded)):
                if proto in ('tcp', 'both', 'udp'):
                    use_proto = 'tcp' if proto in ('tcp', 'both') else 'udp'
                    for ip in whitelist_v4:
                        lines.append(f'ufw allow from {ip} to any port {port} proto {use_proto}')
                    lines.append(f'ufw deny {port}/{use_proto}')
                    if proto == 'both':
                        for ip in whitelist_v4:
                            lines.append(f'ufw allow from {ip} to any port {port} proto udp')
                        lines.append(f'ufw deny {port}/udp')
    else:
        lines.append('# --- blacklist: block listed IPs, allow rest ---')
        for row in services:
            proto = (row['protocol'] or 'tcp').lower()
            ports_raw = row['ports_raw'] or str(row['port'])
            expanded = parse_ports_raw(ports_raw) or [row['port']]
            for port in sorted(set(expanded)):
                use_proto = 'tcp' if proto in ('tcp', 'both') else 'udp'
                for ip in blacklist_v4:
                    lines.append(f'ufw deny from {ip} to any port {port} proto {use_proto}')
                lines.append(f'ufw allow {port}/{use_proto}')
                if proto == 'both':
                    for ip in blacklist_v4:
                        lines.append(f'ufw deny from {ip} to any port {port} proto udp')
                    lines.append(f'ufw allow {port}/udp')

    return '\n'.join(lines) + '\n', mode, all_skipped


def _ufw_write_rules_file() -> Path:
    generated_dir = _generated_dir()
    generated_file = generated_dir / 'butler-ufw.sh'
    rules, _, _ = _ufw_build_rules()
    generated_file.write_text(rules, encoding='utf-8')
    generated_file.chmod(0o755)
    return generated_file


def _ufw_apply() -> tuple[Path, None, None]:
    """Apply rules via UFW.

    Protected ports (SSH + Butler web UI) are always allowed first
    to prevent self-lockout, regardless of whitelist/blacklist mode.
    """
    generated_file = _ufw_write_rules_file()
    db = get_db()
    mode = get_setting('firewall_mode', 'whitelist')
    butler_port = _get_butler_port()

    services = db.execute('SELECT port, ports_raw, protocol FROM services ORDER BY port').fetchall()
    whitelist_rows = db.execute('SELECT ip_address FROM whitelist_entries WHERE enabled = 1 ORDER BY ip_address').fetchall()
    blacklist_rows = db.execute('SELECT ip_address FROM blacklist_entries WHERE enabled = 1 ORDER BY ip_address').fetchall()

    whitelist_v4, _ = _collect_ipv4(whitelist_rows)
    blacklist_v4, _ = _collect_ipv4(blacklist_rows)

    # Step 1 — enable UFW
    run_command(['sudo', '-n', _UFW, '--force', 'enable'],
                'Не удалось включить UFW:')

    # Step 2 — always protect SSH and Butler UI port (self-lockout prevention)
    run_command(['sudo', '-n', _UFW, 'allow', '22/tcp'],
                'Не удалось добавить правило SSH:')
    run_command(['sudo', '-n', _UFW, 'allow', f'{butler_port}/tcp'],
                f'Не удалось защитить порт Butler ({butler_port}/tcp):')

    # Step 3 — apply service rules
    for row in services:
        proto = (row['protocol'] or 'tcp').lower()
        ports_raw = row['ports_raw'] or str(row['port'])
        expanded = parse_ports_raw(ports_raw) or [row['port']]

        for port in sorted(set(expanded)):
            # Never touch SSH or Butler port — already protected above
            if port in (22, butler_port):
                continue
            for use_proto in (['tcp', 'udp'] if proto == 'both' else [proto if proto in ('tcp', 'udp') else 'tcp']):
                if mode == 'whitelist':
                    for ip in whitelist_v4:
                        run_command(
                            ['sudo', '-n', _UFW, 'allow', 'from', ip, 'to', 'any', 'port', str(port), 'proto', use_proto],
                            f'Не удалось добавить whitelist-правило {ip}:{port}/{use_proto}:'
                        )
                    run_command(
                        ['sudo', '-n', _UFW, 'deny', f'{port}/{use_proto}'],
                        f'Не удалось добавить deny {port}/{use_proto}:'
                    )
                else:
                    for ip in blacklist_v4:
                        run_command(
                            ['sudo', '-n', _UFW, 'deny', 'from', ip, 'to', 'any', 'port', str(port), 'proto', use_proto],
                            f'Не удалось добавить blacklist-правило {ip}:{port}/{use_proto}:'
                        )
                    run_command(
                        ['sudo', '-n', _UFW, 'allow', f'{port}/{use_proto}'],
                        f'Не удалось добавить allow {port}/{use_proto}:'
                    )

    return generated_file, None, None


def _ufw_reset() -> tuple[None, None]:
    """Remove all Butler-managed UFW rules by resetting to defaults.

    After reset, SSH and Butler UI port are immediately re-allowed.
    """
    butler_port = _get_butler_port()
    run_command(['sudo', '-n', _UFW, '--force', 'reset'],
                'Не удалось сбросить UFW:')
    run_command(['sudo', '-n', _UFW, '--force', 'enable'],
                'Не удалось включить UFW после сброса:')
    run_command(['sudo', '-n', _UFW, 'allow', '22/tcp'],
                'Не удалось восстановить правило SSH после сброса:')
    run_command(['sudo', '-n', _UFW, 'allow', f'{butler_port}/tcp'],
                f'Не удалось защитить порт Butler ({butler_port}/tcp) после сброса:')
    return None, None
