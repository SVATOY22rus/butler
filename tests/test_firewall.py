"""
Тесты генерации UFW-правил и защиты критичных портов (чек-лист §6, §7).
"""
import pytest

from conftest import post


def set_mode(client, mode):
    return post(client, '/settings/firewall-mode', data={'mode': mode},
                follow_redirects=True)


def add_whitelist(client, ip):
    post(client, '/whitelist', data={'ip_address': ip, 'owner_name': '', 'comment': ''},
         follow_redirects=True)


def add_blacklist(client, ip):
    post(client, '/blacklist', data={'ip_address': ip, 'reason': '', 'comment': ''},
         follow_redirects=True)


def add_service(client, name, ports_raw, protocol='tcp'):
    post(client, '/services', data={'name': name, 'ports_raw': ports_raw,
                                     'protocol': protocol, 'description': ''},
         follow_redirects=True)


# ──────────────────────────────────────────────
# Переключение режима
# ──────────────────────────────────────────────

def test_firewall_page_loads(auth_client):
    r = auth_client.get('/firewall')
    assert r.status_code == 200


def test_switch_mode_to_blacklist(auth_client):
    """6.1 — переключить в blacklist."""
    r = set_mode(auth_client, 'blacklist')
    assert r.status_code == 200
    assert b'blacklist' in r.data or b'\xd1\x87\xd1\x91\xd1\x80\xd0\xbd' in r.data  # "чёрн"


def test_switch_mode_persists(auth_client, app):
    """6.3 — режим сохраняется в БД."""
    set_mode(auth_client, 'blacklist')
    with app.app_context():
        from app.db import get_setting
        assert get_setting('firewall_mode') == 'blacklist'

    set_mode(auth_client, 'whitelist')
    with app.app_context():
        from app.db import get_setting
        assert get_setting('firewall_mode') == 'whitelist'


# ──────────────────────────────────────────────
# Генерация UFW-правил
# ──────────────────────────────────────────────

def test_build_rules_whitelist_mode(auth_client, app):
    """7.4 — в whitelist-режиме allow для белого IP + deny на порт."""
    add_service(auth_client, 'WEB', '80')
    add_whitelist(auth_client, '192.168.1.1')
    set_mode(auth_client, 'whitelist')

    with app.app_context():
        from app.firewall import build_rules
        rules, mode, skipped = build_rules()

    assert mode == 'whitelist'
    assert '192.168.1.1' in rules
    assert 'allow from 192.168.1.1' in rules
    assert 'deny 80/tcp' in rules


def test_build_rules_blacklist_mode(auth_client, app):
    """7.5 — в blacklist-режиме deny для чёрного IP + allow на порт."""
    add_service(auth_client, 'WEB2', '443')
    add_blacklist(auth_client, '5.5.5.5')
    set_mode(auth_client, 'blacklist')

    with app.app_context():
        from app.firewall import build_rules
        rules, mode, skipped = build_rules()

    assert mode == 'blacklist'
    assert '5.5.5.5' in rules
    assert 'deny from 5.5.5.5' in rules
    assert 'allow 443/tcp' in rules


def test_build_rules_multiport(auth_client, app):
    """7.2 — мультипорт через запятую раскрывается в правилах."""
    add_service(auth_client, 'MULTI', '80,443')

    with app.app_context():
        from app.firewall import build_rules
        rules, _, _ = build_rules()

    assert '80/tcp' in rules
    assert '443/tcp' in rules


def test_build_rules_port_range(auth_client, app):
    """7.3 — диапазон портов раскрывается корректно."""
    add_service(auth_client, 'RANGE', '8000-8010')

    with app.app_context():
        from app.firewall import build_rules
        rules, _, _ = build_rules()

    for port in range(8000, 8011):
        assert f'{port}/tcp' in rules


def test_build_rules_subnet_in_whitelist(auth_client, app):
    """7.4 — CIDR-подсеть корректно попадает в правила."""
    add_whitelist(auth_client, '188.243.183.0/24')
    add_service(auth_client, 'TEST', '80')
    set_mode(auth_client, 'whitelist')

    with app.app_context():
        from app.firewall import build_rules
        rules, _, skipped = build_rules()

    assert '188.243.183.0/24' in rules
    assert skipped == []


def test_udp_service_uses_udp_proto(auth_client, app):
    """UDP-сервис даёт правило с proto udp, а не tcp."""
    add_service(auth_client, 'DNS', '53', protocol='udp')

    with app.app_context():
        from app.firewall import build_rules
        rules, _, _ = build_rules()

    assert '53/udp' in rules
    assert '53/tcp' not in rules


def test_both_protocol_appears_in_both(auth_client, app):
    """Протокол 'both' даёт правило и для tcp, и для udp."""
    add_service(auth_client, 'BOTH', '1194', protocol='both')

    with app.app_context():
        from app.firewall import build_rules
        rules, _, _ = build_rules()

    assert '1194/tcp' in rules
    assert '1194/udp' in rules


# ──────────────────────────────────────────────
# IPv6
# ──────────────────────────────────────────────

def test_build_rules_ipv6_whitelist(auth_client, app):
    """IPv6-адрес из белого списка попадает в правила."""
    add_whitelist(auth_client, '2001:db8::1')
    add_service(auth_client, 'V6WEB', '80')
    set_mode(auth_client, 'whitelist')

    with app.app_context():
        from app.firewall import build_rules
        rules, _, skipped = build_rules()

    assert '2001:db8::1' in rules
    assert skipped == []


def test_build_rules_ipv6_subnet(auth_client, app):
    """IPv6-подсеть из чёрного списка попадает в правила."""
    add_blacklist(auth_client, '2001:db8::/32')
    add_service(auth_client, 'V6WEB2', '443')
    set_mode(auth_client, 'blacklist')

    with app.app_context():
        from app.firewall import build_rules
        rules, _, skipped = build_rules()

    assert '2001:db8::/32' in rules
    assert skipped == []


# ──────────────────────────────────────────────
# Защита SSH и порта панели от deny
# ──────────────────────────────────────────────

def test_ssh_never_denied(auth_client, app):
    """SSH(22) всегда allow и никогда не появляется в deny-правилах сервисов."""
    add_service(auth_client, 'SSHSVC', '22')
    add_whitelist(auth_client, '192.168.1.1')
    set_mode(auth_client, 'whitelist')

    with app.app_context():
        from app.firewall import build_rules
        rules, _, _ = build_rules()

    assert 'allow 22/tcp' in rules
    assert 'deny 22/tcp' not in rules


def test_butler_port_never_denied(auth_client, app):
    """Порт панели Butler (5050) всегда allow и не блокируется deny."""
    add_service(auth_client, 'PANEL', '5050')
    add_whitelist(auth_client, '192.168.1.1')
    set_mode(auth_client, 'whitelist')

    with app.app_context():
        from app.firewall import build_rules
        rules, _, _ = build_rules()

    assert 'allow 5050/tcp' in rules
    assert 'deny 5050/tcp' not in rules


def test_firewall_preview_endpoint(auth_client):
    """Страница /firewall возвращает предпросмотр правил."""
    r = auth_client.get('/firewall')
    assert r.status_code == 200
    assert b'ufw' in r.data.lower() or b'butler' in r.data.lower()
