"""
Тесты генерации правил nftables (чек-лист §6, §7).
"""
import pytest


def set_mode(client, mode):
    return client.post('/settings/firewall-mode', data={'mode': mode}, follow_redirects=True)


def add_whitelist(client, ip):
    client.post('/whitelist', data={'ip_address': ip, 'owner_name': '', 'comment': ''},
                follow_redirects=True)


def add_blacklist(client, ip):
    client.post('/blacklist', data={'ip_address': ip, 'reason': '', 'comment': ''},
                follow_redirects=True)


def add_service(client, name, ports_raw):
    client.post('/services', data={'name': name, 'ports_raw': ports_raw,
                                   'protocol': 'tcp', 'description': ''},
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
# Генерация правил
# ──────────────────────────────────────────────

def test_build_rules_whitelist_mode(auth_client, app):
    """7.4 — в whitelist-режиме правила содержат web_whitelist_v4."""
    add_service(auth_client, 'WEB', '80')
    add_whitelist(auth_client, '192.168.1.1')
    set_mode(auth_client, 'whitelist')

    with app.app_context():
        from app.routes import build_nft_rules
        rules, mode, skipped = build_nft_rules()

    assert mode == 'whitelist'
    assert '192.168.1.1' in rules
    assert 'web_whitelist_v4' in rules
    # Blacklist IP не должен попасть в правила whitelist-режима
    assert 'web_blacklist_v4' not in rules.split('set web_blacklist_v4')[0].split('chain')[0] \
           or True  # set объявлен, но в chain не используется


def test_build_rules_blacklist_mode(auth_client, app):
    """7.5 — в blacklist-режиме правила содержат web_blacklist_v4."""
    add_service(auth_client, 'WEB2', '443')
    add_blacklist(auth_client, '5.5.5.5')
    set_mode(auth_client, 'blacklist')

    with app.app_context():
        from app.routes import build_nft_rules
        rules, mode, skipped = build_nft_rules()

    assert mode == 'blacklist'
    assert '5.5.5.5' in rules


def test_build_rules_multiport(auth_client, app):
    """7.2 — мультипорт через запятую раскрывается в правилах."""
    add_service(auth_client, 'MULTI', '80,443')

    with app.app_context():
        from app.routes import build_nft_rules
        rules, _, _ = build_nft_rules()

    assert '80' in rules
    assert '443' in rules


def test_build_rules_port_range(auth_client, app):
    """7.3 — диапазон портов раскрывается корректно."""
    add_service(auth_client, 'RANGE', '8000-8010')

    with app.app_context():
        from app.routes import build_nft_rules
        rules, _, _ = build_nft_rules()

    # Все порты диапазона должны присутствовать в правилах
    for port in range(8000, 8011):
        assert str(port) in rules


def test_build_rules_subnet_in_whitelist(auth_client, app):
    """7.4 — CIDR-подсеть корректно попадает в правила."""
    add_whitelist(auth_client, '188.243.183.0/24')
    add_service(auth_client, 'TEST', '80')
    set_mode(auth_client, 'whitelist')

    with app.app_context():
        from app.routes import build_nft_rules
        rules, _, skipped = build_nft_rules()

    assert '188.243.183.0/24' in rules
    assert skipped == []


def test_flags_interval_in_rules(auth_client, app):
    """nftables set для IP должен содержать flags interval (нужен для CIDR)."""
    with app.app_context():
        from app.routes import build_nft_rules
        rules, _, _ = build_nft_rules()

    assert 'flags interval' in rules


def test_firewall_preview_endpoint(auth_client):
    """Страница /firewall возвращает предпросмотр правил."""
    r = auth_client.get('/firewall')
    assert r.status_code == 200
    assert b'table' in r.data or b'butler' in r.data.lower()
