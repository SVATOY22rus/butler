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
    # В whitelist-режиме chain содержит web_whitelist_v4, а не web_blacklist_v4
    chain_section = rules.split('chain input')[1] if 'chain input' in rules else ''
    assert 'web_whitelist_v4' in chain_section
    assert 'web_blacklist_v4' not in chain_section


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

    assert rules.count('flags interval') >= 2  # web_whitelist_v4 и web_blacklist_v4


def test_firewall_preview_endpoint(auth_client):
    """Страница /firewall возвращает предпросмотр правил."""
    r = auth_client.get('/firewall')
    assert r.status_code == 200
    assert b'table' in r.data or b'butler' in r.data.lower()


def test_udp_service_goes_to_udp_set(auth_client, app):
    """UDP-сервис попадает в web_udp_ports, а не в web_tcp_ports."""
    add_service(auth_client, 'DNS', '53')
    # Обновим протокол напрямую в БД
    with app.app_context():
        from app.db import get_db
        get_db().execute("UPDATE services SET protocol='udp' WHERE name='DNS'")
        get_db().commit()
        from app.routes import build_nft_rules
        rules, _, _ = build_nft_rules()

    # 53 должен быть в udp-части
    udp_section = rules.split('set web_udp_ports')[1].split('}')[0]
    tcp_section = rules.split('set web_tcp_ports')[1].split('}')[0]
    assert '53' in udp_section
    assert '53' not in tcp_section


def test_tcp_service_not_in_udp_set(auth_client, app):
    """TCP-сервис не попадает в web_udp_ports."""
    add_service(auth_client, 'HTTP', '80')
    with app.app_context():
        from app.db import get_db
        get_db().execute("UPDATE services SET protocol='tcp' WHERE name='HTTP'")
        get_db().commit()
        from app.routes import build_nft_rules
        rules, _, _ = build_nft_rules()

    udp_section = rules.split('set web_udp_ports')[1].split('}')[0]
    assert '80' not in udp_section


def test_both_protocol_appears_in_both_sets(auth_client, app):
    """Протокол 'both' даёт порт и в TCP, и в UDP set."""
    add_service(auth_client, 'BOTH', '1194')
    with app.app_context():
        from app.db import get_db
        get_db().execute("UPDATE services SET protocol='both' WHERE name='BOTH'")
        get_db().commit()
        from app.routes import build_nft_rules
        rules, _, _ = build_nft_rules()

    tcp_section = rules.split('set web_tcp_ports')[1].split('}')[0]
    udp_section = rules.split('set web_udp_ports')[1].split('}')[0]
    assert '1194' in tcp_section
    assert '1194' in udp_section


def test_chain_uses_correct_proto_keyword(auth_client, app):
    """В chain input tcp-правила используют 'tcp dport', udp-правила 'udp dport'."""
    add_service(auth_client, 'WEB_T', '80')
    add_service(auth_client, 'DNS_U', '53')
    with app.app_context():
        from app.db import get_db
        get_db().execute("UPDATE services SET protocol='tcp' WHERE name='WEB_T'")
        get_db().execute("UPDATE services SET protocol='udp' WHERE name='DNS_U'")
        get_db().commit()
        from app.routes import build_nft_rules
        rules, _, _ = build_nft_rules()

    chain = rules.split('chain input')[1]
    assert 'tcp dport @web_tcp_ports' in chain
    assert 'udp dport @web_udp_ports' in chain
