"""
Тесты белого и чёрного списков, включая CIDR-подсети (чек-лист §4, §5).
"""
import pytest


# ──────────────────────────────────────────────
# Белый список
# ──────────────────────────────────────────────

def add_whitelist(client, ip, owner='', comment=''):
    return client.post('/whitelist', data={
        'ip_address': ip,
        'owner_name': owner,
        'comment': comment,
    }, follow_redirects=True)


def test_whitelist_page_loads(auth_client):
    """4.1 — страница белого списка открывается."""
    r = auth_client.get('/whitelist')
    assert r.status_code == 200


def test_whitelist_add_single_ip(auth_client):
    """4.2 — добавить одиночный IP."""
    r = add_whitelist(auth_client, '192.168.1.10', owner='Тест')
    assert r.status_code == 200
    assert b'192.168.1.10' in r.data


def test_whitelist_add_subnet(auth_client):
    """4.3 — добавить подсеть CIDR."""
    r = add_whitelist(auth_client, '188.243.183.0/24', owner='Клиент')
    assert r.status_code == 200
    assert b'188.243.183.0/24' in r.data


def test_whitelist_invalid_ip(auth_client):
    """4.4 — некорректный IP не добавляется."""
    r = add_whitelist(auth_client, '999.999.x.x')
    assert r.status_code == 200
    # IP не должен появиться в таблице
    assert b'999.999.x.x' not in r.data


def test_whitelist_delete(auth_client, app):
    """4.6 — удаление записи из белого списка."""
    add_whitelist(auth_client, '1.2.3.4')
    with app.app_context():
        from app.db import get_db
        entry = get_db().execute(
            "SELECT id FROM whitelist_entries WHERE ip_address IN ('1.2.3.4', '1.2.3.4/32')"
        ).fetchone()
        assert entry is not None
        entry_id = entry['id']

    r = auth_client.post(f'/whitelist/{entry_id}/delete', follow_redirects=True)
    assert r.status_code == 200

    with app.app_context():
        from app.db import get_db
        entry = get_db().execute(
            "SELECT id FROM whitelist_entries WHERE ip_address IN ('1.2.3.4', '1.2.3.4/32') AND enabled=1"
        ).fetchone()
        assert entry is None


# ──────────────────────────────────────────────
# Чёрный список
# ──────────────────────────────────────────────

def add_blacklist(client, ip, reason='', comment=''):
    return client.post('/blacklist', data={
        'ip_address': ip,
        'reason': reason,
        'comment': comment,
    }, follow_redirects=True)


def test_blacklist_page_loads(auth_client):
    r = auth_client.get('/blacklist')
    assert r.status_code == 200


def test_blacklist_add_single_ip(auth_client):
    """5.2 — добавить одиночный IP в чёрный список."""
    r = add_blacklist(auth_client, '5.6.7.8', reason='сканирование')
    assert r.status_code == 200
    assert b'5.6.7.8' in r.data


def test_blacklist_add_subnet(auth_client):
    """5.3 — добавить подсеть в чёрный список."""
    r = add_blacklist(auth_client, '10.0.0.0/24', reason='тест')
    assert r.status_code == 200
    assert b'10.0.0.0/24' in r.data


def test_blacklist_invalid_ip(auth_client):
    """5.4 — некорректный IP не добавляется."""
    r = add_blacklist(auth_client, 'not-an-ip')
    assert r.status_code == 200
    assert b'not-an-ip' not in r.data
