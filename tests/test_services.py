"""
Тесты управления сервисами (чек-лист §3).
"""
import pytest


def add_service(client, name, ports_raw, protocol='tcp', description=''):
    return client.post('/services', data={
        'name': name,
        'ports_raw': ports_raw,
        'protocol': protocol,
        'description': description,
    }, follow_redirects=True)


def test_services_page_loads(auth_client):
    """3.1 — страница сервисов открывается."""
    r = auth_client.get('/services')
    assert r.status_code == 200


def test_add_service_single_port(auth_client):
    """3.2 — добавить сервис с одним портом."""
    r = add_service(auth_client, 'SSH', '22')
    assert r.status_code == 200
    assert b'SSH' in r.data


def test_add_service_multi_port(auth_client):
    """3.3 — добавить сервис с несколькими портами через запятую."""
    r = add_service(auth_client, 'WEB', '80,443')
    assert r.status_code == 200
    assert b'WEB' in r.data


def test_add_service_port_range(auth_client):
    """3.4 — добавить сервис с диапазоном портов."""
    r = add_service(auth_client, 'PROXY', '8000-8100', protocol='tcp')
    assert r.status_code == 200
    assert b'PROXY' in r.data


def test_delete_service(auth_client, app):
    """3.7 — удаление сервиса."""
    add_service(auth_client, 'TEMP', '9999')
    with app.app_context():
        from app.db import get_db
        db = get_db()
        service = db.execute("SELECT id FROM services WHERE name='TEMP'").fetchone()
        assert service is not None
        service_id = service['id']

    r = auth_client.post(f'/services/{service_id}/delete', follow_redirects=True)
    assert r.status_code == 200

    with app.app_context():
        from app.db import get_db
        db = get_db()
        service = db.execute("SELECT id FROM services WHERE name='TEMP'").fetchone()
        assert service is None
