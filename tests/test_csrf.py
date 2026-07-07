"""
Тесты CSRF-защиты (чек-лист §2).

Все изменяющие POST-запросы должны требовать корректный csrf_token.
Исключение — /login (там сессии ещё нет).
"""
import pytest

from conftest import post, get_csrf


def test_post_without_token_rejected(auth_client):
    """POST без csrf_token → 400."""
    r = auth_client.post('/whitelist', data={
        'ip_address': '1.2.3.4', 'owner_name': '', 'comment': ''
    })
    assert r.status_code == 400


def test_post_with_wrong_token_rejected(auth_client):
    """POST с неверным csrf_token → 400."""
    r = auth_client.post('/whitelist', data={
        'ip_address': '1.2.3.4', 'owner_name': '', 'comment': '',
        'csrf_token': 'deadbeefdeadbeef',
    })
    assert r.status_code == 400


def test_post_with_valid_token_ok(auth_client, app):
    """POST с корректным csrf_token проходит и запись создаётся."""
    r = post(auth_client, '/whitelist', data={
        'ip_address': '9.8.7.6', 'owner_name': '', 'comment': ''
    }, follow_redirects=True)
    assert r.status_code == 200

    with app.app_context():
        from app.db import get_db
        row = get_db().execute(
            "SELECT id FROM whitelist_entries WHERE ip_address IN ('9.8.7.6', '9.8.7.6/32')"
        ).fetchone()
        assert row is not None


def test_login_exempt_from_csrf(client):
    """/login не требует csrf_token (сессии ещё нет)."""
    r = client.post('/login', data={'username': 'admin', 'password': 'password'},
                    follow_redirects=True)
    assert r.status_code == 200


def test_logout_requires_csrf(auth_client):
    """/logout защищён CSRF — без токена 400."""
    r = auth_client.post('/logout')
    assert r.status_code == 400
