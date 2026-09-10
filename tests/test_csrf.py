"""
Тесты CSRF-защиты.

Регрессия: бэкенд валидировал csrf_token на всех POST-эндпоинтах, но ни один
шаблон не отдавал скрытое поле csrf_token — из-за чего любое действие в
веб-интерфейсе падало с "Bad Request: CSRF token missing or invalid."
"""
import re

import pytest

# Страницы, которые рендерят формы и требуют авторизации
PAGES = ['/', '/whitelist', '/blacklist', '/services', '/firewall', '/attempts']

FORM_RE = re.compile(r'<form\b[^>]*method\s*=\s*["\']?post', re.I | re.S)
TOKEN_RE = re.compile(r'name="csrf_token"')


@pytest.mark.parametrize('path', PAGES)
def test_every_post_form_has_csrf_field(auth_client, path):
    """Каждая POST-форма на странице должна содержать скрытое поле csrf_token."""
    r = auth_client.get(path)
    assert r.status_code == 200, f'{path} не открылась'

    html = r.get_data(as_text=True)
    forms = len(FORM_RE.findall(html))
    tokens = len(TOKEN_RE.findall(html))

    assert forms > 0, f'{path}: POST-форм не найдено, тест бесполезен'
    assert tokens >= forms, (
        f'{path}: POST-форм {forms}, а полей csrf_token {tokens} — '
        f'формы без токена дадут 400'
    )


def test_login_page_has_csrf_field(client):
    """Страница входа тоже должна отдавать токен."""
    html = client.get('/login').get_data(as_text=True)
    assert TOKEN_RE.search(html), 'login.html без поля csrf_token'


def test_post_without_token_is_rejected(auth_client):
    """Без токена запрос обязан отклоняться — защита реально работает."""
    r = auth_client.post(
        '/services',
        data={'name': 'EVIL', 'ports_raw': '22', 'protocol': 'tcp'},
        no_csrf=True,
    )
    assert r.status_code == 400


def test_post_with_wrong_token_is_rejected(auth_client):
    """Подделанный токен не должен проходить."""
    r = auth_client.post(
        '/services',
        data={
            'name': 'EVIL',
            'ports_raw': '22',
            'protocol': 'tcp',
            'csrf_token': 'deadbeef' * 8,
        },
    )
    assert r.status_code == 400
