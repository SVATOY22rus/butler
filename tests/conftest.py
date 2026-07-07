"""
Общие фикстуры pytest для Butler.
"""
import os
import pytest


@pytest.fixture
def app(tmp_path):
    db_path = str(tmp_path / 'test.sqlite3')

    # Конфигурация через env-переменные (как в реальном деплое)
    os.environ['BUTLER_ENV_FILE']   = ''
    os.environ['BUTLER_SECRET_KEY'] = 'test-secret-key'
    os.environ['BUTLER_DATABASE']   = db_path
    os.environ['BUTLER_ADMIN_USER'] = 'admin'
    os.environ['BUTLER_ADMIN_PASS'] = 'password'
    os.environ['BUTLER_PORT']       = '5050'

    from app import create_app
    application = create_app()
    application.config['TESTING'] = True

    with application.app_context():
        from app.db import init_db
        init_db()

    yield application

    # Очищаем env чтобы не протекало между тестами
    for key in ['BUTLER_ENV_FILE', 'BUTLER_SECRET_KEY', 'BUTLER_DATABASE',
                'BUTLER_ADMIN_USER', 'BUTLER_ADMIN_PASS', 'BUTLER_PORT']:
        os.environ.pop(key, None)


def get_csrf(client):
    """Получить CSRF-токен из сессии клиента.

    Контекст-процессор кладёт токен в сессию при рендере любого шаблона,
    поэтому сначала делаем GET (login или, после входа, редирект на index —
    в обоих случаях рендерится base.html), затем читаем токен из сессии.
    """
    client.get('/login', follow_redirects=True)
    with client.session_transaction() as sess:
        return sess.get('csrf_token')


def post(client, url, data=None, **kwargs):
    """POST с автоматически подставленным CSRF-токеном."""
    payload = dict(data or {})
    payload.setdefault('csrf_token', get_csrf(client))
    return client.post(url, data=payload, **kwargs)


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def auth_client(client):
    """Клиент с активной сессией (login освобождён от CSRF-проверки)."""
    client.post('/login', data={'username': 'admin', 'password': 'password'})
    return client
