"""
Общие фикстуры pytest для Butler.
"""
import os
import tempfile
import pytest


@pytest.fixture
def app(tmp_path):
    db_path = str(tmp_path / 'test.sqlite3')

    # Конфигурация через env-переменные (как в реальном деплое)
    os.environ['BUTLER_ENV_FILE']        = ''
    os.environ['BUTLER_SECRET_KEY']      = 'test-secret-key'
    os.environ['BUTLER_DATABASE']        = db_path
    os.environ['BUTLER_ADMIN_USER']      = 'admin'
    os.environ['BUTLER_ADMIN_PASS']      = 'password'
    os.environ['BUTLER_FIREWALL_TARGET'] = str(tmp_path / 'butler.nft')
    os.environ['BUTLER_NFTABLES_CONF']   = str(tmp_path / 'nftables.conf')

    from app import create_app
    application = create_app()
    application.config['TESTING'] = True

    with application.app_context():
        from app.db import init_db
        init_db()

    yield application

    # Очищаем env чтобы не протекало между тестами
    for key in ['BUTLER_ENV_FILE', 'BUTLER_SECRET_KEY', 'BUTLER_DATABASE',
                'BUTLER_ADMIN_USER', 'BUTLER_ADMIN_PASS',
                'BUTLER_FIREWALL_TARGET', 'BUTLER_NFTABLES_CONF']:
        os.environ.pop(key, None)


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def auth_client(client):
    """Клиент с активной сессией."""
    client.post('/login', data={'username': 'admin', 'password': 'password'})
    return client
