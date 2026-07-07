import logging
import os
import secrets
from pathlib import Path
from dotenv import load_dotenv
from flask import Flask

from .db import close_db, init_app as init_db_app

_DEFAULT_SECRET = 'dev-secret-change-me'
_DEFAULT_ADMIN_PASS = 'change-me-now'


def _find_env_file():
    """
    Ищем butler.env:
    1. Через переменную окружения BUTLER_ENV_FILE
    2. Рядом с wsgi.py (в рабочей директории gunicorn)
    3. Уровнем выше (рядом с .butler/)
    4. Стандартный .env в текущей директории
    """
    explicit = os.environ.get('BUTLER_ENV_FILE')
    if explicit and Path(explicit).is_file():
        return Path(explicit)

    cwd = Path.cwd()
    for name in ('butler.env', '.env'):
        p = cwd / name
        if p.is_file():
            return p

    parent = cwd.parent
    for name in ('butler.env', '.env'):
        p = parent / name
        if p.is_file():
            return p

    return None


def create_app():
    env_file = _find_env_file()
    if env_file:
        load_dotenv(env_file, override=True)

    app = Flask(__name__, instance_relative_config=True)

    default_db = str(Path.cwd() / 'instance' / 'butler.sqlite3')

    # Безопасный дефолт SECRET_KEY: если ключ не задан или остался дефолтным —
    # генерируем случайный на старте (не падаем). Сессии будут инвалидироваться
    # при рестарте, но это лучше предсказуемого dev-ключа в проде.
    secret_key = os.environ.get('BUTLER_SECRET_KEY') or ''
    if not secret_key or secret_key == _DEFAULT_SECRET:
        secret_key = secrets.token_hex(32)
        logging.getLogger(__name__).warning(
            'BUTLER_SECRET_KEY не задан или дефолтный — сгенерирован случайный ключ. '
            'Задайте BUTLER_SECRET_KEY в butler.env для стабильных сессий.'
        )

    admin_pass = os.environ.get('BUTLER_ADMIN_PASS', _DEFAULT_ADMIN_PASS)
    if admin_pass == _DEFAULT_ADMIN_PASS:
        logging.getLogger(__name__).warning(
            'BUTLER_ADMIN_PASS оставлен дефолтным — смените пароль администратора в butler.env.'
        )

    app.config.from_mapping(
        SECRET_KEY=secret_key,
        DATABASE=os.environ.get('BUTLER_DATABASE') or default_db,
        BUTLER_HOST=os.environ.get('BUTLER_HOST', '0.0.0.0'),
        BUTLER_PORT=int(os.environ.get('BUTLER_PORT', '5050')),
        BUTLER_ADMIN_USER=os.environ.get('BUTLER_ADMIN_USER', 'admin'),
        BUTLER_ADMIN_PASS=admin_pass,
    )

    Path(app.config['DATABASE']).parent.mkdir(parents=True, exist_ok=True)
    os.makedirs(app.instance_path, exist_ok=True)

    init_db_app(app)

    from .routes import bp
    app.register_blueprint(bp)

    return app
