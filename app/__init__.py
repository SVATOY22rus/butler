import os
from pathlib import Path
from dotenv import load_dotenv
from flask import Flask

from .db import close_db, init_app as init_db_app


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

    app.config.from_mapping(
        SECRET_KEY=os.environ.get('BUTLER_SECRET_KEY', 'dev-secret-change-me'),
        DATABASE=os.environ.get('BUTLER_DATABASE') or default_db,
        BUTLER_HOST=os.environ.get('BUTLER_HOST', '0.0.0.0'),
        BUTLER_PORT=int(os.environ.get('BUTLER_PORT', '5000')),
        BUTLER_ADMIN_USER=os.environ.get('BUTLER_ADMIN_USER', 'admin'),
        BUTLER_ADMIN_PASS=os.environ.get('BUTLER_ADMIN_PASS', 'change-me-now'),
        # Firewall backend: 'ufw' or 'nftables' (default)
        BUTLER_BACKEND=os.environ.get('BUTLER_BACKEND', 'nftables'),
        # nftables-specific paths (ignored when BUTLER_BACKEND=ufw)
        BUTLER_FIREWALL_TARGET=os.environ.get('BUTLER_FIREWALL_TARGET', '/etc/nftables.d/butler.nft'),
        BUTLER_NFTABLES_CONF=os.environ.get('BUTLER_NFTABLES_CONF', '/etc/nftables.conf'),
    )

    Path(app.config['DATABASE']).parent.mkdir(parents=True, exist_ok=True)
    os.makedirs(app.instance_path, exist_ok=True)

    init_db_app(app)

    from .routes import bp
    app.register_blueprint(bp)

    return app
