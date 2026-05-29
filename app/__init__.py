import os
from dotenv import load_dotenv
from flask import Flask

from .db import close_db, init_app as init_db_app


load_dotenv()


def create_app():
    app = Flask(__name__, instance_relative_config=True)

    app.config.from_mapping(
        SECRET_KEY=os.environ.get('BUTLER_SECRET_KEY', 'dev-secret-change-me'),
        DATABASE=os.environ.get('BUTLER_DATABASE', os.path.join(app.instance_path, 'butler.sqlite3')),
        BUTLER_HOST=os.environ.get('BUTLER_HOST', '0.0.0.0'),
        BUTLER_PORT=int(os.environ.get('BUTLER_PORT', '5000')),
        BUTLER_ADMIN_USER=os.environ.get('BUTLER_ADMIN_USER', 'admin'),
        BUTLER_ADMIN_PASS=os.environ.get('BUTLER_ADMIN_PASS', 'change-me-now'),
        BUTLER_FIREWALL_TARGET=os.environ.get('BUTLER_FIREWALL_TARGET', '/etc/nftables.d/butler.nft'),
        BUTLER_NFTABLES_CONF=os.environ.get('BUTLER_NFTABLES_CONF', '/etc/nftables.conf'),
    )

    os.makedirs(app.instance_path, exist_ok=True)

    init_db_app(app)

    from .routes import bp
    app.register_blueprint(bp)

    return app
