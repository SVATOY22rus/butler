import os
from flask import Flask
from .db import init_app as init_db_app


def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=True)

    app.config.from_mapping(
        SECRET_KEY='dev',
        DATABASE=os.path.join(app.instance_path, 'dvoretsky.sqlite'),
    )

    if test_config is not None:
        app.config.update(test_config)

    os.makedirs(app.instance_path, exist_ok=True)

    init_db_app(app)

    from .routes import bp
    app.register_blueprint(bp)

    return app
