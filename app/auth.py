import secrets
from functools import wraps

from flask import current_app, flash, redirect, request, session, url_for


def check_auth(username, password):
    expected_user = current_app.config.get('BUTLER_ADMIN_USER', '')
    expected_pass = current_app.config.get('BUTLER_ADMIN_PASS', '')

    username_bytes = (username or '').encode('utf-8')
    password_bytes = (password or '').encode('utf-8')
    expected_user_bytes = expected_user.encode('utf-8')
    expected_pass_bytes = expected_pass.encode('utf-8')

    return (
        secrets.compare_digest(username_bytes, expected_user_bytes) and
        secrets.compare_digest(password_bytes, expected_pass_bytes)
    )


def login_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if not session.get('authenticated'):
            return redirect(url_for('main.login'))

        return view(*args, **kwargs)

    return wrapped_view