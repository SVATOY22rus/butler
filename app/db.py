import sqlite3
from flask import current_app, g


SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS services (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    port INTEGER NOT NULL UNIQUE,
    protocol TEXT NOT NULL DEFAULT 'tcp',
    description TEXT,
    is_enabled INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS whitelist_entries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address TEXT NOT NULL,
    owner_name TEXT,
    comment TEXT,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS blacklist_entries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address TEXT NOT NULL,
    reason TEXT,
    comment TEXT,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address TEXT NOT NULL,
    service_name TEXT NOT NULL,
    port INTEGER NOT NULL,
    first_seen TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    attempts_count INTEGER NOT NULL DEFAULT 1,
    status TEXT NOT NULL DEFAULT 'new',
    note TEXT
);

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    action TEXT NOT NULL,
    target_type TEXT NOT NULL,
    target_value TEXT NOT NULL,
    comment TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
"""


def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(current_app.config['DATABASE'])
        g.db.row_factory = sqlite3.Row
    return g.db


def close_db(e=None):
    db = g.pop('db', None)
    if db is not None:
        db.close()


def init_db():
    db = get_db()
    db.executescript(SCHEMA_SQL)
    db.commit()


def get_setting(key, default=None):
    db = get_db()
    row = db.execute('SELECT value FROM settings WHERE key = ?', (key,)).fetchone()
    if row is None:
        return default
    return row['value']


def set_setting(key, value):
    db = get_db()
    db.execute(
        'INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value',
        (key, value)
    )
    db.commit()


def seed_demo_data():
    db = get_db()

    services_count = db.execute('SELECT COUNT(*) AS count FROM services').fetchone()['count']
    if services_count == 0:
        db.executemany(
            'INSERT INTO services (name, port, protocol, description) VALUES (?, ?, ?, ?)',
            [
                ('CRM', 8011, 'tcp', 'Внутренний CRM сервис'),
                ('API', 8080, 'tcp', 'Основной API сервис'),
                ('Admin Panel', 9000, 'tcp', 'Административная панель'),
            ]
        )

    attempts_count = db.execute('SELECT COUNT(*) AS count FROM attempts').fetchone()['count']
    if attempts_count == 0:
        db.executemany(
            'INSERT INTO attempts (ip_address, service_name, port, attempts_count, status, note) VALUES (?, ?, ?, ?, ?, ?)',
            [
                ('1.2.3.4', 'CRM', 8011, 4, 'new', 'Похоже на клиента'),
                ('5.6.7.8', 'API', 8080, 2, 'new', 'Неизвестный адрес'),
                ('9.9.9.9', 'Admin Panel', 9000, 7, 'blocked', 'Подозрительная активность'),
            ]
        )

    whitelist_count = db.execute('SELECT COUNT(*) AS count FROM whitelist_entries').fetchone()['count']
    if whitelist_count == 0:
        db.execute(
            'INSERT INTO whitelist_entries (ip_address, owner_name, comment) VALUES (?, ?, ?)',
            ('10.10.10.10', 'Тестовый клиент', 'Разрешен для проверки интерфейса')
        )

    blacklist_count = db.execute('SELECT COUNT(*) AS count FROM blacklist_entries').fetchone()['count']
    if blacklist_count == 0:
        db.execute(
            'INSERT INTO blacklist_entries (ip_address, reason, comment) VALUES (?, ?, ?)',
            ('11.11.11.11', 'Ручная блокировка', 'Тестовая запись в черном списке')
        )

    # Режим работы по умолчанию: whitelist
    mode_exists = db.execute("SELECT COUNT(*) AS count FROM settings WHERE key = 'firewall_mode'").fetchone()['count']
    if mode_exists == 0:
        db.execute("INSERT INTO settings (key, value) VALUES ('firewall_mode', 'whitelist')")

    db.commit()


def init_app(app):
    app.teardown_appcontext(close_db)

    @app.cli.command('init-db')
    def init_db_command():
        init_db()
        seed_demo_data()
        print('Database initialized and demo data added.')
