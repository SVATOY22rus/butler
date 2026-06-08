"""
Тесты парсера логов и страницы попыток (чек-лист §10).
"""
import pytest


SAMPLE_LOG = """\
Jun  8 10:00:01 server kernel: BUTLER IN=eth0 OUT= MAC=... SRC=1.2.3.4 DST=5.5.5.5 LEN=60 TOS=0x00 PREC=0x00 TTL=50 ID=0 DF PROTO=TCP SPT=54321 DPT=80 WINDOW=65535 RES=0x00 SYN URGP=0
Jun  8 10:01:01 server kernel: BUTLER IN=eth0 OUT= MAC=... SRC=9.9.9.9 DST=5.5.5.5 LEN=60 TOS=0x00 PREC=0x00 TTL=50 ID=0 DF PROTO=TCP SPT=12345 DPT=443 WINDOW=65535 RES=0x00 SYN URGP=0
"""


def test_attempts_page_loads(auth_client):
    """10 — страница попыток открывается."""
    r = auth_client.get('/attempts')
    assert r.status_code == 200


def test_parse_nft_log_line(app):
    """Парсер лога выделяет SRC и DPT из строки с префиксом BUTLER."""
    with app.app_context():
        from app.routes import parse_nft_log_line
        line = 'Jun  8 10:00:01 server kernel: BUTLER IN=eth0 SRC=1.2.3.4 DST=5.5.5.5 PROTO=TCP SPT=54321 DPT=80'
        result = parse_nft_log_line(line)
        assert result is not None
        assert result['ip'] == '1.2.3.4'
        assert result['port'] == 80


def test_parse_nft_log_line_requires_src_dpt(app):
    """parse_nft_log_line возвращает None если нет SRC или DPT или IP невалиден."""
    with app.app_context():
        from app.routes import parse_nft_log_line
        assert parse_nft_log_line('Jun  8 kernel: BUTLER IN=eth0 DPT=80') is None
        assert parse_nft_log_line('Jun  8 kernel: BUTLER IN=eth0 SRC=1.2.3.4') is None
        assert parse_nft_log_line('Jun  8 kernel: BUTLER IN=eth0 SRC=invalid DPT=80') is None


def test_import_log_text(auth_client, app):
    """Импорт лога через API добавляет записи в таблицу attempts."""
    # Сначала добавим сервис на порт 80
    auth_client.post('/services', data={'name': 'WEB', 'ports_raw': '80',
                                        'protocol': 'tcp', 'description': ''},
                     follow_redirects=True)

    r = auth_client.post('/attempts/import-log', data={
        'log_source': 'text',
        'log_text': SAMPLE_LOG,
    }, follow_redirects=True)
    assert r.status_code == 200

    with app.app_context():
        from app.db import get_db
        rows = get_db().execute('SELECT * FROM attempts').fetchall()
        ips = [row['ip_address'] for row in rows]
        assert '1.2.3.4' in ips


def test_ip_label_in_attempts(auth_client, app):
    """10.5 — IP из белого списка имеет подпись в таблице попыток."""
    # Добавляем IP в белый список
    auth_client.post('/whitelist', data={
        'ip_address': '1.2.3.4', 'owner_name': 'Тестовый клиент', 'comment': ''
    }, follow_redirects=True)

    r = auth_client.get('/attempts')
    assert r.status_code == 200
    # На странице должны быть данные о метке (тест проверяет что страница не падает)
