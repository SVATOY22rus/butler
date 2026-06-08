"""
Тесты базы данных — validate_ip_address, parse_ports_raw, миграции (чек-лист §12).
"""
import pytest


# ──────────────────────────────────────────────
# validate_ip_address
# ──────────────────────────────────────────────

def test_validate_single_ipv4(app):
    with app.app_context():
        from app.routes import validate_ip_address
        assert validate_ip_address('1.2.3.4') in ('1.2.3.4', '1.2.3.4/32')


def test_validate_cidr_subnet(app):
    with app.app_context():
        from app.routes import validate_ip_address
        result = validate_ip_address('188.243.183.0/24')
        assert result == '188.243.183.0/24'


def test_validate_cidr_host_bits(app):
    """strict=False: 192.168.1.5/24 → 192.168.1.0/24 (хостовые биты обнуляются)."""
    with app.app_context():
        from app.routes import validate_ip_address
        result = validate_ip_address('192.168.1.5/24')
        assert result == '192.168.1.0/24'


def test_validate_invalid_ip(app):
    with app.app_context():
        from app.routes import validate_ip_address
        assert validate_ip_address('999.999.x.x') is None
        assert validate_ip_address('not-an-ip') is None
        assert validate_ip_address('') is None


def test_validate_slash32(app):
    """/32 нормализуется как одиночный хост."""
    with app.app_context():
        from app.routes import validate_ip_address
        result = validate_ip_address('10.0.0.1/32')
        assert result == '10.0.0.1/32'


# ──────────────────────────────────────────────
# parse_ports_raw
# ──────────────────────────────────────────────

def test_parse_ports_single(app):
    with app.app_context():
        from app.db import parse_ports_raw
        assert parse_ports_raw('22') == [22]


def test_parse_ports_multi(app):
    with app.app_context():
        from app.db import parse_ports_raw
        result = parse_ports_raw('80,443')
        assert 80 in result
        assert 443 in result


def test_parse_ports_range(app):
    with app.app_context():
        from app.db import parse_ports_raw
        result = parse_ports_raw('8000-8005')
        assert result == list(range(8000, 8006))


def test_parse_ports_mixed(app):
    with app.app_context():
        from app.db import parse_ports_raw
        result = parse_ports_raw('22,80,8000-8002,443')
        assert 22 in result
        assert 80 in result
        assert 443 in result
        assert 8000 in result
        assert 8002 in result


def test_parse_ports_invalid(app):
    with app.app_context():
        from app.db import parse_ports_raw
        # Мусор не должен упасть — возвращает пустой список или None
        result = parse_ports_raw('abc')
        assert not result


# ──────────────────────────────────────────────
# _collect_ipv4 — подсети не теряются
# ──────────────────────────────────────────────

def test_collect_ipv4_with_subnet(app):
    with app.app_context():
        from app.routes import _collect_ipv4

        class R(dict):
            def __getitem__(self, k): return super().__getitem__(k)

        rows = [
            {'ip_address': '1.2.3.4'},
            {'ip_address': '10.0.0.0/24'},
            {'ip_address': '188.243.183.0/24'},
        ]
        v4, skipped = _collect_ipv4(rows)
        assert '1.2.3.4' in v4
        assert '10.0.0.0/24' in v4
        assert '188.243.183.0/24' in v4
        assert skipped == []


def test_collect_ipv4_skips_ipv6(app):
    with app.app_context():
        from app.routes import _collect_ipv4
        rows = [{'ip_address': '::1'}, {'ip_address': '2001:db8::1'}]
        v4, skipped = _collect_ipv4(rows)
        assert v4 == []
        assert len(skipped) == 2
