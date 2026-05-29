import ipaddress
import sqlite3
import subprocess
from datetime import datetime
from pathlib import Path

import click
from flask import Blueprint, current_app, flash, redirect, render_template, request, session, url_for
from .auth import check_auth, login_required
from .db import get_db

bp = Blueprint('main', __name__)


def validate_ip_address(value):
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


def build_nft_rules():
    db = get_db()

    services = db.execute(
        'SELECT port FROM services ORDER BY port'
    ).fetchall()

    whitelist_rows = db.execute(
        'SELECT ip_address FROM whitelist_entries WHERE enabled = 1 ORDER BY ip_address'
    ).fetchall()

    blacklist_rows = db.execute(
        'SELECT ip_address FROM blacklist_entries WHERE enabled = 1 ORDER BY ip_address'
    ).fetchall()

    ports = [str(row['port']) for row in services]
    whitelist_v4 = []
    blacklist_v4 = []

    for row in whitelist_rows:
        try:
            ip_obj = ipaddress.ip_address(row['ip_address'])
            if ip_obj.version == 4:
                whitelist_v4.append(str(ip_obj))
        except ValueError:
            continue

    for row in blacklist_rows:
        try:
            ip_obj = ipaddress.ip_address(row['ip_address'])
            if ip_obj.version == 4:
                blacklist_v4.append(str(ip_obj))
        except ValueError:
            continue

    ports_text = ', '.join(ports) if ports else ''
    whitelist_text = ', '.join(whitelist_v4) if whitelist_v4 else ''
    blacklist_text = ', '.join(blacklist_v4) if blacklist_v4 else ''

    rules = f"""table inet butler {{
    set web_ports {{
        type inet_service
        elements = {{ {ports_text} }}
    }}

    set web_whitelist_v4 {{
        type ipv4_addr
        elements = {{ {whitelist_text} }}
    }}

    set web_blacklist_v4 {{
        type ipv4_addr
        elements = {{ {blacklist_text} }}
    }}

    chain input {{
        type filter hook input priority filter; policy accept;

        iif lo accept
        ct state established,related accept

        # SSH пока не трогаем панелью
        tcp dport 22 accept

        ip saddr @web_blacklist_v4 tcp dport @web_ports drop
        ip saddr @web_whitelist_v4 tcp dport @web_ports accept
        tcp dport @web_ports drop
    }}
}}
"""
    return rules


def ensure_firewall_dirs():
    generated_dir = Path('generated')
    backups_dir = Path('generated/backups')

    generated_dir.mkdir(exist_ok=True)
    backups_dir.mkdir(exist_ok=True)

    return generated_dir, backups_dir


@bp.cli.command('firewall-apply')
def firewall_apply_command():
    """Сгенерировать, проверить и применить Butler через основной nftables.conf."""
    try:
        generated_file, target_file, backup_file = apply_firewall_rules()
        click.echo(f'Правила успешно применены: {generated_file}')
        click.echo(f'Target обновлён: {target_file}')
        if backup_file:
            click.echo(f'Backup сохранён в: {backup_file}')
    except Exception as exc:
        raise click.ClickException(str(exc))


def get_firewall_paths():
    generated_dir = Path('generated')
    generated_dir.mkdir(exist_ok=True)

    generated_file = generated_dir / 'butler.nft'
    target_file = Path(current_app.config.get('BUTLER_FIREWALL_TARGET', '/etc/nftables.d/butler.nft'))
    nftables_conf = Path(current_app.config.get('BUTLER_NFTABLES_CONF', '/etc/nftables.conf'))

    return generated_dir, generated_file, target_file, nftables_conf


def write_generated_rules_file():
    _, generated_file, _, _ = get_firewall_paths()
    rules = build_nft_rules()
    generated_file.write_text(rules, encoding='utf-8')
    return generated_file


def run_command(command, error_prefix, timeout=10):
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError(f'{error_prefix}\nКоманда превысила timeout ({timeout}s).')

    if result.returncode != 0:
        raise RuntimeError(
            f'{error_prefix}\n' + (result.stderr.strip() or result.stdout.strip())
        )

    return result


def backup_existing_target_file(target_file):
    backup_dir = Path('generated/backups')
    backup_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime('%Y%m%d-%H%M%S')
    backup_file = backup_dir / f'butler-target-backup-{timestamp}.nft'

    exists_result = subprocess.run(
        ['sudo', '-n', 'test', '-f', str(target_file)],
        capture_output=True,
        text=True,
        timeout=5
    )
    if exists_result.returncode != 0:
        return None

    read_result = run_command(
        ['sudo', '-n', 'cat', str(target_file)],
        'Не удалось прочитать target-файл для backup:'
    )
    backup_file.write_text(read_result.stdout, encoding='utf-8')
    return backup_file


def apply_firewall_rules():
    _, generated_file, target_file, nftables_conf = get_firewall_paths()

    write_generated_rules_file()
    backup_file = backup_existing_target_file(target_file)

    run_command(
        ['sudo', '-n', 'mkdir', '-p', str(target_file.parent)],
        'Не удалось создать каталог для target-файла:'
    )

    run_command(
        ['sudo', '-n', 'install', '-m', '0644', str(generated_file), str(target_file)],
        'Не удалось установить target-файл:'
    )

    run_command(
        ['sudo', '-n', 'nft', '-c', '-f', str(nftables_conf)],
        'Проверка nftables-конфига не прошла:'
    )

    run_command(
        ['sudo', '-n', 'nft', '-f', str(nftables_conf)],
        'Не удалось применить правила:'
    )

    return generated_file, target_file, backup_file


def build_empty_butler_rules():
    return """table inet butler {
    set web_ports {
        type inet_service
        elements = { }
    }

    set web_whitelist_v4 {
        type ipv4_addr
        elements = { }
    }

    set web_blacklist_v4 {
        type ipv4_addr
        elements = { }
    }

    chain input {
        type filter hook input priority filter; policy accept;

        iif lo accept
        ct state established,related accept

        # Butler reset state: no managed ports
    }
}
"""


def reset_firewall_rules():
    _, generated_file, target_file, nftables_conf = get_firewall_paths()

    backup_file = backup_existing_target_file(target_file)

    empty_rules = build_empty_butler_rules()
    generated_file.write_text(empty_rules, encoding='utf-8')

    run_command(
        ['sudo', '-n', 'mkdir', '-p', str(target_file.parent)],
        'Не удалось создать каталог для target-файла:'
    )

    run_command(
        ['sudo', '-n', 'install', '-m', '0644', str(generated_file), str(target_file)],
        'Не удалось установить reset target-файл:'
    )

    run_command(
        ['sudo', '-n', 'nft', '-c', '-f', str(nftables_conf)],
        'Проверка reset-конфига не прошла:'
    )

    run_command(
        ['sudo', '-n', 'nft', '-f', str(nftables_conf)],
        'Не удалось сбросить Butler-правила:'
    )

    return target_file, backup_file


@bp.cli.command('firewall-reset')
def firewall_reset_command():
    """Сбросить Butler через основной nftables.conf."""
    try:
        target_file, backup_file = reset_firewall_rules()
        click.echo(f'Butler-правила сброшены: {target_file}')
        if backup_file:
            click.echo(f'Backup сохранён в: {backup_file}')
    except Exception as exc:
        raise click.ClickException(str(exc))
    

@bp.route('/')
@login_required
def index():
    db = get_db()
    stats = {
        'services': db.execute('SELECT COUNT(*) AS count FROM services').fetchone()['count'],
        'attempts': db.execute('SELECT COUNT(*) AS count FROM attempts').fetchone()['count'],
        'whitelist': db.execute('SELECT COUNT(*) AS count FROM whitelist_entries WHERE enabled = 1').fetchone()['count'],
        'blacklist': db.execute('SELECT COUNT(*) AS count FROM blacklist_entries WHERE enabled = 1').fetchone()['count'],
    }
    return render_template('index.html', stats=stats)


@bp.route('/services', methods=['GET', 'POST'])
@login_required
def services():
    db = get_db()

    if request.method == 'POST':
        name = request.form['name'].strip()
        port_raw = request.form['port'].strip()
        protocol = request.form['protocol'].strip() or 'tcp'
        description = request.form['description'].strip()

        error = None

        if not name:
            error = 'Имя сервиса обязательно.'
        elif not port_raw:
            error = 'Порт обязателен.'
        else:
            try:
                port = int(port_raw)
                if port < 1 or port > 65535:
                    error = 'Порт должен быть в диапазоне от 1 до 65535.'
            except ValueError:
                error = 'Порт должен быть числом.'

        if error is None:
            existing_service = db.execute(
                'SELECT id FROM services WHERE port = ?',
                (port,)
            ).fetchone()

            if existing_service is not None:
                error = f'Порт {port} уже занят другим сервисом.'

        if error is None:
            try:
                db.execute(
                    'INSERT INTO services (name, port, protocol, description) VALUES (?, ?, ?, ?)',
                    (name, port, protocol, description)
                )
                db.execute(
                    'INSERT INTO audit_log (action, target_type, target_value, comment) VALUES (?, ?, ?, ?)',
                    ('create', 'service', f'{name}:{port}', 'Сервис добавлен через веб-форму')
                )
                db.commit()
                flash(f'Сервис "{name}" успешно добавлен.', 'success')
                return redirect(url_for('main.services'))
            except sqlite3.IntegrityError:
                flash(f'Не удалось добавить сервис: порт {port} уже существует.', 'error')
        else:
            flash(error, 'error')

    rows = db.execute('SELECT * FROM services ORDER BY port').fetchall()
    return render_template('services.html', services=rows)


@bp.route('/services/<int:service_id>/delete', methods=['POST'])
@login_required
def delete_service(service_id):
    db = get_db()

    service = db.execute(
        'SELECT * FROM services WHERE id = ?',
        (service_id,)
    ).fetchone()

    if service is None:
        flash('Сервис не найден.', 'error')
        return redirect(url_for('main.services'))

    db.execute('DELETE FROM services WHERE id = ?', (service_id,))
    db.execute(
        'INSERT INTO audit_log (action, target_type, target_value, comment) VALUES (?, ?, ?, ?)',
        ('delete', 'service', f"{service['name']}:{service['port']}", 'Сервис удалён')
    )
    db.commit()

    flash(f'Сервис "{service["name"]}" удалён.', 'success')
    return redirect(url_for('main.services'))


@bp.route('/attempts')
@login_required
def attempts():
    db = get_db()
    rows = db.execute('SELECT * FROM attempts ORDER BY last_seen DESC, id DESC').fetchall()
    return render_template('attempts.html', attempts=rows)


@bp.route('/whitelist', methods=['GET', 'POST'])
@login_required
def whitelist():
    db = get_db()

    if request.method == 'POST':
        ip_address_raw = request.form['ip_address'].strip()
        owner_name = request.form['owner_name'].strip()
        comment = request.form['comment'].strip()

        error = None
        normalized_ip = None

        if not ip_address_raw:
            error = 'IP-адрес обязателен.'
        else:
            normalized_ip = validate_ip_address(ip_address_raw)
            if normalized_ip is None:
                error = 'Укажите корректный IPv4 или IPv6 адрес.'

        if error is None:
            existing_entry = db.execute(
                'SELECT id FROM whitelist_entries WHERE ip_address = ? AND enabled = 1',
                (normalized_ip,)
            ).fetchone()

            if existing_entry is not None:
                error = f'IP-адрес {normalized_ip} уже есть в белом списке.'

        if error is None:
            try:
                db.execute(
                    'INSERT INTO whitelist_entries (ip_address, owner_name, comment) VALUES (?, ?, ?)',
                    (normalized_ip, owner_name, comment)
                )
                db.execute(
                    'INSERT INTO audit_log (action, target_type, target_value, comment) VALUES (?, ?, ?, ?)',
                    ('allow', 'ip', normalized_ip, comment or 'IP добавлен в белый список')
                )
                db.commit()
                flash(f'IP {normalized_ip} добавлен в белый список.', 'success')
                return redirect(url_for('main.whitelist'))
            except sqlite3.IntegrityError:
                flash(f'Не удалось добавить IP {normalized_ip} в белый список.', 'error')
        else:
            flash(error, 'error')

    rows = db.execute(
        'SELECT * FROM whitelist_entries WHERE enabled = 1 ORDER BY created_at DESC, id DESC'
    ).fetchall()
    return render_template('whitelist.html', entries=rows)


@bp.route('/whitelist/<int:entry_id>/delete', methods=['POST'])
@login_required
def delete_whitelist_entry(entry_id):
    db = get_db()

    entry = db.execute(
        'SELECT * FROM whitelist_entries WHERE id = ? AND enabled = 1',
        (entry_id,)
    ).fetchone()

    if entry is None:
        flash('Запись белого списка не найдена.', 'error')
        return redirect(url_for('main.whitelist'))

    db.execute(
        'UPDATE whitelist_entries SET enabled = 0 WHERE id = ?',
        (entry_id,)
    )
    db.execute(
        'INSERT INTO audit_log (action, target_type, target_value, comment) VALUES (?, ?, ?, ?)',
        ('delete', 'whitelist', entry['ip_address'], 'Запись отключена в белом списке')
    )
    db.commit()

    flash(f'IP {entry["ip_address"]} удалён из белого списка.', 'success')
    return redirect(url_for('main.whitelist'))


@bp.route('/whitelist/<int:entry_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_whitelist_entry(entry_id):
    db = get_db()

    entry = db.execute(
        'SELECT * FROM whitelist_entries WHERE id = ? AND enabled = 1',
        (entry_id,)
    ).fetchone()

    if entry is None:
        flash('Запись белого списка не найдена.', 'error')
        return redirect(url_for('main.whitelist'))

    if request.method == 'POST':
        ip_address_raw = request.form['ip_address'].strip()
        owner_name = request.form['owner_name'].strip()
        comment = request.form['comment'].strip()

        error = None
        normalized_ip = None

        if not ip_address_raw:
            error = 'IP-адрес обязателен.'
        else:
            normalized_ip = validate_ip_address(ip_address_raw)
            if normalized_ip is None:
                error = 'Укажите корректный IPv4 или IPv6 адрес.'

        if error is None:
            existing_entry = db.execute(
                'SELECT id FROM whitelist_entries WHERE ip_address = ? AND enabled = 1 AND id != ?',
                (normalized_ip, entry_id)
            ).fetchone()

            if existing_entry is not None:
                error = f'IP-адрес {normalized_ip} уже есть в белом списке.'

        if error is None:
            db.execute(
                '''
                UPDATE whitelist_entries
                SET ip_address = ?, owner_name = ?, comment = ?
                WHERE id = ?
                ''',
                (normalized_ip, owner_name, comment, entry_id)
            )
            db.execute(
                'INSERT INTO audit_log (action, target_type, target_value, comment) VALUES (?, ?, ?, ?)',
                ('update', 'whitelist', normalized_ip, 'Запись белого списка изменена')
            )
            db.commit()

            flash(f'Запись {normalized_ip} обновлена.', 'success')
            return redirect(url_for('main.whitelist'))

        flash(error, 'error')

        entry = {
            'id': entry_id,
            'ip_address': ip_address_raw,
            'owner_name': owner_name,
            'comment': comment
        }

    return render_template('whitelist_edit.html', entry=entry)


@bp.route('/blacklist', methods=['GET', 'POST'])
@login_required
def blacklist():
    db = get_db()
    if request.method == 'POST':
        ip_address = request.form['ip_address'].strip()
        reason = request.form['reason'].strip()
        comment = request.form['comment'].strip()

        if ip_address:
            db.execute(
                'INSERT INTO blacklist_entries (ip_address, reason, comment) VALUES (?, ?, ?)',
                (ip_address, reason, comment)
            )
            db.execute(
                'INSERT INTO audit_log (action, target_type, target_value, comment) VALUES (?, ?, ?, ?)',
                ('block', 'ip', ip_address, comment or reason or 'IP добавлен в черный список')
            )
            db.commit()
        return redirect(url_for('main.blacklist'))

    rows = db.execute(
        'SELECT * FROM blacklist_entries WHERE enabled = 1 ORDER BY created_at DESC, id DESC'
    ).fetchall()
    return render_template('blacklist.html', entries=rows)


@bp.route('/blacklist/<int:entry_id>/delete', methods=['POST'])
@login_required
def delete_blacklist_entry(entry_id):
    db = get_db()

    entry = db.execute(
        'SELECT * FROM blacklist_entries WHERE id = ? AND enabled = 1',
        (entry_id,)
    ).fetchone()

    if entry is None:
        flash('Запись чёрного списка не найдена.', 'error')
        return redirect(url_for('main.blacklist'))

    db.execute(
        'UPDATE blacklist_entries SET enabled = 0 WHERE id = ?',
        (entry_id,)
    )
    db.execute(
        'INSERT INTO audit_log (action, target_type, target_value, comment) VALUES (?, ?, ?, ?)',
        ('delete', 'blacklist', entry['ip_address'], 'Запись отключена в чёрном списке')
    )
    db.commit()

    flash(f'IP {entry["ip_address"]} удалён из чёрного списка.', 'success')
    return redirect(url_for('main.blacklist'))


@bp.route('/blacklist/<int:entry_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_blacklist_entry(entry_id):
    db = get_db()

    entry = db.execute(
        'SELECT * FROM blacklist_entries WHERE id = ? AND enabled = 1',
        (entry_id,)
    ).fetchone()

    if entry is None:
        flash('Запись чёрного списка не найдена.', 'error')
        return redirect(url_for('main.blacklist'))

    if request.method == 'POST':
        ip_address_raw = request.form['ip_address'].strip()
        reason = request.form['reason'].strip()
        comment = request.form['comment'].strip()

        error = None
        normalized_ip = None

        if not ip_address_raw:
            error = 'IP-адрес обязателен.'
        else:
            normalized_ip = validate_ip_address(ip_address_raw)
            if normalized_ip is None:
                error = 'Укажите корректный IPv4 или IPv6 адрес.'

        if error is None:
            existing_entry = db.execute(
                'SELECT id FROM blacklist_entries WHERE ip_address = ? AND enabled = 1 AND id != ?',
                (normalized_ip, entry_id)
            ).fetchone()

            if existing_entry is not None:
                error = f'IP-адрес {normalized_ip} уже есть в чёрном списке.'

        if error is None:
            db.execute(
                '''
                UPDATE blacklist_entries
                SET ip_address = ?, reason = ?, comment = ?
                WHERE id = ?
                ''',
                (normalized_ip, reason, comment, entry_id)
            )
            db.execute(
                'INSERT INTO audit_log (action, target_type, target_value, comment) VALUES (?, ?, ?, ?)',
                ('update', 'blacklist', normalized_ip, 'Запись чёрного списка изменена')
            )
            db.commit()

            flash(f'Запись {normalized_ip} обновлена.', 'success')
            return redirect(url_for('main.blacklist'))

        flash(error, 'error')

        entry = {
            'id': entry_id,
            'ip_address': ip_address_raw,
            'reason': reason,
            'comment': comment
        }

    return render_template('blacklist_edit.html', entry=entry)


@bp.route('/audit-log')
@login_required
def audit_log():
    db = get_db()
    rows = db.execute('SELECT * FROM audit_log ORDER BY created_at DESC, id DESC').fetchall()
    return render_template('audit_log.html', entries=rows)


@bp.route('/firewall')
@login_required
def firewall():
    rules = build_nft_rules()
    return render_template('firewall.html', rules=rules)

@bp.route('/firewall/export', methods=['POST'])
@login_required
def export_firewall():
    rules = build_nft_rules()

    output_dir = Path('generated')
    output_dir.mkdir(exist_ok=True)

    output_file = output_dir / 'butler.nft'
    output_file.write_text(rules, encoding='utf-8')

    flash(f'Файл правил сохранён: {output_file}', 'success')
    return redirect(url_for('main.firewall'))


@bp.route('/firewall/apply', methods=['POST'])
@login_required
def firewall_apply():
    try:
        generated_file, target_file, backup_file = apply_firewall_rules()

        if backup_file:
            flash(
                f'Правила применены. Generated: {generated_file}. Target: {target_file}. Backup: {backup_file}',
                'success'
            )
        else:
            flash(
                f'Правила применены. Generated: {generated_file}. Target: {target_file}',
                'success'
            )
    except Exception as exc:
        flash(str(exc), 'error')

    return redirect(url_for('main.firewall'))


@bp.route('/firewall/reset', methods=['POST'])
@login_required
def firewall_reset():
    try:
        target_file, backup_file = reset_firewall_rules()

        if backup_file:
            flash(
                f'Butler-правила сброшены. Target: {target_file}. Backup: {backup_file}',
                'success'
            )
        else:
            flash(
                f'Butler-правила сброшены. Target: {target_file}',
                'success'
            )
    except Exception as exc:
        flash(str(exc), 'error')

    return redirect(url_for('main.firewall'))


@bp.route('/login', methods=['GET', 'POST'])
def login():
    if session.get('authenticated'):
        return redirect(url_for('main.index'))

    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')

        if check_auth(username, password):
            session.clear()
            session['authenticated'] = True
            session['username'] = username
            flash('Вы успешно вошли в систему.', 'success')
            return redirect(url_for('main.index'))

        flash('Неверный логин или пароль.', 'error')

    return render_template('login.html')


@bp.route('/logout', methods=['POST'])
def logout():
    session.clear()
    flash('Вы вышли из системы.', 'success')
    return redirect(url_for('main.login'))


