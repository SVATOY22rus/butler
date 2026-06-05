# Инструкция по деплою Butler на Linux-сервер (Debian/Ubuntu)

> Без использования git и без доступа в интернет на целевом сервере.

---

## Часть 1 — Подготовка архива (машина разработчика, с интернетом)

### Переменные

```bash
PROJECT_DIR="/path/to/butler"       # путь к проекту локально
ARCHIVE_NAME="butler-deploy.tar.gz"
PYTHON_BIN="python3"
```

### 1.1 Скачать Python-зависимости в папку `wheels/`

```bash
cd "$PROJECT_DIR"
rm -rf wheels/ && mkdir wheels/

# --python-version и --abi должны совпадать с Python на целевом сервере
# Проверить заранее: python3 --version
$PYTHON_BIN -m pip download \
  --dest wheels/ \
  --platform linux_x86_64 \
  --python-version 3.11 \
  --implementation cp \
  --abi cp311 \
  --only-binary=:all: \
  -r requirements.txt

# Если часть пакетов не имеет бинарных wheels — без флагов:
# $PYTHON_BIN -m pip download --dest wheels/ -r requirements.txt
```

### 1.2 Собрать архив

```bash
cd "$(dirname "$PROJECT_DIR")"

tar -czf "$ARCHIVE_NAME" \
  --exclude="$(basename "$PROJECT_DIR")/.git" \
  --exclude="$(basename "$PROJECT_DIR")/.venv" \
  --exclude="$(basename "$PROJECT_DIR")/instance" \
  --exclude="$(basename "$PROJECT_DIR")/generated" \
  --exclude="$(basename "$PROJECT_DIR")/__pycache__" \
  --exclude="$(basename "$PROJECT_DIR")/app/__pycache__" \
  --exclude="$(basename "$PROJECT_DIR")/*.pyc" \
  "$(basename "$PROJECT_DIR")"

ls -lh "$ARCHIVE_NAME"
```

### 1.3 Проверить содержимое архива

```bash
tar -tzf "$ARCHIVE_NAME" | sort
```

Обязательно присутствуют:
```
butler/app/
butler/wsgi.py
butler/requirements.txt
butler/wheels/
butler/butler.service
butler/butler-log-import.service
butler/butler-log-import.timer
butler/install_butler_sudoers.sh
butler/env.example
```

Не должны присутствовать: `.git/`, `.venv/`, `instance/`, `__pycache__/`

### 1.4 Перенести архив на сервер

```bash
scp "$ARCHIVE_NAME" user@target-server:/tmp/
```

---

## Часть 2 — Установка на сервере (без интернета)

### Переменные

```bash
APP_USER="loktar"
APP_GROUP="loktar"
APP_DIR="/home/${APP_USER}/serv/butler"
ARCHIVE_PATH="/tmp/butler-deploy.tar.gz"
ENV_DIR="/etc/butler"
ENV_FILE="${ENV_DIR}/butler.env"
```

### 2.1 Создать пользователя (если нужно)

```bash
id "${APP_USER}" &>/dev/null || useradd -m -s /bin/bash "${APP_USER}"
```

### 2.2 Установить системные пакеты

```bash
apt-get install -y python3 python3-venv python3-pip conntrack nftables

# Проверить
python3 --version
conntrack --version
nft --version
```

### 2.3 Распаковать архив

```bash
mkdir -p "$(dirname "$APP_DIR")"
cd "$(dirname "$APP_DIR")"
tar -xzf "$ARCHIVE_PATH"
chown -R "${APP_USER}:${APP_GROUP}" "$APP_DIR"
```

### 2.4 Создать venv и установить зависимости

```bash
su - "${APP_USER}" -c "python3 -m venv ${APP_DIR}/.venv"

su - "${APP_USER}" -c "
  ${APP_DIR}/.venv/bin/pip install \
    --no-index \
    --find-links=${APP_DIR}/wheels/ \
    -r ${APP_DIR}/requirements.txt
"

# Проверить
su - "${APP_USER}" -c "${APP_DIR}/.venv/bin/pip list"
```

### 2.5 Создать конфиг окружения

```bash
mkdir -p "$ENV_DIR"
SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")

cat > "$ENV_FILE" <<EOF
BUTLER_SECRET_KEY=${SECRET_KEY}
BUTLER_DATABASE=${APP_DIR}/instance/butler.sqlite3
BUTLER_HOST=0.0.0.0
BUTLER_PORT=5050
BUTLER_ADMIN_USER=admin
BUTLER_ADMIN_PASS=change-me-now
BUTLER_FIREWALL_TARGET=/etc/nftables.d/butler.nft
BUTLER_NFTABLES_CONF=/etc/nftables.conf
EOF

chmod 640 "$ENV_FILE"
chown root:"${APP_GROUP}" "$ENV_FILE"
```

> **Обязательно** смените `BUTLER_ADMIN_PASS` перед запуском.

### 2.6 Адаптировать systemd unit-файлы под пользователя

```bash
for UNIT_FILE in \
  "${APP_DIR}/butler.service" \
  "${APP_DIR}/butler-log-import.service"; do

  sed -i \
    -e "s|User=.*|User=${APP_USER}|g" \
    -e "s|Group=.*|Group=${APP_GROUP}|g" \
    -e "s|/home/loktar/serv/butler|${APP_DIR}|g" \
    "$UNIT_FILE"
done
```

### 2.7 Инициализировать БД

```bash
mkdir -p "${APP_DIR}/instance"
chown "${APP_USER}:${APP_GROUP}" "${APP_DIR}/instance"

su - "${APP_USER}" -c "
  cd ${APP_DIR}
  ${APP_DIR}/.venv/bin/flask --app app init-db
"
```

Если БД уже существовала (обновление) — добавить таблицу settings вручную:

```bash
su - "${APP_USER}" -c "
  ${APP_DIR}/.venv/bin/python3 -c \"
import sqlite3
con = sqlite3.connect('${APP_DIR}/instance/butler.sqlite3')
con.execute('CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)')
con.execute(\\\"INSERT OR IGNORE INTO settings (key, value) VALUES ('firewall_mode', 'whitelist')\\\")
con.commit(); con.close()
print('settings OK')
\"
"
```

### 2.8 Настроить sudoers

```bash
chmod +x "${APP_DIR}/install_butler_sudoers.sh"
bash "${APP_DIR}/install_butler_sudoers.sh" "${APP_USER}"
visudo -c && echo "sudoers OK"
```

### 2.9 Установить и активировать systemd units

```bash
cp "${APP_DIR}/butler.service"            /etc/systemd/system/
cp "${APP_DIR}/butler-log-import.service" /etc/systemd/system/
cp "${APP_DIR}/butler-log-import.timer"   /etc/systemd/system/

systemctl daemon-reload
systemctl enable --now butler.service
systemctl enable --now butler-log-import.timer
```

### 2.10 Проверка после установки

```bash
systemctl status butler.service --no-pager
ss -tlnp | grep 5050
curl -s http://127.0.0.1:5050/ | head -5
```

---

## Часть 3 — Обновление существующей установки

### Переменные

```bash
APP_USER="loktar"
APP_DIR="/home/${APP_USER}/serv/butler"
NEW_ARCHIVE="/tmp/butler-deploy.tar.gz"
BACKUP_DIR="/tmp/butler-backup-$(date +%Y%m%d_%H%M%S)"
```

### 3.1 Остановить сервисы

```bash
systemctl stop butler.service
systemctl stop butler-log-import.timer
```

### 3.2 Резервная копия данных

```bash
mkdir -p "$BACKUP_DIR"
cp -a "${APP_DIR}/instance"  "${BACKUP_DIR}/"
cp /etc/butler/butler.env    "${BACKUP_DIR}/butler.env.bak"
echo "Бэкап: $BACKUP_DIR"
```

### 3.3 Распаковать новый архив

```bash
cd "$(dirname "$APP_DIR")"
tar -xzf "$NEW_ARCHIVE"
chown -R "${APP_USER}:${APP_GROUP}" "$APP_DIR"
```

### 3.4 Обновить зависимости

```bash
su - "${APP_USER}" -c "
  ${APP_DIR}/.venv/bin/pip install \
    --no-index \
    --find-links=${APP_DIR}/wheels/ \
    -r ${APP_DIR}/requirements.txt
"
```

### 3.5 Применить миграции БД

```bash
# init-db безопасно запускать повторно — таблицы CREATE IF NOT EXISTS
su - "${APP_USER}" -c "
  cd ${APP_DIR}
  ${APP_DIR}/.venv/bin/flask --app app init-db
"
```

### 3.6 Обновить unit-файлы и перезапустить

```bash
for UNIT_FILE in \
  "${APP_DIR}/butler.service" \
  "${APP_DIR}/butler-log-import.service"; do
  sed -i \
    -e "s|User=.*|User=${APP_USER}|g" \
    -e "s|Group=.*|Group=${APP_GROUP}|g" \
    -e "s|/home/loktar/serv/butler|${APP_DIR}|g" \
    "$UNIT_FILE"
done

cp "${APP_DIR}/butler.service"            /etc/systemd/system/
cp "${APP_DIR}/butler-log-import.service" /etc/systemd/system/
cp "${APP_DIR}/butler-log-import.timer"   /etc/systemd/system/

systemctl daemon-reload
systemctl start butler.service
systemctl start butler-log-import.timer
systemctl status butler.service --no-pager
```

---

## Часть 4 — Проверка работоспособности

### Flask / Gunicorn

```bash
systemctl is-active butler.service
pgrep -a gunicorn
ss -tlnp | grep :5050
curl -sv http://127.0.0.1:5050/
```

### Логи приложения

```bash
journalctl -u butler.service -n 100 --no-pager
journalctl -u butler.service -f          # live
```

### Таймер импорта логов

```bash
systemctl list-timers butler-log-import.timer

# Принудительный запуск для теста
systemctl start butler-log-import.service
journalctl -u butler-log-import.service -n 20 --no-pager
```

### conntrack

```bash
lsmod | grep nf_conntrack
conntrack -L 2>/dev/null | head -10

# Если модуль не загружен
modprobe nf_conntrack
```

### nftables

```bash
systemctl is-active nftables
nft list ruleset
nft -c -f /etc/nftables.conf && echo "config OK"
```

### Всё одной командой

```bash
for SVC in butler.service butler-log-import.timer nftables.service; do
  printf "%-35s %s\n" "$SVC" "$(systemctl is-active $SVC 2>/dev/null)"
done
ss -tlnp | grep :5050 && echo "PORT 5050: OK" || echo "PORT 5050: NOT LISTENING"
curl -so /dev/null -w "HTTP %{http_code}\n" http://127.0.0.1:5050/
```

---

## Структура файлов после установки

```
/home/${APP_USER}/serv/butler/
├── app/                        # Flask-приложение
├── wheels/                     # Python wheels (оффлайн-установка)
├── .venv/                      # виртуальное окружение
├── instance/
│   ├── butler.sqlite3          # SQLite-база
│   └── log-import.state        # курсор journald (создаётся автоматически)
├── wsgi.py
├── butler-log-import.py
├── requirements.txt
└── install_butler_sudoers.sh

/etc/butler/
└── butler.env                  # конфиг (права 640, owner root:${APP_GROUP})

/etc/systemd/system/
├── butler.service
├── butler-log-import.service
└── butler-log-import.timer

/etc/nftables.d/
└── butler.nft                  # создаётся приложением при нажатии "Применить"
```
