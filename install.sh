#!/usr/bin/env bash
# =============================================================================
# install.sh — установка Butler как системной службы
#
# Запуск из папки ~/serv/butler/:
#   ./install.sh
#   ./install.sh --user myuser    # если запускать службу от другого пользователя
#   ./install.sh --port 8080      # если нужен другой порт
#   ./install.sh --uninstall      # удалить службу
# =============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Параметры по умолчанию
# ---------------------------------------------------------------------------
BUTLER_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INNER_DIR="${BUTLER_DIR}/.butler"
VENV_DIR="${BUTLER_DIR}/.butler/.venv"
WHEELS_DIR="${BUTLER_DIR}/.butler/wheels"
WSGI_PATH="${INNER_DIR}/wsgi.py"
ENV_FILE="${BUTLER_DIR}/butler.env"
ENV_EXAMPLE="${BUTLER_DIR}/.butler/env.example"
SERVICE_NAME="butler"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"

BUTLER_USER="$(whoami)"
BUTLER_PORT=""   # если не задан — берётся из butler.env или дефолт 5050
UNINSTALL=0

# ---------------------------------------------------------------------------
# Аргументы
# ---------------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --user)   BUTLER_USER="$2"; shift 2 ;;
    --port)   BUTLER_PORT="$2"; shift 2 ;;
    --uninstall) UNINSTALL=1; shift ;;
    -h|--help)
      echo "Использование: $0 [--user USER] [--port PORT] [--uninstall]"
      exit 0 ;;
    *) echo "Неизвестный аргумент: $1" >&2; exit 1 ;;
  esac
done

# ---------------------------------------------------------------------------
# Цвета
# ---------------------------------------------------------------------------
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
ok()   { echo -e "${GREEN}[✓]${NC} $*"; }
info() { echo -e "    $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
die()  { echo -e "${RED}[✗]${NC} $*" >&2; exit 1; }

# ---------------------------------------------------------------------------
# Удаление
# ---------------------------------------------------------------------------
if [[ $UNINSTALL -eq 1 ]]; then
  echo "Удаление службы Butler..."
  sudo systemctl stop "$SERVICE_NAME"   2>/dev/null || true
  sudo systemctl disable "$SERVICE_NAME" 2>/dev/null || true
  sudo rm -f "$SERVICE_FILE"
  sudo systemctl daemon-reload
  ok "Служба удалена. Файлы приложения и БД не тронуты."
  exit 0
fi

# ---------------------------------------------------------------------------
# Проверки
# ---------------------------------------------------------------------------
[[ -d "$INNER_DIR" ]]   || die "Папка .butler/ не найдена. Распакуй архив правильно."
[[ -f "$WSGI_PATH" ]]   || die "Файл .butler/wsgi.py не найден."
[[ -d "$WHEELS_DIR" ]]  || die "Папка .butler/wheels/ не найдена."

# ---------------------------------------------------------------------------
# Конфиг
# ---------------------------------------------------------------------------
if [[ ! -f "$ENV_FILE" ]]; then
  if [[ -f "$ENV_EXAMPLE" ]]; then
    cp "$ENV_EXAMPLE" "$ENV_FILE"
    warn "Создан butler.env из шаблона. Отредактируй пароль и пути перед запуском."
  else
    die "butler.env не найден и шаблон не доступен."
  fi
fi

# Читаем порт из конфига если не задан флагом
if [[ -z "$BUTLER_PORT" ]]; then
  BUTLER_PORT="$(grep -m1 '^BUTLER_PORT=' "$ENV_FILE" 2>/dev/null | cut -d= -f2 | tr -d '[:space:]')"
  BUTLER_PORT="${BUTLER_PORT:-5050}"
fi

echo ""
echo "Butler — установка"
echo "  Директория: $BUTLER_DIR"
echo "  Пользователь: $BUTLER_USER"
echo "  Порт: $BUTLER_PORT"
echo ""

# ---------------------------------------------------------------------------
# Шаг 1 — venv
# ---------------------------------------------------------------------------
echo "Создаю виртуальное окружение..."

PYTHON_BIN=""
for PY in python3.13 python3.12 python3.11 python3.10 python3; do
  if command -v "$PY" &>/dev/null; then
    PYTHON_BIN="$(command -v "$PY")"
    break
  fi
done
[[ -n "$PYTHON_BIN" ]] || die "Python3 не найден. Установи: sudo apt install python3"

"$PYTHON_BIN" -m venv "$VENV_DIR"
ok "venv создан: $VENV_DIR"

# ---------------------------------------------------------------------------
# Шаг 2 — установка зависимостей из wheels
# ---------------------------------------------------------------------------
echo "Устанавливаю зависимости из wheels..."

"${VENV_DIR}/bin/pip" install \
  --no-index \
  --find-links "$WHEELS_DIR" \
  --quiet \
  -r "${INNER_DIR}/requirements.txt"

ok "Зависимости установлены."

# ---------------------------------------------------------------------------
# Шаг 3 — инициализация БД
# ---------------------------------------------------------------------------
echo "Инициализирую базу данных..."
DB_PATH="$(grep -m1 '^BUTLER_DATABASE=' "$ENV_FILE" 2>/dev/null | cut -d= -f2 | tr -d '[:space:]')"

if [[ -z "$DB_PATH" ]]; then
  DB_PATH="${BUTLER_DIR}/.butler/instance/butler.sqlite3"
  warn "BUTLER_DATABASE не задан в butler.env — использую: $DB_PATH"
fi

mkdir -p "$(dirname "$DB_PATH")"

# init-db если БД не существует или пустая
if [[ ! -f "$DB_PATH" ]] || [[ ! -s "$DB_PATH" ]]; then
  (
    cd "$INNER_DIR"
    FLASK_APP=app \
    BUTLER_DATABASE="$DB_PATH" \
      "${VENV_DIR}/bin/flask" --app app init-db
  )
  ok "База данных инициализирована: $DB_PATH"
else
  ok "База данных уже существует: $DB_PATH"
fi

# ---------------------------------------------------------------------------
# Шаг 4 — systemd unit
# ---------------------------------------------------------------------------
echo "Устанавливаю systemd службу..."

sudo tee "$SERVICE_FILE" > /dev/null <<UNIT
[Unit]
Description=Butler — управление доступом через nftables
After=network.target

[Service]
User=${BUTLER_USER}
Group=${BUTLER_USER}
WorkingDirectory=${INNER_DIR}
EnvironmentFile=${ENV_FILE}
Environment=BUTLER_ENV_FILE=${ENV_FILE}
ExecStart=${VENV_DIR}/bin/gunicorn --workers 2 --bind 0.0.0.0:${BUTLER_PORT} wsgi:app
Restart=always
RestartSec=3
PrivateTmp=true

[Install]
WantedBy=multi-user.target
UNIT

sudo systemctl daemon-reload
sudo systemctl enable "$SERVICE_NAME"
sudo systemctl restart "$SERVICE_NAME"

sleep 2

if sudo systemctl is-active --quiet "$SERVICE_NAME"; then
  ok "Служба запущена и работает."
else
  warn "Служба не запустилась. Смотри логи:"
  info "sudo journalctl -u butler -n 30 --no-pager"
  exit 1
fi

# ---------------------------------------------------------------------------
# Шаг 5 — systemd timer для автосбора логов
# ---------------------------------------------------------------------------
TIMER_SERVICE_SRC="${INNER_DIR}/butler-log-import.service"
TIMER_SRC="${INNER_DIR}/butler-log-import.timer"

if [[ -f "$TIMER_SERVICE_SRC" ]] && [[ -f "$TIMER_SRC" ]]; then
  # Добавляем пользователя в группу systemd-journal для чтения kernel-логов
  if getent group systemd-journal > /dev/null 2>&1; then
    sudo usermod -aG systemd-journal "${BUTLER_USER}" 2>/dev/null || true
    ok "Пользователь ${BUTLER_USER} добавлен в группу systemd-journal."
  fi

  # Генерируем полный unit с реальными путями
  sudo tee /etc/systemd/system/butler-log-import.service > /dev/null <<TIMER_UNIT
[Unit]
Description=Butler — импорт попыток подключений из journald
After=network.target

[Service]
Type=oneshot
User=${BUTLER_USER}
Group=${BUTLER_USER}
SupplementaryGroups=systemd-journal
WorkingDirectory=${INNER_DIR}
EnvironmentFile=${ENV_FILE}
Environment=BUTLER_ENV_FILE=${ENV_FILE}
ExecStart=${PYTHON_BIN} ${INNER_DIR}/butler-log-import.py
StandardOutput=journal
StandardError=journal
TIMER_UNIT

  sudo cp "$TIMER_SRC" /etc/systemd/system/butler-log-import.timer
  sudo systemctl daemon-reload
  sudo systemctl enable --now butler-log-import.timer
  ok "Таймер автосбора логов включён (каждые 5 минут)."
fi

# ---------------------------------------------------------------------------
# Готово
# ---------------------------------------------------------------------------
echo ""
echo -e "${GREEN}Butler успешно установлен.${NC}"
echo ""
echo "  Адрес:    http://$(hostname -I | awk '{print $1}'):${BUTLER_PORT}"
echo "  Конфиг:   ${ENV_FILE}"
echo "  База:     ${DB_PATH}"
echo ""
echo "  Управление службой:"
echo "    sudo systemctl status butler"
echo "    sudo systemctl restart butler"
echo "    sudo journalctl -u butler -f"
echo ""
echo "  Если не настроены sudoers — запусти: ./sudoers.sh"
echo ""
