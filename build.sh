#!/usr/bin/env bash
# =============================================================================
# build.sh — сборка дистрибутива Butler для деплоя без git и без интернета
#
# Запуск из корня проекта:
#   ./build.sh
#   ./build.sh --python-version 3.12 --abi cp312   # для конкретного сервера
#   ./build.sh --output /tmp/butler.tar.gz
#   ./build.sh --no-wheels                          # если wheels уже скачаны
#
# Результат: butler-YYYYMMDD-HHMMSS.tar.gz
#
# Структура архива:
#   butler/
#   ├── butler.env.example   ← переименовать в butler.env и настроить
#   ├── butler               ← тестовый запуск
#   ├── install.sh           ← установка службы
#   ├── sudoers.sh           ← настройка sudoers
#   └── .butler/             ← подкапотное (не трогать)
#       ├── app/
#       ├── wheels/
#       ├── wsgi.py
#       ├── requirements.txt
#       ├── butler-log-import.py
#       ├── butler-log-import.service
#       ├── butler-log-import.timer
#       └── env.example
#
# Деплой на сервер:
#   scp butler-*.tar.gz user@server:~/serv/
#   ssh user@server
#   cd ~/serv && tar -xzf butler-*.tar.gz
#   cd butler
#   nano butler.env          # поправить пароль
#   ./install.sh
#   ./sudoers.sh
# =============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Параметры
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TIMESTAMP="$(date +%Y%m%d-%H%M%S)"
OUTPUT_NAME="butler-${TIMESTAMP}.tar.gz"
OUTPUT_DIR="$(dirname "$SCRIPT_DIR")"
PLATFORM="linux_x86_64"
SKIP_WHEELS=0

# Автоопределение Python
_find_python() {
  local VENV_PY="${SCRIPT_DIR}/.venv/bin/python3"
  if [[ -x "$VENV_PY" ]]; then
    echo "$VENV_PY"
  elif command -v python3 &>/dev/null; then
    echo "python3"
  else
    echo ""
  fi
}

PYTHON_BIN="${PYTHON_BIN:-$(_find_python)}"

# ---------------------------------------------------------------------------
# Разбор аргументов
# ---------------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --python-version) PYTHON_VERSION="$2"; shift 2 ;;
    --abi)            ABI="$2"; shift 2 ;;
    --platform)       PLATFORM="$2"; shift 2 ;;
    --output)         OUTPUT_DIR="$(dirname "$2")"; OUTPUT_NAME="$(basename "$2")"; shift 2 ;;
    --no-wheels)      SKIP_WHEELS=1; shift ;;
    --python)         PYTHON_BIN="$2"; shift 2 ;;
    -h|--help)
      sed -n '3,30p' "$0" | sed 's/^# \?//'
      exit 0 ;;
    *) echo "Неизвестный аргумент: $1" >&2; exit 1 ;;
  esac
done

[[ -n "$PYTHON_BIN" ]] || { echo "[error] Python3 не найден." >&2; exit 1; }

PYTHON_VERSION="${PYTHON_VERSION:-$("$PYTHON_BIN" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')}"
ABI="${ABI:-cp$("$PYTHON_BIN" -c 'import sys; print(f"{sys.version_info.major}{sys.version_info.minor}")')}"
OUTPUT_PATH="${OUTPUT_DIR}/${OUTPUT_NAME}"

# ---------------------------------------------------------------------------
# Цвета
# ---------------------------------------------------------------------------
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
ok()   { echo -e "${GREEN}[✓]${NC} $*"; }
info() { echo -e "    $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
die()  { echo -e "${RED}[✗]${NC} $*" >&2; exit 1; }

# ---------------------------------------------------------------------------
# Проверки
# ---------------------------------------------------------------------------
[[ -f "${SCRIPT_DIR}/requirements.txt" ]] || die "requirements.txt не найден."
[[ -f "${SCRIPT_DIR}/wsgi.py" ]]          || die "wsgi.py не найден."
[[ -f "${SCRIPT_DIR}/install.sh" ]]       || die "install.sh не найден."

echo ""
echo "Butler — сборка дистрибутива"
echo "  Python:    $("$PYTHON_BIN" --version 2>&1)"
echo "  Версия:    ${PYTHON_VERSION}  |  ABI: ${ABI}  |  Платформа: ${PLATFORM}"
echo "  Архив:     ${OUTPUT_PATH}"
echo ""

# ---------------------------------------------------------------------------
# Шаг 1 — wheels
# ---------------------------------------------------------------------------
WHEELS_DIR="${SCRIPT_DIR}/wheels"

if [[ $SKIP_WHEELS -eq 0 ]]; then
  echo "Скачиваю wheels..."
  rm -rf "$WHEELS_DIR" && mkdir -p "$WHEELS_DIR"

  if "$PYTHON_BIN" -m pip download \
      --dest "$WHEELS_DIR" \
      --platform "$PLATFORM" \
      --python-version "$PYTHON_VERSION" \
      --implementation cp \
      --abi "$ABI" \
      --only-binary=:all: \
      -r "${SCRIPT_DIR}/requirements.txt" \
      --quiet 2>&1; then
    ok "Wheels скачаны: $(ls "$WHEELS_DIR" | wc -l) файлов."
  else
    warn "Не все бинарные wheels найдены — пробую с sdist..."
    rm -rf "$WHEELS_DIR" && mkdir -p "$WHEELS_DIR"
    "$PYTHON_BIN" -m pip download \
      --dest "$WHEELS_DIR" \
      -r "${SCRIPT_DIR}/requirements.txt" \
      --quiet
    warn "Часть пакетов — sdist. На сервере нужен компилятор (gcc, python3-dev)."
    ok "Wheels скачаны: $(ls "$WHEELS_DIR" | wc -l) файлов."
  fi
else
  warn "--no-wheels: пропускаю скачивание."
fi

# ---------------------------------------------------------------------------
# Шаг 2 — сборка во временную директорию
# ---------------------------------------------------------------------------
echo "Собираю архив..."

BUILD_TMP="$(mktemp -d)"
trap 'rm -rf "$BUILD_TMP"' EXIT

DIST_DIR="${BUILD_TMP}/butler"
INNER_DIR="${DIST_DIR}/.butler"

mkdir -p "$INNER_DIR"

# Скрипты в корне папки butler/
install -m 755 "${SCRIPT_DIR}/install.sh"  "${DIST_DIR}/install.sh"
install -m 755 "${SCRIPT_DIR}/sudoers.sh"  "${DIST_DIR}/sudoers.sh"
install -m 755 "${SCRIPT_DIR}/butler"      "${DIST_DIR}/butler"
install -m 644 "${SCRIPT_DIR}/env.example" "${DIST_DIR}/butler.env.example"

# Всё остальное — в .butler/
cp -r "${SCRIPT_DIR}/app"                              "${INNER_DIR}/app"
cp    "${SCRIPT_DIR}/wsgi.py"                          "${INNER_DIR}/wsgi.py"
cp    "${SCRIPT_DIR}/requirements.txt"                 "${INNER_DIR}/requirements.txt"
cp    "${SCRIPT_DIR}/env.example"                      "${INNER_DIR}/env.example"
cp    "${SCRIPT_DIR}/butler-log-import.py"             "${INNER_DIR}/butler-log-import.py"
cp    "${SCRIPT_DIR}/butler-log-import.service"        "${INNER_DIR}/butler-log-import.service"
cp    "${SCRIPT_DIR}/butler-log-import.timer"          "${INNER_DIR}/butler-log-import.timer"
cp -r "${WHEELS_DIR}"                                  "${INNER_DIR}/wheels"

# Убираем кэш python
find "${INNER_DIR}/app" -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
find "${INNER_DIR}/app" -name "*.pyc" -delete 2>/dev/null || true

# ---------------------------------------------------------------------------
# Шаг 3 — упаковка
# ---------------------------------------------------------------------------
tar -czf "$OUTPUT_PATH" -C "$BUILD_TMP" butler

ARCHIVE_SIZE="$(du -sh "$OUTPUT_PATH" | cut -f1)"
ok "Архив готов: ${OUTPUT_PATH} (${ARCHIVE_SIZE})"

# ---------------------------------------------------------------------------
# Шаг 4 — проверка содержимого
# ---------------------------------------------------------------------------
echo ""
echo "Содержимое:"
tar -tzf "$OUTPUT_PATH" | grep -v '__pycache__' | sort

TAR_LIST="$(tar -tzf "$OUTPUT_PATH")"

echo ""
echo "Проверка обязательных файлов:"
REQUIRED=(
  "butler/install.sh"
  "butler/sudoers.sh"
  "butler/butler"
  "butler/butler.env.example"
  "butler/.butler/wsgi.py"
  "butler/.butler/requirements.txt"
  "butler/.butler/app/"
  "butler/.butler/wheels/"
  "butler/.butler/butler-log-import.py"
  "butler/.butler/butler-log-import.service"
  "butler/.butler/butler-log-import.timer"
)

ALL_OK=1
for F in "${REQUIRED[@]}"; do
  if echo "$TAR_LIST" | grep -qE "^${F}"; then
    echo -e "  ${GREEN}✓${NC}  $F"
  else
    echo -e "  ${RED}✗${NC}  $F  — ОТСУТСТВУЕТ"
    ALL_OK=0
  fi
done

echo ""
if [[ $ALL_OK -eq 1 ]]; then
  ok "Готово к деплою."
  echo ""
  echo "  Перенести на сервер:"
  echo "    scp ${OUTPUT_PATH} user@server:~/serv/"
  echo ""
  echo "  На сервере:"
  echo "    cd ~/serv && tar -xzf ${OUTPUT_NAME}"
  echo "    cd butler"
  echo "    cp butler.env.example butler.env && nano butler.env"
  echo "    ./install.sh"
  echo "    ./sudoers.sh"
else
  warn "Есть проблемы — проверь архив."
fi
echo ""
