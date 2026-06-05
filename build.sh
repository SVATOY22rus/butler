#!/usr/bin/env bash
# =============================================================================
# build.sh — упаковка Butler для деплоя без git и без интернета
#
# Запуск из корня проекта:
#   ./build.sh
#   ./build.sh --python-version 3.11 --abi cp311
#   ./build.sh --output /tmp/myserver.tar.gz
#   ./build.sh --no-wheels   # без скачивания wheels (если уже есть)
#
# Результат: butler-deploy-YYYYMMDD-HHMMSS.tar.gz рядом с проектом
# =============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Дефолтные параметры
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$SCRIPT_DIR"
TIMESTAMP="$(date +%Y%m%d-%H%M%S)"
OUTPUT_NAME="butler-deploy-${TIMESTAMP}.tar.gz"
OUTPUT_DIR="$(dirname "$PROJECT_DIR")"

PYTHON_BIN="python3"
PLATFORM="linux_x86_64"
SKIP_WHEELS=0

# Автоопределение версии Python
PYTHON_VERSION="$("$PYTHON_BIN" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
ABI="cp$("$PYTHON_BIN" -c 'import sys; print(f"{sys.version_info.major}{sys.version_info.minor}")')"

# ---------------------------------------------------------------------------
# Разбор аргументов
# ---------------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --python-version)
      PYTHON_VERSION="$2"; shift 2 ;;
    --abi)
      ABI="$2"; shift 2 ;;
    --platform)
      PLATFORM="$2"; shift 2 ;;
    --output)
      OUTPUT_DIR="$(dirname "$2")"
      OUTPUT_NAME="$(basename "$2")"
      shift 2 ;;
    --no-wheels)
      SKIP_WHEELS=1; shift ;;
    --python)
      PYTHON_BIN="$2"; shift 2 ;;
    -h|--help)
      echo "Использование: $0 [OPTIONS]"
      echo ""
      echo "  --python-version VER   Версия Python на сервере (по умолчанию: $PYTHON_VERSION)"
      echo "  --abi ABI              ABI тег (по умолчанию: $ABI)"
      echo "  --platform PLAT        Платформа (по умолчанию: $PLATFORM)"
      echo "  --output PATH          Путь к выходному архиву"
      echo "  --no-wheels            Пропустить скачивание wheels"
      echo "  --python BIN           Путь к python (по умолчанию: python3)"
      exit 0 ;;
    *)
      echo "Неизвестный аргумент: $1" >&2
      exit 1 ;;
  esac
done

OUTPUT_PATH="${OUTPUT_DIR}/${OUTPUT_NAME}"

# ---------------------------------------------------------------------------
# Утилиты вывода
# ---------------------------------------------------------------------------
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

info()    { echo -e "${GREEN}[build]${NC} $*"; }
warn()    { echo -e "${YELLOW}[warn] ${NC} $*"; }
error()   { echo -e "${RED}[error]${NC} $*" >&2; }
die()     { error "$*"; exit 1; }

# ---------------------------------------------------------------------------
# Предварительные проверки
# ---------------------------------------------------------------------------
info "Python:   $("$PYTHON_BIN" --version 2>&1)"
info "Версия:   $PYTHON_VERSION  |  ABI: $ABI  |  Платформа: $PLATFORM"
info "Архив:    $OUTPUT_PATH"
echo ""

[[ -f "${PROJECT_DIR}/requirements.txt" ]] \
  || die "requirements.txt не найден. Запусти скрипт из корня проекта."

[[ -f "${PROJECT_DIR}/wsgi.py" ]] \
  || die "wsgi.py не найден. Это не корень проекта Butler."

# ---------------------------------------------------------------------------
# Шаг 1 — скачать wheels
# ---------------------------------------------------------------------------
WHEELS_DIR="${PROJECT_DIR}/wheels"

if [[ $SKIP_WHEELS -eq 0 ]]; then
  info "Скачиваю wheels для Python ${PYTHON_VERSION} / ${ABI} / ${PLATFORM}..."
  rm -rf "$WHEELS_DIR"
  mkdir -p "$WHEELS_DIR"

  # Сначала пробуем только бинарные wheels (быстро, без компилятора на сервере)
  if "$PYTHON_BIN" -m pip download \
      --dest "$WHEELS_DIR" \
      --platform "$PLATFORM" \
      --python-version "$PYTHON_VERSION" \
      --implementation cp \
      --abi "$ABI" \
      --only-binary=:all: \
      -r "${PROJECT_DIR}/requirements.txt" \
      --quiet; then
    info "Бинарные wheels скачаны успешно."
  else
    warn "Не все пакеты имеют бинарные wheels — скачиваю sdist тоже..."
    rm -rf "$WHEELS_DIR" && mkdir -p "$WHEELS_DIR"
    "$PYTHON_BIN" -m pip download \
      --dest "$WHEELS_DIR" \
      -r "${PROJECT_DIR}/requirements.txt" \
      --quiet
    warn "Часть пакетов — sdist. На сервере потребуется компилятор (gcc, python3-dev)."
  fi

  WHEELS_COUNT="$(ls "$WHEELS_DIR" | wc -l)"
  info "Скачано файлов: ${WHEELS_COUNT}"
else
  warn "--no-wheels: пропускаю скачивание."
  if [[ ! -d "$WHEELS_DIR" ]] || [[ -z "$(ls -A "$WHEELS_DIR" 2>/dev/null)" ]]; then
    warn "Папка wheels/ пуста или отсутствует — установка на сервере потребует интернет."
  fi
fi

# ---------------------------------------------------------------------------
# Шаг 2 — собрать архив
# ---------------------------------------------------------------------------
info "Собираю архив..."

PARENT_DIR="$(dirname "$PROJECT_DIR")"
BASE_NAME="$(basename "$PROJECT_DIR")"

tar -czf "$OUTPUT_PATH" \
  -C "$PARENT_DIR" \
  --exclude="${BASE_NAME}/.git" \
  --exclude="${BASE_NAME}/.venv" \
  --exclude="${BASE_NAME}/instance" \
  --exclude="${BASE_NAME}/generated" \
  --exclude="${BASE_NAME}/__pycache__" \
  --exclude="${BASE_NAME}/app/__pycache__" \
  --exclude="${BASE_NAME}/.env" \
  --exclude="${BASE_NAME}/*.pyc" \
  --exclude="${BASE_NAME}/butler-deploy-*.tar.gz" \
  "$BASE_NAME"

ARCHIVE_SIZE="$(du -sh "$OUTPUT_PATH" | cut -f1)"
info "Архив готов: ${OUTPUT_PATH} (${ARCHIVE_SIZE})"

# ---------------------------------------------------------------------------
# Шаг 3 — проверка содержимого
# ---------------------------------------------------------------------------
echo ""
info "Содержимое архива:"
tar -tzf "$OUTPUT_PATH" | grep -v '__pycache__' | sort

# Читаем список файлов один раз
TAR_LIST="$(tar -tzf "$OUTPUT_PATH")"

# Обязательные файлы
REQUIRED=(
  "${BASE_NAME}/wsgi.py"
  "${BASE_NAME}/requirements.txt"
  "${BASE_NAME}/butler.service"
  "${BASE_NAME}/butler-log-import.service"
  "${BASE_NAME}/butler-log-import.timer"
  "${BASE_NAME}/install_butler_sudoers.sh"
  "${BASE_NAME}/env.example"
)

echo ""
info "Проверка обязательных файлов:"
ALL_OK=1
for F in "${REQUIRED[@]}"; do
  if echo "$TAR_LIST" | grep -qE "^${F}/?$"; then
    echo -e "  ${GREEN}✓${NC}  $F"
  else
    echo -e "  ${RED}✗${NC}  $F  — ОТСУТСТВУЕТ"
    ALL_OK=0
  fi
done

# Проверяем что нет лишнего
echo ""
info "Проверка что лишнего нет:"
for EXCL in ".git" ".venv" "instance" "generated"; do
  if echo "$TAR_LIST" | grep -q "/${EXCL}/"; then
    echo -e "  ${RED}✗${NC}  Найдено: ${EXCL}/  — нужно проверить исключения"
    ALL_OK=0
  else
    echo -e "  ${GREEN}✓${NC}  ${EXCL}/ не включён"
  fi
done

echo ""
if [[ $ALL_OK -eq 1 ]]; then
  info "Всё готово. Архив можно деплоить."
  echo ""
  echo "  Перенести на сервер:"
  echo "    scp ${OUTPUT_PATH} user@server:/tmp/"
  echo ""
  echo "  На сервере:"
  echo "    tar -xzf /tmp/${OUTPUT_NAME}"
  echo "    см. DEPLOY.md"
else
  warn "Есть предупреждения — проверь архив перед деплоем."
fi
