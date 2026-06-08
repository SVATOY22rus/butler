#!/usr/bin/env bash
# =============================================================================
# sudoers.sh — настройка sudoers для Butler
#
# Разрешает пользователю вызывать nft, conntrack и journalctl без пароля.
# Запускается один раз после install.sh.
#
# Использование:
#   ./sudoers.sh                  # для текущего пользователя
#   ./sudoers.sh --user myuser    # для конкретного пользователя
#   ./sudoers.sh --remove         # удалить правило
# =============================================================================

set -euo pipefail

BUTLER_USER="$(whoami)"
SUDOERS_FILE="/etc/sudoers.d/butler"
REMOVE=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --user)   BUTLER_USER="$2"; shift 2 ;;
    --remove) REMOVE=1; shift ;;
    -h|--help)
      echo "Использование: $0 [--user USER] [--remove]"
      exit 0 ;;
    *) echo "Неизвестный аргумент: $1" >&2; exit 1 ;;
  esac
done

GREEN='\033[0;32m'; RED='\033[0;31m'; NC='\033[0m'
ok()  { echo -e "${GREEN}[✓]${NC} $*"; }
die() { echo -e "${RED}[✗]${NC} $*" >&2; exit 1; }

# ---------------------------------------------------------------------------
# Удаление
# ---------------------------------------------------------------------------
if [[ $REMOVE -eq 1 ]]; then
  sudo rm -f "$SUDOERS_FILE"
  sudo visudo -cf /etc/sudoers > /dev/null
  ok "Правило sudoers удалено."
  exit 0
fi

# ---------------------------------------------------------------------------
# Проверяем наличие команд
# ---------------------------------------------------------------------------
REQUIRED_CMDS=(visudo mkdir install test cat nft journalctl)
OPTIONAL_CMDS=(conntrack)

for cmd in "${REQUIRED_CMDS[@]}"; do
  command -v "$cmd" > /dev/null || die "Команда не найдена: $cmd — установи пакет (apt install $cmd)"
done

for cmd in "${OPTIONAL_CMDS[@]}"; do
  if ! command -v "$cmd" > /dev/null 2>&1; then
    echo "  [!] Команда '$cmd' не найдена. Установи: sudo apt install conntrack"
    echo "      После установки перезапусти этот скрипт."
  fi
done

# ---------------------------------------------------------------------------
# Определяем пути
# ---------------------------------------------------------------------------
VISUDO_BIN="$(command -v visudo)"
MKDIR_BIN="$(command -v mkdir)"
INSTALL_BIN="$(command -v install)"
TEST_BIN="$(command -v test)"
CAT_BIN="$(command -v cat)"
NFT_BIN="$(command -v nft)"
JOURNALCTL_BIN="$(command -v journalctl)"

CONNTRACK_ENTRY=""
if command -v conntrack > /dev/null 2>&1; then
  CONNTRACK_BIN="$(command -v conntrack)"
  CONNTRACK_ENTRY=", ${CONNTRACK_BIN}"
fi

# ---------------------------------------------------------------------------
# Пишем файл
# ---------------------------------------------------------------------------
TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT

cat > "$TMP" <<RULES
# Managed by sudoers.sh (Butler)
${BUTLER_USER} ALL=(root) NOPASSWD: ${MKDIR_BIN}, ${INSTALL_BIN}, ${TEST_BIN}, ${CAT_BIN}, ${NFT_BIN}, ${JOURNALCTL_BIN}${CONNTRACK_ENTRY}
RULES

# Проверяем синтаксис
"$VISUDO_BIN" -cf "$TMP" > /dev/null || die "Ошибка синтаксиса sudoers — файл не установлен."

sudo install -m 0440 "$TMP" "$SUDOERS_FILE"
sudo "$VISUDO_BIN" -cf "$SUDOERS_FILE" > /dev/null

ok "Sudoers настроен для пользователя: $BUTLER_USER"
echo "  Файл: $SUDOERS_FILE"
echo "  Разрешены: nft, journalctl${CONNTRACK_ENTRY:+, conntrack}"
