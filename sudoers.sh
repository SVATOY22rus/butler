#!/usr/bin/env bash
# =============================================================================
# sudoers.sh — настройка sudoers для Butler
#
# Разрешает пользователю вызывать команды брандмауэра, conntrack и journalctl
# без пароля. Поддерживает два бэкенда: nftables (default) и ufw.
#
# Использование:
#   ./sudoers.sh                          # для текущего пользователя, бэкенд nftables
#   ./sudoers.sh --backend ufw            # для текущего пользователя, бэкенд ufw
#   ./sudoers.sh --user myuser            # для конкретного пользователя
#   ./sudoers.sh --user myuser --backend ufw
#   ./sudoers.sh --remove                 # удалить правило
# =============================================================================

set -euo pipefail

BUTLER_USER="$(whoami)"
SUDOERS_FILE="/etc/sudoers.d/butler"
REMOVE=0
BACKEND="nftables"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --user)    BUTLER_USER="$2"; shift 2 ;;
    --backend) BACKEND="$2";    shift 2 ;;
    --remove)  REMOVE=1;        shift ;;
    -h|--help)
      echo "Использование: $0 [--user USER] [--backend nftables|ufw] [--remove]"
      exit 0 ;;
    *) echo "Неизвестный аргумент: $1" >&2; exit 1 ;;
  esac
done

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
ok()   { echo -e "${GREEN}[✓]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
die()  { echo -e "${RED}[✗]${NC} $*" >&2; exit 1; }

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
REQUIRED_CMDS=(visudo mkdir install test cat journalctl)
OPTIONAL_CMDS=(conntrack)

if [[ "$BACKEND" == "nftables" ]]; then
  REQUIRED_CMDS+=(nft)
elif [[ "$BACKEND" == "ufw" ]]; then
  REQUIRED_CMDS+=(ufw)
else
  die "Неизвестный бэкенд: $BACKEND. Допустимые значения: nftables, ufw"
fi

for cmd in "${REQUIRED_CMDS[@]}"; do
  command -v "$cmd" > /dev/null || die "Команда не найдена: $cmd\n  Установи: sudo apt install $cmd"
done

for cmd in "${OPTIONAL_CMDS[@]}"; do
  if ! command -v "$cmd" > /dev/null 2>&1; then
    warn "Команда '$cmd' не найдена. Conntrack-сброс соединений будет недоступен."
    warn "  Установи: sudo apt install conntrack"
  fi
done

# ---------------------------------------------------------------------------
# Определяем пути к бинарям
# ---------------------------------------------------------------------------
VISUDO_BIN="$(command -v visudo)"
MKDIR_BIN="$(command -v mkdir)"
INSTALL_BIN="$(command -v install)"
TEST_BIN="$(command -v test 2>/dev/null || true)"
[[ "$TEST_BIN" == /* ]] || TEST_BIN="/usr/bin/test"
CAT_BIN="$(command -v cat)"
JOURNALCTL_BIN="$(command -v journalctl)"

# Бэкенд-специфичные команды
FIREWALL_ENTRIES=""
if [[ "$BACKEND" == "nftables" ]]; then
  NFT_BIN="$(command -v nft)"
  FIREWALL_ENTRIES=", ${NFT_BIN}"
elif [[ "$BACKEND" == "ufw" ]]; then
  UFW_BIN="$(command -v ufw)"
  FIREWALL_ENTRIES=", ${UFW_BIN}"
fi

# Conntrack (опционально)
CONNTRACK_ENTRY=""
if command -v conntrack > /dev/null 2>&1; then
  CONNTRACK_BIN="$(command -v conntrack)"
  CONNTRACK_ENTRY=", ${CONNTRACK_BIN}"
fi

# ---------------------------------------------------------------------------
# Пишем файл sudoers
# ---------------------------------------------------------------------------
TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT

cat > "$TMP" <<RULES
# Managed by sudoers.sh (Butler) — backend: ${BACKEND}
${BUTLER_USER} ALL=(root) NOPASSWD: ${MKDIR_BIN}, ${INSTALL_BIN}, ${TEST_BIN}, ${CAT_BIN}, ${JOURNALCTL_BIN}${FIREWALL_ENTRIES}${CONNTRACK_ENTRY}
RULES

"$VISUDO_BIN" -cf "$TMP" > /dev/null || die "Ошибка синтаксиса sudoers — файл не установлен."

sudo install -m 0440 "$TMP" "$SUDOERS_FILE"
sudo "$VISUDO_BIN" -cf "$SUDOERS_FILE" > /dev/null

ok "Sudoers настроен для пользователя: ${BUTLER_USER}  (бэкенд: ${BACKEND})"
echo "  Файл: $SUDOERS_FILE"
echo "  Бэкенд: $BACKEND"
if [[ "$BACKEND" == "nftables" ]]; then
  echo "  Разрешены: nft, journalctl${CONNTRACK_ENTRY:+, conntrack}"
else
  echo "  Разрешены: ufw, journalctl${CONNTRACK_ENTRY:+, conntrack}"
fi
echo ""
warn "Не забудь установить BUTLER_BACKEND=${BACKEND} в butler.env!"
