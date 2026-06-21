#!/usr/bin/env bash
# =============================================================================
# sudoers.sh — настройка sudoers для Butler
#
# Разрешает пользователю вызывать команды брандмауэра, conntrack и journalctl
# без пароля, в том числе без tty (нужно для вызовов из Python/Flask).
# Поддерживает два бэкенда: nftables (default) и ufw.
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
  ok "Правило sudoers удалено."
  exit 0
fi

# ---------------------------------------------------------------------------
# Проверяем наличие команд
# ---------------------------------------------------------------------------
REQUIRED_CMDS=(mkdir install test cat journalctl)
OPTIONAL_CMDS=(conntrack)

if [[ "$BACKEND" == "nftables" ]]; then
  REQUIRED_CMDS+=(nft)
elif [[ "$BACKEND" == "ufw" ]]; then
  REQUIRED_CMDS+=(ufw)
else
  die "Неизвестный бэкенд: $BACKEND. Допустимые значения: nftables, ufw"
fi

# visudo нужен только для валидации, ищем в PATH
VISUDO_BIN="$(PATH="$PATH:/usr/sbin" command -v visudo 2>/dev/null || true)"
[[ -n "$VISUDO_BIN" ]] || die "Команда visudo не найдена.\n  Убедись что sudo установлен: sudo apt install sudo"

for cmd in "${REQUIRED_CMDS[@]}"; do
  PATH="$PATH:/usr/sbin" command -v "$cmd" > /dev/null ||
    die "Команда не найдена: $cmd\n  Установи: sudo apt install $cmd"
done

for cmd in "${OPTIONAL_CMDS[@]}"; do
  if ! PATH="$PATH:/usr/sbin" command -v "$cmd" > /dev/null 2>&1; then
    warn "Команда '$cmd' не найдена. Conntrack-сброс соединений будет недоступен."
    warn "  Установи: sudo apt install conntrack"
  fi
done

# ---------------------------------------------------------------------------
# Определяем пути к бинарям (полные пути обязательны для sudoers)
# ---------------------------------------------------------------------------
_bin() { PATH="$PATH:/usr/sbin:/usr/bin:/sbin:/bin" command -v "$1"; }

MKDIR_BIN="$(_bin mkdir)"
INSTALL_BIN="$(_bin install)"
TEST_BIN="$(_bin test 2>/dev/null || echo /usr/bin/test)"
[[ "$TEST_BIN" == /* ]] || TEST_BIN="/usr/bin/test"
CAT_BIN="$(_bin cat)"
JOURNALCTL_BIN="$(_bin journalctl)"

# Бэкенд-специфичные команды
FIREWALL_BIN=""
if [[ "$BACKEND" == "nftables" ]]; then
  FIREWALL_BIN="$(_bin nft)"
elif [[ "$BACKEND" == "ufw" ]]; then
  FIREWALL_BIN="$(_bin ufw)"
fi

# Conntrack (опционально)
CONNTRACK_BIN=""
if PATH="$PATH:/usr/sbin" command -v conntrack > /dev/null 2>&1; then
  CONNTRACK_BIN="$(_bin conntrack)"
fi

# ---------------------------------------------------------------------------
# Формируем список всех команд для sudoers
# ---------------------------------------------------------------------------
ALL_BINS=("$FIREWALL_BIN" "$MKDIR_BIN" "$INSTALL_BIN" "$TEST_BIN" "$CAT_BIN" "$JOURNALCTL_BIN")
[[ -n "$CONNTRACK_BIN" ]] && ALL_BINS+=("$CONNTRACK_BIN")

# Строка NOPASSWD для sudoers
NOPASSWD_LIST=$(printf '%s, ' "${ALL_BINS[@]}")
NOPASSWD_LIST="${NOPASSWD_LIST%, }"  # убрать трейлинг запятую

# Строки !requiretty для каждой команды
REQUIRETTY_LINES=""
for bin in "${ALL_BINS[@]}"; do
  REQUIRETTY_LINES+="Defaults!${bin} !requiretty"$'\n'
done

# ---------------------------------------------------------------------------
# Пишем файл sudoers
# ---------------------------------------------------------------------------
TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT

cat > "$TMP" <<RULES
# Managed by sudoers.sh (Butler) — backend: ${BACKEND}
# !requiretty needed for passwordless sudo from Python/Flask (no tty)
${REQUIRETTY_LINES}
${BUTLER_USER} ALL=(root) NOPASSWD: ${NOPASSWD_LIST}
RULES

"$VISUDO_BIN" -cf "$TMP" > /dev/null || die "Ошибка синтаксиса sudoers — файл не установлен."

sudo install -m 0440 -o root -g root "$TMP" "$SUDOERS_FILE"
sudo "$VISUDO_BIN" -cf "$SUDOERS_FILE" > /dev/null

ok "Sudoers настроен для пользователя: ${BUTLER_USER}  (бэкенд: ${BACKEND})"
echo "  Файл: $SUDOERS_FILE"
echo "  Бэкенд: $BACKEND"
if [[ "$BACKEND" == "nftables" ]]; then
  echo "  Разрешены: nft, journalctl${CONNTRACK_BIN:+, conntrack}"
else
  echo "  Разрешены: ufw, journalctl${CONNTRACK_BIN:+, conntrack}"
fi
echo ""
warn "Не забудь установить BUTLER_BACKEND=${BACKEND} в butler.env!"
warn "ВАЖНО: после \"ufw reset\" файл sudoers удаляется. Butler восстанавливает его автоматически."
