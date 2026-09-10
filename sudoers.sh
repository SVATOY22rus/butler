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

# ВАЖНО: скрипт обычно запускают через sudo, и тогда whoami == root — правило
# уходило root'у, а реальный пользователь так и оставался без прав.
BUTLER_USER="${SUDO_USER:-$(id -un)}"
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

# Системные бинарники (visudo, nft, conntrack) живут в /usr/sbin и /sbin,
# которых нет в PATH непривилегированного пользователя на Debian/Astra.
PATH="${PATH}:/usr/local/sbin:/usr/sbin:/sbin"

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
ok()   { echo -e "${GREEN}[✓]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
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

# Имя команды != имя пакета. "apt install visudo" не существует.
pkg_for() {
  case "$1" in
    visudo)     echo sudo ;;
    nft)        echo nftables ;;
    conntrack)  echo conntrack ;;
    journalctl) echo systemd ;;
    *)          echo coreutils ;;
  esac
}

for cmd in "${REQUIRED_CMDS[@]}"; do
  command -v "$cmd" > /dev/null \
    || die "Команда не найдена: ${cmd} — установи: sudo apt install $(pkg_for "$cmd")"
done

for cmd in "${OPTIONAL_CMDS[@]}"; do
  if ! command -v "$cmd" > /dev/null 2>&1; then
    warn "Команда '${cmd}' не найдена. Установи: sudo apt install $(pkg_for "$cmd")"
    echo "      Без неё Butler не сможет сбрасывать активные соединения."
    echo "      После установки перезапусти этот скрипт."
  fi
done

# ---------------------------------------------------------------------------
# Определяем пути
# ---------------------------------------------------------------------------
VISUDO_BIN="$(command -v visudo)"
MKDIR_BIN="$(command -v mkdir)"
INSTALL_BIN="$(command -v install)"
# 'test' — встроенная команда bash, command -v может вернуть просто 'test' без пути
TEST_BIN="$(command -v test 2>/dev/null || true)"
[[ "$TEST_BIN" == /* ]] || TEST_BIN="/usr/bin/test"
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
if [[ "$BUTLER_USER" == "root" ]]; then
  die "Правило нельзя выписывать на root — Butler работает не от root.
    Укажи пользователя явно: sudo $0 --user ИМЯ"
fi
id "$BUTLER_USER" &>/dev/null || die "Пользователь '${BUTLER_USER}' не существует."

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

# Проверяем, что правило реально применилось к нужному пользователю,
# а не просто записалось в файл.
if sudo -l -U "$BUTLER_USER" 2>/dev/null | grep -q "NOPASSWD.*${NFT_BIN}"; then
  ok "Проверено: ${BUTLER_USER} может вызывать nft без пароля."
else
  warn "Файл записан, но sudo не подтверждает права для ${BUTLER_USER}."
  echo "      Проверь вручную: sudo -l -U ${BUTLER_USER}"
fi

ok "Sudoers настроен для пользователя: $BUTLER_USER"
echo "  Файл: $SUDOERS_FILE"
echo "  Разрешены: nft, journalctl${CONNTRACK_ENTRY:+, conntrack}"
