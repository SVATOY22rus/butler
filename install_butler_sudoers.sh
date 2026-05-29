#!/usr/bin/env bash
set -euo pipefail

BUTLER_USER="${1:-butler}"
SUDOERS_FILE="/etc/sudoers.d/butler"

for cmd in visudo install mkdir test cat nft; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "Required command not found: $cmd" >&2
    exit 1
  fi
done

VISUDO_BIN="$(command -v visudo)"
INSTALL_BIN="$(command -v install)"
MKDIR_BIN="$(command -v mkdir)"
TEST_BIN="$(command -v test)"
CAT_BIN="$(command -v cat)"
NFT_BIN="$(command -v nft)"

TMP_FILE="$(mktemp)"
trap 'rm -f "$TMP_FILE"' EXIT

cat > "$TMP_FILE" <<RULES
# Managed by install_butler_sudoers.sh
# Allows the Butler application user to manage its nftables include file
${BUTLER_USER} ALL=(root) NOPASSWD: ${MKDIR_BIN}, ${INSTALL_BIN}, ${TEST_BIN}, ${CAT_BIN}, ${NFT_BIN}
RULES

sudo install -m 0440 "$TMP_FILE" "$SUDOERS_FILE"
sudo "$VISUDO_BIN" -cf "$SUDOERS_FILE"

echo "Installed sudoers policy to $SUDOERS_FILE for user $BUTLER_USER"
echo "Allowed commands: $MKDIR_BIN, $INSTALL_BIN, $TEST_BIN, $CAT_BIN, $NFT_BIN"