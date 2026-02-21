#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET_BIN="/usr/local/bin/pfwd"
TARGET_SERVICE="/etc/systemd/system/pfwd-restore.service"

if [ "$EUID" -ne 0 ]; then
    echo "Run as root: sudo ./install.sh" >&2
    exit 1
fi

install -m 0755 "$SCRIPT_DIR/pfwd.sh" "$TARGET_BIN"
install -d -m 0755 /etc/pfwd
install -d -m 0755 /etc/systemd/system
install -m 0644 "$SCRIPT_DIR/systemd/pfwd-restore.service" "$TARGET_SERVICE"

if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload >/dev/null 2>&1 || true
    systemctl enable pfwd-restore.service >/dev/null 2>&1 || true
fi

"$TARGET_BIN" init

echo "Installed: $TARGET_BIN"
echo "Service:   pfwd-restore.service"
echo "Done."
