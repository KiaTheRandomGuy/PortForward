#!/usr/bin/env bash
set -euo pipefail

REPO_URL="${REPO_URL:-https://github.com/KiaTheRandomGuy/PortForward.git}"
INSTALL_DIR="${INSTALL_DIR:-/opt/PortForward}"
RUN_PFWD="${RUN_PFWD:-1}"

need_cmd() {
    command -v "$1" >/dev/null 2>&1
}

install_git_if_missing() {
    if need_cmd git; then
        return 0
    fi

    if need_cmd apt-get; then
        apt-get update
        apt-get install -y git
        return 0
    fi
    if need_cmd dnf; then
        dnf install -y git
        return 0
    fi
    if need_cmd yum; then
        yum install -y git
        return 0
    fi

    echo "Error: git is required and no supported package manager was found." >&2
    exit 1
}

main() {
    if [ "${EUID:-$(id -u)}" -ne 0 ]; then
        echo "Please run as root (example: curl ... | sudo bash)" >&2
        exit 1
    fi

    install_git_if_missing

    if [ -d "$INSTALL_DIR/.git" ]; then
        git -C "$INSTALL_DIR" fetch --all --prune
        git -C "$INSTALL_DIR" pull --ff-only
    else
        rm -rf "$INSTALL_DIR"
        git clone "$REPO_URL" "$INSTALL_DIR"
    fi

    chmod +x "$INSTALL_DIR/install.sh"
    "$INSTALL_DIR/install.sh"

    if [ "$RUN_PFWD" = "1" ]; then
        # When launched via "curl | bash", stdin is a pipe.
        # Reattach pfwd to the real terminal so the interactive menu opens.
        if [ -r /dev/tty ] && [ -w /dev/tty ]; then
            exec pfwd </dev/tty >/dev/tty 2>/dev/tty
        fi
        exec pfwd
    fi
}

main "$@"
