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

refresh_repo() {
    local target="${1:?}"
    local url="${2:?}"
    local remote_head branch

    if [ -d "$target/.git" ]; then
        if git -C "$target" fetch --all --prune; then
            remote_head="$(git -C "$target" symbolic-ref --short refs/remotes/origin/HEAD 2>/dev/null || true)"
            if [ -z "$remote_head" ]; then
                if git -C "$target" show-ref --verify --quiet refs/remotes/origin/main; then
                    remote_head="origin/main"
                elif git -C "$target" show-ref --verify --quiet refs/remotes/origin/master; then
                    remote_head="origin/master"
                fi
            fi

            if [ -n "$remote_head" ]; then
                branch="${remote_head#origin/}"
                git -C "$target" checkout -f "$branch" >/dev/null 2>&1 || true
                if git -C "$target" reset --hard "$remote_head"; then
                    return 0
                fi
            fi
        fi
    fi

    rm -rf "$target"
    git clone "$url" "$target"
}

main() {
    if [ "${EUID:-$(id -u)}" -ne 0 ]; then
        echo "Please run as root (example: curl ... | sudo bash)" >&2
        exit 1
    fi

    install_git_if_missing

    refresh_repo "$INSTALL_DIR" "$REPO_URL"

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
