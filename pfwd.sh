#!/usr/bin/env bash
set -euo pipefail

VERSION="1.0.0"

PFWD_DIR="${PFWD_DIR:-/etc/pfwd}"
RULES_FILE="$PFWD_DIR/rules.tsv"
COUNTER_FILE="$PFWD_DIR/.id_counter"
PERF_CONFIG_FILE="$PFWD_DIR/pfwd.conf"
SYSCTL_FILE="/etc/sysctl.d/99-pfwd.conf"
SERVICE_NAME="pfwd-restore.service"

CHAIN_NAT_PRE="PFWD_PREROUTING"
CHAIN_NAT_POST="PFWD_POSTROUTING"
CHAIN_FILTER_FWD="PFWD_FORWARD"

HEADER=$'id\tenabled\tproto\tlisten_ip\tlisten_port\tdest_ip\tdest_port\tname\tcreated_at\tupdated_at'

DRY_RUN=0
OUTPUT_JSON=0
PFWD_MATCH_PUB_IFACE="1"
PFWD_SNAT_MODE="auto"
PFWD_SNAT_IP=""

usage() {
    cat <<'EOF'
pfwd - Single-server port forwarding manager

Usage:
  pfwd [--dry-run] [--json] <command> [args]
  pfwd                      # opens interactive menu (TTY)

Commands:
  init
  perf show
  perf set [--match-pub-iface 0|1] [--snat-mode auto|snat|masquerade] [--snat-ip IP]
  add [--proto tcp|udp|both] --listen IP:PORT --to IP:PORT [--name NAME] [--enable|--disable]
  list
  show <id>
  update <id> [--proto tcp|udp|both] [--listen IP:PORT] [--to IP:PORT] [--name NAME] [--enable|--disable]
  remove <id>
  enable <id>
  disable <id>
  apply
  status
  flush --managed-only [--purge-state]
  export [file]
  import <file>
  help

Global flags:
  --dry-run   Preview changes without writing state or changing firewall rules
  --json      JSON output for list/show/status
  --version   Print version
EOF
}

log() {
    printf '%s\n' "$*"
}

err() {
    printf 'Error: %s\n' "$*" >&2
}

die() {
    err "$*"
    exit 1
}

require_root() {
    if [ "$EUID" -ne 0 ]; then
        die "This command requires root."
    fi
}

require_root_if_needed() {
    if [ "$DRY_RUN" -eq 0 ]; then
        require_root
    fi
}

need_cmd() {
    local c
    for c in "$@"; do
        command -v "$c" >/dev/null 2>&1 || die "Missing command: $c"
    done
}

need_iptables() {
    need_cmd iptables iptables-save
}

json_escape() {
    printf '%s' "$1" | sed \
        -e 's/\\/\\\\/g' \
        -e 's/"/\\"/g' \
        -e 's/\t/\\t/g' \
        -e 's/\r/\\r/g' \
        -e ':a;N;$!ba;s/\n/\\n/g'
}

sanitize_name() {
    local name="${1:-}"
    name="${name//$'\t'/ }"
    name="${name//$'\r'/ }"
    name="${name//$'\n'/ }"
    printf '%s' "$name"
}

now_ts() {
    date -u '+%Y-%m-%dT%H:%M:%SZ'
}

validate_ipv4() {
    local ip="${1:-}"
    local o1 o2 o3 o4 o
    [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
    IFS='.' read -r o1 o2 o3 o4 <<< "$ip"
    for o in "$o1" "$o2" "$o3" "$o4"; do
        ((10#$o >= 0 && 10#$o <= 255)) || return 1
    done
    return 0
}

validate_port() {
    local port="${1:-}"
    [[ "$port" =~ ^[0-9]+$ ]] || return 1
    local p=$((10#$port))
    ((p >= 1 && p <= 65535))
}

validate_proto() {
    case "${1:-}" in
        tcp|udp|both) return 0 ;;
        *) return 1 ;;
    esac
}

parse_endpoint() {
    local raw="${1:-}"
    local ip port
    [[ "$raw" == *:* ]] || return 1
    ip="${raw%:*}"
    port="${raw##*:}"
    validate_ipv4 "$ip" || return 1
    validate_port "$port" || return 1
    printf '%s\t%s\n' "$ip" "$((10#$port))"
}

parse_port_mappings() {
    local spec="${1:-}"
    local part left right
    local -a out=()
    declare -A seen=()

    spec="${spec// /}"
    [ -n "$spec" ] || return 1

    IFS=',' read -r -a parts <<< "$spec"
    for part in "${parts[@]}"; do
        [ -n "$part" ] || continue
        if [[ "$part" == *:* ]]; then
            left="${part%%:*}"
            right="${part##*:}"
            validate_port "$left" || return 1
            validate_port "$right" || return 1
            left=$((10#$left))
            right=$((10#$right))
        else
            validate_port "$part" || return 1
            left=$((10#$part))
            right="$left"
        fi
        if [ -n "${seen[$left]:-}" ]; then
            return 1
        fi
        seen[$left]=1
        out+=("${left}:${right}")
    done

    [ "${#out[@]}" -gt 0 ] || return 1
    printf '%s\n' "${out[@]}"
}

detect_pub_iface() {
    local dev=""
    dev="$(ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}' || true)"
    if [ -n "$dev" ] && ip link show "$dev" >/dev/null 2>&1; then
        printf '%s' "$dev"
        return 0
    fi
    dev="$(ip route show default 2>/dev/null | awk 'NR==1{print $5}' || true)"
    if [ -n "$dev" ] && ip link show "$dev" >/dev/null 2>&1; then
        printf '%s' "$dev"
        return 0
    fi
    return 1
}

detect_src_ip_for_dst() {
    local dst="${1:-}"
    local src=""
    [ -n "$dst" ] || return 1
    src="$(ip -4 route get "$dst" 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}' || true)"
    validate_ipv4 "$src" || return 1
    printf '%s' "$src"
}

detect_server_ipv4() {
    local ip=""
    ip="$(detect_src_ip_for_dst "1.1.1.1" || true)"
    if validate_ipv4 "$ip"; then
        printf '%s' "$ip"
        return 0
    fi

    ip="$(ip -4 -o addr show scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -n1 || true)"
    if validate_ipv4 "$ip"; then
        printf '%s' "$ip"
        return 0
    fi

    ip="$(hostname -I 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/){print $i; exit}}' || true)"
    if validate_ipv4 "$ip"; then
        printf '%s' "$ip"
        return 0
    fi

    printf 'N/A'
}

ensure_perf_config_file() {
    mkdir -p "$PFWD_DIR"
    if [ -f "$PERF_CONFIG_FILE" ]; then
        return 0
    fi
    cat > "$PERF_CONFIG_FILE" <<'EOF'
# PFWD performance profile
# 1 = match only public interface for forwarded traffic (faster/stricter)
PFWD_MATCH_PUB_IFACE="1"
# auto = prefer SNAT with detected source IP, fallback to MASQUERADE
# snat = force SNAT when a source IP is available (or from PFWD_SNAT_IP), fallback to MASQUERADE
# masquerade = always use MASQUERADE
PFWD_SNAT_MODE="auto"
# Optional fixed SNAT source IP for performance/stability (empty = auto detect)
PFWD_SNAT_IP=""
EOF
}

load_perf_profile() {
    PFWD_MATCH_PUB_IFACE="1"
    PFWD_SNAT_MODE="auto"
    PFWD_SNAT_IP=""
    ensure_perf_config_file
    # shellcheck disable=SC1090
    source "$PERF_CONFIG_FILE" 2>/dev/null || true

    case "${PFWD_MATCH_PUB_IFACE:-}" in
        0|1) ;;
        *) PFWD_MATCH_PUB_IFACE="1" ;;
    esac

    case "${PFWD_SNAT_MODE:-}" in
        auto|snat|masquerade) ;;
        *) PFWD_SNAT_MODE="auto" ;;
    esac

    if [ -n "${PFWD_SNAT_IP:-}" ] && ! validate_ipv4 "$PFWD_SNAT_IP"; then
        PFWD_SNAT_IP=""
    fi
}

resolve_snat_ip_for_dst() {
    local dst="${1:-}"
    local snat_ip=""
    if [ -n "${PFWD_SNAT_IP:-}" ]; then
        validate_ipv4 "$PFWD_SNAT_IP" && printf '%s' "$PFWD_SNAT_IP"
        return 0
    fi
    snat_ip="$(detect_src_ip_for_dst "$dst" || true)"
    if validate_ipv4 "$snat_ip" && [[ "$snat_ip" != 127.* ]]; then
        printf '%s' "$snat_ip"
        return 0
    fi
    return 1
}

ensure_state_files() {
    mkdir -p "$PFWD_DIR"
    if [ ! -f "$RULES_FILE" ]; then
        printf '%s\n' "$HEADER" > "$RULES_FILE"
    fi
    if [ ! -f "$COUNTER_FILE" ]; then
        printf '0\n' > "$COUNTER_FILE"
    fi
    local first
    first="$(head -n 1 "$RULES_FILE" 2>/dev/null || true)"
    if [ "$first" != "$HEADER" ]; then
        die "Invalid state header in $RULES_FILE"
    fi
    ensure_perf_config_file
}

next_rule_id() {
    ensure_state_files
    local current
    current="$(cat "$COUNTER_FILE" 2>/dev/null || echo 0)"
    [[ "$current" =~ ^[0-9]+$ ]] || current=0
    printf '%s\n' $((current + 1))
}

set_counter_value() {
    local id="${1:-0}"
    if [ "$DRY_RUN" -eq 1 ]; then
        log "dry-run: would set counter to $id"
        return 0
    fi
    printf '%s\n' "$id" > "$COUNTER_FILE"
}

get_rule_line() {
    local id="$1"
    awk -F'\t' -v id="$id" 'NR>1 && $1==id {print; exit}' "$RULES_FILE"
}

rule_exists() {
    local id="$1"
    [ -n "$(get_rule_line "$id")" ]
}

is_duplicate_listener() {
    local proto="$1"
    local ip="$2"
    local port="$3"
    local skip_id="${4:-}"
    awk -F'\t' -v proto="$proto" -v ip="$ip" -v port="$port" -v skip="$skip_id" '
        NR>1 && $1!=skip && $4==ip && $5==port {
            if ($3=="both" || proto=="both" || $3==proto) found=1
        }
        END {exit found ? 0 : 1}
    ' "$RULES_FILE"
}

append_rule_line() {
    local line="$1"
    if [ "$DRY_RUN" -eq 1 ]; then
        log "dry-run: would append rule -> $line"
        return 0
    fi
    local tmp
    tmp="$(mktemp)"
    cat "$RULES_FILE" > "$tmp"
    printf '%s\n' "$line" >> "$tmp"
    mv -f "$tmp" "$RULES_FILE"
}

rewrite_rule_line() {
    local id="$1"
    local new_line="$2"
    if [ "$DRY_RUN" -eq 1 ]; then
        log "dry-run: would rewrite rule $id -> $new_line"
        return 0
    fi
    local tmp
    local changed=0
    tmp="$(mktemp)"
    printf '%s\n' "$HEADER" > "$tmp"
    while IFS=$'\t' read -r rid en proto lip lport dip dport name created updated; do
        [ -n "${rid:-}" ] || continue
        if [ "$rid" = "$id" ]; then
            printf '%s\n' "$new_line" >> "$tmp"
            changed=1
        else
            printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
                "$rid" "$en" "$proto" "$lip" "$lport" "$dip" "$dport" "$name" "$created" "$updated" >> "$tmp"
        fi
    done < <(tail -n +2 "$RULES_FILE")
    [ "$changed" -eq 1 ] || { rm -f "$tmp"; die "Rule not found: $id"; }
    mv -f "$tmp" "$RULES_FILE"
}

remove_rule_line() {
    local id="$1"
    if [ "$DRY_RUN" -eq 1 ]; then
        log "dry-run: would remove rule id=$id"
        return 0
    fi
    local tmp
    local removed=0
    tmp="$(mktemp)"
    printf '%s\n' "$HEADER" > "$tmp"
    while IFS=$'\t' read -r rid en proto lip lport dip dport name created updated; do
        [ -n "${rid:-}" ] || continue
        if [ "$rid" = "$id" ]; then
            removed=1
            continue
        fi
        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$rid" "$en" "$proto" "$lip" "$lport" "$dip" "$dport" "$name" "$created" "$updated" >> "$tmp"
    done < <(tail -n +2 "$RULES_FILE")
    [ "$removed" -eq 1 ] || { rm -f "$tmp"; die "Rule not found: $id"; }
    mv -f "$tmp" "$RULES_FILE"
}

ipt_append_unique() {
    local table="$1"
    local chain="$2"
    shift 2
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '+ iptables -t %s -A %s %s\n' "$table" "$chain" "$*"
        return 0
    fi
    if ! iptables -t "$table" -C "$chain" "$@" 2>/dev/null; then
        iptables -t "$table" -A "$chain" "$@"
    fi
}

ensure_chains() {
    need_iptables
    if [ "$DRY_RUN" -eq 1 ]; then
        log "+ ensure chains: $CHAIN_NAT_PRE, $CHAIN_NAT_POST, $CHAIN_FILTER_FWD"
        log "+ ensure jumps from PREROUTING/POSTROUTING/FORWARD"
        return 0
    fi

    iptables -t nat -N "$CHAIN_NAT_PRE" 2>/dev/null || true
    iptables -t nat -N "$CHAIN_NAT_POST" 2>/dev/null || true
    iptables -t filter -N "$CHAIN_FILTER_FWD" 2>/dev/null || true

    iptables -t nat -C PREROUTING -m comment --comment "pfwd-jump" -j "$CHAIN_NAT_PRE" >/dev/null 2>&1 || \
        iptables -t nat -A PREROUTING -m comment --comment "pfwd-jump" -j "$CHAIN_NAT_PRE"
    iptables -t nat -C POSTROUTING -m comment --comment "pfwd-jump" -j "$CHAIN_NAT_POST" >/dev/null 2>&1 || \
        iptables -t nat -A POSTROUTING -m comment --comment "pfwd-jump" -j "$CHAIN_NAT_POST"
    iptables -t filter -C FORWARD -m comment --comment "pfwd-jump" -j "$CHAIN_FILTER_FWD" >/dev/null 2>&1 || \
        iptables -t filter -A FORWARD -m comment --comment "pfwd-jump" -j "$CHAIN_FILTER_FWD"
}

delete_matching_rules_table() {
    local table="$1"
    local pattern="$2"
    local line rule
    while IFS= read -r line; do
        [[ "$line" == -A* ]] || continue
        rule="${line/-A /-D }"
        if [ "$DRY_RUN" -eq 1 ]; then
            printf '+ iptables -t %s %s\n' "$table" "$rule"
        else
            eval "iptables -t \"$table\" $rule" >/dev/null 2>&1 || true
        fi
    done < <(iptables-save -t "$table" 2>/dev/null | grep -- "$pattern" || true)
}

purge_rules_by_id() {
    local id="$1"
    delete_matching_rules_table nat "pfwd:${id}:"
    delete_matching_rules_table filter "pfwd:${id}:"
}

purge_all_managed_rules() {
    delete_matching_rules_table nat "pfwd:"
    delete_matching_rules_table filter "pfwd:"
}

apply_rule_proto() {
    local id="$1"
    local proto="$2"
    local listen_ip="$3"
    local listen_port="$4"
    local dest_ip="$5"
    local dest_port="$6"
    local pub_if="${7:-}"

    local comment_base="pfwd:${id}"
    local dmatch=()
    local in_if=()
    local out_if=()
    if [ "$listen_ip" != "0.0.0.0" ]; then
        dmatch=(-d "$listen_ip")
    fi
    if [ "${PFWD_MATCH_PUB_IFACE:-1}" = "1" ] && [ -n "$pub_if" ] && [ "$listen_ip" = "0.0.0.0" ]; then
        in_if=(-i "$pub_if")
        out_if=(-o "$pub_if")
    fi

    ipt_append_unique nat "$CHAIN_NAT_PRE" \
        "${in_if[@]}" "${dmatch[@]}" -p "$proto" --dport "$listen_port" \
        -m comment --comment "${comment_base}:dnat:${listen_ip}:${listen_port}->${dest_ip}:${dest_port}" \
        -j DNAT --to-destination "${dest_ip}:${dest_port}"

    ipt_append_unique filter "$CHAIN_FILTER_FWD" \
        "${in_if[@]}" -p "$proto" -d "$dest_ip" --dport "$dest_port" \
        -m conntrack --ctstate NEW,ESTABLISHED,RELATED \
        -m comment --comment "${comment_base}:fwd:${listen_port}->${dest_port}" \
        -j ACCEPT

    ipt_append_unique filter "$CHAIN_FILTER_FWD" \
        "${out_if[@]}" -p "$proto" -s "$dest_ip" --sport "$dest_port" \
        -m conntrack --ctstate ESTABLISHED,RELATED \
        -m comment --comment "${comment_base}:rev:${listen_port}->${dest_port}" \
        -j ACCEPT

    local snat_ip=""
    case "${PFWD_SNAT_MODE:-auto}" in
        auto|snat)
            snat_ip="$(resolve_snat_ip_for_dst "$dest_ip" || true)"
            ;;
        masquerade)
            snat_ip=""
            ;;
    esac

    if [ -n "$snat_ip" ]; then
        ipt_append_unique nat "$CHAIN_NAT_POST" \
            "${out_if[@]}" -p "$proto" -d "$dest_ip" --dport "$dest_port" \
            -m comment --comment "${comment_base}:snat-fixed:${listen_port}->${dest_port}:${snat_ip}" \
            -j SNAT --to-source "$snat_ip"
    else
        ipt_append_unique nat "$CHAIN_NAT_POST" \
            "${out_if[@]}" -p "$proto" -d "$dest_ip" --dport "$dest_port" \
            -m comment --comment "${comment_base}:snat-masq:${listen_port}->${dest_port}" \
            -j MASQUERADE
    fi
}

apply_rule() {
    local id="$1"
    local enabled="$2"
    local proto="$3"
    local listen_ip="$4"
    local listen_port="$5"
    local dest_ip="$6"
    local dest_port="$7"
    local pub_if="${8:-}"

    [ "$enabled" = "1" ] || return 0

    if [ "$proto" = "both" ]; then
        apply_rule_proto "$id" tcp "$listen_ip" "$listen_port" "$dest_ip" "$dest_port" "$pub_if"
        apply_rule_proto "$id" udp "$listen_ip" "$listen_port" "$dest_ip" "$dest_port" "$pub_if"
    else
        apply_rule_proto "$id" "$proto" "$listen_ip" "$listen_port" "$dest_ip" "$dest_port" "$pub_if"
    fi
}

chain_exists() {
    local table="$1"
    local chain="$2"
    iptables -t "$table" -S "$chain" >/dev/null 2>&1
}

jump_exists() {
    local table="$1"
    local parent="$2"
    local target="$3"
    iptables-save -t "$table" 2>/dev/null | grep -qE "^-A ${parent} .* -j ${target}([[:space:]]|$)"
}

json_print_rules_array() {
    local first=1
    printf '['
    while IFS=$'\t' read -r id enabled proto lip lport dip dport name created updated; do
        [ -n "${id:-}" ] || continue
        [ "$first" -eq 1 ] || printf ','
        first=0
        printf '{"id":%s,"enabled":%s,"proto":"%s","listen_ip":"%s","listen_port":%s,"dest_ip":"%s","dest_port":%s,"name":"%s","created_at":"%s","updated_at":"%s"}' \
            "$id" \
            "$([ "$enabled" = "1" ] && printf true || printf false)" \
            "$(json_escape "$proto")" \
            "$(json_escape "$lip")" \
            "$lport" \
            "$(json_escape "$dip")" \
            "$dport" \
            "$(json_escape "$name")" \
            "$(json_escape "$created")" \
            "$(json_escape "$updated")"
    done < <(tail -n +2 "$RULES_FILE")
    printf ']\n'
}

json_lines_array() {
    local text="${1:-}"
    local first=1
    printf '['
    while IFS= read -r line; do
        [ -n "$line" ] || continue
        [ "$first" -eq 1 ] || printf ','
        first=0
        printf '"%s"' "$(json_escape "$line")"
    done <<< "$text"
    printf ']'
}

enable_ip_forward() {
    if [ "$DRY_RUN" -eq 1 ]; then
        log "+ sysctl -w net.ipv4.ip_forward=1"
        log "+ write $SYSCTL_FILE"
        return 0
    fi
    mkdir -p "$(dirname "$SYSCTL_FILE")"
    printf 'net.ipv4.ip_forward=1\n' > "$SYSCTL_FILE"
    sysctl -w net.ipv4.ip_forward=1 >/dev/null
    sysctl -p "$SYSCTL_FILE" >/dev/null 2>&1 || true
}

cmd_init() {
    require_root_if_needed
    ensure_state_files
    need_iptables
    enable_ip_forward
    ensure_chains

    if command -v systemctl >/dev/null 2>&1 && [ -f "/etc/systemd/system/$SERVICE_NAME" ]; then
        if [ "$DRY_RUN" -eq 1 ]; then
            log "+ systemctl daemon-reload"
            log "+ systemctl enable $SERVICE_NAME"
        else
            systemctl daemon-reload >/dev/null 2>&1 || true
            systemctl enable "$SERVICE_NAME" >/dev/null 2>&1 || true
        fi
    fi

    cmd_apply
}

cmd_perf() {
    ensure_state_files
    load_perf_profile

    local sub="${1:-show}"
    shift || true

    case "$sub" in
        show)
            if [ "$OUTPUT_JSON" -eq 1 ]; then
                printf '{"match_pub_iface":%s,"snat_mode":"%s","snat_ip":"%s"}\n' \
                    "$([ "$PFWD_MATCH_PUB_IFACE" = "1" ] && printf true || printf false)" \
                    "$(json_escape "$PFWD_SNAT_MODE")" \
                    "$(json_escape "$PFWD_SNAT_IP")"
                return 0
            fi
            log "Performance profile:"
            log "  match_pub_iface: $PFWD_MATCH_PUB_IFACE"
            log "  snat_mode:       $PFWD_SNAT_MODE"
            log "  snat_ip:         ${PFWD_SNAT_IP:-auto}"
            ;;
        set)
            require_root_if_needed
            local new_match="$PFWD_MATCH_PUB_IFACE"
            local new_mode="$PFWD_SNAT_MODE"
            local new_ip="$PFWD_SNAT_IP"

            while [ $# -gt 0 ]; do
                case "$1" in
                    --match-pub-iface)
                        new_match="${2:-}"
                        shift 2
                        ;;
                    --snat-mode)
                        new_mode="${2:-}"
                        shift 2
                        ;;
                    --snat-ip)
                        new_ip="${2:-}"
                        shift 2
                        ;;
                    *)
                        die "Unknown option for perf set: $1"
                        ;;
                esac
            done

            case "$new_match" in
                0|1) ;;
                *) die "Invalid --match-pub-iface (use 0 or 1)." ;;
            esac
            case "$new_mode" in
                auto|snat|masquerade) ;;
                *) die "Invalid --snat-mode (use auto|snat|masquerade)." ;;
            esac
            if [ -n "$new_ip" ] && ! validate_ipv4 "$new_ip"; then
                die "Invalid --snat-ip"
            fi

            if [ "$DRY_RUN" -eq 1 ]; then
                log "dry-run: would update $PERF_CONFIG_FILE"
                log "  PFWD_MATCH_PUB_IFACE=\"$new_match\""
                log "  PFWD_SNAT_MODE=\"$new_mode\""
                log "  PFWD_SNAT_IP=\"$new_ip\""
                return 0
            fi

            cat > "$PERF_CONFIG_FILE" <<EOF
# PFWD performance profile
PFWD_MATCH_PUB_IFACE="$new_match"
PFWD_SNAT_MODE="$new_mode"
PFWD_SNAT_IP="$new_ip"
EOF
            log "Performance profile updated."
            cmd_apply
            ;;
        *)
            die "Usage: pfwd perf show | pfwd perf set [--match-pub-iface 0|1] [--snat-mode auto|snat|masquerade] [--snat-ip IP]"
            ;;
    esac
}

cmd_add() {
    ensure_state_files
    require_root_if_needed

    local proto="both"
    local listen=""
    local dest=""
    local name=""
    local enabled="1"

    while [ $# -gt 0 ]; do
        case "$1" in
            --proto) proto="${2:-}"; shift 2 ;;
            --listen) listen="${2:-}"; shift 2 ;;
            --to) dest="${2:-}"; shift 2 ;;
            --name) name="${2:-}"; shift 2 ;;
            --enable) enabled="1"; shift ;;
            --disable) enabled="0"; shift ;;
            *) die "Unknown option for add: $1" ;;
        esac
    done

    validate_proto "$proto" || die "Invalid --proto (use tcp, udp, or both)."
    [ -n "$listen" ] || die "Missing --listen IP:PORT"
    [ -n "$dest" ] || die "Missing --to IP:PORT"

    local parsed lip lport dip dport
    parsed="$(parse_endpoint "$listen")" || die "Invalid --listen endpoint: $listen"
    IFS=$'\t' read -r lip lport <<< "$parsed"
    parsed="$(parse_endpoint "$dest")" || die "Invalid --to endpoint: $dest"
    IFS=$'\t' read -r dip dport <<< "$parsed"

    name="$(sanitize_name "$name")"

    if is_duplicate_listener "$proto" "$lip" "$lport"; then
        die "Duplicate listen endpoint already exists for $proto $lip:$lport"
    fi

    local id now row
    id="$(next_rule_id)"
    now="$(now_ts)"
    row="$(printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s' "$id" "$enabled" "$proto" "$lip" "$lport" "$dip" "$dport" "$name" "$now" "$now")"

    if [ "$DRY_RUN" -eq 1 ]; then
        log "dry-run: would add rule id=$id"
        log "  proto=$proto listen=$lip:$lport to=$dip:$dport enabled=$enabled name=$name"
        load_perf_profile
        ensure_chains
        purge_rules_by_id "$id"
        local dry_pub_if=""
        if [ "${PFWD_MATCH_PUB_IFACE:-1}" = "1" ]; then
            dry_pub_if="$(detect_pub_iface || true)"
        fi
        apply_rule "$id" "$enabled" "$proto" "$lip" "$lport" "$dip" "$dport" "$dry_pub_if"
        return 0
    fi

    append_rule_line "$row"
    set_counter_value "$id"
    cmd_apply
    log "Added rule id=$id"
}

cmd_list() {
    ensure_state_files
    if [ "$OUTPUT_JSON" -eq 1 ]; then
        json_print_rules_array
        return 0
    fi

    printf '%-4s %-2s %-5s %-21s %-21s %-24s %-20s\n' "ID" "EN" "P" "LISTEN" "DEST" "NAME" "UPDATED"
    printf '%-4s %-2s %-5s %-21s %-21s %-24s %-20s\n' "----" "--" "-----" "---------------------" "---------------------" "------------------------" "--------------------"
    while IFS=$'\t' read -r id enabled proto lip lport dip dport name _created updated; do
        [ -n "${id:-}" ] || continue
        local en="N"
        [ "$enabled" = "1" ] && en="Y"
        printf '%-4s %-2s %-5s %-21s %-21s %-24s %-20s\n' \
            "$id" "$en" "$proto" "$lip:$lport" "$dip:$dport" "${name:--}" "${updated:-"-"}"
    done < <(tail -n +2 "$RULES_FILE")
}

cmd_show() {
    ensure_state_files
    local id="${1:-}"
    [ -n "$id" ] || die "Usage: pfwd show <id>"
    [[ "$id" =~ ^[0-9]+$ ]] || die "Invalid id: $id"

    local line
    line="$(get_rule_line "$id")"
    [ -n "$line" ] || die "Rule not found: $id"

    local rid enabled proto lip lport dip dport name created updated
    IFS=$'\t' read -r rid enabled proto lip lport dip dport name created updated <<< "$line"

    local nat_rules="" filter_rules=""
    if command -v iptables-save >/dev/null 2>&1; then
        nat_rules="$(iptables-save -t nat 2>/dev/null | grep -- "pfwd:${id}:" || true)"
        filter_rules="$(iptables-save -t filter 2>/dev/null | grep -- "pfwd:${id}:" || true)"
    fi

    if [ "$OUTPUT_JSON" -eq 1 ]; then
        printf '{'
        printf '"id":%s,' "$rid"
        printf '"enabled":%s,' "$([ "$enabled" = "1" ] && printf true || printf false)"
        printf '"proto":"%s",' "$(json_escape "$proto")"
        printf '"listen_ip":"%s",' "$(json_escape "$lip")"
        printf '"listen_port":%s,' "$lport"
        printf '"dest_ip":"%s",' "$(json_escape "$dip")"
        printf '"dest_port":%s,' "$dport"
        printf '"name":"%s",' "$(json_escape "$name")"
        printf '"created_at":"%s",' "$(json_escape "$created")"
        printf '"updated_at":"%s",' "$(json_escape "$updated")"
        printf '"nat_rules":'
        json_lines_array "$nat_rules"
        printf ','
        printf '"filter_rules":'
        json_lines_array "$filter_rules"
        printf '}\n'
        return 0
    fi

    log "ID:          $rid"
    log "Enabled:     $enabled"
    log "Protocol:    $proto"
    log "Listen:      $lip:$lport"
    log "Destination: $dip:$dport"
    log "Name:        ${name:--}"
    log "Created:     ${created:--}"
    log "Updated:     ${updated:--}"
    log ""
    log "NAT rules:"
    if [ -n "$nat_rules" ]; then
        printf '%s\n' "$nat_rules"
    else
        log "  (none)"
    fi
    log ""
    log "Filter rules:"
    if [ -n "$filter_rules" ]; then
        printf '%s\n' "$filter_rules"
    else
        log "  (none)"
    fi
}

cmd_update() {
    ensure_state_files
    require_root_if_needed

    local id="${1:-}"
    [ -n "$id" ] || die "Usage: pfwd update <id> [options]"
    shift || true
    [[ "$id" =~ ^[0-9]+$ ]] || die "Invalid id: $id"

    local line
    line="$(get_rule_line "$id")"
    [ -n "$line" ] || die "Rule not found: $id"

    local rid enabled proto lip lport dip dport name created _updated
    IFS=$'\t' read -r rid enabled proto lip lport dip dport name created _updated <<< "$line"

    local new_proto="$proto"
    local new_lip="$lip"
    local new_lport="$lport"
    local new_dip="$dip"
    local new_dport="$dport"
    local new_name="$name"
    local new_enabled="$enabled"

    while [ $# -gt 0 ]; do
        case "$1" in
            --proto)
                new_proto="${2:-}"
                shift 2
                ;;
            --listen)
                local parsed
                parsed="$(parse_endpoint "${2:-}")" || die "Invalid --listen endpoint: ${2:-}"
                IFS=$'\t' read -r new_lip new_lport <<< "$parsed"
                shift 2
                ;;
            --to)
                local parsed_to
                parsed_to="$(parse_endpoint "${2:-}")" || die "Invalid --to endpoint: ${2:-}"
                IFS=$'\t' read -r new_dip new_dport <<< "$parsed_to"
                shift 2
                ;;
            --name)
                new_name="$(sanitize_name "${2:-}")"
                shift 2
                ;;
            --enable)
                new_enabled="1"
                shift
                ;;
            --disable)
                new_enabled="0"
                shift
                ;;
            *)
                die "Unknown option for update: $1"
                ;;
        esac
    done

    validate_proto "$new_proto" || die "Invalid --proto (use tcp, udp, or both)."

    if is_duplicate_listener "$new_proto" "$new_lip" "$new_lport" "$id"; then
        die "Duplicate listen endpoint already exists for $new_proto $new_lip:$new_lport"
    fi

    local updated now new_line
    now="$(now_ts)"
    updated="$now"
    new_line="$(printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s' "$id" "$new_enabled" "$new_proto" "$new_lip" "$new_lport" "$new_dip" "$new_dport" "$new_name" "$created" "$updated")"

    if [ "$DRY_RUN" -eq 1 ]; then
        log "dry-run: would update rule id=$id"
        log "  old: proto=$proto listen=$lip:$lport to=$dip:$dport enabled=$enabled name=$name"
        log "  new: proto=$new_proto listen=$new_lip:$new_lport to=$new_dip:$new_dport enabled=$new_enabled name=$new_name"
        load_perf_profile
        ensure_chains
        purge_rules_by_id "$id"
        local dry_pub_if=""
        if [ "${PFWD_MATCH_PUB_IFACE:-1}" = "1" ]; then
            dry_pub_if="$(detect_pub_iface || true)"
        fi
        apply_rule "$id" "$new_enabled" "$new_proto" "$new_lip" "$new_lport" "$new_dip" "$new_dport" "$dry_pub_if"
        return 0
    fi

    rewrite_rule_line "$id" "$new_line"
    cmd_apply
    log "Updated rule id=$id"
}

cmd_remove() {
    ensure_state_files
    require_root_if_needed

    local id="${1:-}"
    [ -n "$id" ] || die "Usage: pfwd remove <id>"
    [[ "$id" =~ ^[0-9]+$ ]] || die "Invalid id: $id"
    rule_exists "$id" || die "Rule not found: $id"

    if [ "$DRY_RUN" -eq 1 ]; then
        log "dry-run: would remove rule id=$id"
        purge_rules_by_id "$id"
        return 0
    fi

    remove_rule_line "$id"
    cmd_apply
    log "Removed rule id=$id"
}

cmd_set_enabled() {
    local id="$1"
    local value="$2"
    ensure_state_files
    require_root_if_needed
    [[ "$id" =~ ^[0-9]+$ ]] || die "Invalid id: $id"

    local line
    line="$(get_rule_line "$id")"
    [ -n "$line" ] || die "Rule not found: $id"

    local rid _enabled proto lip lport dip dport name created _updated
    IFS=$'\t' read -r rid _enabled proto lip lport dip dport name created _updated <<< "$line"
    local updated
    updated="$(now_ts)"
    local new_line
    new_line="$(printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s' "$id" "$value" "$proto" "$lip" "$lport" "$dip" "$dport" "$name" "$created" "$updated")"

    if [ "$DRY_RUN" -eq 1 ]; then
        log "dry-run: would set rule id=$id enabled=$value"
        load_perf_profile
        ensure_chains
        purge_rules_by_id "$id"
        local dry_pub_if=""
        if [ "${PFWD_MATCH_PUB_IFACE:-1}" = "1" ]; then
            dry_pub_if="$(detect_pub_iface || true)"
        fi
        apply_rule "$id" "$value" "$proto" "$lip" "$lport" "$dip" "$dport" "$dry_pub_if"
        return 0
    fi

    rewrite_rule_line "$id" "$new_line"
    cmd_apply
    log "Rule id=$id enabled=$value"
}

cmd_apply() {
    ensure_state_files
    require_root_if_needed
    need_iptables
    load_perf_profile
    ensure_chains
    purge_all_managed_rules

    local applied=0
    local pub_if=""
    if [ "${PFWD_MATCH_PUB_IFACE:-1}" = "1" ]; then
        pub_if="$(detect_pub_iface || true)"
    fi
    while IFS=$'\t' read -r rid renabled rproto rlip rlport rdip rdport _name _created _updated; do
        [ -n "${rid:-}" ] || continue
        apply_rule "$rid" "$renabled" "$rproto" "$rlip" "$rlport" "$rdip" "$rdport" "$pub_if"
        if [ "$renabled" = "1" ]; then
            applied=$((applied + 1))
        fi
    done < <(tail -n +2 "$RULES_FILE")

    log "Applied $applied enabled rule(s)."
}

cmd_status() {
    ensure_state_files
    load_perf_profile

    local ipfwd="unknown"
    local server_ipv4="N/A"
    [ -r /proc/sys/net/ipv4/ip_forward ] && ipfwd="$(cat /proc/sys/net/ipv4/ip_forward)"
    server_ipv4="$(detect_server_ipv4 || echo N/A)"

    local chains_ok="unknown"
    local hooks_ok="unknown"
    local managed_count="0"
    if command -v iptables >/dev/null 2>&1 && command -v iptables-save >/dev/null 2>&1; then
        if chain_exists nat "$CHAIN_NAT_PRE" && chain_exists nat "$CHAIN_NAT_POST" && chain_exists filter "$CHAIN_FILTER_FWD"; then
            chains_ok="yes"
        else
            chains_ok="no"
        fi
        if jump_exists nat PREROUTING "$CHAIN_NAT_PRE" && jump_exists nat POSTROUTING "$CHAIN_NAT_POST" && jump_exists filter FORWARD "$CHAIN_FILTER_FWD"; then
            hooks_ok="yes"
        else
            hooks_ok="no"
        fi
        local nat_count filter_count
        nat_count="$(iptables-save -t nat 2>/dev/null | grep -c 'pfwd:' || true)"
        filter_count="$(iptables-save -t filter 2>/dev/null | grep -c 'pfwd:' || true)"
        managed_count=$((nat_count + filter_count))
    fi

    local total_rules enabled_rules
    total_rules="$(awk 'END {print (NR>0 ? NR-1 : 0)}' "$RULES_FILE")"
    enabled_rules="$(awk -F'\t' 'NR>1 && $2=="1" {c++} END {print c+0}' "$RULES_FILE")"

    local svc_enabled="unknown" svc_active="unknown"
    if command -v systemctl >/dev/null 2>&1; then
        svc_enabled="$(systemctl is-enabled "$SERVICE_NAME" 2>/dev/null | head -n 1 || true)"
        svc_active="$(systemctl is-active "$SERVICE_NAME" 2>/dev/null | head -n 1 || true)"
        [ -n "$svc_enabled" ] || svc_enabled="disabled"
        [ -n "$svc_active" ] || svc_active="inactive"
    fi

    if [ "$OUTPUT_JSON" -eq 1 ]; then
        printf '{'
        printf '"server_ipv4":"%s",' "$(json_escape "$server_ipv4")"
        printf '"ip_forward":"%s",' "$(json_escape "$ipfwd")"
        printf '"chains_ok":"%s",' "$(json_escape "$chains_ok")"
        printf '"hooks_ok":"%s",' "$(json_escape "$hooks_ok")"
        printf '"managed_rule_count":%s,' "$managed_count"
        printf '"state_rule_count":%s,' "$total_rules"
        printf '"state_enabled_count":%s,' "$enabled_rules"
        printf '"service_enabled":"%s",' "$(json_escape "$svc_enabled")"
        printf '"service_active":"%s",' "$(json_escape "$svc_active")"
        printf '"perf_match_pub_iface":%s,' "$([ "$PFWD_MATCH_PUB_IFACE" = "1" ] && printf true || printf false)"
        printf '"perf_snat_mode":"%s",' "$(json_escape "$PFWD_SNAT_MODE")"
        printf '"perf_snat_ip":"%s"' "$(json_escape "$PFWD_SNAT_IP")"
        printf '}\n'
        return 0
    fi

    log "pfwd version:        $VERSION"
    log "state dir:           $PFWD_DIR"
    log "server ipv4:         $server_ipv4"
    log "ip_forward:          $ipfwd"
    log "chains ready:        $chains_ok"
    log "hooks ready:         $hooks_ok"
    log "managed fw rules:    $managed_count"
    log "state rules:         $total_rules (enabled: $enabled_rules)"
    log "restore service:     enabled=$svc_enabled active=$svc_active"
    log "perf match iface:    $PFWD_MATCH_PUB_IFACE"
    log "perf SNAT mode:      $PFWD_SNAT_MODE"
    log "perf SNAT ip:        ${PFWD_SNAT_IP:-auto}"
    log ""
    log "Doctor:"
    [ "$ipfwd" = "1" ] || log "  - net.ipv4.ip_forward is not 1"
    [ "$chains_ok" = "yes" ] || log "  - pfwd chains are missing (run: pfwd init)"
    [ "$hooks_ok" = "yes" ] || log "  - pfwd hooks are missing (run: pfwd init)"
    [ "$svc_enabled" = "enabled" ] || log "  - restore service is not enabled (run install.sh or systemctl enable $SERVICE_NAME)"
}

cmd_flush() {
    ensure_state_files
    require_root_if_needed

    local managed_only=0
    local purge_state=0

    while [ $# -gt 0 ]; do
        case "$1" in
            --managed-only) managed_only=1; shift ;;
            --purge-state) purge_state=1; shift ;;
            *) die "Unknown option for flush: $1" ;;
        esac
    done

    [ "$managed_only" -eq 1 ] || die "flush requires --managed-only"
    need_iptables
    purge_all_managed_rules

    if [ "$purge_state" -eq 1 ]; then
        if [ "$DRY_RUN" -eq 1 ]; then
            log "dry-run: would clear $RULES_FILE and reset counter"
        else
            printf '%s\n' "$HEADER" > "$RULES_FILE"
            printf '0\n' > "$COUNTER_FILE"
        fi
    fi

    log "Flushed managed firewall rules."
}

cmd_export() {
    ensure_state_files
    local out="${1:-}"
    if [ -z "$out" ]; then
        cat "$RULES_FILE"
        return 0
    fi

    if [ "$DRY_RUN" -eq 1 ]; then
        log "dry-run: would export rules to $out"
        return 0
    fi

    cp "$RULES_FILE" "$out"
    log "Exported rules to $out"
}

cmd_import() {
    ensure_state_files
    require_root_if_needed

    local input="${1:-}"
    [ -n "$input" ] || die "Usage: pfwd import <file>"
    [ -f "$input" ] || die "File not found: $input"

    local first
    first="$(head -n 1 "$input" 2>/dev/null || true)"
    [ "$first" = "$HEADER" ] || die "Invalid import header."

    local tmp
    tmp="$(mktemp)"
    printf '%s\n' "$HEADER" > "$tmp"

    local max_id=0 count=0
    declare -A seen_ids=()
    declare -A seen_tcp=()
    declare -A seen_udp=()
    declare -A seen_both=()

    local line
    while IFS= read -r line || [ -n "$line" ]; do
        [ -n "$line" ] || continue
        [ "$line" = "$HEADER" ] && continue

        local id enabled proto lip lport dip dport name created updated
        IFS=$'\t' read -r id enabled proto lip lport dip dport name created updated <<< "$line"

        [[ "$id" =~ ^[0-9]+$ ]] || { rm -f "$tmp"; die "Invalid id in import: $id"; }
        [ "$id" -ge 1 ] || { rm -f "$tmp"; die "Import id must be >=1: $id"; }
        [ "$enabled" = "0" ] || [ "$enabled" = "1" ] || { rm -f "$tmp"; die "Invalid enabled value for id $id"; }
        validate_proto "$proto" || { rm -f "$tmp"; die "Invalid proto for id $id"; }
        validate_ipv4 "$lip" || { rm -f "$tmp"; die "Invalid listen_ip for id $id"; }
        validate_port "$lport" || { rm -f "$tmp"; die "Invalid listen_port for id $id"; }
        validate_ipv4 "$dip" || { rm -f "$tmp"; die "Invalid dest_ip for id $id"; }
        validate_port "$dport" || { rm -f "$tmp"; die "Invalid dest_port for id $id"; }
        name="$(sanitize_name "$name")"
        [ -n "${created:-}" ] || created="$(now_ts)"
        [ -n "${updated:-}" ] || updated="$created"

        if [ -n "${seen_ids[$id]:-}" ]; then
            rm -f "$tmp"
            die "Duplicate id in import: $id"
        fi
        seen_ids[$id]=1

        local pkey="${lip}:${lport}"
        case "$proto" in
            both)
                if [ -n "${seen_both[$pkey]:-}" ] || [ -n "${seen_tcp[$pkey]:-}" ] || [ -n "${seen_udp[$pkey]:-}" ]; then
                    rm -f "$tmp"
                    die "Duplicate listen endpoint in import: both $lip:$lport"
                fi
                seen_both[$pkey]=1
                ;;
            tcp)
                if [ -n "${seen_both[$pkey]:-}" ] || [ -n "${seen_tcp[$pkey]:-}" ]; then
                    rm -f "$tmp"
                    die "Duplicate listen endpoint in import: tcp $lip:$lport"
                fi
                seen_tcp[$pkey]=1
                ;;
            udp)
                if [ -n "${seen_both[$pkey]:-}" ] || [ -n "${seen_udp[$pkey]:-}" ]; then
                    rm -f "$tmp"
                    die "Duplicate listen endpoint in import: udp $lip:$lport"
                fi
                seen_udp[$pkey]=1
                ;;
        esac

        [ "$id" -gt "$max_id" ] && max_id="$id"
        count=$((count + 1))

        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$id" "$enabled" "$proto" "$lip" "$lport" "$dip" "$dport" "$name" "$created" "$updated" >> "$tmp"
    done < "$input"

    if [ "$DRY_RUN" -eq 1 ]; then
        rm -f "$tmp"
        log "dry-run: import validated ($count rule(s), max id: $max_id)"
        return 0
    fi

    mv -f "$tmp" "$RULES_FILE"
    printf '%s\n' "$max_id" > "$COUNTER_FILE"
    cmd_apply
    log "Imported $count rule(s) from $input"
}

pause_prompt() {
    if [ -t 0 ]; then
        read -r -p "Press Enter to continue... " _
    fi
}

run_menu_cmd() {
    if ( "$@" ); then
        return 0
    fi
    local rc=$?
    err "Action failed (exit code: $rc)"
    return "$rc"
}

prompt_menu_choice() {
    local prompt="$1"
    local default="${2:-}"
    local ans=""
    if [ -n "$default" ]; then
        read -r -p "$prompt [$default]: " ans
        ans="${ans:-$default}"
    else
        read -r -p "$prompt: " ans
    fi
    printf '%s' "$ans"
}

menu_header() {
    local server_ipv4="N/A"
    if [ -t 1 ]; then
        clear
    fi
    server_ipv4="$(detect_server_ipv4 || echo N/A)"
    echo "========================================"
    echo " PFWD Interactive Manager v$VERSION"
    echo "========================================"
    if [ "$DRY_RUN" -eq 1 ]; then
        echo "Mode: DRY-RUN (no real changes)"
    fi
    if [ -r "$RULES_FILE" ]; then
        local total enabled
        total="$(awk 'END {print (NR>0 ? NR-1 : 0)}' "$RULES_FILE" 2>/dev/null || echo 0)"
        enabled="$(awk -F'\t' 'NR>1 && $2=="1"{c++} END{print c+0}' "$RULES_FILE" 2>/dev/null || echo 0)"
        echo "Rules: $total (enabled: $enabled)"
    else
        echo "Rules: 0"
    fi
    echo "Server IPv4: $server_ipv4"
    echo ""
}

menu_quick_add() {
    echo "Add New Forward"
    echo "---------------"
    local pchoice proto listen_ip ports_input mappings dest_ip name enable_ans enabled
    local map_count=0
    pchoice="$(prompt_menu_choice "Protocol 1)both 2)tcp 3)udp" "1")"
    case "$pchoice" in
        1|both|BOTH) proto="both" ;;
        2|tcp|TCP) proto="tcp" ;;
        3|udp|UDP) proto="udp" ;;
        *) err "Invalid protocol choice."; return 1 ;;
    esac

    listen_ip="$(prompt_menu_choice "Incoming listen IP" "0.0.0.0")"
    validate_ipv4 "$listen_ip" || { err "Invalid incoming IP."; return 1; }

    echo "Ports format:"
    echo "  8080,2020,3030            => 8080->8080, 2020->2020, 3030->3030"
    echo "  8080:9090,2020:3030       => 8080->9090, 2020->3030"
    ports_input="$(prompt_menu_choice "Ports/mappings (comma-separated)")"
    mappings="$(parse_port_mappings "$ports_input" || true)"
    [ -n "$mappings" ] || { err "Invalid ports format."; return 1; }
    map_count="$(printf '%s\n' "$mappings" | sed '/^\s*$/d' | wc -l | tr -d ' ')"

    dest_ip="$(prompt_menu_choice "Destination IP (for all mappings)")"
    validate_ipv4 "$dest_ip" || { err "Invalid destination IP."; return 1; }

    read -r -p "Name (optional): " name
    enable_ans="$(prompt_menu_choice "Enable now? (y/n)" "y")"
    case "$enable_ans" in
        y|Y|yes|YES) enabled="1" ;;
        n|N|no|NO) enabled="0" ;;
        *) err "Invalid enable choice."; return 1 ;;
    esac

    name="$(sanitize_name "$name")"

    local pair ext inport
    while IFS= read -r pair; do
        [ -n "$pair" ] || continue
        ext="${pair%%:*}"
        inport="${pair##*:}"
        if is_duplicate_listener "$proto" "$listen_ip" "$ext"; then
            err "Duplicate listener exists for $proto $listen_ip:$ext"
            return 1
        fi
    done <<< "$mappings"

    if [ "$DRY_RUN" -eq 1 ]; then
        while IFS= read -r pair; do
            [ -n "$pair" ] || continue
            ext="${pair%%:*}"
            inport="${pair##*:}"
            local rule_name="$name"
            if [ -n "$name" ] && [ "${map_count:-0}" -gt 1 ]; then
                rule_name="${name}-${ext}-to-${inport}"
            fi
            local args=(--proto "$proto" --listen "${listen_ip}:${ext}" --to "${dest_ip}:${inport}")
            [ -n "$rule_name" ] && args+=(--name "$rule_name")
            [ "$enabled" = "0" ] && args+=(--disable)
            run_menu_cmd cmd_add "${args[@]}" || return 1
        done <<< "$mappings"
        return 0
    fi

    local current now id row created_count=0
    current="$(cat "$COUNTER_FILE" 2>/dev/null || echo 0)"
    [[ "$current" =~ ^[0-9]+$ ]] || current=0

    while IFS= read -r pair; do
        [ -n "$pair" ] || continue
        ext="${pair%%:*}"
        inport="${pair##*:}"
        current=$((current + 1))
        id="$current"
        now="$(now_ts)"
        local rule_name="$name"
        if [ -n "$name" ] && [ "${map_count:-0}" -gt 1 ]; then
            rule_name="${name}-${ext}-to-${inport}"
        fi
        row="$(printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s' "$id" "$enabled" "$proto" "$listen_ip" "$ext" "$dest_ip" "$inport" "$rule_name" "$now" "$now")"
        append_rule_line "$row"
        created_count=$((created_count + 1))
    done <<< "$mappings"

    set_counter_value "$current"
    cmd_apply
    log "Added $created_count rule(s)."
}

menu_select_rule_id() {
    local id
    id="$(prompt_menu_choice "Rule ID")"
    [[ "$id" =~ ^[0-9]+$ ]] || { err "Invalid rule ID."; return 1; }
    printf '%s' "$id"
}

menu_update_rule() {
    echo "Update Rule"
    echo "-----------"
    local id
    id="$(menu_select_rule_id)" || return 1
    echo ""
    run_menu_cmd cmd_show "$id" || true
    echo ""
    echo "Leave fields empty to keep current values."

    local proto_input listen_input dest_input name_input state_input
    local args=()
    read -r -p "Protocol (tcp/udp/both, Enter=keep): " proto_input
    if [ -n "$proto_input" ]; then
        validate_proto "$proto_input" || { err "Invalid protocol."; return 1; }
        args+=(--proto "$proto_input")
    fi

    read -r -p "Listen IP:PORT (Enter=keep): " listen_input
    if [ -n "$listen_input" ]; then
        parse_endpoint "$listen_input" >/dev/null 2>&1 || { err "Invalid listen endpoint."; return 1; }
        args+=(--listen "$listen_input")
    fi

    read -r -p "Destination IP:PORT (Enter=keep): " dest_input
    if [ -n "$dest_input" ]; then
        parse_endpoint "$dest_input" >/dev/null 2>&1 || { err "Invalid destination endpoint."; return 1; }
        args+=(--to "$dest_input")
    fi

    read -r -p "Name (Enter=keep, type 'clear' to clear): " name_input
    if [ "$name_input" = "clear" ]; then
        args+=(--name "")
    elif [ -n "$name_input" ]; then
        args+=(--name "$name_input")
    fi

    read -r -p "State (enable/disable/keep) [keep]: " state_input
    state_input="${state_input:-keep}"
    case "$state_input" in
        keep|KEEP) ;;
        enable|ENABLE) args+=(--enable) ;;
        disable|DISABLE) args+=(--disable) ;;
        *) err "Invalid state option."; return 1 ;;
    esac

    run_menu_cmd cmd_update "$id" "${args[@]}"
}

menu_remove_rule() {
    local input confirm
    read -r -p "Rule ID(s) (e.g. 3 or 1,2,5) or 'all': " input
    input="${input// /}"
    [ -n "$input" ] || { err "No input."; return 1; }

    local -a ids=()
    if [ "$input" = "all" ]; then
        while IFS=$'\t' read -r rid _rest; do
            [ -n "${rid:-}" ] || continue
            ids+=("$rid")
        done < <(tail -n +2 "$RULES_FILE")
        [ "${#ids[@]}" -gt 0 ] || { log "No rules to remove."; return 0; }
    else
        IFS=',' read -r -a ids <<< "$input"
    fi

    local clean_ids=()
    local id
    for id in "${ids[@]}"; do
        [ -n "$id" ] || continue
        [[ "$id" =~ ^[0-9]+$ ]] || { err "Invalid rule ID: $id"; return 1; }
        clean_ids+=("$id")
    done
    [ "${#clean_ids[@]}" -gt 0 ] || { err "No valid rule IDs."; return 1; }

    read -r -p "Remove selected rule(s): ${clean_ids[*]} ? (yes/no) [no]: " confirm
    confirm="${confirm:-no}"
    case "$confirm" in
        yes|YES|y|Y)
            for id in "${clean_ids[@]}"; do
                run_menu_cmd cmd_remove "$id" || true
            done
            ;;
        *)
            log "Canceled."
            ;;
    esac
}

menu_toggle_rule() {
    local action="$1"
    local id
    id="$(menu_select_rule_id)" || return 1
    case "$action" in
        enable) run_menu_cmd cmd_set_enabled "$id" "1" ;;
        disable) run_menu_cmd cmd_set_enabled "$id" "0" ;;
        *) err "Unknown toggle action."; return 1 ;;
    esac
}

menu_export_rules() {
    local default_file out
    default_file="/root/pfwd-backup-$(date +%Y%m%d-%H%M%S).tsv"
    out="$(prompt_menu_choice "Export file path" "$default_file")"
    [ -n "$out" ] || { err "Export path cannot be empty."; return 1; }
    run_menu_cmd cmd_export "$out"
}

menu_import_rules() {
    local input
    input="$(prompt_menu_choice "Import file path")"
    [ -n "$input" ] || { err "Import path is required."; return 1; }
    run_menu_cmd cmd_import "$input"
}

menu_flush_rules() {
    local purge confirm
    read -r -p "Also purge saved state? (y/n) [n]: " purge
    purge="${purge:-n}"
    read -r -p "Flush managed firewall rules now? (yes/no) [no]: " confirm
    confirm="${confirm:-no}"
    case "$confirm" in
        yes|YES|y|Y)
            if [[ "$purge" =~ ^([Yy]|yes|YES)$ ]]; then
                run_menu_cmd cmd_flush --managed-only --purge-state
            else
                run_menu_cmd cmd_flush --managed-only
            fi
            ;;
        *)
            log "Canceled."
            ;;
    esac
}

menu_perf_profile() {
    load_perf_profile
    run_menu_cmd cmd_perf show || true
    echo ""
    echo "1) Optimized (recommended): match public iface + SNAT auto"
    echo "2) Compatibility: no iface match + MASQUERADE"
    echo "3) Custom"
    echo "0) Back"
    local ch
    ch="$(prompt_menu_choice "Choose profile" "1")"
    case "$ch" in
        1)
            run_menu_cmd cmd_perf set --match-pub-iface 1 --snat-mode auto --snat-ip ""
            ;;
        2)
            run_menu_cmd cmd_perf set --match-pub-iface 0 --snat-mode masquerade --snat-ip ""
            ;;
        3)
            local m s ip
            m="$(prompt_menu_choice "match-pub-iface (0/1)" "$PFWD_MATCH_PUB_IFACE")"
            s="$(prompt_menu_choice "snat-mode (auto/snat/masquerade)" "$PFWD_SNAT_MODE")"
            ip="$(prompt_menu_choice "snat-ip (type 'auto' to clear)" "${PFWD_SNAT_IP:-auto}")"
            [ "$ip" = "auto" ] && ip=""
            run_menu_cmd cmd_perf set --match-pub-iface "$m" --snat-mode "$s" --snat-ip "$ip"
            ;;
        0)
            ;;
        *)
            err "Invalid profile option."
            ;;
    esac
}

interactive_menu() {
    [ -t 0 ] || die "Interactive menu requires a TTY."
    require_root
    ensure_state_files

    while true; do
        menu_header
        echo "1) Quick Add Forward"
        echo "2) List Forwards"
        echo "3) Show Forward Details"
        echo "4) Update Forward"
        echo "5) Remove Forward"
        echo "6) Enable Forward"
        echo "7) Disable Forward"
        echo "8) Apply Rules"
        echo "9) Status / Doctor"
        echo "10) Initialize PFWD"
        echo "11) Export Rules"
        echo "12) Import Rules"
        echo "13) Flush Managed Rules"
        echo "14) Performance Profile"
        echo "0) Exit"
        echo ""

        local choice
        choice="$(prompt_menu_choice "Select")"
        echo ""

        case "${choice:-}" in
            1) menu_quick_add ;;
            2) run_menu_cmd cmd_list ;;
            3)
                local id
                id="$(menu_select_rule_id)" || true
                [ -n "${id:-}" ] && run_menu_cmd cmd_show "$id" || true
                ;;
            4) menu_update_rule ;;
            5) menu_remove_rule ;;
            6) menu_toggle_rule enable ;;
            7) menu_toggle_rule disable ;;
            8) run_menu_cmd cmd_apply ;;
            9) run_menu_cmd cmd_status ;;
            10) run_menu_cmd cmd_init ;;
            11) menu_export_rules ;;
            12) menu_import_rules ;;
            13) menu_flush_rules ;;
            14) menu_perf_profile ;;
            0|q|Q|exit|EXIT) break ;;
            *) err "Invalid menu choice." ;;
        esac

        echo ""
        pause_prompt
    done
}

main() {
    local args=()
    while [ $# -gt 0 ]; do
        case "$1" in
            --dry-run)
                DRY_RUN=1
                shift
                ;;
            --json)
                OUTPUT_JSON=1
                shift
                ;;
            --version)
                log "$VERSION"
                exit 0
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                args+=("$1")
                shift
                ;;
        esac
    done

    set -- "${args[@]}"
    local cmd="${1:-}"
    if [ -z "$cmd" ]; then
        if [ "$OUTPUT_JSON" -eq 1 ]; then
            die "--json requires a command."
        fi
        if [ -t 0 ] && [ -t 1 ]; then
            interactive_menu
            exit 0
        fi
        usage
        exit 0
    fi
    shift || true

    case "$cmd" in
        init) cmd_init "$@" ;;
        perf) cmd_perf "$@" ;;
        add) cmd_add "$@" ;;
        list) cmd_list "$@" ;;
        show) cmd_show "$@" ;;
        update) cmd_update "$@" ;;
        remove) cmd_remove "$@" ;;
        enable) [ $# -eq 1 ] || die "Usage: pfwd enable <id>"; cmd_set_enabled "$1" "1" ;;
        disable) [ $# -eq 1 ] || die "Usage: pfwd disable <id>"; cmd_set_enabled "$1" "0" ;;
        apply) cmd_apply "$@" ;;
        status) cmd_status "$@" ;;
        flush) cmd_flush "$@" ;;
        export) cmd_export "$@" ;;
        import) cmd_import "$@" ;;
        help) usage ;;
        *) die "Unknown command: $cmd (run: pfwd help)" ;;
    esac
}

main "$@"
