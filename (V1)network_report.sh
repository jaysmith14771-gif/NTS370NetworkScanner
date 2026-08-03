#!/bin/bash

# ==========================================
# Secure Network Report Template Generator
# ==========================================
# This script is intended for authorized lab/learning use.
# It collects sanitized user input, generates a report,
# and annotates discovered ports with known functions.
#
# NOTE:
# This version does NOT actively scan a target.
# ==========================================

set -o errexit
set -o nounset
set -o pipefail

OUTPUT_FILE="report.txt"

# ---------- Error Handling ----------
error_exit() {
    echo "Error: $1" >&2
    exit 1
}

trap 'error_exit "An unexpected error occurred while generating the report."' ERR

# ---------- Common Port Reference Table ----------
# You can expand this list over time.
declare -A PORT_NAME=(
    [20]="ftp-data"
    [21]="ftp"
    [22]="ssh"
    [23]="telnet"
    [25]="smtp"
    [53]="dns"
    [67]="dhcp"
    [68]="dhcp"
    [69]="tftp"
    [80]="http"
    [110]="pop3"
    [123]="ntp"
    [143]="imap"
    [161]="snmp"
    [162]="snmptrap"
    [179]="bgp"
    [389]="ldap"
    [443]="https"
    [465]="smtps"
    [514]="syslog"
    [587]="submission"
    [636]="ldaps"
    [993]="imaps"
    [995]="pop3s"
    [1433]="ms-sql"
    [1521]="oracle"
    [2049]="nfs"
    [3306]="mysql"
    [3389]="rdp"
    [5432]="postgresql"
    [5900]="vnc"
    [6379]="redis"
    [8080]="http-alt"
    [8443]="https-alt"
)

declare -A PORT_DESC=(
    [20]="FTP data transfer channel"
    [21]="FTP control channel for file transfer"
    [22]="Secure Shell remote administration"
    [23]="Unencrypted remote terminal access"
    [25]="Simple Mail Transfer Protocol email relay"
    [53]="Domain Name System name resolution"
    [67]="DHCP server service"
    [68]="DHCP client service"
    [69]="Trivial File Transfer Protocol"
    [80]="Hypertext Transfer Protocol web service"
    [110]="POP3 email retrieval"
    [123]="Network Time Protocol time synchronization"
    [143]="IMAP email retrieval"
    [161]="SNMP network monitoring"
    [162]="SNMP trap notifications"
    [179]="Border Gateway Protocol routing"
    [389]="Lightweight Directory Access Protocol"
    [443]="HTTPS encrypted web traffic"
    [465]="SMTP over implicit TLS"
    [514]="System logging service"
    [587]="SMTP mail submission"
    [636]="LDAP over TLS/SSL"
    [993]="IMAP over TLS/SSL"
    [995]="POP3 over TLS/SSL"
    [1433]="Microsoft SQL Server"
    [1521]="Oracle database listener"
    [2049]="Network File System"
    [3306]="MySQL database service"
    [3389]="Remote Desktop Protocol"
    [5432]="PostgreSQL database service"
    [5900]="VNC remote desktop"
    [6379]="Redis key-value store"
    [8080]="Alternate HTTP web service"
    [8443]="Alternate HTTPS web service"
)

# ---------- Utility Functions ----------
trim() {
    local s="$1"
    s="${s#"${s%%[![:space:]]*}"}"
    s="${s%"${s##*[![:space:]]}"}"
    printf '%s' "$s"
}

validate_ipv4() {
    local ip="$1"
    [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1

    IFS='.' read -r o1 o2 o3 o4 <<< "$ip"
    for octet in "$o1" "$o2" "$o3" "$o4"; do
        [[ "$octet" =~ ^[0-9]+$ ]] || return 1
        (( octet >= 0 && octet <= 255 )) || return 1
    done
    return 0
}

validate_hostname() {
    local host="$1"

    # Allow localhost
    [[ "$host" == "localhost" ]] && return 0

    # Basic hostname validation
    [[ ${#host} -le 253 ]] || return 1
    [[ "$host" =~ ^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)$ ]]
}

validate_target() {
    local target="$1"
    validate_ipv4 "$target" || validate_hostname "$target"
}

validate_port_number() {
    local port="$1"
    [[ "$port" =~ ^[0-9]{1,5}$ ]] || return 1
    (( port >= 1 && port <= 65535 ))
}

normalize_port_spec() {
    local raw="$1"
    local cleaned

    cleaned="$(printf '%s' "$raw" | tr -d '[:space:]')"

    # Only digits, commas, and dashes allowed
    [[ "$cleaned" =~ ^[0-9,-]+$ ]] || return 1

    local IFS=','
    read -r -a items <<< "$cleaned"

    local item start end
    for item in "${items[@]}"; do
        [[ -n "$item" ]] || return 1

        if [[ "$item" =~ ^([0-9]{1,5})-([0-9]{1,5})$ ]]; then
            start="${BASH_REMATCH[1]}"
            end="${BASH_REMATCH[2]}"
            validate_port_number "$start" || return 1
            validate_port_number "$end" || return 1
            (( start <= end )) || return 1
        elif [[ "$item" =~ ^[0-9]{1,5}$ ]]; then
            validate_port_number "$item" || return 1
        else
            return 1
        fi
    done

    printf '%s' "$cleaned"
}

expand_port_spec() {
    local spec="$1"
    local IFS=','
    local -a items
    local -A seen=()
    read -r -a items <<< "$spec"

    local item start end p
    for item in "${items[@]}"; do
        if [[ "$item" =~ ^([0-9]{1,5})-([0-9]{1,5})$ ]]; then
            start="${BASH_REMATCH[1]}"
            end="${BASH_REMATCH[2]}"
            for (( p=start; p<=end; p++ )); do
                seen["$p"]=1
            done
        else
            seen["$item"]=1
        fi
    done

    for p in "${!seen[@]}"; do
        echo "$p"
    done | sort -n
}

lookup_port_info() {
    local port="$1"
    local protocol="${2:-tcp}"

    if [[ -n "${PORT_NAME[$port]+x}" ]]; then
        printf '%s/%s - %s - %s\n' \
            "$port" "$protocol" "${PORT_NAME[$port]}" "${PORT_DESC[$port]}"
        return 0
    fi

    # Fallback to local services database if available
    local service=""
    service="$(getent services "$port/$protocol" 2>/dev/null | awk 'NR==1 {print $1}')"

    if [[ -n "$service" ]]; then
        printf '%s/%s - %s - Known service listed in local services database\n' \
            "$port" "$protocol" "$service"
    else
        printf '%s/%s - unknown - No local reference description available\n' \
            "$port" "$protocol"
    fi
}

# ---------- User Input ----------
echo "========================================="
echo " Network Security Scan Report Generator"
echo "========================================="
echo

read -r -p "Enter target IP address or hostname: " TARGET_INPUT
TARGET_INPUT="$(trim "$TARGET_INPUT")"

[[ -n "$TARGET_INPUT" ]] || error_exit "Target cannot be empty."
validate_target "$TARGET_INPUT" || error_exit "Invalid target. Enter a valid IPv4 address or hostname."

read -r -p "Enter ports to include (example: 22,80,443 or 1-1024): " PORT_SPEC_INPUT
PORT_SPEC_INPUT="$(trim "$PORT_SPEC_INPUT")"

[[ -n "$PORT_SPEC_INPUT" ]] || error_exit "Port list cannot be empty."
PORT_SPEC="$(normalize_port_spec "$PORT_SPEC_INPUT")" || error_exit "Invalid port specification."

echo
echo "For this assignment version, enter any OPEN ports you want shown in the report."
echo "Example: 22,80,443"
echo "(If you press Enter, placeholder ports 80,443 will be used.)"
read -r -p "Enter open ports found: " OPEN_PORTS_INPUT
OPEN_PORTS_INPUT="$(trim "$OPEN_PORTS_INPUT")"

if [[ -z "$OPEN_PORTS_INPUT" ]]; then
    OPEN_PORTS_INPUT="80,443"
fi

OPEN_PORTS_SPEC="$(normalize_port_spec "$OPEN_PORTS_INPUT")" || error_exit "Invalid open ports list."

# ---------- Build Section Content ----------
REQUESTED_PORTS_LIST="$(expand_port_spec "$PORT_SPEC")"
OPEN_PORTS_LIST="$(expand_port_spec "$OPEN_PORTS_SPEC")"

OPEN_PORTS_REPORT=""
while IFS= read -r port; do
    OPEN_PORTS_REPORT+=$(lookup_port_info "$port" "tcp")
    OPEN_PORTS_REPORT+=$'\n'
done <<< "$OPEN_PORTS_LIST"

REQUESTED_PORTS_REPORT=""
while IFS= read -r port; do
    REQUESTED_PORTS_REPORT+="Port $port/tcp"$'\n'
done <<< "$REQUESTED_PORTS_LIST"

# ---------- Generate Report ----------
cat > "$OUTPUT_FILE" <<EOF
=========================================
        Network Security Scan Report
=========================================

Target IP Address/Hostname: $TARGET_INPUT
Requested Ports/Range: $PORT_SPEC
Report Generated: $(date)

-----------------------------------------
Requested Ports to Assess
-----------------------------------------
$REQUESTED_PORTS_REPORT
-----------------------------------------
Open Ports and Detected Services
-----------------------------------------
$OPEN_PORTS_REPORT
-----------------------------------------
Potential Vulnerabilities Identified
-----------------------------------------
CVE-2023-XXXX - Placeholder: Review detected services for outdated software
Default Credentials - Placeholder: Verify administrative services use strong credentials
Weak Configuration - Placeholder: Check exposed services for insecure settings

-----------------------------------------
Recommendations for Remediation
-----------------------------------------
1. Update all exposed services to current supported versions.
2. Disable or restrict unnecessary ports and services.
3. Replace default or weak credentials immediately.
4. Apply host firewall rules and service hardening.
5. Review service exposure and segment sensitive systems.

=========================================
              End of Report
=========================================
EOF

echo
echo "Report generated successfully: $OUTPUT_FILE"
echo "Open it with:"
echo "  cat $OUTPUT_FILE"
echo "or"
echo "  nano $OUTPUT_FILE"
