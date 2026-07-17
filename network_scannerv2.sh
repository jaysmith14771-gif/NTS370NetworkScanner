#!/bin/bash

## ==========================================
## Secure Network Report Template Generator
## ==========================================

set -o errexit
set -o nounset
set -o pipefail

## ---------- Error Handling ----------

error_exit() {
    echo "Error: $1" >&2
    exit 1
}

trap 'error_exit "An unexpected error occurred while generating the report."' ERR

## ---------- Common Port Reference Table ----------

declare -A PORT_NAME=(
    [20]="ftp-data"
    [21]="ftp"
    [22]="ssh"
    [23]="telnet"
    [25]="smtp"
    [53]="dns"
    [80]="http"
    [110]="pop3"
    [143]="imap"
    [443]="https"
    [993]="imaps"
    [995]="pop3s"
    [1433]="ms-sql"
    [1521]="oracle"
    [3306]="mysql"
    [3389]="rdp"
    [5432]="postgresql"
    [8080]="http-alt"
    [8443]="https-alt"
)

declare -A PORT_DESC=(
    [20]="FTP data transfer channel"
    [21]="FTP control channel"
    [22]="Secure Shell remote administration"
    [23]="Unencrypted remote terminal access"
    [25]="SMTP email relay"
    [53]="DNS name resolution"
    [80]="HTTP web service"
    [110]="POP3 email retrieval"
    [143]="IMAP email retrieval"
    [443]="HTTPS encrypted web traffic"
    [993]="IMAPS secure email retrieval"
    [995]="POP3S secure email retrieval"
    [1433]="Microsoft SQL Server"
    [1521]="Oracle database listener"
    [3306]="MySQL database service"
    [3389]="Remote Desktop Protocol"
    [5432]="PostgreSQL database service"
    [8080]="Alternate HTTP web service"
    [8443]="Alternate HTTPS web service"
)

## ---------- Utility Functions ----------

trim() {
    local s="$1"
    s="${s#"${s%%[![:space:]]*}"}"
    s="${s%"${s##*[![:space:]]}"}"
    printf '%s' "$s"
}

validate_ipv4() {
    local ip="$1"

    [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1

    local o1 o2 o3 o4
    IFS='.' read -r o1 o2 o3 o4 <<< "$ip"

    # (1-255).(0-255).(0-255).(1-255)

    (( o1 >= 1 && o1 <= 255 )) || return 1
    (( o2 >= 0 && o2 <= 255 )) || return 1
    (( o3 >= 0 && o3 <= 255 )) || return 1
    (( o4 >= 1 && o4 <= 255 )) || return 1

    return 0
}

prompt_for_target() {

    local target

    while true; do

        read -rp "Enter target IPv4 address: " target
        target="$(trim "$target")"

        if validate_ipv4 "$target"; then
            printf '%s\n' "$target"
            return 0
        fi

        echo
        echo "Invalid IPv4 address."
        echo "Format must be (1-255).(0-255).(0-255).(1-255)"
        echo "Example: 192.168.1.10"
        echo

    done
}

validate_port_number() {
    local port="$1"

    [[ "$port" =~ ^[0-9]+$ ]] || return 1
    (( port >= 1 && port <= 65535 ))
}

normalize_port_spec() {

    local raw="$1"
    local cleaned="${raw// /}"

    [[ -n "$cleaned" ]] || return 1

    local IFS=','
    local item
    read -ra items <<< "$cleaned"

    for item in "${items[@]}"; do

        if [[ "$item" =~ ^([0-9]+)-([0-9]+)$ ]]; then

            local start="${BASH_REMATCH[1]}"
            local end="${BASH_REMATCH[2]}"

            validate_port_number "$start" || return 1
            validate_port_number "$end" || return 1

            (( start <= end )) || return 1

        elif validate_port_number "$item"; then
            :
        else
            return 1
        fi

    done

    printf '%s\n' "$cleaned"
}

prompt_for_ports() {

    local ports

    while true; do

        read -rp "Enter ports to include (example: 22,80,443 or 1-1024): " ports

        if ports="$(normalize_port_spec "$ports")"; then
            printf '%s\n' "$ports"
            return 0
        fi

        echo
        echo "Invalid port specification."
        echo "Examples:"
        echo "  22"
        echo "  22,80,443"
        echo "  1-1024"
        echo "  22,80,1000-2000"
        echo

    done
}

prompt_for_open_ports() {

    local ports

    while true; do

        read -rp "Enter open ports found (default: 80,443): " ports

        [[ -z "$ports" ]] && ports="80,443"

        if ports="$(normalize_port_spec "$ports")"; then
            printf '%s\n' "$ports"
            return 0
        fi

        echo
        echo "Invalid port specification."
        echo

    done
}

expand_port_spec() {

    local spec="$1"
    local IFS=','
    local item

    read -ra items <<< "$spec"

    for item in "${items[@]}"; do

        if [[ "$item" =~ ^([0-9]+)-([0-9]+)$ ]]; then

            local start="${BASH_REMATCH[1]}"
            local end="${BASH_REMATCH[2]}"

            for ((i=start; i<=end; i++)); do
                echo "$i"
            done

        else
            echo "$item"
        fi

    done | sort -n -u
}

lookup_port_info() {

    local port="$1"

    local name="${PORT_NAME[$port]:-unknown}"
    local desc="${PORT_DESC[$port]:-No description available}"

    printf 'Port %s/tcp - %s - %s' \
        "$port" \
        "$name" \
        "$desc"
}

## ---------- Report Functions ----------

write_header() {

    local target="$1"

    echo "========================================="
    echo "Secure Network Assessment Report"
    echo "========================================="
    echo
    echo "Target IP Address: $target"
    echo "Requested Ports/Range: $PORT_SPEC"
    echo "Report Generated: $(date)"
    echo
}

write_ports_section() {

    echo "### Requested Ports to Assess"
    echo
    echo "$REQUESTED_PORTS_REPORT"
    echo
    echo "### Open Ports and Detected Services"
    echo
    echo "$OPEN_PORTS_REPORT"
    echo
}

write_vulns_section() {

    echo "### Potential Vulnerabilities Identified"
    echo
    echo "CVE-2023-XXXX - Placeholder: Review detected services for outdated software"
    echo "Default Credentials - Placeholder: Verify administrative services use strong credentials"
    echo "Weak Configuration - Placeholder: Check exposed services for insecure settings"
    echo
}

write_recs_section() {

    echo "### Recommendations for Remediation"
    echo
    echo "- Update all exposed services to current supported versions."
    echo "- Disable or restrict unnecessary ports and services."
    echo "- Replace default or weak credentials immediately."
    echo "- Apply host firewall rules and service hardening."
    echo "- Review service exposure and segment sensitive systems."
    echo
}

write_footer() {

    echo "========================================="
    echo "End of Report"
}

## ---------- Main Function ----------

main() {

    local target

    if [[ $# -eq 1 ]]; then

        target="$1"

        validate_ipv4 "$target" \
            || error_exit "Invalid IPv4 address. Format must be (1-255).(0-255).(0-255).(1-255)"

    else

        target="$(prompt_for_target)"

    fi

    PORT_SPEC="$(prompt_for_ports)"
    OPEN_PORTS_SPEC="$(prompt_for_open_ports)"

    REQUESTED_PORTS_LIST="$(expand_port_spec "$PORT_SPEC")"
    OPEN_PORTS_LIST="$(expand_port_spec "$OPEN_PORTS_SPEC")"

    REQUESTED_PORTS_REPORT=""
    while IFS= read -r port; do
        REQUESTED_PORTS_REPORT+="Port $port"$'\n'
    done <<< "$REQUESTED_PORTS_LIST"

    OPEN_PORTS_REPORT=""
    while IFS= read -r port; do
        OPEN_PORTS_REPORT+="$(lookup_port_info "$port")"$'\n'
    done <<< "$OPEN_PORTS_LIST"

    REPORT_FILE="report.txt"

    write_header "$target" > "$REPORT_FILE"
    write_ports_section >> "$REPORT_FILE"
    write_vulns_section >> "$REPORT_FILE"
    write_recs_section >> "$REPORT_FILE"
    write_footer >> "$REPORT_FILE"

    echo
    echo "Report generated successfully: $REPORT_FILE"
    echo "========== REPORT =========="
    cat "$REPORT_FILE"
    echo "============================"
}

main "$@"
