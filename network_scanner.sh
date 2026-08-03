#!/bin/bash

# ==========================================
# Secure Network Report Generator v4
# ==========================================

set -o errexit
set -o nounset
set -o pipefail


#------------Initial Configuration-----------

#-#----Directories--------
#-API KEY CONFIGURATION
SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"
CONFIG_FILE="${SCRIPT_DIR}/scanner.conf"
NVD_API_KEY=""
VULNER_API_KEY=""
set -a
[ -f "$CONFIG_FILE" ] && source "$CONFIG_FILE"
set +a
# GLOBAL DIRECTORY CONFIGURATION
export VAULT_DIR="scan_vault"
export INPROGRESS_SCANS="${VAULT_DIR}/in_progress_scans"
export LOGS_DIR="${VAULT_DIR}/nmaplogs"
export REPORTS_DIR="${VAULT_DIR}/reports"
export XML_DIR="${VAULT_DIR}/vulnxml"
export INTERRUPTED_DIR="${VAULT_DIR}/interrupted_scans"

# GLOBAL RUNTIME FILE DEFINITIONS
TIMESTAMP="$(date +%m-%d-%Y-%H-%M-%S)"
REPORT_NAME="report-${TIMESTAMP}.txt"

OUTPUT_FILE="${INPROGRESS_SCANS}/${REPORT_NAME}"
FINAL_REPORT="${REPORTS_DIR}/${REPORT_NAME}"
RAW_SCAN_LOG="${INPROGRESS_SCANS}/raw_scan_${TIMESTAMP}.log"
XML_REPORT="${INPROGRESS_SCANS}/tmpscan_report_${TIMESTAMP}.xml"

export TIMESTAMP
export REPORT_NAME
export OUTPUT_FILE
export FINAL_REPORT
export RAW_SCAN_LOG
export XML_REPORT
#-create missing directories
init_persistence_vault(){
mkdir -p "$LOGS_DIR" "$REPORTS_DIR" "$XML_DIR" "$INTERRUPTED_DIR" "$INPROGRESS_SCANS"
}
init_persistence_vault
# ---------- Error Handling ----------

error_exit() {
    echo "Error: $1" >&2
    exit 1
}

trap 'error_exit "An unexpected error occurred while generating the report."' ERR

#------------ Required Tools-----------
if ! command -v parallel &> /dev/null; then
    echo "GNU Parallel is not installed. Installing..."
    sudo apt update && sudo apt install -y parallel
fi

if ! command -v xmlstarlet &> /dev/null; then
    sudo apt update && sudo apt install -y xmlstarlet
fi

PACKAGE="nmap"
DEFAULT_DIR=$(pwd)
SCRIPTS_DIR="/usr/share/nmap/scripts"
VULNERS_SCRIPT_PATH="/usr/share/nmap/scripts/vulners.nse"

if ! command -v $PACKAGE &> /dev/null; then
    echo "$PACKAGE is not installed. Installing..."
    sudo apt update && sudo apt install -y "$PACKAGE"
fi

echo "Nmap is verified. Updating Nmap 3rd party scripts and database..."

#--update Nmap scripts and download 3rd party vulners 
sudo nmap --script-updatedb
if [[ ! -f "$VULNERS_SCRIPT_PATH" ]]; then
    echo "[-] Nmap 'vulners' script missing.clonging git into the installation dir..."
    
    # change directory to Nmap's script folder
    cd /usr/share/nmap/scripts/ || { echo "Error: Nmap script directory not found."; exit 1; }
    
    # Run the installation operations with root privileges
    sudo git clone https://github.com/vulnersCom/nmap-vulners.git
    sudo cp nmap-vulners/vulners.nse .
    sudo nmap --script-updatedb
    
    echo "[+] 'vulners' script successfully installed and registered with Nmap."
else
    echo "[+] Nmap 'vulners' script is already installed. Skipping deployment."
fi
cd "$DEFAULT_DIR"

echo "Setup complete!"

#-removed port description block now that nmap is integrated
#-legacy component to simulate nmap results removed

# ---------- Utility Functions ----------

trim() {
    local s="$1"
    s="${s#"${s%%[![:space:]]*}"}"
    s="${s%"${s##*[![:space:]]}"}"
    printf '%s' "$s"
}

cleanup_interrupted_scan() {
    # Save the original exit code or signal behavior
    local exit_code=$?
    echo -e "\n\n[!] WARNING: Scan interrupted or failed! Initializing cleanup..."

    # 1. Kill the nmap background process if it is still running
    # (Since we are using a pipe, we target nmap specifically via jobs or state)
    local nmap_pid
    nmap_pid=$(pgrep -f "nmap.*$target" | head -n 1)
    if [[ -n "$nmap_pid" ]]; then
        echo " [+] Stopping active Nmap engine process (PID: $nmap_pid)..."
        kill -9 "$nmap_pid" 2>/dev/null
    fi

    # 2. Ensure the destination folder exists
    mkdir -p "$INTERRUPTED_DIR"

    # 3. Move the raw log file if it contains data
    if [[ -f "${RAW_SCAN_LOG:-}" ]]; then
        mv "$RAW_SCAN_LOG" "$INTERRUPTED_DIR/FAILED_RAW_${TIMESTAMP:-$(date +%s)}_${RAW_SCAN_LOG##*/}"
        echo " [+] Moved partial raw log data to: $INTERRUPTED_DIR"
    fi

    # 4. Move partial XML data if option 3 was selected
    if [[ -n "${XML_REPORT:-}" && -f "$XML_REPORT" ]]; then
        mv "$XML_REPORT" "$INTERRUPTED_DIR/FAILED_XML_${TIMESTAMP:-$(date +%s)}_${XML_REPORT##*/}"
        echo " [+] Moved partial XML data to: $INTERRUPTED_DIR"
    fi

    # 5. Clean up temporary output layout masks to keep workspace clean
    if [[ -f "${OUTPUT_FILE:-}" ]]; then
        rm -f "$OUTPUT_FILE"
    fi

    echo "[+] Workspace reset complete. Exiting safely."
    exit "$exit_code"
}

trap cleanup_interrupted_scan INT ERR

validate_ipv4() {
    local ip="$1"

    [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
    local o1 o2 o3 o4
    IFS='.' read -r o1 o2 o3 o4 <<< "$ip"

    (( o1 >= 1 && o1 <= 255 )) || return 1
    (( o2 >= 0 && o2 <= 255 )) || return 1
    (( o3 >= 0 && o3 <= 255 )) || return 1
    (( o4 >= 1 && o4 <= 255 )) || return 1

    return 0
}

validate_hostname() {
    local host="$1"

    [[ ${#host} -le 253 ]] || return 1

    [[ "$host" =~ ^[A-Za-z0-9][A-Za-z0-9.-]*[A-Za-z0-9]$ ]] || return 1

    getent hosts "$host" >/dev/null 2>&1
}

validate_reachable() {
    local target="$1"

    nmap -sn "$target" 2>/dev/null | grep -q "Host is up"
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
        read -rp "Enter ports to include. Seperate individual port numbers with a comma (example: 22,80,443) And Seperate spans of ports with - (example 100-1024, 1-65535): " ports
        if ports="$(normalize_port_spec "$ports")"; then
            printf 'T:%s\n' "$ports"
            return 0
        fi
        echo
        echo "Invalid port specification."
        echo "Examples:"
        echo "  22"
        echo "  22,80,443"
        echo "  1-1024"
        echo "  22,80,1000-2000"
        echo " 1-65535 (all ports)"
        echo

    done
}

expand_port_spec() {

    local spec="${1#T:}"
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

#-removed legacy port lookup that was emulating nmap scans

# ---------- Report Functions ----------

write_header() {
    local target="$1"
    local scan_name="$2"

    echo "========================================="
    echo "Network Security Scan Report"
    echo "========================================="
    echo
    echo "Target: $target"
    echo "Scan Type: $scan_name"
    echo "Generated: $(date)"
    echo
}

write_ports_section() {
    echo "### Open Ports and Detected Services"
    echo
    if [[ -f "$RAW_SCAN_LOG" ]]; then
        local raw_line found_any=0
        
        while IFS= read -r raw_line; do
            # Matches: [Port]/tcp [Space] open [Space] [Service] [Optional Version Details]
            if [[ "$raw_line" =~ ^([0-9]+)/tcp[[:space:]]+open[[:space:]]+([^[:space:]]+)(.*)$ ]]; then
                found_any=1
                local port_num="${BASH_REMATCH[1]}"
                local service_name="${BASH_REMATCH[2]}"
                local version_info
                version_info=$(trim "${BASH_REMATCH[3]}")
                
                # If Nmap didn't catch a specific version, label it cleanly
                if [[ -z "$version_info" ]]; then
                    version_info="No version details detected"
                fi

                echo " [+] Discovered: Port ${port_num}/tcp"
                echo "     Service:    ${service_name}"
                echo "     Version:    ${version_info}"
                echo "----------------------------------------"
            fi
        done < "$RAW_SCAN_LOG"

        if [[ "$found_any" -eq 0 ]]; then
            echo "No open ports detected."
        fi
    else
        echo "Error: Raw scan log missing. Unable to parse ports."
    fi
    echo
}
write_vulns_section() {
    echo "### Vulnerabilities & CVEs"
    echo ""

    if [[ -z "${XML_REPORT:-}" || ! -f "$XML_REPORT" ]]; then
        echo "_Vulnerability XML dataset missing or unreachable._"
        echo ""
        return 0
    fi

    local cve_list
    cve_list="$(
        grep -oE 'CVE-[0-9]{4}-[0-9]{4,}' "$XML_REPORT" 2>/dev/null | sort -u || true )"

    if [[ -z "$cve_list" ]]; then
        echo "_No explicit CVE records were discovered inside the XML structure._"
        echo ""
        return 0
    fi

    if ! command -v curl >/dev/null 2>&1; then
        echo "_CVE records were discovered, but curl is unavailable for NVD enrichment._"
        echo ""
        return 0
    fi

    if ! command -v jq >/dev/null 2>&1; then
        echo "_CVE records were discovered, but jq is unavailable for NVD enrichment._"
        echo ""
        return 0
    fi

    echo "| Vulnerability | Summary | NVD Reference |"
    echo "| :--- | :--- | :--- |"

    local cve
    while IFS= read -r cve; do
        [[ -z "$cve" ]] && continue

        local -a curl_args=(
            --silent
            --show-error
            --location
            --connect-timeout 10
            --max-time 30
            --write-out $'\n%{http_code}'
        )

        local sleep_duration=6

        if [[ -n "${NVD_API_KEY:-}" ]]; then
            curl_args+=(
                --header "apiKey: ${NVD_API_KEY}"
            )
            sleep_duration=1
        fi

        local response
        local curl_status=0

        response="$(
            curl "${curl_args[@]}" \
                "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${cve}" \
                2>/dev/null
        )" || curl_status=$?

        local http_status
        local raw_json

        http_status="${response##*$'\n'}"

        if [[ "$response" == *$'\n'* ]]; then
            raw_json="${response%$'\n'*}"
        else
            raw_json=""
            http_status="000"
        fi

        local summary=""

        if [[ $curl_status -eq 0 && "$http_status" == "200" ]]; then
            summary="$(
                jq -r '
                    first(
                        .vulnerabilities[]?
                        .cve
                        .descriptions[]?
                        | select(.lang == "en")
                        | .value
                    ) // empty
                ' <<< "$raw_json" 2>/dev/null
            )"
        fi

        if [[ -z "$summary" || "$summary" == "null" ]]; then
            case "$http_status" in
                403)
                    summary="NVD rejected the request. The API key may be invalid or access may be restricted."
                    ;;
                404)
                    summary="No matching NVD record was returned for this CVE."
                    ;;
                429)
                    summary="NVD rate limiting prevented retrieval of the description."
                    ;;
                500|502|503|504)
                    summary="The NVD service was temporarily unavailable."
                    ;;
                000)
                    summary="The NVD description could not be retrieved because of a network or curl error."
                    ;;
                *)
                    summary="No description summary is currently available from NVD."
                    ;;
            esac 
        fi

        # Keep each description inside one Markdown table cell.
        summary="$(
            printf '%s' "$summary" |
                tr '\r\n\t' '   ' |
                sed \
                    -e 's/\\/\\\\/g' \
                    -e 's/|/\\|/g' \
                    -e 's/[[:space:]][[:space:]]*/ /g' \
                    -e 's/^ //' \
                    -e 's/ $//'
        )"

        printf '| **%s** | %s | [View NVD Details](https://nvd.nist.gov/vuln/detail/%s) |\n' \
            "$cve" \
            "$summary" \
            "$cve"

        sleep "$sleep_duration"
    done <<< "$cve_list"

    echo ""
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

# ---------- Main Function ----------

main() {
    set -o pipefail
    echo "========================================="
    echo "Network Security Scan Report Generator"
    echo "This Nmap scans runs in GNU Parallel"
    echo "========================================="
    echo

    while true; do
        echo "Select target type:"
        echo "1) IPv4 Address"
        echo "2) Hostname"
        echo
        read -rp "Choice [1-2]: " target_type
        case "$target_type" in
            1|2) break ;;
            *) echo; echo "ERROR: Please enter 1 or 2."; echo ;;
        esac
  done  
    while true; do
        if [[ "$target_type" -eq 1 ]]; then
            read -rp "Enter IPv4 address: " target
            if ! validate_ipv4 "$target"; then
                echo; echo "ERROR: Invalid IPv4 address."
                echo "Required format: (1-255).(0-255).(0-255).(1-255)"; echo
                continue
            fi
        else
            read -rp "Enter hostname: " target
            if ! validate_hostname "$target"; then
                echo; echo "ERROR: Invalid or unresolvable hostname."; echo
                continue
            fi
        fi

        echo; echo "Validating reachability..."
        if validate_reachable "$target"; then
            echo "Target reachable."
            break
        fi
        echo; echo "ERROR: Target appears unreachable."
        echo "Please enter another target."; echo
    done

    PORT_SPEC="$(prompt_for_ports)"
    REQUESTED_PORTS_LIST="$(expand_port_spec "$PORT_SPEC")"
    PORT_ARGS=()
    if [[ -n "$PORT_SPEC" ]]; then
    PORT_ARGS=(-p "${PORT_SPEC#T:}")
    fi

    while true; do
        echo; echo "Select scan type:"
        echo "1) Basic Service Version Detection (-sV)"
        echo "2) (Sudo) Service + OS Detection (-sV -O -T3 -n -Pn)"
        echo "3) (Sudo) Vulnerability script detection (-sV -O -T3 -n -Pn --script \ (vuln and not (dos or brute or broadcast)),vulners --script-timeout 3m"
        echo
        read -rp "Choice [1-3]: " scan_type
        case "$scan_type" in
            1)
                SCAN_COMMAND=(nmap -sV  "${PORT_ARGS[@]}"  --open -oN "$RAW_SCAN_LOG" "$target")
                SCAN_NAME="Service Version Detection (-sV)"
                break
                ;;
            2)
                SCAN_COMMAND=(sudo nmap -sV -O -T3 -n -Pn "${PORT_ARGS[@]}" -oN "$RAW_SCAN_LOG" "$target")
                SCAN_NAME="Service + OS Detection (-sV -O)"
                break
                ;;
            3)
                SCAN_COMMAND=(sudo nmap -sV -T3 -n --script="(vuln and not (dos or brute or broadcast)),vulners" "${PORT_ARGS[@]}" --script-timeout 3m -oN "$RAW_SCAN_LOG" -oX "$XML_REPORT" "$target")
                SCAN_NAME="Parallel Vuln script detection (--script nmap vuln,vulners)"
                break
                ;;
            *)
                echo; echo "ERROR: Invalid scan selection."; echo
                ;;
        esac
    done

     echo; echo "Running scan..."
     echo "Press (or hold) "Spacebar" to see Nmap Progress"

    # Capture Nmap's complete console output for report parsing while also
    # displaying it live in the terminal.
    stdbuf -oL -eL "${SCAN_COMMAND[@]}" > "$RAW_SCAN_LOG" 2>&1
    #stdbuf -oL -eL sudo -d "${SCAN_COMMAND[@]:1}" > "$RAW_SCAN_LOG" 2>&1
    scan_exit_code=$?
    if (( scan_exit_code != 0 )); then
      echo "ERROR: Nmap exited with status ${scan_exit_code}." >&2
      return "$scan_exit_code"
    fi

    #printf "\nScan Progress: [%-20s] 100%%\n\n" "####################"
    # Generate final parsed markdown report
    {
    write_header "$target" "$SCAN_NAME"
    write_ports_section
    write_vulns_section
    write_recs_section
    write_footer
} > "$OUTPUT_FILE"

    # Print the report output to standard output BEFORE archiving files
    echo; echo "========== REPORT =========="
    cat "$OUTPUT_FILE"
    echo "============================"
    # Archieve Raw Log Data For Review
    echo
echo "Archiving scan data to log vault"

# Archive completed report.
if [[ -s "$OUTPUT_FILE" ]]; then
    mv -- "$OUTPUT_FILE" "$FINAL_REPORT"
    OUTPUT_FILE="$FINAL_REPORT"

    echo "  [+] Saved Report: $FINAL_REPORT"
else
    echo "  [!] Report is missing or empty: $OUTPUT_FILE" >&2
    return 1
fi

# Archive raw Nmap log.
if [[ -s "$RAW_SCAN_LOG" ]]; then
    raw_log_name="$(basename "$RAW_SCAN_LOG")"
    final_raw_log="${LOGS_DIR}/${raw_log_name}"

    mv -- "$RAW_SCAN_LOG" "$final_raw_log"
    RAW_SCAN_LOG="$final_raw_log"

    echo "  [+] Saved Raw Log: $final_raw_log"
else
    echo "  [!] Raw scan log is missing or empty: $RAW_SCAN_LOG" >&2
fi

# Archive XML when generated.
if [[ -n "${XML_REPORT:-}" && -s "$XML_REPORT" ]]; then
    xml_report_name="$(basename "$XML_REPORT")"
    final_xml_report="${XML_DIR}/${xml_report_name}"

    mv -- "$XML_REPORT" "$final_xml_report"
    XML_REPORT="$final_xml_report"

    echo "  [+] Saved XML Data: $final_xml_report"
fi


    echo; echo "All processing tasks complete! Vault archived."
    echo
}

main "$@"