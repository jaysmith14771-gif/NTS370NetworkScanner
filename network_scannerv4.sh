#!/bin/bash

# ==========================================
# Secure Network Report Generator v4
# ==========================================

set -Eeuo pipefail

# ==================================================
# Failure Cleanup Declaration
# ==================================================
# The cleanup implementation is located with the remaining utility helpers so
# scan lifecycle functions remain grouped together and are declared only once.

#------------Initial Configuration-----------
# ==================================================
# Global Time Variables
# ==================================================

readonly START_EPOCH="$(date +%s)"
readonly TIMESTAMP="$(date +'%Y-%m-%d_%H-%M-%S')"
readonly RUN_ID="${TIMESTAMP}"

# ==================================================
# Paths
# ==================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Preserve the operator's launch directory as the portable environment root.
# Project-relative resources such as reports/HtmlSchema/report_schema.html are
# resolved from this directory rather than from a fixed user home or script path.
LAUNCH_DIR="$(pwd -P)"

CONFIG_FILE="${SCRIPT_DIR}/scanner.conf"

# ==================================================
# Load Configuration
# ==================================================

NVD_API_KEY="${NVD_API_KEY:-}"
VULNERS_API_KEY="${VULNERS_API_KEY:-}"

if [[ -f "$CONFIG_FILE" ]]; then
# shellcheck disable=SC1090
source "$CONFIG_FILE"
fi

# ==================================================
# API Configuration
# ==================================================

readonly NVD_API_URL="https://services.nvd.nist.gov/rest/json/cves/2.0"

readonly KEV_URL="https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# ==================================================
# Permanent Storage
# ==================================================

CACHE_ROOT="${SCRIPT_DIR}/cache"

KEV_CACHE_DIR="${CACHE_ROOT}/kev"

NVD_CACHE_DIR="${CACHE_ROOT}/nvd"

REPORT_ROOT="${SCRIPT_DIR}/reports"

# ==================================================
# Temporary Assessment Workspace
# ==================================================

ASSESSMENT_ROOT="${SCRIPT_DIR}/assessments"

RUN_DIR="${ASSESSMENT_ROOT}/assessment-${RUN_ID}"

RAW_DIR="${RUN_DIR}/raw"

RAW_NMAP_DIR="${RAW_DIR}/nmap"

EXTRACTED_DIR="${RUN_DIR}/extracted"

NORMALIZED_DIR="${RUN_DIR}/normalized"

STATE_DIR="${RUN_DIR}/state"

LOG_DIR="${RUN_DIR}/logs"

MANIFEST_DIR="${RUN_DIR}/manifests"

# ==================================================
# Report Output
# ==================================================

REPORT_DIR="${REPORT_ROOT}/${RUN_ID}"

REPORT_JSON="${REPORT_DIR}/report.json"

REPORT_HTML="${REPORT_DIR}/report.html"

# Resolve the project HTML schema from the directory where the scanner was
# launched. A configured absolute HTML_SCHEMA_FILE is used unchanged; a relative
# value is resolved below LAUNCH_DIR. This supports different user home roots
# without constructing invalid paths such as /home/user//home/user/....
HTML_SCHEMA_CONFIG="${HTML_SCHEMA_FILE:-reports/HtmlSchema/report_schema.html}"
case "$HTML_SCHEMA_CONFIG" in
    /*) HTML_SCHEMA_FILE="$HTML_SCHEMA_CONFIG" ;;
    *)  HTML_SCHEMA_FILE="${LAUNCH_DIR}/${HTML_SCHEMA_CONFIG#./}" ;;
esac

REPORT_TXT="${REPORT_DIR}/report.txt"

REPORT_LOG="${REPORT_DIR}/report.log"

SCAN_BASENAME="network-scan-${RUN_ID}"
BASE_PATH="${RAW_NMAP_DIR}/${SCAN_BASENAME}"

RAW_SCAN_LOG="${BASE_PATH}.nmap"
SCAN_XML="${BASE_PATH}.xml"
SCAN_GNMAP="${BASE_PATH}.gnmap"
KEEP_ASSESSMENT_DATA=1

# Compatibility aliases while old report functions remain.
XML_REPORT="$SCAN_XML"
OUTPUT_FILE="$REPORT_TXT"
REPORT="$REPORT_TXT"
FINAL_REPORT="$REPORT_TXT"

# ==================================================
# Permanent Cache Files
# ==================================================

KEV_FILE="${KEV_CACHE_DIR}/known_exploited_vulnerabilities.json"

# ==================================================
# Runtime Log
# ==================================================

LOG_FILE="${LOG_DIR}/pipeline.log"
NMAP_CONSOLE_LOG="${LOG_DIR}/nmap-console.log"

# ==================================================
# Statistics
# ==================================================

TOTAL_HOSTS=0
TOTAL_PORTS=0
TOTAL_CVES=0
TOTAL_KEV=0

TOTAL_CRITICAL=0
TOTAL_HIGH=0
TOTAL_MEDIUM=0
TOTAL_LOW=0

# ==================================================
# Runtime Databases
# ==================================================

declare -A KEV_SET
declare -A KEV_RECORDS
declare -A NVD_CACHE
declare -A SERVICES
declare -A SERVICE_HOST
declare -A SERVICE_PORT
declare -A SERVICE_NAME
declare -A SERVICE_PRODUCT
declare -A SERVICE_VERSION
declare -A SERVICE_CVES
declare -A SERVICE_KEV_CVES
declare -A SERVICE_NONKEV_CVES
declare -A SERVICE_EXPLOITDB
declare -A SERVICE_PACKETSTORM
declare -A SERVICE_GITHUB
declare -A SERVICE_CNVD
declare -A SERVICE_SEEBUG
declare -A SERVICE_METASPLOIT
declare -A SERVICE_CANVAS
declare -A SERVICE_EXPLOITPACK
declare -A SERVICE_GITEE
declare -A SERVICE_ZDT
declare -A SERVICE_HTTPD
declare -A SERVICE_EVIDENCE
declare -A DISCOVERED_CVES
declare -A KEV_MATCHES
declare -A NON_KEV_CVES
declare -A FINDINGS_JSON



# ==================================================
# Refresh KEV Cache
# ==================================================

refresh_kev_catalog() {
    local temporary_file
    local refresh_required=0

    temporary_file="${KEV_FILE}.tmp.$$"

    if [[ ! -s "$KEV_FILE" ]]; then
        refresh_required=1
        echo "[+] KEV catalog is missing. Downloading..."
    elif find "$KEV_FILE" -mtime +1 -print -quit | grep -q .; then
        refresh_required=1
        echo "[+] KEV catalog is older than one day. Refreshing..."
    fi

    (( refresh_required == 1 )) || {
        echo "[+] Using cached KEV catalog: $KEV_FILE"
        return 0
    }

    if ! curl \
        --fail \
        --silent \
        --show-error \
        --location \
        --connect-timeout 10 \
        --max-time 60 \
        --retry 3 \
        --retry-delay 2 \
        "$KEV_URL" \
        --output "$temporary_file"; then

        rm -f -- "$temporary_file"

        if [[ -s "$KEV_FILE" ]]; then
            echo "[!] KEV refresh failed; retaining existing cache." >&2
            return 0
        fi

        error_exit "Unable to download the KEV catalog."
    fi

    if ! jq -e '
        .vulnerabilities
        | type == "array" and length > 0
    ' "$temporary_file" >/dev/null 2>&1; then
        rm -f -- "$temporary_file"
        error_exit "Downloaded KEV catalog failed JSON/schema validation."
    fi

    mv -- "$temporary_file" "$KEV_FILE"

    echo "[+] KEV catalog updated successfully."
}

# ==================================================
# NVD Cache Helper
# ==================================================

get_nvd_cache_file() {

    local cve="$1"

    printf '%s/%s.json\n' \
        "$NVD_CACHE_DIR" \
        "$cve"

}
# ---------- Error Handling ----------

error_exit() {
    echo "Error: $1" >&2
    exit 1
}

#------------ Required Tools-----------
if ! command -v parallel &> /dev/null; then
    echo "GNU Parallel is not installed. Installing..."
    sudo apt update && sudo apt install -y parallel
fi
if ! command -v xmlstarlet &> /dev/null; then
    echo "XmlStarlet is not installed. Installing..."
    sudo apt update && sudo apt install -y xmlstarlet
fi
if ! command -v curl &> /dev/null; then
    echo "Curl is not installed. Installing..."
    sudo apt update && sudo apt install -y curl
fi
if ! command -v sha256sum &> /dev/null; then
    echo "Sha256sum is not installed. Installing..."
    sudo apt update && sudo apt install -y sha256sum
fi
if ! command -v sort &> /dev/null; then
    echo "sort is not installed. Installing..."
    sudo apt update && sudo apt install -y sort
fi
if ! command -v awk &> /dev/null; then
    echo "awk is not installed. Installing..."
    sudo apt update && sudo apt install -y awk
fi
if ! command -v tr &> /dev/null; then
    sudo apt update && sudo apt install -y tr
fi
if ! command -v jq &> /dev/null; then
    sudo apt update && sudo apt install -y jq
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
    echo "[-] Nmap 'vulners' script missing.cloning git into the installation dir..."
    
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


remove_partial_scan_artifacts() {
local artifact
 
# Do not continue unless the required paths are initialized.
if [[ -z "${RUN_DIR:-}" ||
-z "${RAW_NMAP_DIR:-}" ||
-z "${BASE_PATH:-}" ]]; then
printf '[!] Runtime paths are incomplete; skipping artifact cleanup.\n' \
>&2
return 0
fi
 
# Safety boundary: only operate inside this assessment's Nmap directory.
case "$BASE_PATH" in
"${RAW_NMAP_DIR}/"*)
;;
*)
printf '[!] Refusing cleanup outside RAW_NMAP_DIR: %s\n' \
"$BASE_PATH" >&2
return 0
;;
esac
 
local -a partial_artifacts=(
"${BASE_PATH}.nmap"
"${BASE_PATH}.xml"
"${BASE_PATH}.gnmap"
)
 
for artifact in "${partial_artifacts[@]}"; do
if [[ -e "$artifact" || -L "$artifact" ]]; then
chmod u+w -- "$artifact" 2>/dev/null || true
rm -f -- "$artifact" 2>/dev/null || {
printf '[!] Could not remove partial artifact: %s\n' \
"$artifact" >&2
}
fi
done
}

cleanup_interrupted_scan() {
    local exit_code=$?

    # Prevent recursive ERR trap execution while cleanup runs.
    trap - ERR INT TERM
    set +e

    printf '\n[!] Scan interrupted or failed. Initializing cleanup...\n' >&2

    # Stop the exact Nmap process started by this script.
    if [[ -n "${NMAP_PID:-}" ]] && kill -0 "$NMAP_PID" 2>/dev/null; then
        printf '[+] Stopping Nmap process PID %s...\n' "$NMAP_PID" >&2

        kill -TERM "$NMAP_PID" 2>/dev/null || true

        local attempt
        for ((attempt = 0; attempt < 10; attempt++)); do
            kill -0 "$NMAP_PID" 2>/dev/null || break
            sleep 0.5
        done

        if kill -0 "$NMAP_PID" 2>/dev/null; then
            printf '[!] Nmap did not stop gracefully; terminating PID %s.\n' \
                "$NMAP_PID" >&2

            kill -KILL "$NMAP_PID" 2>/dev/null || true
        fi
    fi

    unset NMAP_PID 2>/dev/null || true

    # Remove only incomplete Nmap artifacts for this run.
    remove_partial_scan_artifacts

    # Preserve logs, manifest, and assessment directory for diagnostics.
    printf '[+] Failure diagnostics retained in: %s\n' \
        "${RUN_DIR:-unavailable}" >&2

    exit "$exit_code"
}



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
        echo ""
        read -rp $'Enter ports to include.\n- Separate individual ports with a comma (e.g., 22,80,443)\n- Separate ranges with a hyphen (e.g., 100-1024,1025-65535)\n> ' ports
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

# ==================================================
# Initialize Directory Structure
# ==================================================

initialize_runtime() {
    REPORT_DATE="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

    TOTAL_HOSTS=0
    TOTAL_PORTS=0
    TOTAL_CVES=0
    TOTAL_KEV=0

    TOTAL_CRITICAL=0
    TOTAL_HIGH=0
    TOTAL_MEDIUM=0
    TOTAL_LOW=0

    mkdir -p \
        "$CACHE_ROOT" \
        "$KEV_CACHE_DIR" \
        "$NVD_CACHE_DIR" \
        "$ASSESSMENT_ROOT" \
        "$RUN_DIR" \
        "$RAW_DIR" \
        "$RAW_NMAP_DIR" \
        "$EXTRACTED_DIR" \
        "$NORMALIZED_DIR" \
        "$STATE_DIR" \
        "$LOG_DIR" \
        "$MANIFEST_DIR" \
        "$REPORT_ROOT" \
        "$REPORT_DIR"
      : > "$LOG_FILE"
      : > "$NMAP_CONSOLE_LOG"
}

validate_runtime_paths() {
    local required_directories=(
        "$KEV_CACHE_DIR"
        "$NVD_CACHE_DIR"
        "$RUN_DIR"
        "$RAW_NMAP_DIR"
        "$LOG_DIR"
        "$MANIFEST_DIR"
        "$REPORT_DIR"
    )

    local directory

    for directory in "${required_directories[@]}"; do
        [[ -d "$directory" ]] ||
            error_exit "Runtime directory was not created: $directory"
    done

    [[ -n "$SCAN_XML" ]] ||
        error_exit "SCAN_XML path was not initialized."

    [[ "$SCAN_XML" == "${RAW_NMAP_DIR}/"* ]] ||
        error_exit "SCAN_XML is outside the assessment Nmap directory."
}
# ==================================================
# Post-Scan Report Pipeline
# ==================================================
# The functions in this section preserve the calls already made by main().
# Phase 1 normalizes Nmap XML into service and evidence NDJSON records.
# Phase 2 enriches every discovered CVE and assembles report.json.
# Scan options 1 and 2 do not run vulnerability NSE scripts, so an empty CVE
# or exploit result is treated as valid limited-coverage output, not a failure.

# Validate the KEV cache and optional NVD configuration before scanning.
validate_pre_scan_inputs() {
    [[ -r "$KEV_FILE" && -s "$KEV_FILE" ]] ||
        error_exit "KEV catalog is missing or unreadable: $KEV_FILE"

    jq -e '.vulnerabilities | type == "array"' "$KEV_FILE" >/dev/null 2>&1 ||
        error_exit "KEV catalog failed JSON/schema validation: $KEV_FILE"

    if [[ -z "${NVD_API_KEY:-}" ]]; then
        printf '[!] NVD_API_KEY is not configured. NVD requests will use the lower unauthenticated rate limit.\n' >&2
    fi
}

# Verify that Nmap produced a nonempty, well-formed XML document.
validate_post_scan_outputs() {
    [[ -s "$SCAN_XML" ]] ||
        error_exit "Nmap XML output is missing or empty: $SCAN_XML"

    xmlstarlet val -q "$SCAN_XML" ||
        error_exit "Nmap XML output is not valid XML: $SCAN_XML"
}

# Record immutable run metadata before the scan begins.
create_assessment_manifest() {
    jq -n \
        --arg run_id "$RUN_ID" \
        --arg timestamp "$TIMESTAMP" \
        --arg host "$(hostname)" \
        '{run_id:$run_id,timestamp:$timestamp,host:$host}' \
        > "${MANIFEST_DIR}/assessment.json"
}

# Retained compatibility validator for callers outside main().
validate_inputs() {
    validate_post_scan_outputs
    [[ -r "$KEV_FILE" ]] || error_exit "Missing KEV catalog: $KEV_FILE"
    command -v jq >/dev/null 2>&1 || error_exit "jq is required"
    command -v xmlstarlet >/dev/null 2>&1 || error_exit "xmlstarlet is required"
}

# Load KEV identifiers and selected metadata into associative arrays.
load_kev_catalog() {
    local cve vendor product date_added due_date required_action ransomware_use vulnerability_name notes

    KEV_SET=()
    KEV_RECORDS=()

    while IFS=$'\t' read -r cve vendor product date_added due_date required_action ransomware_use vulnerability_name notes; do
        [[ "$cve" =~ ^CVE-[0-9]{4}-[0-9]{4,}$ ]] || continue
        KEV_SET["$cve"]=1
        KEV_RECORDS["$cve"]="$(jq -cn \
            --arg vendor_project "$vendor" \
            --arg product "$product" \
            --arg date_added "$date_added" \
            --arg due_date "$due_date" \
            --arg required_action "$required_action" \
            --arg known_ransomware_campaign_use "$ransomware_use" \
            --arg vulnerability_name "$vulnerability_name" \
            --arg notes "$notes" \
            '{vendor_project:$vendor_project,product:$product,date_added:$date_added,due_date:$due_date,required_action:$required_action,known_ransomware_campaign_use:$known_ransomware_campaign_use,vulnerability_name:$vulnerability_name,notes:$notes}')"
    done < <(jq -r '.vulnerabilities[] | [
        .cveID // "", .vendorProject // "", .product // "", .dateAdded // "",
        .dueDate // "", .requiredAction // "", .knownRansomwareCampaignUse // "",
        .vulnerabilityName // "", .notes // ""
    ] | @tsv' "$KEV_FILE")

    ((${#KEV_SET[@]} > 0)) || error_exit "No valid KEV records were loaded"
    printf '[+] Loaded %d KEV records into memory.\n' "${#KEV_SET[@]}"
}

# Remove control characters that would break temporary TSV records.
sanitize_tsv_field() {
    local value="${1:-}"
    value="${value//$'\t'/ }"
    value="${value//$'\r'/ }"
    value="${value//$'\n'/ }"
    value="${value//$'\x1f'/ }"
    printf '%s' "$value"
}

# Derive a stable service identifier from the asset, endpoint, and version.
service_id_for() {
    local key="$1" digest
    digest="$(printf '%s' "$key" | sha256sum)"
    digest="${digest%% *}"
    printf 'svc-%s' "${digest:0:16}"
}

# Construct a Vulners reference URL from a source name and source identifier.
build_vulners_reference_url() {
    local source="${1,,}" record_id="$2" encoded_id
    encoded_id="${record_id//%/%25}"
    encoded_id="${encoded_id// /%20}"
    encoded_id="${encoded_id//#/%23}"
    encoded_id="${encoded_id//\?/%3F}"
    printf 'https://vulners.com/%s/%s' "$source" "$encoded_id"
}

# Phase 1: extract every open service and every structured Vulners record.
# The service dataset is generated for all three scan options. Evidence will
# normally be empty for options 1 and 2 because they do not invoke vulners.nse.
# Print a visible start marker and return an epoch value to the caller. Stage
# timing prevents large local parsing jobs from appearing frozen in the terminal.
stage_start() {
    local stage_name="$1"
    printf '[+] Starting: %s\n' "$stage_name" >&2
    date +%s
}

# Print a stage completion marker with elapsed wall-clock time.
stage_finish() {
    local stage_name="$1"
    local started_at="$2"
    local finished_at
    local duration

    finished_at="$(date +%s)"
    duration=$((finished_at - started_at))
    printf '[+] Completed: %s in %d second(s).\n' "$stage_name" "$duration" >&2
}

parse_nmap_xml() {
    local services_tsv="${STATE_DIR}/services.tsv"
    local evidence_tsv="${STATE_DIR}/evidence.tsv"
    local evidence_normalized="${STATE_DIR}/evidence-normalized.usv"
    local services_ndjson="${NORMALIZED_DIR}/services.ndjson"
    local evidence_ndjson="${NORMALIZED_DIR}/evidence.ndjson"
    local host hostname protocol port state service_name product version extrainfo ostype method confidence cpes
    local context source record_id exploit_text cvss category exploit_json reference_url
    local service_key service_id evidence_key
    local service_count=0 evidence_count=0 cve_count=0 exploit_count=0 raw_evidence_count=0
    local stage_epoch
    declare -A seen_services=()
    declare -A seen_evidence=()
    declare -A service_id_by_key=()

    stage_epoch="$(stage_start "Phase 1 XML normalization")"

    : > "$services_tsv"
    : > "$evidence_tsv"
    : > "$evidence_normalized"
    : > "$services_ndjson"
    : > "$evidence_ndjson"

    printf '[+] Extracting open service records from Nmap XML...\n' >&2
    xmlstarlet sel -T -t \
        -m '/nmaprun/host[status/@state="up"]/ports/port[state/@state="open"]' \
        -v 'ancestor::host/address[@addrtype="ipv4"][1]/@addr' -o $'\x1f' \
        -v 'ancestor::host/hostnames/hostname[1]/@name' -o $'\x1f' \
        -v '@protocol' -o $'\x1f' -v '@portid' -o $'\x1f' -v 'state/@state' -o $'\x1f' \
        -v 'service/@name' -o $'\x1f' -v 'service/@product' -o $'\x1f' \
        -v 'service/@version' -o $'\x1f' -v 'service/@extrainfo' -o $'\x1f' \
        -v 'service/@ostype' -o $'\x1f' -v 'service/@method' -o $'\x1f' \
        -v 'service/@conf' -o $'\x1f' \
        -m 'service/cpe' -v '.' -o '|' -b -n "$SCAN_XML" > "$services_tsv"

    while IFS=$'\x1f' read -r host hostname protocol port state service_name product version extrainfo ostype method confidence cpes; do
        host="$(sanitize_tsv_field "${host:-unknown}")"
        hostname="$(sanitize_tsv_field "$hostname")"
        protocol="$(sanitize_tsv_field "${protocol:-tcp}")"
        port="$(sanitize_tsv_field "${port:-0}")"
        if [[ ! "$port" =~ ^[0-9]+$ ]] || ((10#$port < 1 || 10#$port > 65535)); then
            printf '[!] Skipping malformed service record: host=%s protocol=%s port=%s state=%s\n' \
                "$host" "$protocol" "$port" "${state:-unknown}" >&2
            continue
        fi
        port="$((10#$port))"
        state="$(sanitize_tsv_field "${state:-open}")"
        service_name="$(sanitize_tsv_field "${service_name:-unknown}")"
        product="$(sanitize_tsv_field "$product")"
        version="$(sanitize_tsv_field "$version")"
        extrainfo="$(sanitize_tsv_field "$extrainfo")"
        ostype="$(sanitize_tsv_field "$ostype")"
        method="$(sanitize_tsv_field "$method")"
        confidence="$(sanitize_tsv_field "$confidence")"
        [[ "$confidence" =~ ^[0-9]+$ ]] || confidence=0
        cpes="$(sanitize_tsv_field "$cpes")"

        service_key="$host|$protocol|$port|$product|$version"
        service_id="${service_id_by_key[$service_key]:-}"
        if [[ -z "$service_id" ]]; then
            service_id="$(service_id_for "$service_key")"
            service_id_by_key["$service_key"]="$service_id"
        fi
        [[ -z "${seen_services[$service_id]:-}" ]] || continue
        seen_services["$service_id"]=1

        jq -cn --arg service_id "$service_id" --arg address "$host" --arg hostname "$hostname" \
            --arg protocol "$protocol" --argjson port "$port" --arg state "$state" \
            --arg name "$service_name" --arg product "$product" --arg version "$version" \
            --arg extrainfo "$extrainfo" --arg ostype "$ostype" --arg method "$method" \
            --argjson confidence "$confidence" --arg cpes "$cpes" '
            {service_id:$service_id,asset:{address:$address,hostname:$hostname},
             endpoint:{protocol:$protocol,port:$port,state:$state},
             service:{name:$name,product:$product,version:$version,extrainfo:$extrainfo,
                      ostype:$ostype,method:$method,confidence:$confidence,
                      cpe:($cpes|split("|")|map(select(length>0)))}}' \
            >> "$services_ndjson" || error_exit "Failed to encode service record for $host:$port"
        service_count=$((service_count + 1))
    done < "$services_tsv"
    printf '[+] Normalized %d open service record(s).\n' "$service_count" >&2

    printf '[+] Extracting structured Vulners evidence records...\n' >&2
    xmlstarlet sel -T -t \
        -m '/nmaprun/host[status/@state="up"]/ports/port[state/@state="open"]/script[@id="vulners"]/table/table' \
        -v 'ancestor::host/address[@addrtype="ipv4"][1]/@addr' -o $'\x1f' \
        -v 'ancestor::port[1]/@protocol' -o $'\x1f' -v 'ancestor::port[1]/@portid' -o $'\x1f' \
        -v 'ancestor::port[1]/service/@product' -o $'\x1f' -v 'ancestor::port[1]/service/@version' -o $'\x1f' \
        -v 'parent::table/@key' -o $'\x1f' -v 'elem[@key="type"]' -o $'\x1f' \
        -v 'elem[@key="id"]' -o $'\x1f' -v 'elem[@key="is_exploit"]' -o $'\x1f' \
        -v 'elem[@key="cvss"]' -n "$SCAN_XML" > "$evidence_tsv" || true

    raw_evidence_count="$(wc -l < "$evidence_tsv")"
    printf '[+] Processing %d extracted evidence record(s)...\n' "$raw_evidence_count" >&2

    DISCOVERED_CVES=()
    while IFS=$'\x1f' read -r host protocol port product version context source record_id exploit_text cvss; do
        host="$(sanitize_tsv_field "${host:-unknown}")"
        protocol="$(sanitize_tsv_field "${protocol:-tcp}")"
        port="$(sanitize_tsv_field "${port:-0}")"
        if [[ ! "$port" =~ ^[0-9]+$ ]] || ((10#$port < 1 || 10#$port > 65535)); then
            printf '[!] Skipping malformed evidence record: host=%s protocol=%s port=%s id=%s\n' \
                "$host" "$protocol" "$port" "${record_id:-unknown}" >&2
            continue
        fi
        port="$((10#$port))"
        product="$(sanitize_tsv_field "$product")"
        version="$(sanitize_tsv_field "$version")"
        context="$(sanitize_tsv_field "$context")"
        source="$(sanitize_tsv_field "${source,,}")"
        record_id="$(sanitize_tsv_field "$record_id")"
        cvss="$(sanitize_tsv_field "${cvss:-0}")"
        [[ -n "$record_id" ]] || continue
        [[ "$cvss" =~ ^[0-9]+([.][0-9]+)?$ ]] || cvss=0

        service_key="$host|$protocol|$port|$product|$version"
        service_id="${service_id_by_key[$service_key]:-}"
        if [[ -z "$service_id" ]]; then
            service_id="$(service_id_for "$service_key")"
            service_id_by_key["$service_key"]="$service_id"
        fi

        evidence_key="$service_id|$source|$record_id"
        [[ -z "${seen_evidence[$evidence_key]:-}" ]] || continue
        seen_evidence["$evidence_key"]=1

        if [[ "$record_id" =~ ^[Cc][Vv][Ee]-[0-9]{4}-[0-9]{4,}$ ]]; then
            record_id="${record_id^^}"
            category="cve"
            exploit_json=false
            DISCOVERED_CVES["$record_id"]=1
            cve_count=$((cve_count + 1))
        elif [[ "${exploit_text,,}" == "true" ]]; then
            category="exploit"
            exploit_json=true
            exploit_count=$((exploit_count + 1))
        else
            category="advisory"
            exploit_json=false
        fi
        reference_url="$(build_vulners_reference_url "$source" "$record_id")"

        # Write one normalized Unit-Separator record. A single jq process below
        # converts the full collection into NDJSON, avoiding one jq process per
        # evidence item while preserving exact field boundaries.
        printf '%s\x1f%s\x1f%s\x1f%s\x1f%s\x1f%s\x1f%s\x1f%s\n' \
            "$service_id" "$context" "$source" "$record_id" "$category" \
            "$cvss" "$exploit_json" "$reference_url" >> "$evidence_normalized"

        evidence_count=$((evidence_count + 1))
        if ((evidence_count % 25 == 0 || evidence_count == raw_evidence_count)); then
            printf '[+] Evidence progress: %d / %d processed.\n' \
                "$evidence_count" "$raw_evidence_count" >&2
        fi
    done < "$evidence_tsv"

    if [[ -s "$evidence_normalized" ]]; then
        jq -R -c '
            split("\u001f") as $f |
            select(($f|length) >= 8) |
            {
                service_id:$f[0],context:$f[1],source:$f[2],id:$f[3],category:$f[4],
                cvss_observed:($f[5]|tonumber),
                exploit_available:($f[6]=="true"),
                reference_url:$f[7]
            }' "$evidence_normalized" > "$evidence_ndjson" ||
            error_exit "Failed to batch-encode normalized evidence records"
    fi

    TOTAL_HOSTS="$(jq -r '.asset.address' "$services_ndjson" 2>/dev/null | sort -u | sed '/^$/d' | wc -l)"
    TOTAL_PORTS="$service_count"
    TOTAL_CVES="${#DISCOVERED_CVES[@]}"

    printf '[+] Phase 1 normalized %d open service(s), %d evidence record(s), %d unique CVE(s), and %d exploit reference(s).\n' \
        "$service_count" "$evidence_count" "$TOTAL_CVES" "$exploit_count"

    if ((TOTAL_CVES == 0 && exploit_count == 0)); then
        if [[ "${scan_type:-}" == "1" || "${scan_type:-}" == "2" ]]; then
            printf '[!] Scan option %s does not execute the Vulners NSE script. No CVEs or exploit references were expected; the report will contain service inventory and an explicit LIMITED coverage status.\n' "$scan_type" >&2
        else
            printf '[!] Vulnerability scan completed without structured CVE or exploit matches. The report will remain valid and record a COMPLETE_NO_MATCHES result.\n' >&2
        fi
    fi

    stage_finish "Phase 1 XML normalization" "$stage_epoch"
}

# Retained main() call: Phase 1 already deduplicates by service/source/ID.
deduplicate_cves() {
    UNIQUE_CVES=("${!DISCOVERED_CVES[@]}")
    printf '[+] Unique CVE records retained: %d\n' "${#UNIQUE_CVES[@]}"
}

# Classify all unique CVEs into KEV and non-KEV collections.
validate_kev_matches() {
    local cve
    KEV_MATCHES=()
    NON_KEV_CVES=()
    for cve in "${UNIQUE_CVES[@]}"; do
        if [[ -n "${KEV_SET[$cve]:-}" ]]; then
            KEV_MATCHES["$cve"]=1
        else
            NON_KEV_CVES["$cve"]=1
        fi
    done
    TOTAL_KEV="${#KEV_MATCHES[@]}"
    printf '[+] CISA KEV matches: %d; CVEs without KEV matches: %d.\n' \
        "$TOTAL_KEV" "${#NON_KEV_CVES[@]}"
}

# Compatibility wrapper retained for any external caller.
classify_cves() {
    validate_kev_matches
}

# Return a human-readable exploitability tier from public exploit count.
calculate_exploitability() {
    local count="$1"
    if ((count >= 20)); then echo "Very High"
    elif ((count >= 10)); then echo "High"
    elif ((count >= 4)); then echo "Moderate"
    elif ((count > 0)); then echo "Low"
    else echo "None"; fi
}

# Query and cache one NVD CVE record. API failures are nonfatal so the report
# can preserve observed scanner evidence even when NVD is unavailable.
query_nvd() {
    local cve="$1" cache_file temporary_file http_code
    local -a headers=()
    cache_file="$(get_nvd_cache_file "$cve")"

    if [[ -s "$cache_file" ]] && jq -e --arg cve "$cve" \
        '.vulnerabilities[0].cve.id == $cve' "$cache_file" >/dev/null 2>&1; then
        NVD_CACHE["$cve"]="$(<"$cache_file")"
        return 0
    fi

    [[ -z "${NVD_API_KEY:-}" ]] || headers=(--header "apiKey: ${NVD_API_KEY}")
    temporary_file="${cache_file}.tmp.$$"
    http_code="$(curl --silent --show-error --location --connect-timeout 10 --max-time 60 \
        --retry 3 --retry-delay 2 "${headers[@]}" --get --data-urlencode "cveId=$cve" \
        --output "$temporary_file" --write-out '%{http_code}' "$NVD_API_URL" || true)"

    if [[ "$http_code" == "200" ]] && jq -e --arg cve "$cve" \
        '.vulnerabilities[0].cve.id == $cve' "$temporary_file" >/dev/null 2>&1; then
        mv -- "$temporary_file" "$cache_file"
        NVD_CACHE["$cve"]="$(<"$cache_file")"
        [[ -n "${NVD_API_KEY:-}" ]] || sleep 6
        return 0
    fi

    rm -f -- "$temporary_file"
    printf '[!] NVD enrichment unavailable for %s (HTTP %s); retaining observed evidence.\n' \
        "$cve" "${http_code:-000}" >&2
    return 1
}

# Enrich every CVE, including CVEs that do not appear in KEV.
enrich_nvd_data() {
    local cve success_count=0 failure_count=0
    NVD_CACHE=()
    for cve in "${UNIQUE_CVES[@]}"; do
        if query_nvd "$cve"; then
            success_count=$((success_count + 1))
        else
            failure_count=$((failure_count + 1))
        fi
    done
    printf '[+] NVD enrichment completed: %d succeeded, %d unavailable.\n' \
        "$success_count" "$failure_count"
}

# Classify a reference URL into a presentation and mitigation source family.
# The helper is deterministic and intentionally conservative. Unknown domains
# remain in the "other" group instead of being assigned unsupported authority.
classify_reference_url() {
    local url="${1,,}"
    case "$url" in
        *nvd.nist.gov*) printf 'nvd\n' ;;
        *cisa.gov*|*.gov/*) printf 'government\n' ;;
        *exploit-db.com*|*packetstormsecurity.com*|*metasploit.com*|*vulners.com/exploitdb/*|*vulners.com/packetstorm/*|*vulners.com/metasploit/*) printf 'exploit\n' ;;
        *github.com*|*gitlab.com*|*gitee.com*) printf 'research\n' ;;
        *) printf 'other\n' ;;
    esac
}

# Convert cached NVD responses into detailed NDJSON for Phase 2. This retains
# CVSS version/source/components, reference tags, weaknesses, and enrichment
# state so the HTML report can distinguish source data from derived guidance.
build_report_dataset() {
    local stage_epoch
    local cve cache_file
    local nvd_ndjson="${NORMALIZED_DIR}/nvd.ndjson"
    local source_status_json="${NORMALIZED_DIR}/source-status.json"
    local requested_count="${#UNIQUE_CVES[@]}"
    local succeeded_count=0
    local failed_count=0

    stage_epoch="$(stage_start "Phase 2 NVD dataset normalization")"
    : > "$nvd_ndjson"

    for cve in "${UNIQUE_CVES[@]}"; do
        cache_file="$(get_nvd_cache_file "$cve")"
        if [[ ! -s "$cache_file" ]]; then
            failed_count=$((failed_count + 1))
            continue
        fi

        if jq -c '
            .vulnerabilities[0].cve as $c |
            def metric:
                ($c.metrics.cvssMetricV40[0] //
                 $c.metrics.cvssMetricV31[0] //
                 $c.metrics.cvssMetricV30[0] //
                 $c.metrics.cvssMetricV2[0] // null);
            (metric) as $m |
            {
                id:$c.id,
                source_identifier:($c.sourceIdentifier//null),
                published:($c.published//null),
                last_modified:($c.lastModified//null),
                status:($c.vulnStatus//null),
                description:(([$c.descriptions[]?|select(.lang=="en")|.value][0])//null),
                cvss:($m.cvssData.baseScore//null),
                severity:($m.cvssData.baseSeverity//$m.baseSeverity//null),
                vector:($m.cvssData.vectorString//null),
                cvss_details:(if $m==null then null else {
                    preferred_version:($m.cvssData.version//null),
                    base_score:($m.cvssData.baseScore//null),
                    base_severity:($m.cvssData.baseSeverity//$m.baseSeverity//null),
                    vector:($m.cvssData.vectorString//null),
                    source:($m.source//null),
                    type:($m.type//null),
                    metrics:{
                        attack_vector:($m.cvssData.attackVector//null),
                        attack_complexity:($m.cvssData.attackComplexity//null),
                        privileges_required:($m.cvssData.privilegesRequired//null),
                        user_interaction:($m.cvssData.userInteraction//null),
                        scope:($m.cvssData.scope//null),
                        confidentiality_impact:($m.cvssData.confidentialityImpact//null),
                        integrity_impact:($m.cvssData.integrityImpact//null),
                        availability_impact:($m.cvssData.availabilityImpact//null)
                    }
                } end),
                weaknesses:([$c.weaknesses[]?.description[]?|select(.lang=="en")|.value]|unique),
                references:([$c.references[]?|{url:(.url//""),source:(.source//null),tags:(.tags//[])}]|unique_by(.url)),
                enrichment:{status:"complete",source:"NVD"}
            }' "$cache_file" >> "$nvd_ndjson"; then
            succeeded_count=$((succeeded_count + 1))
        else
            failed_count=$((failed_count + 1))
            printf '[!] Failed to normalize cached NVD data for %s.\n' "$cve" >&2
        fi
    done

    jq -n \
        --argjson nmap_records "$TOTAL_PORTS" \
        --argjson vulners_records "$(wc -l < "${NORMALIZED_DIR}/evidence.ndjson")" \
        --argjson kev_records "${#KEV_SET[@]}" \
        --argjson nvd_requested "$requested_count" \
        --argjson nvd_succeeded "$succeeded_count" \
        --argjson nvd_failed "$failed_count" '
        {
            nmap:{status:"READY",records:$nmap_records,reason:null},
            vulners:{
                status:(if $vulners_records>0 then "READY" else "NOT_REQUESTED" end),
                records:$vulners_records,
                reason:(if $vulners_records>0 then null else "No structured Vulners evidence was produced by the selected scan profile." end)
            },
            kev:{status:"READY",records:$kev_records,reason:null},
            nvd:{
                status:(if $nvd_requested==0 then "NOT_REQUESTED" elif $nvd_failed==0 then "READY" elif $nvd_succeeded>0 then "DEGRADED" else "UNAVAILABLE" end),
                requested:$nvd_requested,
                succeeded:$nvd_succeeded,
                failed:$nvd_failed,
                reason:(if $nvd_failed==0 then null else (($nvd_failed|tostring)+" CVE record(s) could not be enriched from NVD.") end)
            }
        }' > "$source_status_json" || error_exit "Failed to build enrichment source status"

    printf '[+] Phase 2 enrichment dataset prepared: %s\n' "$nvd_ndjson"
    stage_finish "Phase 2 NVD dataset normalization" "$stage_epoch"
}

# Retained interface for future unit use. The complete finding is assembled in
# export_report_json because service, CVE, KEV, and intelligence arrays must be
# joined in one deterministic operation.
build_finding_record() {
    local service_id="${1:-}"
    [[ -n "$service_id" ]] || return 1
    return 0
}

# Embed report.json into the project HTML template. The template must contain a
# line consisting only of <!-- REPORT_DATA -->. The file is not created in this
# stage; until it is added, JSON generation succeeds and HTML generation records
# a clear nonfatal warning. This allows the next schema-file stage to be deployed
# independently without changing main() or the established post-scan call chain.
generate_html_report() {
    local temporary_html="${REPORT_HTML}.tmp.$$"
    local line marker_count=0

    if [[ ! -r "$HTML_SCHEMA_FILE" ]]; then
        printf '[!] HTML schema template is not installed: %s\n' "$HTML_SCHEMA_FILE" >&2
        printf '[!] JSON reporting completed. HTML generation will activate when the project template is added.\n' >&2
        return 0
    fi

    [[ -s "$REPORT_JSON" ]] || error_exit "Cannot generate HTML because report JSON is missing: $REPORT_JSON"

    : > "$temporary_html"
    while IFS= read -r line || [[ -n "$line" ]]; do
        if [[ "$line" == '<!-- REPORT_DATA -->' ]]; then
            marker_count=$((marker_count + 1))
            printf '<script id="report-data" type="application/json">\n' >> "$temporary_html"
            # Escape a closing script sequence without changing JSON semantics
            # after JSON.parse reads the textContent value in the browser.
            sed 's#</script#<\\/script#g' "$REPORT_JSON" >> "$temporary_html"
            printf '\n</script>\n' >> "$temporary_html"
        else
            printf '%s\n' "$line" >> "$temporary_html"
        fi
    done < "$HTML_SCHEMA_FILE"

    if ((marker_count != 1)); then
        rm -f -- "$temporary_html"
        error_exit "HTML schema must contain exactly one <!-- REPORT_DATA --> marker"
    fi

    [[ -s "$temporary_html" ]] || error_exit "Generated HTML report is empty"
    mv -- "$temporary_html" "$REPORT_HTML"
    printf '[+] Generated HTML report: %s\n' "$REPORT_HTML"
}

# Assemble the complete service-centric report. This implementation intentionally
# omits generator version fields, root schema identifiers, and schema-version
# validation. Structural and count consistency checks remain because they protect
# report integrity without publishing or enforcing a generator/schema version.
export_report_json() {
    local stage_epoch
    local services_ndjson="${NORMALIZED_DIR}/services.ndjson"
    local evidence_ndjson="${NORMALIZED_DIR}/evidence.ndjson"
    local nvd_ndjson="${NORMALIZED_DIR}/nvd.ndjson"
    local source_status_json="${NORMALIZED_DIR}/source-status.json"
    local temporary_report="${REPORT_JSON}.tmp.$$"
    local scan_coverage coverage_status coverage_message
    local generated_at="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
    local end_epoch="$(date +%s)"
    local duration_seconds=$((end_epoch - START_EPOCH))

    stage_epoch="$(stage_start "Report JSON and HTML generation")"

    if [[ "${scan_type:-}" == "1" ]]; then
        scan_coverage="service_inventory"
        coverage_status="LIMITED"
        coverage_message="Service and version detection was performed. OS detection and vulnerability correlation were not performed. Empty CVE and exploit arrays mean not assessed, not vulnerability-free."
    elif [[ "${scan_type:-}" == "2" ]]; then
        scan_coverage="service_and_os_inventory"
        coverage_status="LIMITED"
        coverage_message="Service/version and OS detection were requested. Vulnerability correlation was not performed. Empty CVE and exploit arrays mean not assessed, not vulnerability-free."
    elif ((${#DISCOVERED_CVES[@]} == 0)) && [[ ! -s "$evidence_ndjson" ]]; then
        scan_coverage="vulnerability_correlation"
        coverage_status="COMPLETE_NO_MATCHES"
        coverage_message="The vulnerability profile executed, but no structured CVE or intelligence matches were returned. Validate fingerprints and raw evidence before concluding that no vulnerabilities apply."
    else
        scan_coverage="vulnerability_correlation"
        coverage_status="COMPLETE"
        coverage_message="Structured Vulners records were normalized and correlated with KEV and available NVD data."
    fi

    jq -n \
        --arg run_id "$RUN_ID" --arg generated_at "$generated_at" --arg target "$target" \
        --arg scan_type "${scan_type:-unknown}" --arg scan_name "$SCAN_NAME" \
        --arg scan_coverage "$scan_coverage" --arg coverage_status "$coverage_status" \
        --arg coverage_message "$coverage_message" --arg scan_xml "$SCAN_XML" \
        --arg scan_normal "$RAW_SCAN_LOG" --arg scan_grepable "$SCAN_GNMAP" \
        --arg console_log "$NMAP_CONSOLE_LOG" --arg requested_ports "$PORT_SPEC" \
        --argjson duration_seconds "$duration_seconds" \
        --slurpfile services "$services_ndjson" --slurpfile evidence "$evidence_ndjson" \
        --slurpfile nvd "$nvd_ndjson" --slurpfile kev "$KEV_FILE" \
        --slurpfile source_status "$source_status_json" '
        def severity($s):
            if $coverage_status=="LIMITED" then "Not Assessed"
            elif $s>=9 then "Critical" elif $s>=7 then "High"
            elif $s>=4 then "Medium" elif $s>0 then "Low" else "Informational" end;
        def tier($n):
            if $coverage_status=="LIMITED" then "Not Assessed"
            elif $n>=20 then "Very High" elif $n>=10 then "High"
            elif $n>=4 then "Moderate" elif $n>0 then "Low" else "None" end;
        def nvdrow($id): ([$nvd[]|select(.id==$id)][0]//{});
        def kevrow($id): ([($kev[0].vulnerabilities//[])[]|select(.cveID==$id)][0]//null);
        def reference_type($url;$tags):
            ($url|ascii_downcase) as $u |
            if ($u|contains("nvd.nist.gov")) then "nvd"
            elif ($u|contains("cisa.gov")) or ($u|test("[.]gov/")) then "government"
            elif (($tags//[])|any(.=="Vendor Advisory" or .=="Patch")) then "vendor"
            elif ($u|contains("exploit-db")) or ($u|contains("packetstorm")) or ($u|contains("metasploit")) then "exploit"
            elif ($u|contains("github.com")) or ($u|contains("gitlab.com")) or ($u|contains("gitee.com")) then "research"
            else "other" end;
        def grouprefs($refs):
            reduce ($refs//[])[] as $r
              ({vendor:[],government:[],nvd:[],advisory:[],exploit:[],research:[],other:[]};
               (reference_type($r.url;$r.tags)) as $t |
               .[$t] += [($r+{type:$t,authoritative:($t=="vendor" or $t=="government"),supports_mitigation:($t=="vendor" or $t=="government")})]);
        def cverec($e):
            (nvdrow($e.id)) as $n | (kevrow($e.id)) as $k |
            {
                id:$e.id,kev_match:($k!=null),
                observed:{cvss:$e.cvss_observed,reference_url:$e.reference_url,trust_class:"observed"},
                cvss:($n.cvss//$e.cvss_observed),severity:($n.severity//severity($e.cvss_observed)),
                vector:($n.vector//null),description:($n.description//null),published:($n.published//null),
                last_modified:($n.last_modified//null),status:($n.status//null),
                weaknesses:($n.weaknesses//[]),cvss_details:(($n.cvss_details//null) as $d |
                    if $d==null then null else $d+{observed_source_score:$e.cvss_observed,
                    score_difference:(if $d.base_score==null then null else (($e.cvss_observed-$d.base_score)*10|round/10) end)} end),
                references_by_type:grouprefs($n.references//[]),
                nvd_references:[$n.references[]?.url],
                enrichment:($n.enrichment//{status:"unavailable",source:"NVD"}),
                kev:(if $k==null then null else {
                    vendor_project:$k.vendorProject,product:$k.product,vulnerability_name:$k.vulnerabilityName,
                    date_added:$k.dateAdded,due_date:$k.dueDate,required_action:$k.requiredAction,
                    known_ransomware_campaign_use:$k.knownRansomwareCampaignUse,notes:$k.notes,
                    trust_class:"authoritative"
                } end)
            };
        def mitigation($s;$cves;$intel;$max;$exploits):
            ([$cves[]|select(.kev_match)][0]//null) as $kcve |
            if $coverage_status=="LIMITED" then {
                status:"NOT_ASSESSED",priority:"Validation Required",
                summary:"The selected scan profile did not perform vulnerability correlation.",
                authoritative_action:{available:false,action:null,source:null,source_type:null,url:null,due_date:null,vendor_fixed_version:null,vendor_workaround:null,confidence:"unavailable"},
                primary_action:{action_type:"manual_validation",action:"Run scan option 3 before assigning vulnerability-specific remediation.",rationale:$coverage_message,basis:["limited_scan_profile"],confidence:"high",authoritative:false},
                compensating_controls:[],
                verification:{required:true,retest_scan_option:3,steps:["Run scan option 3.","Validate the detected product, version, and CPE.","Review the resulting CVE and intelligence correlations."],expected_result:"Vulnerability correlation is completed for the detected service.",evidence_required:["option 3 Nmap XML","operator validation note"]},
                provenance:[],limitations:[$coverage_message],operator_review_required:true
            } else {
                status:(if $kcve!=null then "AUTHORITATIVE" elif ($cves|length)>0 or ($intel|length)>0 then "DERIVED" else "REVIEW_REQUIRED" end),
                priority:(if $kcve!=null or $max>=9 then "Immediate" elif $max>=7 then "High" elif $max>=4 then "Planned" else "Routine" end),
                summary:(if $kcve!=null then ($kcve.kev.required_action//"Apply vendor-approved remediation immediately.") elif ($cves|length)>0 then "Upgrade to a supported vendor-fixed release or remove the affected service." elif ($intel|length)>0 then "Validate the intelligence correlation and replace or upgrade the affected service if applicable." else "No vulnerability-specific remediation can be assigned until applicability is validated." end),
                authoritative_action:(if $kcve==null then {available:false,action:null,source:null,source_type:null,url:null,due_date:null,vendor_fixed_version:null,vendor_workaround:null,confidence:"unavailable"} else {available:true,action:$kcve.kev.required_action,source:"CISA KEV",source_type:"government",url:null,due_date:$kcve.kev.due_date,vendor_fixed_version:null,vendor_workaround:null,confidence:"authoritative"} end),
                primary_action:{action_type:(if ($cves|length)>0 then "upgrade_or_replace" else "manual_validation" end),action:(if ($cves|length)>0 then "Upgrade to a supported vendor-fixed release or remove the service when no supported remediation exists." else "Validate whether the non-CVE intelligence applies to the detected service." end),rationale:(if $kcve!=null then "Known exploitation is documented in CISA KEV." elif $exploits>0 then "Public exploit references increase operational urgency." else "Version and CPE correlation requires remediation review." end),basis:([if $kcve!=null then "kev_match" else empty end,if $exploits>0 then "public_exploit_available" else empty end,if ($cves|length)>0 then "cve_correlation" else empty end]),confidence:(if $kcve!=null then "authoritative" elif ($cves|length)>0 then "high" else "moderate" end),authoritative:($kcve!=null)},
                compensating_controls:[
                    {control_id:"network-restriction",category:"network",action:"Restrict access to approved sources while permanent remediation is completed.",objective:"Reduce service exposure.",temporary:true,priority:"Immediate",confidence:"generic",authoritative:false},
                    {control_id:"monitoring",category:"monitoring",action:"Increase logging and monitor the service for anomalous authentication, process, and network activity.",objective:"Improve detection during the remediation window.",temporary:true,priority:"High",confidence:"generic",authoritative:false}
                ],
                verification:{required:true,retest_scan_option:3,steps:["Confirm the installed product and version.","Apply the approved remediation.","Rerun scan option 3.","Confirm the vulnerable version or CPE is no longer detected.","Confirm the prior CVE and exploit correlations no longer appear."],expected_result:"The affected version and associated correlations are no longer detected.",evidence_required:["post-remediation Nmap XML","updated service version","operator validation note"]},
                provenance:([if $kcve!=null then {source:"CISA KEV",source_type:"government",authoritative:true,cve:$kcve.id} else empty end]),
                limitations:["Derived and generic controls require operator and vendor review."],operator_review_required:true
            } end;
        ($services|unique_by(.service_id)) as $svcs |
        ($evidence|unique_by([.service_id,.source,.id])) as $ev |
        ($ev|map(select(.category=="cve"))|unique_by(.id)|map(cverec(.))) as $allcves |
        ($svcs|map(. as $s |
            ($ev|map(select(.service_id==$s.service_id))) as $se |
            ($se|map(select(.category=="cve"))|unique_by(.id)|map(cverec(.))|sort_by(-(.cvss//0))) as $cves |
            ($se|map(select(.category!="cve"))|map(.+{
                related_cves:[],relationship_type:"same_product_version",relationship_confidence:"unresolved",
                validation_status:"unreviewed",provenance:{provider:"Vulners",original_source:.source,retrieved_at:null}
            })|sort_by(.source,.id)) as $intel |
            ($intel|map(select(.exploit_available))|length) as $exploits |
            ([($cves|map(.cvss)),($intel|map(.cvss_observed))]|flatten|map(select(.!=null))|max//0) as $max |
            ([$cves[].references_by_type.vendor[], $cves[].references_by_type.government[],
              $cves[].references_by_type.nvd[], $cves[].references_by_type.advisory[],
              $cves[].references_by_type.exploit[], $cves[].references_by_type.research[],
              $cves[].references_by_type.other[]]|flatten) as $cve_refs |
            {
                finding_id:("finding-"+$s.service_id),
                title:(($s.service.product//"")+(if ($s.service.version//"")=="" then "" else " "+$s.service.version end)+" on "+$s.asset.address+":"+($s.endpoint.port|tostring)),
                asset:$s.asset,endpoint:$s.endpoint,service:$s.service,
                applicability:{status:(if ($s.service.product//"")!="" and ($s.service.version//"")!="" then "candidate" else "unresolved" end),confidence:(if ($s.service.product//"")!="" and ($s.service.version//"")!="" then "high" else "low" end),validated:false,basis:([if ($s.service.product//"")!="" then "product_match" else empty end,if ($s.service.version//"")!="" then "version_match" else empty end,if ($s.service.cpe|length)>0 then "cpe_match" else empty end]),evidence:[{type:"nmap_service_fingerprint",value:(($s.service.product//"")+" "+($s.service.version//"")|gsub("^ | $";"")),confidence:($s.service.confidence//null)}],operator_notes:null,last_reviewed_at:null,reviewed_by:null},
                exposure:{network_reachable:true,internet_exposed:null,access_scope:"unknown",authentication_required:null,segmentation_observed:null,notes:[]},
                attack_context:{remote_exploitation_possible:null,local_access_required:null,user_interaction_required:null,privileges_required:null,likely_impact:[],public_tooling_available:($exploits>0),known_exploitation:($cves|any(.kev_match))},
                risk:{severity:severity($max),max_cvss:(if $coverage_status=="LIMITED" then null else $max end),exploitability:tier($exploits),public_exploits:(if $coverage_status=="LIMITED" then null else ($exploits>0) end),public_exploit_references:(if $coverage_status=="LIMITED" then null else $exploits end),kev_present:($cves|any(.kev_match)),priority_score:(if $coverage_status=="LIMITED" then null else ([($max*6),if ($cves|any(.kev_match)) then 30 else 0 end,if $exploits>0 then 10 else 0 end]|add|if .>100 then 100 else round end) end),priority_band:(if $coverage_status=="LIMITED" then "Not Assessed" elif ($cves|any(.kev_match)) or $max>=9 then "P1" elif $max>=7 then "P2" elif $max>=4 then "P3" else "P4" end),risk_drivers:([if ($cves|any(.kev_match)) then {type:"kev_match",weight:30,description:"Known exploitation is documented by CISA."} else empty end,if $exploits>0 then {type:"public_exploit",weight:10,description:"Public exploit references are available."} else empty end,if $max>0 then {type:"cvss",weight:($max*6|round),description:("Maximum correlated CVSS is "+($max|tostring)+".")} else empty end]),score_method:"service-risk-v1"},
                coverage:{total_cves:($cves|length),kev_matches:([$cves[]|select(.kev_match)]|length),non_kev_cves:([$cves[]|select(.kev_match|not)]|length),threat_intelligence_records:($intel|length),vulnerability_correlation_performed:($scan_type=="3"),nvd_enrichment:(if ($cves|length)==0 then "not_required" elif ([$cves[]|select(.enrichment.status=="complete")]|length)==($cves|length) then "complete" elif ([$cves[]|select(.enrichment.status=="complete")]|length)>0 then "partial" else "unavailable" end),kev_correlation:(if $scan_type=="3" then "complete" else "not_assessed" end),intelligence_sources_present:([$intel[].source]|unique),missing_sources:[]},
                cves:$cves,kev_cves:[$cves[]|select(.kev_match)],non_kev_cves:[$cves[]|select(.kev_match|not)],
                threat_intelligence:($intel|group_by(.source)|map({key:.[0].source,value:.})|from_entries),
                evidence:($se|sort_by(-(.cvss_observed//0))),
                references:([$se[].reference_url]+[$cve_refs[].url]|map(select(.!=null and .!=""))|unique),
                references_by_type:grouprefs($cve_refs),
                mitigation:mitigation($s;$cves;$intel;$max;$exploits),
                remediation_status:{state:"open",owner:null,assigned_team:null,target_date:null,exception:null,exception_expiration:null,last_updated:null,retest_status:"not_tested",retest_run_id:null,operator_notes:null}
            })|sort_by(-(.risk.priority_score//-1),.asset.address,.endpoint.port)) as $findings |
        ($source_status[0]) as $sources |
        {
            metadata:{run_id:$run_id,generated_at:$generated_at,target:$target,scan_option:$scan_type,scan_name:$scan_name,duration_seconds:$duration_seconds,requested_ports:$requested_ports},
            scan_coverage:{scope:$scan_coverage,status:$coverage_status,message:$coverage_message,vulnerability_script_executed:($scan_type=="3")},
            source_files:{nmap_xml:$scan_xml,nmap_normal:$scan_normal,nmap_grepable:$scan_grepable,nmap_console_log:$console_log},
            statistics:{hosts:([$svcs[].asset.address]|unique|length),open_ports:($svcs|length),findings:($findings|length),total_cves:($allcves|length),kev_matches:([$allcves[]|select(.kev_match)]|length),non_kev_cves:([$allcves[]|select(.kev_match|not)]|length),public_exploit_references:(if $coverage_status=="LIMITED" then null else ([$ev[]|select(.category!="cve" and .exploit_available)]|length) end),enrichment_failures:($sources.nvd.failed//0),severity:{critical:(if $coverage_status=="LIMITED" then null else ([$findings[]|select(.risk.severity=="Critical")]|length) end),high:(if $coverage_status=="LIMITED" then null else ([$findings[]|select(.risk.severity=="High")]|length) end),medium:(if $coverage_status=="LIMITED" then null else ([$findings[]|select(.risk.severity=="Medium")]|length) end),low:(if $coverage_status=="LIMITED" then null else ([$findings[]|select(.risk.severity=="Low")]|length) end),informational:(if $coverage_status=="LIMITED" then null else ([$findings[]|select(.risk.severity=="Informational")]|length) end)}},
            executive_summary:{services_identified:($svcs|length),services_with_public_exploits:(if $coverage_status=="LIMITED" then null else ([$findings[]|select(.risk.public_exploits==true)]|length) end),highest_risk_service:(if $coverage_status=="LIMITED" then null else ($findings[0].title//null) end),highest_cvss:(if $coverage_status=="LIMITED" then null else ($findings[0].risk.max_cvss//0) end),risk_posture:(if $coverage_status=="LIMITED" then "Not Assessed" elif ([$findings[]|select(.risk.severity=="Critical")]|length)>0 then "Critical" elif ([$findings[]|select(.risk.severity=="High")]|length)>0 then "High" elif ([$findings[]|select(.risk.severity=="Medium")]|length)>0 then "Medium" else "Low" end),primary_risk_drivers:([$findings[].risk.risk_drivers[]]|sort_by(-.weight)|unique_by(.type)|.[0:5]),priority_actions:([$findings[].mitigation.primary_action.action]|unique|.[0:5]),limitations:([$coverage_message]+([$findings[].mitigation.limitations[]]|unique)),conclusion:(if $coverage_status=="LIMITED" then $coverage_message elif ($allcves|length)==0 then $coverage_message elif ([$allcves[]|select(.kev_match)]|length)>0 then "One or more identified CVEs match the CISA KEV catalog and require priority validation and remediation." else "CVEs were identified, but none matched the loaded CISA KEV catalog. Non-KEV status does not imply absence of exploitability." end)},
            kev_matched_cves:([$allcves[]|select(.kev_match)]|sort_by(-(.cvss//0),.id)),
            non_kev_cves:([$allcves[]|select(.kev_match|not)]|sort_by(-(.cvss//0),.id)),
            findings:$findings,
            data_quality:{overall_status:(if $coverage_status=="LIMITED" then "PARTIAL" elif $sources.nvd.status=="DEGRADED" or $sources.nvd.status=="UNAVAILABLE" then "PARTIAL" else "READY" end),sources:$sources,nvd_enriched_cves:($nvd|length),source_evidence_records:($ev|length),warnings:([if $coverage_status=="LIMITED" then $coverage_message else empty end,if $sources.nvd.reason!=null then $sources.nvd.reason else empty end]),caveats:["Nmap Vulners matches are version/CPE correlations and require applicability validation.","Third-party exploit references may duplicate the same underlying vulnerability or proof of concept.","Observed source CVSS values may differ from NVD metrics and are retained as observed evidence.","Derived mitigation and generic controls require operator and vendor review."]}
        }' > "$temporary_report" || error_exit "Failed to assemble report JSON"

    jq -e '.metadata and .scan_coverage and .statistics and (.findings|type=="array")' "$temporary_report" >/dev/null ||
        error_exit "Generated report JSON failed structural validation"
    mv -- "$temporary_report" "$REPORT_JSON"

    jq -e '(.statistics.total_cves == ((.kev_matched_cves|length)+(.non_kev_cves|length))) and
           (.statistics.findings == (.findings|length))' "$REPORT_JSON" >/dev/null ||
        error_exit "Generated report JSON failed consistency validation"

    sha256sum "$REPORT_JSON" > "${MANIFEST_DIR}/report.json.sha256"
    printf '[+] Exported detailed service-centric report JSON: %s\n' "$REPORT_JSON"

    # Preserve main() by invoking HTML rendering behind the existing export call.
    generate_html_report
    stage_finish "Report JSON and HTML generation" "$stage_epoch"
}


# Preserve the existing finalization contract and latest-report symlink.
finalize_successful_run() {
    local latest_link="${REPORT_ROOT}/latest"
    ln -sfn "$REPORT_DIR" "$latest_link"
    printf '\n[+] Assessment completed successfully.\n'
    printf '[+] JSON report:      %s\n' "$REPORT_JSON"
    if [[ -s "$REPORT_HTML" ]]; then
        printf '[+] HTML report:      %s\n' "$REPORT_HTML"
    else
        printf '[!] HTML report:      pending project template installation\n'
    fi
    printf '[+] Nmap XML:         %s\n' "$SCAN_XML"
    printf '[+] Nmap normal:      %s\n' "$RAW_SCAN_LOG"
    printf '[+] Nmap grepable:    %s\n' "$SCAN_GNMAP"
    printf '[+] Nmap console log: %s\n' "$NMAP_CONSOLE_LOG"
    printf '[+] Assessment data:  %s\n' "$RUN_DIR"
    printf '[+] Report SHA-256:   %s\n' "$(cut -d' ' -f1 "${MANIFEST_DIR}/report.json.sha256")"

    # Replace the legacy report.txt path-only value before main() prints its
    # existing REPORT block. This preserves main() while showing authoritative
    # JSON and HTML output locations instead of a nonexistent text report.
    if [[ -s "$REPORT_HTML" ]]; then
        printf -v OUTPUT_FILE 'JSON: %s\nHTML: %s' "$REPORT_JSON" "$REPORT_HTML"
    else
        printf -v OUTPUT_FILE 'JSON: %s\nHTML: NOT GENERATED\nTemplate: %s' \
            "$REPORT_JSON" "$HTML_SCHEMA_FILE"
    fi

    if [[ "${KEEP_ASSESSMENT_DATA:-1}" == "0" ]]; then
        if declare -F archive_assessment_evidence >/dev/null 2>&1; then
            archive_assessment_evidence
        fi
        rm -rf -- "$RUN_DIR"
        printf '[+] Temporary assessment workspace removed.\n'
    else
        printf '[+] Assessment workspace retained.\n'
    fi
}


# ---------- Main Function ----------
NMAP_CONSOLE_LOG="${LOG_DIR}/nmap-console.log"
main() {
    #Initialize Scan directory and files
    initialize_runtime
    validate_runtime_paths
    create_assessment_manifest
    refresh_kev_catalog
    validate_pre_scan_inputs
    load_kev_catalog
    #Begin Scan Selection Output
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
                SCAN_COMMAND=(nmap -sV  "${PORT_ARGS[@]}"  --open -oA "${BASE_PATH}" "$target")
                SCAN_NAME="Service Version Detection (-sV)"
                break
                ;;
            2)
                SCAN_COMMAND=(sudo nmap -sV -O -T3 -n -Pn "${PORT_ARGS[@]}" -oA "$BASE_PATH" "$target")
                SCAN_NAME="Service + OS Detection (-sV -O)"
                break
                ;;
            3)
                SCAN_COMMAND=(sudo nmap -sS -sV -O -T3 -n --script=vulners "${PORT_ARGS[@]}" --script-timeout 3m -oA "${BASE_PATH}" "$target")
                SCAN_NAME="Parallel Vuln script detection (--script nmap vuln,vulners)"
                break
                ;;
            *)
                echo; echo "ERROR: Invalid scan selection."; echo
                ;;
        esac
    done

     echo; echo "Running scan..."
     echo "Press (or hold) Spacebar to see Nmap Progress"

    # Capture Nmap's complete console output for report parsing while also
    # displaying it live in the terminal.
    set +e

    stdbuf -oL -eL "${SCAN_COMMAND[@]}" > >(tee -a "$NMAP_CONSOLE_LOG") 2>&1 &

    NMAP_PID=$!
    wait "$NMAP_PID"
    scan_exit_code=$?

    unset NMAP_PID
    set -e

    if (( scan_exit_code != 0 )); then
    error_exit "Nmap exited with status ${scan_exit_code}."
    fi

   
    # Generate final parsed markdown report
    echo "Validating Scan Output"
    validate_post_scan_outputs
    echo "Parsing Report XML Results"
    parse_nmap_xml
    echo "Dedeplicating XML CVE Results"
    deduplicate_cves
    echo "Matching CVE Results to KEV Database"
    validate_kev_matches
    echo "Sourcing NVD CVE Information from NIST"
    enrich_nvd_data
    echo "Building Report Database"
    build_report_dataset
    echo "Exporing Report Json file for Report Compilation"
    export_report_json
    echo "Exporting Results to Archive Directory"
    finalize_successful_run



    # Print the report output to standard output BEFORE archiving files
    echo; echo "========== REPORT =========="
    echo "$OUTPUT_FILE"
    echo "============================"
    echo
echo "Archiving scan data to log vault"

}

main "$@"