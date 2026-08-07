#!/bin/bash

# ==========================================
# Secure Network Report Generator v4
# ==========================================

set -Eeuo pipefail

#------------cleanup logic-----------
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

REPORT_TXT="${REPORT_DIR}/report.txt"

REPORT_LOG="${REPORT_DIR}/report.log"

SCAN_BASENAME="network-scan-${RUN_ID}"
BASE_PATH="${RAW_NMAP_DIR}/${SCAN_BASENAME}"

RAW_SCAN_LOG="${BASE_PATH}.nmap"
SCAN_XML="${BASE_PATH}.xml"
SCAN_GNMAP="${BASE_PATH}.gnmap"

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

declare -A DISCOVERED_CVES
declare -A CVE_COUNTS

declare -A CVE_HOSTS
declare -A CVE_PORTS

declare -A KEV_MATCHES

declare -A NVD_CACHE

declare -A FINDINGS



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
#--------------------------------------------
# ---------Report Parsing Functions ---------
#--------------------------------------------
#---------load nmap xml into memory----------


#---Validate Scan inputs----------
validate_pre_scan_inputs() {
    [[ -r "$KEV_FILE" ]] ||
        error_exit "KEV catalog is missing or unreadable: $KEV_FILE"

    [[ -n "${NVD_API_KEY:-}" ]] ||
        error_exit "NVD_API_KEY is not configured."
}

validate_post_scan_outputs() {
    [[ -s "$SCAN_XML" ]] ||
        error_exit "Nmap XML output is missing or empty: $SCAN_XML"

    xmlstarlet val -q "$SCAN_XML" ||
        error_exit "Nmap XML output is not valid XML: $SCAN_XML"
}
#---Create post-run archive----
create_assessment_manifest() {

cat > "${MANIFEST_DIR}/assessment.json" <<EOF
{
  "run_id":"${RUN_ID}",
  "timestamp":"${TIMESTAMP}",
  "host":"$(hostname)"
}
EOF

}
#--------Validate Datasources---------
validate_inputs() {

    [[ -f "$SCAN_XML" ]] || {
        echo "Missing XML file"
        exit 1
    }

    [[ -f "$KEV_FILE" ]] || {
        echo "Missing KEV catalog"
        exit 1
    }

    command -v jq >/dev/null || exit 1

    command -v xmllint >/dev/null || exit 1
}

#-------Load KEV into memory--------
load_kev_catalog() {
    local cve
    local vendor
    local product
    local date_added

    [[ -r "$KEV_FILE" ]] ||
        error_exit "KEV catalog is missing or unreadable: $KEV_FILE"

    jq -e '
        .vulnerabilities
        | type == "array"
    ' "$KEV_FILE" >/dev/null 2>&1 ||
        error_exit "KEV catalog is invalid: $KEV_FILE"

    while IFS=$'\t' read -r cve vendor product date_added; do
        [[ "$cve" =~ ^CVE-[0-9]{4}-[0-9]{4,}$ ]] || continue

        KEV_SET["$cve"]=1
        KEV_RECORDS["$cve"]="${vendor}|${product}|${date_added}"
    done < <(
        jq -r '
            .vulnerabilities[]
            | [
                .cveID // "",
                .vendorProject // "",
                .product // "",
                .dateAdded // ""
            ]
            | @tsv
        ' "$KEV_FILE"
    )

    (( ${#KEV_SET[@]} > 0 )) ||
        error_exit "No valid CVEs were loaded from $KEV_FILE"

    printf '[+] Loaded %d KEV records into memory.\n' \
        "${#KEV_SET[@]}"
}

#---Extract KEV mathces from Nmap XML----
parse_nmap_xml() {

    while IFS='|' read -r host port service cve
    do

        register_cve \
            "$host" \
            "$port" \
            "$service" \
            "$cve"

    done < <(

        extract_vulners_records

    )

}

#---Build in memory catalog of mathcing NMAP-KEV matches---
extract_vulners_records() {

    xmlstarlet sel \
        -t \
        -m "//host" \
        -v "address/@addr" \
        -n \
        "$SCAN_XML"

}

#---Build CVE List for report generation in memory----
register_cve() {
    local host="$1"
    local port="$2"
    local service="$3"
    local cve="${4^^}"

    [[ "$cve" =~ ^CVE-[0-9]{4}-[0-9]{4,}$ ]] || return 0

    DISCOVERED_CVES["$cve"]=1
    ((CVE_COUNTS["$cve"] += 1))

    CVE_HOSTS["$cve"]+="${host};"
    CVE_PORTS["$cve"]+="${port}:${service};"
}

#---De-deplicate CVE findings-----
deduplicate_cves() {

    UNIQUE_CVES=(
        "${!DISCOVERED_CVES[@]}"
    )

}

#-----Validate Kev Matcches-----
validate_kev_matches() {

    for cve in "${UNIQUE_CVES[@]}"
    do

        if [[ ${KEV_SET[$cve]+x} ]]
        then
            KEV_MATCHES["$cve"]=1

            ((TOTAL_KEV++))
        fi

    done

}



#---Local NVD cache Query----
enrich_nvd_data() {

    for cve in "${!KEV_MATCHES[@]}"
    do

        query_nvd "$cve"

    done

}

#----Live API NVD Query------
query_nvd() {
    local cve="$1"
    local cache_file
    local response
    local temporary_file

    cache_file="$(get_nvd_cache_file "$cve")"

    if [[ -s "$cache_file" ]] &&
       jq -e '.vulnerabilities | type == "array"' \
           "$cache_file" >/dev/null 2>&1; then

        NVD_CACHE["$cve"]="$(<"$cache_file")"
        return 0
    fi

    temporary_file="${cache_file}.tmp.$$"

    if ! curl \
        --show-error \
        --location \
        --connect-timeout 10 \
        --max-time 60 \
        --retry 3 \
        --retry-delay 2 \
        --header "apiKey: ${NVD_API_KEY}" \
        --get \
        --data-urlencode "cveId=${cve}" \
        "$NVD_API_URL" \
        --output "$temporary_file"; then

        rm -f -- "$temporary_file"
        echo "[!] NVD request failed for ${cve}" >&2
        return 1
    fi

    if ! jq -e '.vulnerabilities | type == "array"' \
        "$temporary_file" >/dev/null 2>&1; then

        rm -f -- "$temporary_file"
        echo "[!] Invalid NVD response for ${cve}" >&2
        return 1
    fi

    mv -- "$temporary_file" "$cache_file"
    NVD_CACHE["$cve"]="$(<"$cache_file")"
}

#---Build .json Report Records for report generation---
build_report_dataset() {

    for cve in "${!KEV_MATCHES[@]}"
    do

        build_finding_record "$cve"

    done

}

#---Assemble nvd-kev records 
build_finding_record() {

    local cve="$1"

    local nvd="${NVD_CACHE[$cve]}"

    local cvss
    local severity
    local description

    cvss="$(
    jq -r '
        .vulnerabilities[0].cve.metrics as $metrics
        | (
            $metrics.cvssMetricV31[0].cvssData.baseScore
            // $metrics.cvssMetricV30[0].cvssData.baseScore
            // $metrics.cvssMetricV2[0].cvssData.baseScore
            // null
        )
      ' <<< "$nvd"
    )"

    severity=$(
        jq -r '
        .vulnerabilities[0]
        .cve.metrics.cvssMetricV31[0]
        .cvssData.baseSeverity
        ' <<< "$nvd"
    )

    description="$(
    jq -r '
        first(
            .vulnerabilities[0].cve.descriptions[]?
            | select(.lang == "en")
            | .value
        ) // "No English NVD description available."
    ' <<< "$nvd"
)"

    FINDINGS["$cve"]=$(
        jq -nc \
        --arg cve "$cve" \
        --arg severity "$severity" \
        --arg description "$description" \
        --arg cvss "$cvss" \
        --arg hosts "${CVE_HOSTS[$cve]}" \
        '
        {
            cve:$cve,
            severity:$severity,
            cvss:$cvss,
            description:$description,
            hosts:$hosts
        }
        '
    )

}


#---export final .json report database----
export_report_json() {
    local findings_json

    findings_json="$(
        for cve in "${!FINDINGS[@]}"; do
            printf '%s\n' "${FINDINGS[$cve]}"
        done |
            jq -s 'sort_by(.cve)'
    )"

    jq -n \
        --arg run_id "$RUN_ID" \
        --arg generated_at "$REPORT_DATE" \
        --arg target "$target" \
        --arg scan_type "$SCAN_NAME" \
        --argjson findings "$findings_json" \
        '{
            schema_version: "1.0",
            run_id: $run_id,
            generated_at: $generated_at,
            target: $target,
            scan_type: $scan_type,
            summary: {
                finding_count: ($findings | length),
                kev_count: ($findings | length)
            },
            findings: $findings
        }' > "$REPORT_JSON"

    jq empty "$REPORT_JSON" ||
        error_exit "Generated report JSON failed validation."
}

finalize_successful_run() {
    ln -sfn "$REPORT_DIR" "${REPORT_ROOT}/latest"

    if [[ "${KEEP_ASSESSMENT_DATA:-0}" == "0" ]]; then
        rm -rf -- "$RUN_DIR"
    fi

    printf '[+] JSON report: %s\n' "$REPORT_JSON"
    [[ -s "$REPORT_HTML" ]] &&
        printf '[+] HTML report: %s\n' "$REPORT_HTML"
}

# ---------- OLD Report Functions ----------

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

    if [[ -z "${:-}" || ! -f "$XML_REPORT" ]]; then
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
                SCAN_COMMAND=(sudo nmap -sV -O -T3 -n -Pn "${PORT_ARGS[@]}" -oA "$RAW_SCAN_LOG" "$target")
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