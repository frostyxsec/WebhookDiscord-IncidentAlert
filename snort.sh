#!/bin/bash

# ===========================================
# SNORT LOG MONITORING SCRIPT
# ===========================================

# Discord Webhook Configuration
DISCORD_WEBHOOK=" "

# Log Files Configuration
SNORT_LOG="/var/log/snort/alert"
TEMP_DIR="/tmp/snort_monitor"
SNORT_TEMP="${TEMP_DIR}/snort_last_check"
LOCK_FILE="${TEMP_DIR}/snort_monitor.lock"
ALERT_HISTORY="${TEMP_DIR}/snort_alert_history"
DEDUP_FILE="${TEMP_DIR}/recent_alerts_hashes"
DEDUP_WINDOW=30  # seconds
HOSTNAME=$(hostname)
SERVER_IP=$(ip route get 8.8.8.8 2>/dev/null | awk '/src/ {print $7}' || echo "Unknown")

# Create temp directory if it doesn't exist
mkdir -p "$TEMP_DIR"

# Function to send enhanced Discord message with embed
send_discord_embed() {
    local title="$1"
    local description="$2"
    local color="$3"
    local fields="$4"
    local log_timestamp="$5"
    local max_retries=3
    local retry=0

    # Use log timestamp if provided, else current UTC time
    local timestamp
    if [ -n "$log_timestamp" ]; then
        timestamp="$log_timestamp"
    else
        timestamp=$(date -u +"%Y-%m-%dT%H:%M:%S.000Z")
    fi

    # Escape JSON special characters
    title=$(echo "$title" | sed 's/\\/\\\\/g; s/"/\\"/g')
    description=$(echo "$description" | sed 's/\\/\\\\/g; s/"/\\"/g')

    # Create JSON payload with embed
    local payload=$(cat <<EOF
{
    "embeds": [
        {
            "title": "$title",
            "description": "$description",
            "color": $color,
            "fields": [$fields],
            "footer": {
                "text": "$HOSTNAME - Snort IDS Monitor",
                "icon_url": " "
            },
            "timestamp": "$timestamp"
        }
    ]
}
EOF
)
    
    echo "DEBUG: Sending Discord message for: $title" >&2
    
    while [ $retry -lt $max_retries ]; do
        local response=$(curl -s -w "HTTPSTATUS:%{http_code}" -X POST "$DISCORD_WEBHOOK" \
            -H "Content-Type: application/json" \
            -d "$payload")
        
        local http_code=$(echo "$response" | grep -o "HTTPSTATUS:[0-9]*" | cut -d: -f2)
        local body=$(echo "$response" | sed 's/HTTPSTATUS:[0-9]*$//')
        
        if [ "$http_code" = "200" ] || [ "$http_code" = "204" ]; then
            echo "DEBUG: Discord message sent successfully (HTTP $http_code)" >&2
            return 0
        else
            echo "DEBUG: Discord failed with HTTP $http_code: $body" >&2
            retry=$((retry + 1))
            sleep 2
        fi
    done
    
    echo "Failed to send discord message after $max_retries attempts" >&2
    return 1
}

# Function to escape JSON strings
escape_json() {
    local input="$1"
    echo "$input" | sed 's/\\/\\\\/g; s/"/\\"/g; s/\n/\\n/g; s/\r/\\r/g; s/\t/\\t/g'
}

# Function to get severity level (compare with ur rules)
get_severity() {
    local alert="$1"
    
    critical_patterns=(
        "backdoor" "malware" "trojan" "exploit" "intrusion" "brute force"
    )
    high_patterns=(
        "SQL injection" "XSS" "privilege escalation" "web shell" "attack"
    )
    medium_patterns=(
        "DDoS" "scan" "probe" "suspicious"
    )
    
    for pattern in "${critical_patterns[@]}"; do
        if echo "$alert" | grep -qi "$pattern"; then
            echo "CRITICAL"
            return
        fi
    done
    
    for pattern in "${high_patterns[@]}"; do
        if echo "$alert" | grep -qi "$pattern"; then
            echo "HIGH"
            return
        fi
    done
    
    for pattern in "${medium_patterns[@]}"; do
        if echo "$alert" | grep -qi "$pattern"; then
            echo "MEDIUM"
            return
        fi
    done
    
    echo "LOW"
}

# Function to get color based on severity
get_color() {
    local severity="$1"
    case "$severity" in
        "CRITICAL") echo "15158332" ;;  # Red
        "HIGH") echo "16776960" ;;      # Orange
        "MEDIUM") echo "16776960" ;;    # Yellow
        "LOW") echo "65280" ;;          # Green
        "INFO") echo "3447003" ;;       # Blue
        *) echo "9807270" ;;            # Gray
    esac
}

# Function to format SNORT alert
format_snort_alert() {
    local alert_line="$1"
    local timestamp_raw=$(echo "$alert_line" | grep -o '\[.*\]' | head -1 | sed 's/\[//;s/\]//')
    local rule_msg=$(echo "$alert_line" | grep -o '\*\*.*\*\*' | sed 's/\*\*//g' | sed 's/\[.*\]//' | xargs)
    local priority=$(echo "$alert_line" | grep -o 'Priority: [0-9]*' | cut -d' ' -f2)
    local classification=$(echo "$alert_line" | grep -o 'Classification: [^]]*' | cut -d' ' -f2-)
    local src_ip=$(echo "$alert_line" | grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | head -1)
    local dst_ip=$(echo "$alert_line" | grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | tail -1)
    local src_port=$(echo "$alert_line" | grep -oE ':([0-9]+)' | head -1 | sed 's/://')
    local dst_port=$(echo "$alert_line" | grep -oE ':([0-9]+)' | tail -1 | sed 's/://')
    local protocol=$(echo "$alert_line" | grep -oE '\{[^}]*\}' | sed 's/[{}]//g')

    local severity=$(get_severity "$rule_msg")
    local color=$(get_color "$severity")

    local title="🚨 SNORT ALERT"
    local description="**$(escape_json "${rule_msg:-Unknown Alert}")**"

    local fields=""
    fields+="{\"name\": \"🖥️ Server\", \"value\": \"$(escape_json "$HOSTNAME")\", \"inline\": true},"
    fields+="{\"name\": \"📍 Server IP\", \"value\": \"$(escape_json "$SERVER_IP")\", \"inline\": true},"
    fields+="{\"name\": \"⚠️ Severity\", \"value\": \"$(escape_json "$severity")\", \"inline\": true},"
    fields+="{\"name\": \"🔍 Source IP\", \"value\": \"$(escape_json \"${src_ip:-N/A}\")\", \"inline\": true},"
    fields+="{\"name\": \"🎯 Target IP\", \"value\": \"$(escape_json \"${dst_ip:-N/A}\")\", \"inline\": true},"
    fields+="{\"name\": \"🌐 Protocol\", \"value\": \"$(escape_json \"${protocol:-N/A}\")\", \"inline\": true},"

    if [ -n "$src_port" ]; then
        fields+="{\"name\": \"📤 Source Port\", \"value\": \"$(escape_json "$src_port")\", \"inline\": true},"
    fi
    if [ -n "$dst_port" ]; then
        fields+="{\"name\": \"📥 Target Port\", \"value\": \"$(escape_json "$dst_port")\", \"inline\": true},"
    fi
    if [ -n "$priority" ]; then
        fields+="{\"name\": \"🔢 Priority\", \"value\": \"$(escape_json "$priority")\", \"inline\": true},"
    fi
    if [ -n "$classification" ]; then
        fields+="{\"name\": \"📂 Classification\", \"value\": \"$(escape_json "$classification")\", \"inline\": false},"
    fi

    fields+="{\"name\": \"⏰ Detection Time\", \"value\": \"$(escape_json \"${timestamp_raw:-$(date)}\")\", \"inline\": false}"

    # Convert timestamp_raw to ISO 8601 if possible, else fallback
    local iso_timestamp=""
    if [[ "$timestamp_raw" =~ ^[0-9]{2}/[0-9]{2}-[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}$ ]]; then
        # Format: MM/DD-HH:MM:SS.UUUUUU (Snort default)
        local year=$(date +%Y)
        local month=$(echo "$timestamp_raw" | cut -d'/' -f1)
        local day_hour=$(echo "$timestamp_raw" | cut -d'/' -f2)
        local day=$(echo "$day_hour" | cut -d'-' -f1)
        local time_usec=$(echo "$day_hour" | cut -d'-' -f2)
        local time=$(echo "$time_usec" | cut -d'.' -f1)
        local usec=$(echo "$time_usec" | cut -d'.' -f2)
        iso_timestamp=$(printf "%04d-%02d-%02dT%s.%sZ" "$year" "$month" "$day" "$time" "$usec")
    fi
    if [ -z "$iso_timestamp" ]; then
        iso_timestamp=$(date -u +"%Y-%m-%dT%H:%M:%S.000Z")
    fi

    send_discord_embed "$title" "$description" "$color" "$fields" "$iso_timestamp"
}

# Function to send system notification
send_system_notification() {
    local status="$1"
    local message="$2"
    local current_time=$(date '+%I:%M %p WITA - %A, %B %d, %Y')
    
    local color
    local title
    case "$status" in
        "started") 
            color=$(get_color "INFO")
            title="🟢 SNORT LOG MONITOR STARTED"
            ;;
        "stopped") 
            color="15158332"  # Red
            title="🔴 SNORT LOG MONITOR STOPPED"
            ;;
        "test")
            color=$(get_color "INFO")
            title="🧪 TEST ALERT"
            ;;
    esac
    
    local fields=""
    fields+="{\"name\": \"🖥️ Server\", \"value\": \"$(escape_json "$HOSTNAME")\", \"inline\": true},"
    fields+="{\"name\": \"📍 IP Address\", \"value\": \"$(escape_json "$SERVER_IP")\", \"inline\": true},"
    fields+="{\"name\": \"📊 Status\", \"value\": \"$(escape_json "${status^^}")\", \"inline\": true},"
    
    if [ "$status" = "started" ]; then
        fields+="{\"name\": \"📂 Monitoring Files\", \"value\": \"• Snort Alert: \`$SNORT_LOG\`\", \"inline\": false},"
        fields+="{\"name\": \"⚙️ Configuration\", \"value\": \"• Rate Limit: ${RATE_LIMIT}s\\n• Check Interval: 15s\", \"inline\": false},"
    fi
    
    if [ -n "$message" ]; then
        fields+="{\"name\": \"💬 Message\", \"value\": \"$(escape_json "$message")\", \"inline\": false},"
    fi
    
    fields+="{\"name\": \"⏰ Time\", \"value\": \"$(escape_json "$current_time")\", \"inline\": false}"
    
    send_discord_embed "$title" "$(escape_json "$message")" "$color" "$fields"
}

# Function to initialize log position
initialize_log_position() {
    local log_file="$1"
    local temp_file="$2"
    
    if [ -f "$log_file" ]; then
        local current_lines=$(wc -l < "$log_file")
        echo "$current_lines" > "$temp_file"
        echo "Initialized $log_file position at line $current_lines (current end)"
    else
        echo "0" > "$temp_file"
        echo "Log file $log_file not found, initialized position at 0"
    fi
}

# Function to check if script is already running
check_lock() {
    if [ -f "$LOCK_FILE" ]; then
        local pid=$(cat "$LOCK_FILE")
        if ps -p "$pid" > /dev/null 2>&1; then
            echo "Script is already running with PID $pid"
            exit 1
        else
            rm -f "$LOCK_FILE"
        fi
    fi
    echo $$ > "$LOCK_FILE"
}

# Function to cleanup on exit
cleanup() {
    send_system_notification "stopped" "Snort log monitoring service has been stopped"
    rm -f "$LOCK_FILE"
    exit 0
}

# Function to clean old alert history entries
cleanup_history() {
    local current_time=$(date +%s)
    local cutoff_time=$((current_time - RATE_LIMIT))
    
    if [ -f "$ALERT_HISTORY" ]; then
        awk -F: -v cutoff="$cutoff_time" '$2 > cutoff' "$ALERT_HISTORY" > "${ALERT_HISTORY}.tmp"
        mv "${ALERT_HISTORY}.tmp" "$ALERT_HISTORY"
    fi
}

# Set trap for cleanup
trap cleanup INT TERM EXIT

# Check if already running
check_lock

# Initialize log positions
echo "Initializing log positions to current end..."
initialize_log_position "$SNORT_LOG" "$SNORT_TEMP"

# Send startup notification
send_system_notification "started" "Snort IDS monitoring system is now active"

echo "Starting Snort log monitoring..."
echo "Monitoring:"
echo "- Snort Alert: $SNORT_LOG ($([ -f "$SNORT_LOG" ] && echo "EXISTS" || echo "NOT FOUND"))"
echo "Press Ctrl+C to stop monitoring"
echo "============================================"

# Main monitoring loop
alert_count=0
skipped_count=0
last_skip_message_time=$(date +%s)
skip_message_interval=300  # Show skip message every 5 minutes max

while true; do
    current_time=$(date +%s)
    
    if [ -f "$SNORT_LOG" ]; then
        current_lines=$(wc -l < "$SNORT_LOG")
        last_lines=$(cat "$SNORT_TEMP" 2>/dev/null || echo "0")
        
        if [ "$current_lines" -gt "$last_lines" ]; then
            new_entries=$((current_lines - last_lines))
            echo "$(date): Found $new_entries new entries in $SNORT_LOG"
            
            temp_new_file="${TEMP_DIR}/snort_new_entries"
            tail -n "$new_entries" "$SNORT_LOG" > "$temp_new_file"
            
            # Clean up old hashes
            if [ -f "$DEDUP_FILE" ]; then
                awk -F: -v now="$current_time" -v window="$DEDUP_WINDOW" '{if (now-$2 < window) print $0}' "$DEDUP_FILE" > "${DEDUP_FILE}.tmp"
                mv "${DEDUP_FILE}.tmp" "$DEDUP_FILE"
            fi
            touch "$DEDUP_FILE"
            
            while IFS= read -r line; do
                if [ -n "$line" ] && [[ "$line" == *"[**]"* ]]; then
                    timestamp_raw=$(echo "$line" | grep -o '\[.*\]' | head -1 | sed 's/\[//;s/\]//')
                    rule_msg=$(echo "$line" | grep -o '\*\*.*\*\*' | sed 's/\*\*//g' | sed 's/\[.*\]//' | xargs)
                    src_ip=$(echo "$line" | grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | head -1)
                    hash_key=$(echo "${rule_msg}_${src_ip}_${timestamp_raw}" | md5sum | cut -d' ' -f1)
                    # Check deduplication file
                    if ! grep -q "^$hash_key:" "$DEDUP_FILE"; then
                        echo "$hash_key:$current_time" >> "$DEDUP_FILE"
                        echo "Processing new Snort entry: ${line:0:80}..."
                        format_snort_alert "$line"
                        alert_sent=$?
                        if [ $alert_sent -eq 0 ]; then
                            echo "✓ Enhanced Snort alert sent to Discord"
                            alert_count=$((alert_count + 1))
                        else
                            echo "✗ Failed to send Snort alert"
                        fi
                    else
                        echo "Duplicate alert in dedup window, skipping."
                    fi
                fi
            done < "$temp_new_file"
            
            rm -f "$temp_new_file"
            echo "$current_lines" > "$SNORT_TEMP"
        elif [ "$current_lines" -lt "$last_lines" ]; then
            echo "$current_lines" > "$SNORT_TEMP"
        fi
    else
        echo "$(date): Snort log file not found: $SNORT_LOG"
    fi
    sleep 1
done
