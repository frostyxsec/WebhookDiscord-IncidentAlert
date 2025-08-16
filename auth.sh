#!/bin/bash

# ===========================================
# AUTH LOG MONITORING SCRIPT (DEDUPLICATED)
# ===========================================

DISCORD_WEBHOOK=" "
AUTH_LOG="/var/log/auth.log"
TEMP_DIR="/tmp/auth_monitor"
AUTH_TEMP="${TEMP_DIR}/auth_last_check"
LOCK_FILE="${TEMP_DIR}/auth_monitor.lock"
DEDUP_FILE="${TEMP_DIR}/auth_recent_alerts_hashes"
DEDUP_WINDOW=30  # seconds
HOSTNAME=$(hostname)
SERVER_IP=$(ip route get 8.8.8.8 2>/dev/null | awk '/src/ {print $7}' || echo "Unknown")

mkdir -p "$TEMP_DIR"

send_discord_embed() {
    local title="$1"
    local description="$2"
    local color="$3"
    local fields="$4"
    local timestamp=$(date -u +"%Y-%m-%dT%H:%M:%S.000Z")
    local max_retries=3
    local retry=0
    title=$(echo "$title" | sed 's/\\/\\\\/g; s/"/\\"/g')
    description=$(echo "$description" | sed 's/\\/\\\\/g; s/"/\\"/g')
    local payload=$(cat <<EOF
{
    "embeds": [
        {
            "title": "$title",
            "description": "$description",
            "color": $color,
            "fields": [$fields],
            "footer": {
                "text": "$HOSTNAME - Auth Monitor",
                "icon_url": " "
            },
            "timestamp": "$timestamp"
        }
    ]
}
EOF
)
    while [ $retry -lt $max_retries ]; do
        local response=$(curl -s -w "HTTPSTATUS:%{http_code}" -X POST "$DISCORD_WEBHOOK" \
            -H "Content-Type: application/json" \
            -d "$payload")
        local http_code=$(echo "$response" | grep -o "HTTPSTATUS:[0-9]*" | cut -d: -f2)
        local body=$(echo "$response" | sed 's/HTTPSTATUS:[0-9]*$//')
        if [ "$http_code" = "200" ] || [ "$http_code" = "204" ]; then
            return 0
        else
            echo "Discord webhook failed (HTTP $http_code): $body" >&2
            retry=$((retry + 1))
            sleep 2
        fi
    done
    echo "Failed to send discord message after $max_retries attempts" >&2
    return 1
}

escape_json() {
    local input="$1"
    echo "$input" | sed 's/\\/\\\\/g; s/"/\\"/g; s/\n/\\n/g; s/\r/\\r/g; s/\t/\\t/g'
}

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

cleanup() {
    rm -f "$LOCK_FILE"
    exit 0
}

trap cleanup INT TERM EXIT

check_lock

echo "Initializing log positions to current end..."
initialize_log_position "$AUTH_LOG" "$AUTH_TEMP"

echo "Starting Auth log monitoring (deduplicated)..."
echo "Monitoring:"
echo "- Auth Log: $AUTH_LOG ($([ -f "$AUTH_LOG" ] && echo "EXISTS" || echo "NOT FOUND"))"
echo "Deduplication window: ${DEDUP_WINDOW}s"
echo "Press Ctrl+C to stop monitoring"
echo "============================================"

while true; do
    current_time=$(date +%s)
    if [ -f "$AUTH_LOG" ]; then
        current_lines=$(wc -l < "$AUTH_LOG")
        last_lines=$(cat "$AUTH_TEMP" 2>/dev/null || echo "0")
        if [ "$current_lines" -gt "$last_lines" ]; then
            new_entries=$((current_lines - last_lines))
            echo "$(date): Found $new_entries new entries in $AUTH_LOG"
            temp_new_file="${TEMP_DIR}/auth_new_entries"
            tail -n "$new_entries" "$AUTH_LOG" > "$temp_new_file"
            # Clean up old hashes
            if [ -f "$DEDUP_FILE" ]; then
                awk -F: -v now="$current_time" -v window="$DEDUP_WINDOW" '{if (now-$2 < window) print $0}' "$DEDUP_FILE" > "${DEDUP_FILE}.tmp"
                mv "${DEDUP_FILE}.tmp" "$DEDUP_FILE"
            fi
            touch "$DEDUP_FILE"
            while IFS= read -r line; do
                if [ -n "$line" ]; then
                    # Use the whole line as dedup key for auth log
                    dedup_key="$line"
                    hash_key=$(echo "$dedup_key" | md5sum | cut -d' ' -f1)
                    if ! grep -q "^$hash_key:" "$DEDUP_FILE"; then
                        echo "$hash_key:$current_time" >> "$DEDUP_FILE"
                        # Parse fields for better alert formatting
                        # Example: 2025-08-04T01:35:01.231155+00:00 srv918005 CRON[3146595]: pam_unix(cron:session): session opened for user root(uid=0) by root(uid=0)
                        timestamp=$(echo "$line" | awk '{print $1}')
                        host=$(echo "$line" | awk '{print $2}')
                        process=$(echo "$line" | awk '{print $3}' | sed 's/\[.*//')
                        message=$(echo "$line" | cut -d':' -f2- | sed 's/^ //')
                        # Compose alert
                        title="🔐 AUTH LOG: $process"
                        description="**$message**"
                        fields="{\"name\": \"🖥️ Host\", \"value\": \"$(escape_json "$host")\", \"inline\": true},"
                        fields+="{\"name\": \"⏰ Time\", \"value\": \"$(escape_json "$timestamp")\", \"inline\": true}"
                        send_discord_embed "$title" "$description" "3447003" "$fields"
                        alert_sent=$?
                        if [ $alert_sent -eq 0 ]; then
                            echo "✓ Auth alert sent to Discord"
                        else
                            echo "✗ Failed to send Auth alert"
                        fi
                    else
                        echo "Duplicate Auth alert in dedup window, skipping."
                    fi
                fi
            done < "$temp_new_file"
            rm -f "$temp_new_file"
            echo "$current_lines" > "$AUTH_TEMP"
        elif [ "$current_lines" -lt "$last_lines" ]; then
            echo "$current_lines" > "$AUTH_TEMP"
        fi
    else
        echo "$(date): Auth log file not found: $AUTH_LOG"
    fi
    sleep 1
done
