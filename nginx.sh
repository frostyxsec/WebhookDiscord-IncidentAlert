#!/bin/bash

# ===========================================
# NGINX LOG MONITORING SCRIPT
# ===========================================

# Discord Webhook Configuration
DISCORD_WEBHOOK=" "

# Log Files Configuration
ACCESS_LOG="/var/log/nginx/access.log"
ERROR_LOG="/var/log/nginx/error.log"
TEMP_DIR="/tmp/nginx_monitor"
ACCESS_TEMP="${TEMP_DIR}/access_last_check"
ERROR_TEMP="${TEMP_DIR}/error_last_check"
LOCK_FILE="${TEMP_DIR}/nginx_monitor.lock"
ALERT_HISTORY="${TEMP_DIR}/nginx_alert_history"
HOSTNAME=$(hostname)
SERVER_IP=$(ip route get 8.8.8.8 2>/dev/null | awk '/src/ {print $7}' || echo "Unknown")

# Rate limiting - minimum interval between same alerts (in seconds)
RATE_LIMIT=300  # 5 minutes

# Create temp directory if it doesn't exist
mkdir -p "$TEMP_DIR"

# Function to send enhanced Discord message with embed
send_discord_embed() {
    local title="$1"
    local description="$2"
    local color="$3"
    local fields="$4"
    local timestamp=$(date -u +"%Y-%m-%dT%H:%M:%S.000Z")
    local max_retries=3
    local retry=0
    
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
                "text": "$HOSTNAME - Nginx Monitor",
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

# Function to get alert hash for deduplication
get_alert_hash() {
    local alert_line="$1"
    local log_type="$2"
    echo "$alert_line" | md5sum | cut -d' ' -f1
}

# Function to check if alert should be sent (rate limiting)
should_send_alert() {
    local alert_hash="$1"
    local current_time=$(date +%s)
    
    touch "$ALERT_HISTORY"
    
    if grep -q "^$alert_hash:" "$ALERT_HISTORY"; then
        local last_sent=$(grep "^$alert_hash:" "$ALERT_HISTORY" | cut -d':' -f2)
        local time_diff=$((current_time - last_sent))
        
        if [ $time_diff -lt $RATE_LIMIT ]; then
            return 1
        fi
    fi
    
    grep -v "^$alert_hash:" "$ALERT_HISTORY" > "${ALERT_HISTORY}.tmp" 2>/dev/null || touch "${ALERT_HISTORY}.tmp"
    echo "$alert_hash:$current_time" >> "${ALERT_HISTORY}.tmp"
    mv "${ALERT_HISTORY}.tmp" "$ALERT_HISTORY"
    
    return 0
}

# Function to get severity level
get_severity() {
    local alert="$1"
    local log_type="$2"
    
    case "$log_type" in
        "error")
            if echo "$alert" | grep -qi "critical\|fatal\|emergency"; then
                echo "CRITICAL"
            elif echo "$alert" | grep -qi "error\|failed\|exception"; then
                echo "HIGH"
            elif echo "$alert" | grep -qi "warning\|warn"; then
                echo "MEDIUM"
            else
                echo "LOW"
            fi
            ;;
        "access")
            local status=$(echo "$alert" | awk '{print $9}')
            local user_agent=$(echo "$alert" | grep -oE '"[^"]*"' | tail -1 | sed 's/"//g')
            local endpoint=$(echo "$alert" | grep -oE '"[^"]*"' | head -1 | sed 's/"//g' | awk '{print $2}')
            
            if echo "$user_agent" | grep -qi "fuzz\|scan\|bot\|crawler\|nikto\|sqlmap\|nmap\|dirb\|gobuster\|wfuzz"; then
                echo "HIGH"
                return
            fi
            
            if echo "$endpoint" | grep -qi "\.sql\|\.dump\|\.bak\|\.old\|admin\|wp-admin\|\.php\|\.asp\|\.jsp"; then
                echo "HIGH"
                return
            fi
            
            case "$status" in
                "404"|"403"|"401") echo "MEDIUM" ;;
                "500"|"502"|"503"|"504") echo "HIGH" ;;
                "200"|"301"|"302") echo "LOW" ;;
                *) echo "MEDIUM" ;;
            esac
            ;;
    esac
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

# Function to format NGINX access alert
format_access_alert() {
    local alert_line="$1"
    local ip=$(echo "$alert_line" | grep -oE '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}')
    local timestamp=$(echo "$alert_line" | grep -oE '\[[^]]*\]' | head -1 | sed 's/\[//;s/\]//')
    local method=$(echo "$alert_line" | grep -oE '"[A-Z]+ [^"]*"' | cut -d' ' -f1 | sed 's/"//g')
    local endpoint=$(echo "$alert_line" | grep -oE '"[^"]*"' | head -1 | sed 's/"//g' | awk '{print $2}')
    local protocol=$(echo "$alert_line" | grep -oE '"[^"]*"' | head -1 | sed 's/"//g' | awk '{print $3}')
    local status=$(echo "$alert_line" | awk '{print $9}')
    local size=$(echo "$alert_line" | awk '{print $10}')
    local user_agent=$(echo "$alert_line" | grep -oE '"[^"]*"' | tail -1 | sed 's/"//g')
    local referer=$(echo "$alert_line" | grep -oE '"[^"]*"' | tail -2 | head -1 | sed 's/"//g')
    
    local severity=$(get_severity "$alert_line" "access")
    local color=$(get_color "$severity")
    
    local title="📡 NGINX ACCESS LOG"
    local description="**HTTP Request Detected**"
    
    local fields=""
    fields+="{\"name\": \"🖥️ Server\", \"value\": \"$(escape_json "$HOSTNAME")\", \"inline\": true},"
    fields+="{\"name\": \"📍 Server IP\", \"value\": \"$(escape_json "$SERVER_IP")\", \"inline\": true},"
    fields+="{\"name\": \"⚠️ Severity\", \"value\": \"$(escape_json "$severity")\", \"inline\": true},"
    fields+="{\"name\": \"🔍 Client IP\", \"value\": \"$(escape_json "${ip:-N/A}")\", \"inline\": true},"
    fields+="{\"name\": \"📊 HTTP Status\", \"value\": \"$(escape_json "${status:-N/A}")\", \"inline\": true},"
    fields+="{\"name\": \"⚡ Method\", \"value\": \"$(escape_json "${method:-N/A}")\", \"inline\": true},"
    fields+="{\"name\": \"🌐 Endpoint\", \"value\": \"$(escape_json "${endpoint:-N/A}")\", \"inline\": false},"
    
    if [ -n "$protocol" ]; then
        fields+="{\"name\": \"🔗 Protocol\", \"value\": \"$(escape_json "$protocol")\", \"inline\": true},"
    fi
    if [ -n "$size" ] && [ "$size" != "-" ]; then
        fields+="{\"name\": \"📦 Response Size\", \"value\": \"$(escape_json "$size") bytes\", \"inline\": true},"
    fi
    if [ -n "$user_agent" ] && [ "$user_agent" != "-" ]; then
        # Truncate long user agent strings
        local ua_display="$user_agent"
        if [ ${#ua_display} -gt 100 ]; then
            ua_display="${ua_display:0:100}..."
        fi
        fields+="{\"name\": \"🖥️ User Agent\", \"value\": \"$(escape_json "$ua_display")\", \"inline\": false},"
    fi
    if [ -n "$referer" ] && [ "$referer" != "-" ]; then
        fields+="{\"name\": \"🔗 Referer\", \"value\": \"$(escape_json "$referer")\", \"inline\": false},"
    fi
    
    fields+="{\"name\": \"⏰ Request Time\", \"value\": \"$(escape_json "${timestamp:-$(date)}")\", \"inline\": false}"
    
    send_discord_embed "$title" "$description" "$color" "$fields"
}

# Function to format NGINX error alert
format_error_alert() {
    local alert_line="$1"
    local timestamp=$(echo "$alert_line" | grep -oE '^[0-9]{4}/[0-9]{2}/[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}')
    local level=$(echo "$alert_line" | grep -oE '\[(emerg|alert|crit|error|warn|notice|info|debug)\]' | sed 's/\[//;s/\]//')
    local pid=$(echo "$alert_line" | grep -oE '#[0-9]+' | sed 's/#//')
    local ip=$(echo "$alert_line" | grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}')
    local error_msg=$(echo "$alert_line" | sed 's/^[^:]*: \*[^:]*: //' | cut -d',' -f1)
    
    local severity=$(get_severity "$alert_line" "error")
    local color=$(get_color "$severity")
    
    local title="🚫 NGINX ERROR LOG"
    local description="**Error Detected in Web Server**"
    
    local fields=""
    fields+="{\"name\": \"🖥️ Server\", \"value\": \"$(escape_json "$HOSTNAME")\", \"inline\": true},"
    fields+="{\"name\": \"📍 Server IP\", \"value\": \"$(escape_json "$SERVER_IP")\", \"inline\": true},"
    fields+="{\"name\": \"⚠️ Severity\", \"value\": \"$(escape_json "$severity")\", \"inline\": true},"
    
    if [ -n "$ip" ]; then
        fields+="{\"name\": \"🔍 Client IP\", \"value\": \"$(escape_json "$ip")\", \"inline\": true},"
    fi
    if [ -n "$level" ]; then
        fields+="{\"name\": \"📊 Error Level\", \"value\": \"$(escape_json "${level^^}")\", \"inline\": true},"
    fi
    if [ -n "$pid" ]; then
        fields+="{\"name\": \"🔢 Process ID\", \"value\": \"$(escape_json "$pid")\", \"inline\": true},"
    fi
    
    fields+="{\"name\": \"💬 Error Message\", \"value\": \"$(escape_json "${error_msg:-Unknown Error}")\", \"inline\": false},"
    fields+="{\"name\": \"⏰ Error Time\", \"value\": \"$(escape_json "${timestamp:-$(date)}")\", \"inline\": false}"
    
    send_discord_embed "$title" "$description" "$color" "$fields"
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
            title="🟢 NGINX LOG MONITOR STARTED"
            ;;
        "stopped") 
            color="15158332"  # Red
            title="🔴 NGINX LOG MONITOR STOPPED"
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
        fields+="{\"name\": \"📂 Monitoring Files\", \"value\": \"• Access Log: \`$ACCESS_LOG\`\\n• Error Log: \`$ERROR_LOG\`\", \"inline\": false},"
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
    send_system_notification "stopped" "Nginx log monitoring service has been stopped"
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
initialize_log_position "$ACCESS_LOG" "$ACCESS_TEMP"
initialize_log_position "$ERROR_LOG" "$ERROR_TEMP"

# Send startup notification
send_system_notification "started" "Nginx log monitoring system is now active"

echo "Starting Nginx log monitoring..."
echo "Monitoring:"
echo "- Access Log: $ACCESS_LOG ($([ -f "$ACCESS_LOG" ] && echo "EXISTS" || echo "NOT FOUND"))"
echo "- Error Log: $ERROR_LOG ($([ -f "$ERROR_LOG" ] && echo "EXISTS" || echo "NOT FOUND"))"
echo "Rate limiting: ${RATE_LIMIT}s between duplicate alerts"
echo "Press Ctrl+C to stop monitoring"
echo "============================================"

# Main monitoring loop
alert_count=0
skipped_count=0
last_skip_message_time=$(date +%s)
skip_message_interval=300  # Show skip message every 5 minutes max

while true; do
    current_time=$(date +%s)
    
    # Process each log file
    for log_config in \
        "access:$ACCESS_LOG:$ACCESS_TEMP" \
        "error:$ERROR_LOG:$ERROR_TEMP"; do
        
        log_type=$(echo "$log_config" | cut -d':' -f1)
        log_file=$(echo "$log_config" | cut -d':' -f2)
        temp_file=$(echo "$log_config" | cut -d':' -f3)
        
        if [ -f "$log_file" ]; then
            current_lines=$(wc -l < "$log_file")
            last_lines=$(cat "$temp_file" 2>/dev/null || echo "0")
            
            if [ "$current_lines" -gt "$last_lines" ]; then
                new_entries=$((current_lines - last_lines))
                echo "$(date): Found $new_entries new ${log_type} entries in $log_file"
                
                # Process only new entries
                temp_new_file="${TEMP_DIR}/nginx_${log_type}_new_entries"
                tail -n "$new_entries" "$log_file" > "$temp_new_file"
                
                while IFS= read -r line; do
                    if [ -n "$line" ]; then
                        alert_hash=$(get_alert_hash "$line" "$log_type")
                        
                        if should_send_alert "$alert_hash"; then
                            echo "Processing new ${log_type} entry: ${line:0:80}..."
                            
                            case "$log_type" in
                                "access")
                                    format_access_alert "$line"
                                    alert_sent=$?
                                    ;;
                                "error")
                                    format_error_alert "$line"
                                    alert_sent=$?
                                    ;;
                            esac
                            
                            if [ $alert_sent -eq 0 ]; then
                                echo "✓ Enhanced ${log_type} alert sent to Discord"
                                alert_count=$((alert_count + 1))
                            else
                                echo "✗ Failed to send ${log_type} alert"
                            fi
                        else
                            skipped_count=$((skipped_count + 1))
                        fi
                    fi
                done < "$temp_new_file"
                
                # Clean up temp file
                rm -f "$temp_new_file"
                
                # Update position file after processing
                echo "$current_lines" > "$temp_file"
            fi
        else
            echo "$(date): ${log_type^} log file not found: $log_file"
        fi
    done
    
    # Show skip message summary periodically
    if [ $skipped_count -gt 0 ] && [ $((current_time - last_skip_message_time)) -ge $skip_message_interval ]; then
        echo "⏭ Skipped $skipped_count duplicate entries (rate limited) in the last $((skip_message_interval / 60)) minutes"
        skipped_count=0
        last_skip_message_time=$current_time
    fi
    
    # Cleanup old history every 100 alerts
    if [ $((alert_count % 100)) -eq 0 ] && [ $alert_count -gt 0 ]; then
        cleanup_history
    fi
    
    sleep 15
done
