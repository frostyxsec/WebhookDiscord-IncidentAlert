#!/bin/bash

# ===========================================
# ENHANCED SNORT LOG MONITORING SCRIPT v2.0
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
RATE_LIMIT=60    # Rate limiting for similar alerts
HOSTNAME=$(hostname)
SERVER_IP=$(ip route get 8.8.8.8 2>/dev/null | awk '/src/ {print $7}' || echo "Unknown")

# Create temp directory if it doesn't exist
mkdir -p "$TEMP_DIR"

# Function to get geolocation info from IP
get_ip_info() {
    local ip="$1"
    local info=""
    
    # Skip private/local IPs
    if [[ "$ip" =~ ^(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.|127\.|169\.254\.) ]]; then
        echo "Private/Local IP"
        return
    fi
    
    # Get info from ip-api.com with timeout
    local api_response=$(curl -s --connect-timeout 5 --max-time 10 "http://ip-api.com/json/${ip}?fields=status,message,country,countryCode,region,regionName,city,isp,org,as,query" 2>/dev/null)
    
    if [ $? -eq 0 ] && [ -n "$api_response" ]; then
        local status=$(echo "$api_response" | grep -o '"status":"[^"]*"' | cut -d'"' -f4)
        if [ "$status" = "success" ]; then
            local country=$(echo "$api_response" | grep -o '"country":"[^"]*"' | cut -d'"' -f4)
            local region=$(echo "$api_response" | grep -o '"regionName":"[^"]*"' | cut -d'"' -f4)
            local city=$(echo "$api_response" | grep -o '"city":"[^"]*"' | cut -d'"' -f4)
            local isp=$(echo "$api_response" | grep -o '"isp":"[^"]*"' | cut -d'"' -f4)
            local org=$(echo "$api_response" | grep -o '"org":"[^"]*"' | cut -d'"' -f4)
            
            info="${city:-Unknown}, ${region:-Unknown}, ${country:-Unknown}"
            if [ -n "$isp" ] && [ "$isp" != "null" ]; then
                info="${info} (${isp})"
            fi
        else
            info="Location lookup failed"
        fi
    else
        info="Location lookup timeout"
    fi
    
    echo "$info"
}

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

    # Escape JSON special characters and remove invalid characters
    title=$(echo "$title" | sed 's/\\/\\\\/g; s/"/\\"/g; s/\x0//g')
    description=$(echo "$description" | sed 's/\\/\\\\/g; s/"/\\"/g; s/\x0//g')

    # Validate fields JSON structure
    if [ -n "$fields" ]; then
        # Remove trailing comma if exists
        fields=$(echo "$fields" | sed 's/,$//g')
        # Validate that we have at least one field
        if [[ ! "$fields" =~ ^\{.*\}$ ]]; then
            fields="{\"name\": \"Error\", \"value\": \"Invalid field data\", \"inline\": true}"
        fi
    else
        fields="{\"name\": \"Alert\", \"value\": \"No additional data\", \"inline\": true}"
    fi
    local payload=$(cat <<EOF
{
    "embeds": [
        {
            "title": "$title",
            "description": "$description",
            "color": $color,
            "fields": [$fields],
            "footer": {
                "text": "$HOSTNAME - Enhanced Snort IDS Monitor",
                "icon_url": "https://cdn.discordapp.com/emojis/848218724264230912.png"
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
            -H "User-Agent: SnortMonitor/2.0" \
            --data-raw "$payload")
        
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

# Function to escape JSON strings safely
escape_json() {
    local input="$1"
    # Remove null bytes and other problematic characters
    input=$(echo "$input" | tr -d '\000-\010\013\014\016-\037')
    # Escape JSON special characters
    echo "$input" | sed 's/\\/\\\\/g; s/"/\\"/g; s/\n/\\n/g; s/\r/\\r/g; s/\t/\\t/g'
}

# Function to get severity level based on rule message and classification
get_severity() {
    local alert="$1"
    local priority="$2"
    
    # Check priority first (Snort priority: 1=high, 2=medium, 3=low, etc.)
    if [ -n "$priority" ]; then
        case "$priority" in
            "1") echo "CRITICAL"; return ;;
            "2") echo "HIGH"; return ;;
            "3") echo "MEDIUM"; return ;;
        esac
    fi
    
    # Keyword-based severity detection
    critical_patterns=(
        "backdoor" "malware" "trojan" "exploit" "intrusion" "brute.?force"
        "shellcode" "metasploit" "vulnerability" "compromise" "privilege.escalation"
    )
    high_patterns=(
        "attack" "injection" "xss" "overflow" "scan" "probe" "suspicious"
        "policy.violation" "attempted" "denial.of.service" "ddos"
    )
    medium_patterns=(
        "connection.attempt" "access" "login" "authentication" "protocol.violation"
    )
    
    local alert_lower=$(echo "$alert" | tr '[:upper:]' '[:lower:]')
    
    for pattern in "${critical_patterns[@]}"; do
        if echo "$alert_lower" | grep -qE "$pattern"; then
            echo "CRITICAL"
            return
        fi
    done
    
    for pattern in "${high_patterns[@]}"; do
        if echo "$alert_lower" | grep -qE "$pattern"; then
            echo "HIGH"
            return
        fi
    done
    
    for pattern in "${medium_patterns[@]}"; do
        if echo "$alert_lower" | grep -qE "$pattern"; then
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
        "MEDIUM") echo "16765440" ;;    # Yellow
        "LOW") echo "65280" ;;          # Green
        "INFO") echo "3447003" ;;       # Blue
        *) echo "9807270" ;;            # Gray
    esac
}

# Enhanced function to parse Snort alert with better accuracy
parse_snort_alert() {
    local alert_block="$1"
    
    # Initialize variables
    local timestamp="" rule_msg="" priority="" classification="" 
    local src_ip="" dst_ip="" src_port="" dst_port="" protocol=""
    local rule_id="" rule_rev=""
    
    echo "DEBUG: Parsing alert block:" >&2
    echo "$alert_block" >&2
    echo "---" >&2
    
    # Parse timestamp from the connection line (format: MM/DD-HH:MM:SS.UUUUUU)
    timestamp=$(echo "$alert_block" | grep -oE '[0-9]{2}/[0-9]{2}-[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}' | head -1)
    
    # Parse rule message (between [**] markers)
    rule_msg=$(echo "$alert_block" | grep -oE '\[\*\*\] \[.*\] .* \[\*\*\]' | sed 's/\[\*\*\] \[[^]]*\] //; s/ \[\*\*\]//')
    
    # Parse rule ID and revision
    local rule_info=$(echo "$alert_block" | grep -oE '\[1:[0-9]+:[0-9]+\]')
    if [ -n "$rule_info" ]; then
        rule_id=$(echo "$rule_info" | sed 's/\[1://; s/:[0-9]*\]//')
        rule_rev=$(echo "$rule_info" | sed 's/\[1:[0-9]*://; s/\]//')
    fi
    
    # Parse priority
    priority=$(echo "$alert_block" | grep -oE '\[Priority: [0-9]+\]' | grep -oE '[0-9]+')
    
    # Parse classification
    classification=$(echo "$alert_block" | grep -oE '\[Classification: [^]]*\]' | sed 's/\[Classification: //; s/\]//')
    
    # Enhanced IP parsing - try multiple methods
    # Method 1: Standard format IP:PORT -> IP:PORT
    local connection_line=$(echo "$alert_block" | grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}:[0-9]+ -> [0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}:[0-9]+')
    
    if [ -n "$connection_line" ]; then
        src_ip=$(echo "$connection_line" | cut -d' ' -f1 | cut -d':' -f1)
        src_port=$(echo "$connection_line" | cut -d' ' -f1 | cut -d':' -f2)
        dst_ip=$(echo "$connection_line" | cut -d' ' -f3 | cut -d':' -f1)
        dst_port=$(echo "$connection_line" | cut -d' ' -f3 | cut -d':' -f2)
    else
        # Method 2: Look for IP addresses in the entire block
        local all_ips=($(echo "$alert_block" | grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | sort -u))
        if [ ${#all_ips[@]} -ge 2 ]; then
            # Usually first IP is source, second is destination
            src_ip="${all_ips[0]}"
            dst_ip="${all_ips[1]}"
        elif [ ${#all_ips[@]} -eq 1 ]; then
            # If only one IP found, check if it's our server IP
            if [ "${all_ips[0]}" = "$SERVER_IP" ]; then
                dst_ip="${all_ips[0]}"
            else
                src_ip="${all_ips[0]}"
            fi
        fi
        
        # Try to find ports separately
        local all_ports=($(echo "$alert_block" | grep -oE ':[0-9]+' | sed 's/://' | sort -u))
        if [ ${#all_ports[@]} -ge 2 ]; then
            src_port="${all_ports[0]}"
            dst_port="${all_ports[1]}"
        elif [ ${#all_ports[@]} -eq 1 ]; then
            dst_port="${all_ports[0]}"
        fi
    fi
    
    # Parse protocol from the connection line or packet details
    if echo "$alert_block" | grep -qi "TCP"; then
        protocol="TCP"
    elif echo "$alert_block" | grep -qi "UDP"; then
        protocol="UDP"
    elif echo "$alert_block" | grep -qi "ICMP"; then
        protocol="ICMP"
    fi
    
    echo "DEBUG: Parsed values:" >&2
    echo "  timestamp: $timestamp" >&2
    echo "  rule_msg: $rule_msg" >&2
    echo "  src_ip: $src_ip" >&2
    echo "  dst_ip: $dst_ip" >&2
    echo "  src_port: $src_port" >&2
    echo "  dst_port: $dst_port" >&2
    echo "  protocol: $protocol" >&2
    
    # Output parsed data as JSON-like format for easy processing
    cat <<EOF
timestamp|$timestamp
rule_msg|$rule_msg
rule_id|$rule_id
rule_rev|$rule_rev
priority|$priority
classification|$classification
src_ip|$src_ip
dst_ip|$dst_ip
src_port|$src_port
dst_port|$dst_port
protocol|$protocol
EOF
}

# Function to format and send enhanced SNORT alert
format_snort_alert() {
    local alert_block="$1"
    
    # Parse the alert using enhanced parser
    local parsed_data=$(parse_snort_alert "$alert_block")
    
    # Extract parsed values
    local timestamp_raw=$(echo "$parsed_data" | grep "^timestamp|" | cut -d'|' -f2)
    local rule_msg=$(echo "$parsed_data" | grep "^rule_msg|" | cut -d'|' -f2)
    local rule_id=$(echo "$parsed_data" | grep "^rule_id|" | cut -d'|' -f2)
    local rule_rev=$(echo "$parsed_data" | grep "^rule_rev|" | cut -d'|' -f2)
    local priority=$(echo "$parsed_data" | grep "^priority|" | cut -d'|' -f2)
    local classification=$(echo "$parsed_data" | grep "^classification|" | cut -d'|' -f2)
    local src_ip=$(echo "$parsed_data" | grep "^src_ip|" | cut -d'|' -f2)
    local dst_ip=$(echo "$parsed_data" | grep "^dst_ip|" | cut -d'|' -f2)
    local src_port=$(echo "$parsed_data" | grep "^src_port|" | cut -d'|' -f2)
    local dst_port=$(echo "$parsed_data" | grep "^dst_port|" | cut -d'|' -f2)
    local protocol=$(echo "$parsed_data" | grep "^protocol|" | cut -d'|' -f2)
    
    # Get geolocation info for source IP
    local src_location="N/A"
    if [ -n "$src_ip" ] && [ "$src_ip" != "$SERVER_IP" ]; then
        echo "DEBUG: Getting geolocation for source IP: $src_ip" >&2
        src_location=$(get_ip_info "$src_ip")
    fi
    
    # Determine severity
    local severity=$(get_severity "$rule_msg $classification" "$priority")
    local color=$(get_color "$severity")
    
    # Create enhanced title and description
    local title="🚨 SNORT IDS ALERT"
    local description="**$(escape_json "${rule_msg:-Unknown Alert}")**"
    
    # Build enhanced fields
    local fields=""
    fields+="{\"name\": \"🖥️ Server\", \"value\": \"$(escape_json "$HOSTNAME")\", \"inline\": true},"
    fields+="{\"name\": \"📍 Server IP\", \"value\": \"$(escape_json "$SERVER_IP")\", \"inline\": true},"
    fields+="{\"name\": \"⚠️ Severity\", \"value\": \"$(escape_json "$severity")\", \"inline\": true},"
    
    # Source information with better handling
    if [ -n "$src_ip" ] && [ "$src_ip" != "N/A" ] && [ "$src_ip" != "" ]; then
        fields+="{\"name\": \"🔍 Source IP\", \"value\": \"$(escape_json "$src_ip")\", \"inline\": true},"
        if [ "$src_location" != "N/A" ] && [ "$src_location" != "" ]; then
            fields+="{\"name\": \"🌍 Source Location\", \"value\": \"$(escape_json "$src_location")\", \"inline\": true},"
        fi
        if [ -n "$src_port" ] && [ "$src_port" != "" ]; then
            fields+="{\"name\": \"📤 Source Port\", \"value\": \"$(escape_json "$src_port")\", \"inline\": true},"
        fi
    else
        fields+="{\"name\": \"🔍 Source IP\", \"value\": \"Not detected in alert\", \"inline\": true},"
    fi
    
    # Destination information with better handling
    if [ -n "$dst_ip" ] && [ "$dst_ip" != "N/A" ] && [ "$dst_ip" != "" ]; then
        fields+="{\"name\": \"🎯 Target IP\", \"value\": \"$(escape_json "$dst_ip")\", \"inline\": true},"
        if [ -n "$dst_port" ] && [ "$dst_port" != "" ]; then
            fields+="{\"name\": \"📥 Target Port\", \"value\": \"$(escape_json "$dst_port")\", \"inline\": true},"
        fi
    else
        fields+="{\"name\": \"🎯 Target IP\", \"value\": \"Not detected in alert\", \"inline\": true},"
    fi
    
    # Protocol information
    if [ -n "$protocol" ] && [ "$protocol" != "" ]; then
        fields+="{\"name\": \"🌐 Protocol\", \"value\": \"$(escape_json "$protocol")\", \"inline\": true},"
    fi
    
    # Rule information
    if [ -n "$rule_id" ]; then
        local rule_info="SID: $rule_id"
        if [ -n "$rule_rev" ]; then
            rule_info="$rule_info, Rev: $rule_rev"
        fi
        fields+="{\"name\": \"📋 Rule Info\", \"value\": \"$(escape_json "$rule_info")\", \"inline\": true},"
    fi
    
    if [ -n "$priority" ]; then
        fields+="{\"name\": \"🔢 Priority\", \"value\": \"$(escape_json "$priority")\", \"inline\": true},"
    fi
    
    if [ -n "$classification" ]; then
        fields+="{\"name\": \"📂 Classification\", \"value\": \"$(escape_json "$classification")\", \"inline\": false},"
    fi
    
    # Timestamp
    local display_time="${timestamp_raw:-$(date '+%m/%d-%H:%M:%S')}"
    fields+="{\"name\": \"⏰ Detection Time\", \"value\": \"$(escape_json "$display_time")\", \"inline\": false}"
    
    # Convert timestamp to ISO format for Discord
    local iso_timestamp=""
    if [[ "$timestamp_raw" =~ ^[0-9]{2}/[0-9]{2}-[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}$ ]]; then
        local year=$(date +%Y)
        local month=$(echo "$timestamp_raw" | cut -d'/' -f1)
        local day_time=$(echo "$timestamp_raw" | cut -d'/' -f2)
        local day=$(echo "$day_time" | cut -d'-' -f1)
        local time_part=$(echo "$day_time" | cut -d'-' -f2)
        local time=$(echo "$time_part" | cut -d'.' -f1)
        local microsec=$(echo "$time_part" | cut -d'.' -f2)
        local millisec=${microsec:0:3}
        
        # Remove leading zeros to avoid octal interpretation
        month=$(printf "%d" "$month" 2>/dev/null || echo "1")
        day=$(printf "%d" "$day" 2>/dev/null || echo "1")
        
        # Validate values
        if [ "$month" -lt 1 ] || [ "$month" -gt 12 ]; then month=1; fi
        if [ "$day" -lt 1 ] || [ "$day" -gt 31 ]; then day=1; fi
        
        iso_timestamp=$(printf "%04d-%02d-%02dT%s.%sZ" "$year" "$month" "$day" "$time" "$millisec")
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
            title="🟢 ENHANCED SNORT MONITOR STARTED"
            ;;
        "stopped") 
            color="15158332"  # Red
            title="🔴 SNORT MONITOR STOPPED"
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
        fields+="{\"name\": \"⚙️ Configuration\", \"value\": \"• Dedup Window: ${DEDUP_WINDOW}s\\n• Rate Limit: ${RATE_LIMIT}s\\n• Check Interval: 1s\\n• Geolocation: Enabled\", \"inline\": false},"
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
    send_system_notification "stopped" "Enhanced Snort log monitoring service has been stopped"
    rm -f "$LOCK_FILE"
    exit 0
}

# Function to read multi-line Snort alert blocks
read_alert_blocks() {
    local temp_file="$1"
    local alert_blocks=()
    local current_block=""
    local in_alert=false
    
    while IFS= read -r line; do
        if [[ "$line" == *"[**]"* ]]; then
            # If we were already in an alert, save the previous block
            if [ "$in_alert" = true ] && [ -n "$current_block" ]; then
                alert_blocks+=("$current_block")
            fi
            # Start new alert block
            current_block="$line"
            in_alert=true
        elif [ "$in_alert" = true ]; then
            # Continue building current block
            if [ -n "$line" ]; then
                current_block="$current_block"$'\n'"$line"
            else
                # Empty line might indicate end of alert block
                if [ -n "$current_block" ]; then
                    alert_blocks+=("$current_block")
                    current_block=""
                    in_alert=false
                fi
            fi
        fi
    done < "$temp_file"
    
    # Don't forget the last block if file doesn't end with empty line
    if [ "$in_alert" = true ] && [ -n "$current_block" ]; then
        alert_blocks+=("$current_block")
    fi
    
    # Print all alert blocks
    for block in "${alert_blocks[@]}"; do
        echo "---ALERT_BLOCK_START---"
        echo "$block"
        echo "---ALERT_BLOCK_END---"
    done
}

# Set trap for cleanup
trap cleanup INT TERM EXIT

# Check if already running
check_lock

# Initialize log positions
echo "Initializing enhanced Snort log monitoring..."
initialize_log_position "$SNORT_LOG" "$SNORT_TEMP"

# Send startup notification
send_system_notification "started" "Enhanced Snort IDS monitoring system is now active with geolocation support"

echo "Starting Enhanced Snort Log Monitoring v2.0..."
echo "Features:"
echo "- Enhanced parsing with better IP/Port detection"
echo "- Geolocation lookup via ip-api.com"
echo "- Improved severity classification"
echo "- Multi-line alert block processing"
echo "- Better deduplication"
echo ""
echo "Monitoring: $SNORT_LOG ($([ -f "$SNORT_LOG" ] && echo "EXISTS" || echo "NOT FOUND"))"
echo "Press Ctrl+C to stop monitoring"
echo "============================================"

# Main monitoring loop
alert_count=0
last_processed_time=0

while true; do
    current_time=$(date +%s)
    
    if [ -f "$SNORT_LOG" ]; then
        current_lines=$(wc -l < "$SNORT_LOG")
        last_lines=$(cat "$SNORT_TEMP" 2>/dev/null || echo "0")
        
        if [ "$current_lines" -gt "$last_lines" ]; then
            new_entries=$((current_lines - last_lines))
            echo "$(date): Found $new_entries new entries in Snort log"
            
            temp_new_file="${TEMP_DIR}/snort_new_entries"
            tail -n "$new_entries" "$SNORT_LOG" > "$temp_new_file"
            
            # Clean up old hashes (deduplication)
            if [ -f "$DEDUP_FILE" ]; then
                awk -F: -v now="$current_time" -v window="$DEDUP_WINDOW" '{if (now-$2 < window) print $0}' "$DEDUP_FILE" > "${DEDUP_FILE}.tmp"
                mv "${DEDUP_FILE}.tmp" "$DEDUP_FILE"
            fi
            touch "$DEDUP_FILE"
            
            # Process alert blocks
            read_alert_blocks "$temp_new_file" | while IFS= read -r line; do
                if [ "$line" = "---ALERT_BLOCK_START---" ]; then
                    alert_block=""
                    continue
                elif [ "$line" = "---ALERT_BLOCK_END---" ]; then
                    if [ -n "$alert_block" ]; then
                        # Generate hash for deduplication
                        hash_key=$(echo "$alert_block" | md5sum | cut -d' ' -f1)
                        
                        if ! grep -q "^$hash_key:" "$DEDUP_FILE"; then
                            echo "$hash_key:$current_time" >> "$DEDUP_FILE"
                            echo "Processing new Snort alert block..."
                            format_snort_alert "$alert_block"
                            alert_sent=$?
                            if [ $alert_sent -eq 0 ]; then
                                echo "✅ Enhanced Snort alert sent to Discord"
                                alert_count=$((alert_count + 1))
                            else
                                echo "❌ Failed to send Snort alert"
                            fi
                            sleep 2  # Rate limiting between alerts
                        else
                            echo "🔄 Duplicate alert detected, skipping..."
                        fi
                    fi
                else
                    alert_block="$alert_block"$'\n'"$line"
                fi
            done
            
            rm -f "$temp_new_file"
            echo "$current_lines" > "$SNORT_TEMP"
        elif [ "$current_lines" -lt "$last_lines" ]; then
            # Log file was rotated/truncated
            echo "$(date): Log file appears to have been rotated, resetting position"
            echo "$current_lines" > "$SNORT_TEMP"
        fi
    else
        echo "$(date): Snort log file not found: $SNORT_LOG"
    fi
    
    sleep 1
done
