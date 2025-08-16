#!/bin/bash

# Fail2ban Discord Alert Script
# Monitoring /var/log/fail2ban.log untuk semua jenis serangan dan event

# Konfigurasi
WEBHOOK_URL=" "
LOG_FILE="/var/log/fail2ban.log"
POSITION_FILE="/tmp/fail2ban_position.txt"
HOSTNAME=$(hostname)

# Alert level configuration
ALERT_FOUND=true        # Alert untuk "Found" (deteksi serangan)
ALERT_BAN=true          # Alert untuk Ban
ALERT_UNBAN=true        # Alert untuk Unban
ALERT_ALREADY=false     # Alert untuk "already banned" (bisa spam, default off)

# Warna untuk Discord embed
COLOR_BAN="16711680"      # Merah untuk ban
COLOR_UNBAN="65280"       # Hijau untuk unban
COLOR_FOUND="16753920"    # Orange untuk found/attack
COLOR_INFO="3447003"      # Biru untuk info
COLOR_ALREADY="8421504"   # Abu-abu untuk already banned

# Fungsi untuk menangani Ctrl+C
cleanup() {
    echo -e "\n[$(date '+%Y-%m-%d %H:%M:%S')] Script dihentikan oleh user"
    exit 0
}

# Setup trap untuk Ctrl+C
trap cleanup SIGINT SIGTERM

# Fungsi untuk mendapatkan posisi terakhir file
get_last_position() {
    if [ -f "$POSITION_FILE" ]; then
        cat "$POSITION_FILE"
    else
        echo "0"
    fi
}

# Fungsi untuk menyimpan posisi terakhir file
save_position() {
    echo "$1" > "$POSITION_FILE"
}

# Fungsi untuk mendapatkan informasi IP (negara, ISP, dll)
get_ip_info() {
    local ip="$1"
    local info=$(timeout 10 curl -s "http://ip-api.com/json/$ip" 2>/dev/null)
    if [ $? -eq 0 ] && [ -n "$info" ]; then
        echo "$info"
    else
        echo '{"country":"Unknown","isp":"Unknown","city":"Unknown","region":"Unknown"}'
    fi
}

# Fungsi untuk mengirim alert ke Discord
send_discord_alert() {
    local event_type="$1"
    local jail="$2"
    local ip="$3"
    local timestamp="$4"
    local log_line="$5"
    local additional_info="$6"
    
    # Tentukan warna, emoji, dan title berdasarkan event type
    local color=""
    local emoji=""
    local title=""
    
    case "$event_type" in
        "Ban")
            color="$COLOR_BAN"
            emoji="🚫"
            title="IP Banned"
            ;;
        "Unban")
            color="$COLOR_UNBAN"
            emoji="✅"
            title="IP Unbanned"
            ;;
        "Found")
            color="$COLOR_FOUND"
            emoji="⚠️"
            title="Attack Detected"
            ;;
        "Already")
            color="$COLOR_ALREADY"
            emoji="🔄"
            title="Already Banned"
            ;;
        *)
            color="$COLOR_INFO"
            emoji="ℹ️"
            title="Fail2ban Event"
            ;;
    esac
    
    # Dapatkan info IP hanya untuk IP valid
    local country="Unknown"
    local isp="Unknown" 
    local city="Unknown"
    local region="Unknown"
    
    if [[ "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        echo "Mengambil informasi IP $ip..."
        local ip_info=$(get_ip_info "$ip")
        country=$(echo "$ip_info" | grep -o '"country":"[^"]*"' | cut -d'"' -f4)
        isp=$(echo "$ip_info" | grep -o '"isp":"[^"]*"' | cut -d'"' -f4)
        city=$(echo "$ip_info" | grep -o '"city":"[^"]*"' | cut -d'"' -f4)
        region=$(echo "$ip_info" | grep -o '"region":"[^"]*"' | cut -d'"' -f4)
        
        # Fallback jika parsing gagal
        [ -z "$country" ] && country="Unknown"
        [ -z "$isp" ] && isp="Unknown"
        [ -z "$city" ] && city="Unknown"
        [ -z "$region" ] && region="Unknown"
    fi
    
    # Format timestamp untuk Discord
    local discord_timestamp=$(date -d "$timestamp" -u +"%Y-%m-%dT%H:%M:%S.000Z" 2>/dev/null || date -u +"%Y-%m-%dT%H:%M:%S.000Z")
    
    # Buat fields berdasarkan event type
    local fields=""
    
    if [ "$event_type" = "Found" ]; then
        fields='"fields": [
            {
                "name": "🔒 Jail",
                "value": "`'$jail'`",
                "inline": true
            },
            {
                "name": "🌐 IP Address", 
                "value": "`'$ip'`",
                "inline": true
            },
            {
                "name": "🖥️ Server",
                "value": "`'$HOSTNAME'`",
                "inline": true
            },
            {
                "name": "🌍 Location",
                "value": "'$city', '$region', '$country'",
                "inline": true
            },
            {
                "name": "🏢 ISP",
                "value": "'$isp'",
                "inline": true
            },
            {
                "name": "📊 Attack Info",
                "value": "'$additional_info'",
                "inline": true
            },
            {
                "name": "⏰ Timestamp",
                "value": "'$timestamp'",
                "inline": false
            },
            {
                "name": "📋 Log Entry",
                "value": "```'$log_line'```",
                "inline": false
            }
        ]'
    else
        fields='"fields": [
            {
                "name": "🔒 Jail",
                "value": "`'$jail'`",
                "inline": true
            },
            {
                "name": "🌐 IP Address",
                "value": "`'$ip'`",
                "inline": true
            },
            {
                "name": "🖥️ Server", 
                "value": "`'$HOSTNAME'`",
                "inline": true
            },
            {
                "name": "🌍 Location",
                "value": "'$city', '$region', '$country'",
                "inline": true
            },
            {
                "name": "🏢 ISP",
                "value": "'$isp'",
                "inline": true
            },
            {
                "name": "⏰ Timestamp",
                "value": "'$timestamp'",
                "inline": true
            },
            {
                "name": "📋 Log Entry",
                "value": "```'$log_line'```",
                "inline": false
            }
        ]'
    fi
    
    # Buat payload JSON untuk Discord
    local json_payload=$(cat <<EOF
{
    "embeds": [{
        "title": "$emoji Fail2ban Alert - $title",
        "color": $color,
        "timestamp": "$discord_timestamp",
        $fields,
        "footer": {
            "text": "Fail2ban Monitor • $HOSTNAME",
            "icon_url": "https://cdn.discordapp.com/attachments/123456789/fail2ban-icon.png"
        }
    }]
}
EOF
)
    
    # Kirim ke Discord
    local response=$(curl -s -X POST "$WEBHOOK_URL" \
        -H "Content-Type: application/json" \
        -d "$json_payload")
    
    if [ $? -eq 0 ]; then
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] ✅ Alert berhasil dikirim: $event_type $ip di jail $jail"
    else
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] ❌ Gagal mengirim alert: $response"
    fi
}

# Fungsi untuk parsing log fail2ban
parse_fail2ban_log() {
    local line="$1"
    
    # Extract timestamp
    local timestamp=$(echo "$line" | grep -o "^[0-9-]* [0-9:,]*")
    
    # Extract jail name (dalam format [jail])
    local jail=$(echo "$line" | grep -o "\[[^]]*\]" | sed 's/\[\|\]//g' | head -1)
    
    # Extract IP address
    local ip=$(echo "$line" | grep -oE "([0-9]{1,3}\.){3}[0-9]{1,3}" | head -1)
    
    # Jika tidak ada jail atau timestamp, skip
    [ -z "$jail" ] && return
    [ -z "$timestamp" ] && return
    
    # 1. Deteksi BAN events
    if echo "$line" | grep -q " Ban " && [ "$ALERT_BAN" = true ]; then
        [ -n "$ip" ] && send_discord_alert "Ban" "$jail" "$ip" "$timestamp" "$line"
        return
    fi
    
    # 2. Deteksi UNBAN events  
    if echo "$line" | grep -q " Unban " && [ "$ALERT_UNBAN" = true ]; then
        [ -n "$ip" ] && send_discord_alert "Unban" "$jail" "$ip" "$timestamp" "$line"
        return
    fi
    
    # 3. Deteksi FOUND events (serangan terdeteksi)
    if echo "$line" | grep -qE " Found " && [ "$ALERT_FOUND" = true ]; then
        if [ -n "$ip" ]; then
            # Extract additional info untuk Found events
            local additional_info=""
            if echo "$line" | grep -q "Found"; then
                # Coba extract info setelah "Found"
                additional_info=$(echo "$line" | sed 's/.*Found /Found /' | cut -d' ' -f1-3)
            fi
            send_discord_alert "Found" "$jail" "$ip" "$timestamp" "$line" "$additional_info"
        fi
        return
    fi
    
    # 4. Deteksi "already banned" events
    if echo "$line" | grep -q "already banned" && [ "$ALERT_ALREADY" = true ]; then
        [ -n "$ip" ] && send_discord_alert "Already" "$jail" "$ip" "$timestamp" "$line"
        return
    fi
    
    # 5. Deteksi events lainnya yang mengandung IP (sebagai fallback)
    if [ -n "$ip" ] && echo "$line" | grep -qE "(WARNING|ERROR|NOTICE)" && [ "$ALERT_FOUND" = true ]; then
        send_discord_alert "Info" "$jail" "$ip" "$timestamp" "$line"
        return
    fi
}

# Fungsi utama untuk monitoring log
monitor_log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] 🚀 Memulai monitoring fail2ban log..."
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] 📁 Log file: $LOG_FILE"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] 🔗 Discord webhook: ${WEBHOOK_URL:0:50}..."
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] 📊 Alert Types:"
    echo "   • 🚫 Ban Events: $($ALERT_BAN && echo "✅ Enabled" || echo "❌ Disabled")"
    echo "   • ✅ Unban Events: $($ALERT_UNBAN && echo "✅ Enabled" || echo "❌ Disabled")"  
    echo "   • ⚠️ Attack Detection: $($ALERT_FOUND && echo "✅ Enabled" || echo "❌ Disabled")"
    echo "   • 🔄 Already Banned: $($ALERT_ALREADY && echo "✅ Enabled" || echo "❌ Disabled")"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] ⚠️  Tekan Ctrl+C untuk menghentikan"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    # Periksa apakah file log ada
    if [ ! -f "$LOG_FILE" ]; then
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] ❌ File log tidak ditemukan: $LOG_FILE"
        exit 1
    fi
    
    # Dapatkan posisi terakhir
    local last_position=$(get_last_position)
    local current_size=$(wc -c < "$LOG_FILE")
    
    # Jika file lebih kecil dari posisi terakhir (log rotated), mulai dari awal
    if [ "$current_size" -lt "$last_position" ]; then
        last_position=0
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] 🔄 Log rotation detected, memulai dari awal"
    fi
    
    # Set posisi ke akhir file untuk hanya membaca entry baru
    tail -c +$((last_position + 1)) "$LOG_FILE" > /dev/null
    save_position "$current_size"
    
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] ✅ Monitoring aktif, menunggu event baru..."
    
    # Monitor file secara real-time
    tail -f "$LOG_FILE" | while read -r line; do
        # Update position
        current_size=$(wc -c < "$LOG_FILE")
        save_position "$current_size"
        
        # Parse dan kirim alert jika diperlukan
        parse_fail2ban_log "$line"
    done
}

# Kirim notifikasi bahwa monitoring dimulai
send_startup_notification() {
    local alert_types=""
    $ALERT_BAN && alert_types="${alert_types}🚫 Ban "
    $ALERT_UNBAN && alert_types="${alert_types}✅ Unban "
    $ALERT_FOUND && alert_types="${alert_types}⚠️ Attacks "
    $ALERT_ALREADY && alert_types="${alert_types}🔄 Already-Banned "
    
    local json_payload=$(cat <<EOF
{
    "embeds": [{
        "title": "🚀 Fail2ban Monitor Started",
        "color": $COLOR_INFO,
        "timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%S.000Z")",
        "fields": [
            {
                "name": "🖥️ Server",
                "value": "\`$HOSTNAME\`",
                "inline": true
            },
            {
                "name": "📁 Log File",
                "value": "\`$LOG_FILE\`",
                "inline": true
            },
            {
                "name": "📊 Alert Types",
                "value": "$alert_types",
                "inline": true
            },
            {
                "name": "📊 Status",
                "value": "✅ Monitoring All Events",
                "inline": false
            }
        ],
        "footer": {
            "text": "Fail2ban Monitor • Started",
            "icon_url": "https://cdn.discordapp.com/attachments/123456789/fail2ban-icon.png"
        }
    }]
}
EOF
)
    
    curl -s -X POST "$WEBHOOK_URL" \
        -H "Content-Type: application/json" \
        -d "$json_payload" > /dev/null
}

# Main execution
main() {
    # Kirim notifikasi startup
    send_startup_notification
    
    # Mulai monitoring
    monitor_log
}

# Jalankan script
main
