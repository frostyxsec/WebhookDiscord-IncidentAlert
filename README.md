# IncidentAlert Discord Notifier

This project provides a set of Bash scripts to monitor various security-related logs on a Linux server and send real-time alerts to a Discord channel via webhooks. It is designed for use in a SIEM (Security Information and Event Management) environment.

## Features

- **Nginx Log Monitoring** (`nginx.sh`): Monitors Nginx access and error logs for suspicious activities and errors.
- **Snort IDS Alert Monitoring** (`snort.sh`): Monitors Snort IDS alerts for intrusion detection events.
- **Fail2ban Log Monitoring** (`fail2ban.sh`): Monitors Fail2ban logs for ban/unban/attack events, including IP geolocation info.
- **Auth Log Monitoring** (`auth.sh`): Monitors authentication logs for login attempts and other auth events.

All scripts send formatted alerts to a Discord webhook with deduplication and rate limiting to avoid spam.

## Requirements

- Linux environment
- `curl` installed
- `tmux` (for running scripts in parallel sessions)
- Proper permissions to read log files (e.g., `/var/log/nginx/access.log`, `/var/log/snort/alert`, etc.)
- Discord webhook URL

## Setup

1. **Clone or copy this repository to your server.**

2. **Edit each script** (`nginx.sh`, `snort.sh`, `fail2ban.sh`, `auth.sh`) and set your Discord webhook URL:
   ```sh
   DISCORD_WEBHOOK="https://discord.com/api/webhooks/..."
   # or
   WEBHOOK_URL="https://discord.com/api/webhooks/..."
   ```

3. **Make scripts executable:**
   ```sh
   chmod +x nginx.sh snort.sh fail2ban.sh auth.sh
   ```

4. **(Optional) Adjust log file paths** in each script if your log locations differ from the defaults.

## Running the Scripts with tmux

It is recommended to run each script in its own `tmux` session for easy management and persistence.

### Example Steps

1. **Start a tmux session for each script:**
   ```sh
   tmux new-session -s nginx './nginx.sh'
   tmux new-session -s snort './snort.sh'
   tmux new-session -s fail2ban './fail2ban.sh'
   tmux new-session -s auth './auth.sh'
   ```

2. **Detach from a session:**  
   Press `Ctrl+b` then `d`.

3. **List tmux sessions:**
   ```sh
   tmux ls
   ```

4. **Attach to a session:**
   ```sh
   tmux attach -t nginx
   ```

5. **Stop a script:**  
   Attach to its tmux session and press `Ctrl+C`.

## Notes

- Make sure the user running the scripts has permission to read the log files.
- Each script maintains its own state and lock files in `/tmp`.
- For production, consider running these scripts as a dedicated monitoring user or systemd service.

## License

This project is provided as-is for educational and operational
