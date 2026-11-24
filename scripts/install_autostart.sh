#!/bin/bash
# Starts WE Monitor automatically whenever you log in to this Mac (launchd LaunchAgent),
# and restarts it if it ever stops.
#   ./scripts/install_autostart.sh            install and start
#   ./scripts/install_autostart.sh --remove   stop and uninstall
set -euo pipefail
DIR="$(cd "$(dirname "$0")/.." && pwd)"
LABEL="com.wemonitor.app"
PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"
DOMAIN="gui/$(id -u)"

if [ "$(uname)" != "Darwin" ]; then echo "This script is for macOS." >&2; exit 1; fi

launchctl bootout "$DOMAIN/$LABEL" 2>/dev/null || true
if [ "${1:-}" = "--remove" ]; then
  rm -f "$PLIST"
  echo "Autostart removed."
  exit 0
fi

if [ ! -x "$DIR/.venv/bin/python" ]; then
  echo "Run ./run.sh once first (it creates the Python environment)." >&2; exit 1
fi
mkdir -p "$HOME/Library/LaunchAgents" "$DIR/data"
cat > "$PLIST" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>$LABEL</string>
  <key>ProgramArguments</key>
  <array>
    <string>$DIR/.venv/bin/python</string>
    <string>-m</string>
    <string>app</string>
  </array>
  <key>WorkingDirectory</key><string>$DIR</string>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ThrottleInterval</key><integer>30</integer>
  <key>ProcessType</key><string>Background</string>
  <key>StandardOutPath</key><string>$DIR/data/we-monitor.log</string>
  <key>StandardErrorPath</key><string>$DIR/data/we-monitor.log</string>
</dict>
</plist>
PLIST
launchctl bootstrap "$DOMAIN" "$PLIST"
echo "WE Monitor now starts at login. Dashboard: http://localhost:8000"
echo "Log file: $DIR/data/we-monitor.log"
