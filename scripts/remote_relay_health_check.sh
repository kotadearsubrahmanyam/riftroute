#!/usr/bin/env bash
# ==============================================================================
# RiftRoute Remote Relay Host Status & Health Diagnostic
# ==============================================================================
set -euo pipefail

echo "=== RIFTROUTE RELAY HOST SYSTEM HEALTH CHECK ==="
echo "Date (UTC):       $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "Hostname:         $(hostname)"
echo "Kernel:           $(uname -r)"
echo "Architecture:     $(uname -m)"
echo "Uptime:           $(uptime -p 2>/dev/null || uptime)"
echo "Active Memory:    $(free -m | awk '/Mem:/ {print $3 " MB used / " $2 " MB total"}')"
echo "Root Disk Usage:  $(df -h / | awk 'NR==2 {print $3 " used / " $2 " total (" $5 ")"}')"

echo ""
echo "=== SERVICE STATUS ==="
if systemctl is-active --quiet rift-relay; then
    echo "Service Status:   ACTIVE (Running)"
    systemctl status rift-relay --no-pager | head -n 12
else
    echo "Service Status:   INACTIVE / STOPPED"
fi

echo ""
echo "=== LISTENING PORTS ==="
ss -tulpn | grep 44321 || echo "TCP port 44321 is not currently listening."
