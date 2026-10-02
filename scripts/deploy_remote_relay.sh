#!/usr/bin/env bash
# ==============================================================================
# RiftRoute Phase 5 — Remote Linux Relay Node Automated Deployment Script
# ==============================================================================
#
# HARD PRINCIPLE: OBSERVATION ONLY. NO LIVE TRAFFIC FORWARDING.
# Hardened, unprivileged deployment of the RiftRoute relay daemon on Linux.
#
# Usage:
#   sudo ./deploy_remote_relay.sh --relay-id <relay_id> --client-pubkey <client_pubkey_hex>
# ==============================================================================

set -euo pipefail

RELAY_ID=""
CLIENT_PUBKEY=""
CONTROL_PORT=44321
SERVICE_USER="riftrelay"
CONFIG_DIR="/etc/riftroute"
LOG_DIR="/var/log/riftroute"
BINARY_DEST="/usr/local/bin/rift-relay"

print_usage() {
    echo "Usage: sudo $0 --relay-id <RELAY_ID> --client-pubkey <CLIENT_PUBKEY_HEX> [--port <PORT>]"
    echo ""
    echo "Options:"
    echo "  --relay-id        Unique relay identifier (e.g. relay_in_hyd_01)"
    echo "  --client-pubkey   Ed25519 public key hex of the authorized RiftRoute client"
    echo "  --port            Control channel TCP port (default: 44321)"
    exit 1
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --relay-id)
            RELAY_ID="$2"
            shift 2
            ;;
        --client-pubkey)
            CLIENT_PUBKEY="$2"
            shift 2
            ;;
        --port)
            CONTROL_PORT="$2"
            shift 2
            ;;
        -h|--help)
            print_usage
            ;;
        *)
            echo "Unknown option: $1"
            print_usage
            ;;
    esac
done

if [[ -z "$RELAY_ID" || -z "$CLIENT_PUBKEY" ]]; then
    echo "[ERROR] Both --relay-id and --client-pubkey are required."
    print_usage
fi

if [[ $EUID -ne 0 ]]; then
    echo "[ERROR] This deployment script must be run as root (or with sudo)."
    exit 1
fi

echo "================================================================================"
echo "      RIFTROUTE REMOTE RELAY AUTOMATED DEPLOYMENT & HARDENING ENGINE           "
echo "================================================================================"
echo "Relay ID:             $RELAY_ID"
echo "Authorized Client:    $CLIENT_PUBKEY"
echo "Control Port:         $CONTROL_PORT"
echo "Service User:         $SERVICE_USER"

# 1. System Dependencies
echo "[1/7] Installing system dependencies (ping, ca-certificates, libcap)..."
if command -v apt-get &>/dev/null; then
    apt-get update -qq
    apt-get install -y -qq iputils-ping ca-certificates libcap2-bin curl jq
elif command -v dnf &>/dev/null; then
    dnf install -y -q iputils ca-certificates libcap curl jq
fi

# 2. Service User Creation (Least Privilege)
echo "[2/7] Creating unprivileged service user '$SERVICE_USER'..."
if ! id -u "$SERVICE_USER" &>/dev/null; then
    useradd -r -s /usr/sbin/nologin -d /var/empty -M "$SERVICE_USER"
fi

# 3. Directories & Permissions
echo "[3/7] Setting up secure configuration and logging directories..."
mkdir -p "$CONFIG_DIR" "$LOG_DIR"
chown -R "$SERVICE_USER:$SERVICE_USER" "$CONFIG_DIR" "$LOG_DIR"
chmod 750 "$CONFIG_DIR"
chmod 755 "$LOG_DIR"

# 4. Binary Verification or Compilation
echo "[4/7] Ensuring relay binary is present at '$BINARY_DEST'..."
if [[ ! -f "$BINARY_DEST" ]]; then
    if command -v cargo &>/dev/null; then
        echo "Building rift-relay from local source..."
        cargo build --release --bin rift-relay
        cp target/release/rift-relay "$BINARY_DEST"
    else
        echo "[ERROR] rift-relay binary not found at $BINARY_DEST and cargo not installed."
        echo "Please copy the compiled Linux binary to $BINARY_DEST first."
        exit 1
    fi
fi
chmod 755 "$BINARY_DEST"

# 5. Cryptographic Identity & Configuration Initialization
echo "[5/7] Initializing unique cryptographic identity for $RELAY_ID..."
IDENTITY_FILE="$CONFIG_DIR/identity.json"
CONFIG_FILE="$CONFIG_DIR/config.json"

if [[ ! -f "$IDENTITY_FILE" ]]; then
    "$BINARY_DEST" init --relay-id "$RELAY_ID" --identity-path "$IDENTITY_FILE" --config-path "$CONFIG_FILE"
    chown "$SERVICE_USER:$SERVICE_USER" "$IDENTITY_FILE" "$CONFIG_FILE"
    chmod 600 "$IDENTITY_FILE"
    chmod 644 "$CONFIG_FILE"
fi

# Extract public key and fingerprint
RELAY_PUBKEY=$(jq -r '.public_key_hex' "$IDENTITY_FILE")
RELAY_FP=$(jq -r '.fingerprint' "$IDENTITY_FILE")

# Configure authorized clients
echo "Configuring authorized client whitelist in $CONFIG_FILE..."
cat <<EOF > "$CONFIG_FILE"
{
  "relay_id": "$RELAY_ID",
  "listen_address": "0.0.0.0",
  "control_port": $CONTROL_PORT,
  "identity_path": "$IDENTITY_FILE",
  "authorized_clients_path": null,
  "authorized_clients": [
    {
      "client_id": "riftroute_client",
      "public_key_hex": "$CLIENT_PUBKEY",
      "description": "Authorized RiftRoute Client",
      "added_at_utc": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    }
  ],
  "location": {
    "country": "IN",
    "region": "Remote",
    "city": "Remote Host",
    "provider": "Dedicated Remote Relay",
    "asn": null,
    "provenance": "OperatorDeclared"
  },
  "max_concurrent_jobs": 5,
  "max_request_size_bytes": 65536,
  "rate_limit_per_minute": 120,
  "allow_private_targets": false,
  "challenge_ttl_seconds": 30,
  "session_ttl_minutes": 60,
  "log_level": "info"
}
EOF
chown "$SERVICE_USER:$SERVICE_USER" "$CONFIG_FILE"
chmod 644 "$CONFIG_FILE"

# 6. Install Hardened systemd Service
echo "[6/7] Installing and starting hardened systemd service..."
cat <<EOF > /etc/systemd/system/rift-relay.service
[Unit]
Description=RiftRoute Relay Diagnostic Daemon
Documentation=https://github.com/riftroute/riftroute
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$SERVICE_USER
Group=$SERVICE_USER
WorkingDirectory=$CONFIG_DIR
ExecStart=$BINARY_DEST run --config $CONFIG_FILE
Restart=on-failure
RestartSec=5s

# Security Hardening Directives
ProtectSystem=strict
ProtectHome=yes
NoNewPrivileges=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
CapabilityBoundingSet=CAP_NET_RAW
AmbientCapabilities=CAP_NET_RAW
MemoryDenyWriteExecute=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes

ReadOnlyPaths=$CONFIG_DIR
ReadWritePaths=$LOG_DIR /tmp
LimitNOFILE=8192

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now rift-relay

# 7. Firewall Guidance
echo "[7/7] Verifying firewall status..."
if command -v ufw &>/dev/null && ufw status | grep -q "Status: active"; then
    echo "UFW is active. To allow the control port, run:"
    echo "  sudo ufw allow $CONTROL_PORT/tcp comment 'RiftRoute Relay Control Port'"
fi

echo "================================================================================"
echo "               RIFTROUTE REMOTE RELAY DEPLOYED SUCCESSFULLY                     "
echo "================================================================================"
echo "Relay ID:             $RELAY_ID"
echo "Public Key (Hex):     $RELAY_PUBKEY"
echo "Identity Fingerprint: $RELAY_FP"
echo "Listen Port:          $CONTROL_PORT"
echo ""
echo "NEXT STEP FOR WINDOWS CLIENT:"
echo "Register this node in 'data/relay/registry.json':"
echo "  {"
echo "    \"relay_id\": \"$RELAY_ID\","
echo "    \"public_address\": \"<REMOTE_PUBLIC_IP>\","
echo "    \"control_port\": $CONTROL_PORT,"
echo "    \"identity_fingerprint\": \"$RELAY_FP\","
echo "    \"public_key_hex\": \"$RELAY_PUBKEY\","
echo "    \"status\": \"Online\","
echo "    \"capabilities\": [\"ping\", \"tcp_probe\"]"
echo "  }"
echo "================================================================================"
