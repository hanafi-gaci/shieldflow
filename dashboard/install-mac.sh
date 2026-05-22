#!/bin/bash
# ShieldFlow Agent — Installation macOS
# Usage: bash install-mac.sh TENANT_ID AGENT_KEY

TENANT_ID="$1"
AGENT_KEY="$2"
SERVER="https://shieldflow-rfzv.onrender.com"
INSTALL_DIR="$HOME/shieldflow"
PLIST="$HOME/Library/LaunchAgents/com.shieldflow.agent.plist"

if [ -z "$TENANT_ID" ] || [ -z "$AGENT_KEY" ]; then
    echo "Usage: bash install-mac.sh TENANT_ID AGENT_KEY"
    exit 1
fi

echo ""
echo "  🛡 ShieldFlow Agent — Installation macOS"
echo "  Serveur: $SERVER"
echo ""

# Verifier Python
if ! command -v python3 &>/dev/null; then
    echo "[ERROR] Python3 requis. Installez-le depuis https://python.org"
    exit 1
fi

PYTHON_PATH=$(which python3)

# Installer dependances
echo "[INFO] Installation des dependances..."
pip3 install psutil requests --break-system-packages --quiet 2>/dev/null || pip3 install psutil requests --quiet

# Creer dossier
mkdir -p "$INSTALL_DIR"
cd "$INSTALL_DIR"

# Telecharger agent
echo "[INFO] Telechargement de l'agent..."
curl -sSL "$SERVER/agent/agent_v2.py" -o agent_v2.py
curl -sSL "$SERVER/agent/expert_checks.py" -o expert_checks.py

# Arreter l'ancien agent si present
launchctl unload "$PLIST" 2>/dev/null || true

# Creer LaunchAgent
cat > "$PLIST" << PLISTEOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.shieldflow.agent</string>
    <key>ProgramArguments</key>
    <array>
        <string>$PYTHON_PATH</string>
        <string>$INSTALL_DIR/agent_v2.py</string>
    </array>
    <key>EnvironmentVariables</key>
    <dict>
        <key>SHIELDFLOW_SERVER</key>
        <string>$SERVER</string>
        <key>SHIELDFLOW_TENANT</key>
        <string>$TENANT_ID</string>
        <key>SHIELDFLOW_KEY</key>
        <string>$AGENT_KEY</string>
    </dict>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>$INSTALL_DIR/agent.log</string>
    <key>StandardErrorPath</key>
    <string>$INSTALL_DIR/agent.log</string>
</dict>
</plist>
PLISTEOF

# Charger le service
launchctl load "$PLIST"

sleep 3

if launchctl list | grep -q "com.shieldflow.agent"; then
    echo ""
    echo "================================================================"
    echo "  ✅ ShieldFlow Agent installe et actif !"
    echo "  L'agent surveille cette machine 24h/24."
    echo "  Logs: tail -f $INSTALL_DIR/agent.log"
    echo "================================================================"
else
    echo "[ERROR] Le service n'a pas demarré."
    exit 1
fi
