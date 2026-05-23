#!/bin/bash
# ShieldFlow — Installation universelle
# Usage: curl -sSL https://shieldflow-rfzv.onrender.com/install.sh | bash -s -- TENANT_ID AGENT_KEY

TENANT_ID="$1"
AGENT_KEY="$2"
SERVER="https://shieldflow-rfzv.onrender.com"

if [ -z "$TENANT_ID" ] || [ -z "$AGENT_KEY" ]; then
    echo "Erreur: TENANT_ID et AGENT_KEY requis"
    exit 1
fi

echo ""
echo "  Shield Flow — Installation agent de securite"
echo "  Client ID : $TENANT_ID"
echo ""

# Detecter OS
OS="unknown"
if [[ "$OSTYPE" == "darwin"* ]]; then
    OS="mac"
elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
    OS="linux"
elif [[ "$OSTYPE" == "msys" ]] || [[ "$OSTYPE" == "win32" ]]; then
    OS="windows"
fi

echo "[INFO] Systeme detecte : $OS"

# Installer Python si absent
if ! command -v python3 &>/dev/null; then
    echo "[INFO] Installation Python..."
    if [ "$OS" = "mac" ]; then
        if command -v brew &>/dev/null; then
            brew install python3
        else
            echo "[ERREUR] Installez Python depuis https://python.org puis relancez."
            exit 1
        fi
    elif [ "$OS" = "linux" ]; then
        sudo apt-get install -y python3 python3-pip 2>/dev/null || \
        sudo yum install -y python3 python3-pip 2>/dev/null || \
        sudo dnf install -y python3 python3-pip 2>/dev/null
    fi
fi

# Installer dependances
echo "[INFO] Installation des dependances..."
pip3 install psutil requests --break-system-packages --quiet 2>/dev/null || \
pip3 install psutil requests --quiet 2>/dev/null || \
pip install psutil requests --quiet 2>/dev/null

# Creer dossier
INSTALL_DIR="$HOME/shieldflow"
mkdir -p "$INSTALL_DIR"
cd "$INSTALL_DIR"

# Telecharger agent
echo "[INFO] Telechargement de l'agent ShieldFlow..."
curl -sSL "$SERVER/agent/agent_v2.py" -o agent_v2.py
curl -sSL "$SERVER/agent/expert_checks.py" -o expert_checks.py
curl -sSL "$SERVER/agent/remediation.py" -o remediation.py

# Configurer et lancer selon OS
if [ "$OS" = "mac" ]; then
    PYTHON_PATH=$(which python3)
    PLIST="$HOME/Library/LaunchAgents/com.shieldflow.agent.plist"
    launchctl unload "$PLIST" 2>/dev/null || true
    cat > "$PLIST" << PLISTEOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key><string>com.shieldflow.agent</string>
    <key>ProgramArguments</key>
    <array>
        <string>$PYTHON_PATH</string>
        <string>$INSTALL_DIR/agent_v2.py</string>
    </array>
    <key>EnvironmentVariables</key>
    <dict>
        <key>SHIELDFLOW_SERVER</key><string>$SERVER</string>
        <key>SHIELDFLOW_TENANT</key><string>$TENANT_ID</string>
        <key>SHIELDFLOW_KEY</key><string>$AGENT_KEY</string>
    </dict>
    <key>RunAtLoad</key><true/>
    <key>KeepAlive</key><true/>
    <key>StandardOutPath</key><string>$INSTALL_DIR/agent.log</string>
    <key>StandardErrorPath</key><string>$INSTALL_DIR/agent.log</string>
</dict>
</plist>
PLISTEOF
    launchctl load "$PLIST"
    echo ""
    echo "✅ ShieldFlow Agent installe sur macOS !"
    echo "   L'agent demarre automatiquement au boot."
    echo "   Logs : tail -f $INSTALL_DIR/agent.log"

elif [ "$OS" = "linux" ]; then
    cat > /etc/shieldflow.env << ENVEOF
SHIELDFLOW_SERVER=$SERVER
SHIELDFLOW_TENANT=$TENANT_ID
SHIELDFLOW_KEY=$AGENT_KEY
ENVEOF
    cat > /etc/systemd/system/shieldflow-agent.service << SVCEOF
[Unit]
Description=ShieldFlow Security Agent
After=network.target

[Service]
Type=simple
WorkingDirectory=$INSTALL_DIR
EnvironmentFile=/etc/shieldflow.env
ExecStart=$(which python3) $INSTALL_DIR/agent_v2.py
Restart=always
RestartSec=30

[Install]
WantedBy=multi-user.target
SVCEOF
    systemctl daemon-reload
    systemctl enable shieldflow-agent
    systemctl start shieldflow-agent
    echo ""
    echo "ShieldFlow Agent installe sur Linux !"
    echo "   systemctl status shieldflow-agent"
fi
