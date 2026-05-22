#!/bin/bash
# ShieldFlow Agent — Installation Linux (Ubuntu/Debian/CentOS/Fedora)
# Usage: bash install-linux.sh TENANT_ID AGENT_KEY

set -e

TENANT_ID="$1"
AGENT_KEY="$2"
SERVER="https://shieldflow-rfzv.onrender.com"
INSTALL_DIR="/opt/shieldflow"
SERVICE_NAME="shieldflow-agent"

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

if [ -z "$TENANT_ID" ] || [ -z "$AGENT_KEY" ]; then
    echo -e "${RED}[ERROR]${NC} Usage: bash install-linux.sh TENANT_ID AGENT_KEY"
    exit 1
fi

echo ""
echo -e "${BLUE}  🛡 ShieldFlow Agent — Installation Linux${NC}"
echo -e "${BLUE}  Serveur: $SERVER${NC}"
echo ""

# Detecter le gestionnaire de paquets
if command -v apt-get &>/dev/null; then
    PKG_MGR="apt-get"
    INSTALL_CMD="apt-get install -y"
elif command -v dnf &>/dev/null; then
    PKG_MGR="dnf"
    INSTALL_CMD="dnf install -y"
elif command -v yum &>/dev/null; then
    PKG_MGR="yum"
    INSTALL_CMD="yum install -y"
else
    echo -e "${RED}[ERROR]${NC} Gestionnaire de paquets non supporte."
    exit 1
fi

echo "[INFO] Mise a jour des paquets..."
$PKG_MGR update -qq 2>/dev/null || true

# Installer Python si absent
if ! command -v python3 &>/dev/null; then
    echo "[INFO] Installation de Python3..."
    $INSTALL_CMD python3 python3-pip
fi

# Installer pip si absent
if ! command -v pip3 &>/dev/null; then
    $INSTALL_CMD python3-pip
fi

echo -e "${GREEN}[OK]${NC} Python $(python3 --version) detecte"

# Creer dossier
echo "[INFO] Creation du dossier d'installation..."
mkdir -p "$INSTALL_DIR"
cd "$INSTALL_DIR"

# Installer dependances Python
echo "[INFO] Installation des dependances..."
pip3 install psutil requests --quiet --break-system-packages 2>/dev/null || pip3 install psutil requests --quiet

# Telecharger agent
echo "[INFO] Telechargement de l'agent..."
curl -sSL "$SERVER/agent/agent_v2.py" -o agent_v2.py
curl -sSL "$SERVER/agent/expert_checks.py" -o expert_checks.py

# Creer fichier de config
cat > /etc/shieldflow.env << ENVEOF
SHIELDFLOW_SERVER=$SERVER
SHIELDFLOW_TENANT=$TENANT_ID
SHIELDFLOW_KEY=$AGENT_KEY
ENVEOF
chmod 600 /etc/shieldflow.env

# Creer service systemd
cat > /etc/systemd/system/${SERVICE_NAME}.service << SVCEOF
[Unit]
Description=ShieldFlow Security Agent
After=network.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
EnvironmentFile=/etc/shieldflow.env
ExecStart=/usr/bin/python3 $INSTALL_DIR/agent_v2.py
Restart=always
RestartSec=30
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
SVCEOF

# Activer et demarrer le service
echo "[INFO] Activation du service systemd..."
systemctl daemon-reload
systemctl enable "$SERVICE_NAME"
systemctl start "$SERVICE_NAME"

sleep 3

if systemctl is-active --quiet "$SERVICE_NAME"; then
    echo ""
    echo -e "${GREEN}================================================================${NC}"
    echo -e "${GREEN}  ✅ ShieldFlow Agent installe et actif !${NC}"
    echo -e "${GREEN}  L'agent surveille cette machine 24h/24.${NC}"
    echo -e "${GREEN}  Service: systemctl status $SERVICE_NAME${NC}"
    echo -e "${GREEN}  Logs: journalctl -u $SERVICE_NAME -f${NC}"
    echo -e "${GREEN}================================================================${NC}"
else
    echo -e "${RED}[ERROR]${NC} Le service n'a pas demarré. Verifiez: journalctl -u $SERVICE_NAME"
    exit 1
fi
