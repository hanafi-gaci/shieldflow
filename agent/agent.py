#!/usr/bin/env python3
"""
ShieldFlow Agent — macOS
Collecte les vraies données système et les envoie au serveur ShieldFlow.

Installation :
  pip3 install psutil requests

Utilisation :
  python3 agent.py --server http://localhost:3000 --key shieldflow-secret-key-change-in-prod

L'agent s'enregistre automatiquement et envoie un heartbeat toutes les 60 secondes.
"""

import sys
import time
import json
import socket
import platform
import argparse
import logging
import subprocess
from datetime import datetime

try:
    import psutil
except ImportError:
    print("❌ psutil manquant. Installer avec : pip3 install psutil requests")
    sys.exit(1)

try:
    import requests
except ImportError:
    print("❌ requests manquant. Installer avec : pip3 install psutil requests")
    sys.exit(1)

# ─── Configuration ─────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [ShieldFlow] %(levelname)s — %(message)s',
    datefmt='%H:%M:%S'
)
log = logging.getLogger('shieldflow')

AGENT_VERSION = '1.0.0'
HEARTBEAT_INTERVAL = 60  # secondes

# ─── Collecte des données système ──────────────────────────────

def get_hostname():
    return socket.gethostname()

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return '127.0.0.1'

def get_os_version():
    try:
        p = platform.platform()
        # Sur macOS, récupérer la version lisible
        if platform.system() == 'Darwin':
            result = subprocess.run(['sw_vers', '-productVersion'], capture_output=True, text=True)
            version = result.stdout.strip()
            return f"macOS {version}"
        return p
    except:
        return platform.platform()

def get_cpu_percent():
    # Mesure sur 1 seconde pour être précis
    return psutil.cpu_percent(interval=1)

def get_ram_info():
    mem = psutil.virtual_memory()
    return {
        'percent': mem.percent,
        'total_gb': round(mem.total / (1024**3), 1)
    }

def get_disk_info():
    disk = psutil.disk_usage('/')
    return {
        'percent': disk.percent,
        'total_gb': round(disk.total / (1024**3), 1)
    }

def get_uptime_hours():
    try:
        boot_time = psutil.boot_time()
        uptime_seconds = time.time() - boot_time
        return round(uptime_seconds / 3600, 1)
    except:
        return 0

def get_open_ports():
    """Récupère les ports en écoute sur la machine."""
    ports = set()
    try:
        connections = psutil.net_connections(kind='inet')
        for conn in connections:
            if conn.status == 'LISTEN' and conn.laddr:
                ports.add(conn.laddr.port)
    except (psutil.AccessDenied, Exception):
        # Sur macOS sans sudo, certains ports peuvent être inaccessibles
        try:
            result = subprocess.run(
                ['netstat', '-an', '-p', 'tcp'],
                capture_output=True, text=True, timeout=5
            )
            for line in result.stdout.split('\n'):
                if 'LISTEN' in line:
                    parts = line.split()
                    if parts:
                        addr = parts[3] if len(parts) > 3 else ''
                        port = addr.split('.')[-1]
                        try:
                            ports.add(int(port))
                        except ValueError:
                            pass
        except Exception:
            pass
    return sorted(list(ports))[:50]  # max 50 ports

def get_running_processes():
    try:
        return len(list(psutil.process_iter()))
    except:
        return 0

def get_logged_users():
    try:
        users = psutil.users()
        return list(set([u.name for u in users]))
    except:
        return []

def get_network_connections():
    try:
        conns = psutil.net_connections(kind='inet')
        return len([c for c in conns if c.status == 'ESTABLISHED'])
    except psutil.AccessDenied:
        return -1  # Pas de sudo

def collect_snapshot():
    """Collecte toutes les métriques système."""
    ram = get_ram_info()
    disk = get_disk_info()
    return {
        'cpu_percent':         get_cpu_percent(),
        'ram_percent':         ram['percent'],
        'ram_total_gb':        ram['total_gb'],
        'disk_percent':        disk['percent'],
        'disk_total_gb':       disk['total_gb'],
        'os_version':          get_os_version(),
        'uptime_hours':        get_uptime_hours(),
        'open_ports':          get_open_ports(),
        'running_processes':   get_running_processes(),
        'logged_users':        get_logged_users(),
        'network_connections': get_network_connections(),
        'ip_local':            get_local_ip(),
    }

# ─── Communication avec le serveur ─────────────────────────────

class ShieldFlowAgent:
    def __init__(self, server_url: str, secret_key: str, device_name: str = None):
        self.server_url = server_url.rstrip('/')
        self.secret_key = secret_key
        self.device_id = None
        self.hostname = get_hostname()
        self.device_name = device_name or self.hostname
        self.headers = {
            'Content-Type': 'application/json',
            'X-Agent-Key': self.secret_key
        }

    def register(self) -> bool:
        """Enregistre cet appareil auprès du serveur ShieldFlow."""
        payload = {
            'hostname':      self.hostname,
            'platform':      platform.system(),
            'name':          self.device_name,
            'agent_version': AGENT_VERSION
        }
        try:
            r = requests.post(
                f'{self.server_url}/api/agent/register',
                json=payload, headers=self.headers, timeout=10
            )
            if r.status_code == 200:
                data = r.json()
                self.device_id = data['device_id']
                log.info(f"✅ Appareil enregistré — ID : {self.device_id[:12]}…")
                return True
            else:
                log.error(f"❌ Échec enregistrement : {r.status_code} — {r.text}")
                return False
        except requests.exceptions.ConnectionError:
            log.error(f"❌ Impossible de joindre le serveur : {self.server_url}")
            log.error("   Vérifiez que le backend ShieldFlow est démarré.")
            return False
        except Exception as e:
            log.error(f"❌ Erreur : {e}")
            return False

    def send_heartbeat(self) -> bool:
        """Envoie les données système au serveur."""
        if not self.device_id:
            log.warning("⚠ Appareil non enregistré — tentative de ré-enregistrement…")
            return self.register()

        snapshot = collect_snapshot()
        payload = {'device_id': self.device_id, **snapshot}

        try:
            r = requests.post(
                f'{self.server_url}/api/agent/heartbeat',
                json=payload, headers=self.headers, timeout=10
            )
            if r.status_code == 200:
                log.info(
                    f"📡 Heartbeat envoyé — "
                    f"CPU: {snapshot['cpu_percent']:.1f}% | "
                    f"RAM: {snapshot['ram_percent']:.1f}% | "
                    f"Disque: {snapshot['disk_percent']:.1f}% | "
                    f"Ports ouverts: {len(snapshot['open_ports'])} | "
                    f"Connexions: {snapshot['network_connections']}"
                )
                return True
            else:
                log.error(f"❌ Échec heartbeat : {r.status_code}")
                return False
        except requests.exceptions.ConnectionError:
            log.warning(f"⚠ Serveur inaccessible — réessai dans {HEARTBEAT_INTERVAL}s")
            return False
        except Exception as e:
            log.error(f"❌ Erreur heartbeat : {e}")
            return False

    def run(self):
        """Boucle principale de l'agent."""
        log.info(f"🚀 ShieldFlow Agent v{AGENT_VERSION} démarré")
        log.info(f"   Appareil  : {self.device_name} ({self.hostname})")
        log.info(f"   Serveur   : {self.server_url}")
        log.info(f"   Intervalle: {HEARTBEAT_INTERVAL}s")
        log.info(f"   OS        : {get_os_version()}")
        log.info("")

        # Enregistrement initial
        if not self.register():
            log.error("Impossible de démarrer — vérifiez le serveur et la clé.")
            sys.exit(1)

        # Boucle heartbeat
        while True:
            self.send_heartbeat()
            log.info(f"   Prochain heartbeat dans {HEARTBEAT_INTERVAL}s… (Ctrl+C pour arrêter)")
            time.sleep(HEARTBEAT_INTERVAL)


# ─── Point d'entrée ────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description='ShieldFlow Agent — Surveillance système macOS/Linux',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples :
  python3 agent.py --server http://localhost:3000 --key shieldflow-secret-key-change-in-prod
  python3 agent.py --server http://localhost:3000 --key MON_SECRET --name "MacBook Pro Admin"
        """
    )
    parser.add_argument('--server', required=True, help='URL du serveur ShieldFlow (ex: http://localhost:3000)')
    parser.add_argument('--key',    required=True, help='Clé secrète agent (depuis .env)')
    parser.add_argument('--name',   default=None,  help='Nom de cet appareil (optionnel)')
    args = parser.parse_args()

    agent = ShieldFlowAgent(
        server_url=args.server,
        secret_key=args.key,
        device_name=args.name
    )

    try:
        agent.run()
    except KeyboardInterrupt:
        log.info("\n👋 Agent arrêté proprement.")
        sys.exit(0)

if __name__ == '__main__':
    main()
