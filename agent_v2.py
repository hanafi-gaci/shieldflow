#!/usr/bin/env python3
"""
ShieldFlow — Agent v2 (Expert)
Remplace ou complète ton agent existant.

Usage:
    python3 agent_v2.py

Config via variables d'environnement ou fichier .env :
    SHIELDFLOW_SERVER  = https://shieldflow-rfzv.onrender.com
    SHIELDFLOW_TOKEN   = <ton token d'API — optionnel pour l'instant>
    SHIELDFLOW_INTERVAL = 30  (secondes entre chaque rapport)
"""

import os
import sys
SHIELDFLOW_TENANT = os.getenv('SHIELDFLOW_TENANT', '')
SECRET_KEY = os.getenv('SHIELDFLOW_KEY', 'shieldflow-secret-key-change-in-prod')
import json
import time
import uuid
import socket
import platform
import logging
import requests
from datetime import datetime
from pathlib import Path

# Import expert checks from same directory
sys.path.insert(0, str(Path(__file__).parent))
try:
    from expert_checks import collect_expert_data
    EXPERT_AVAILABLE = True
except ImportError as e:
    print(f'[Warning] Expert checks unavailable: {e}')
    EXPERT_AVAILABLE = False

# ─── CONFIG ──────────────────────────────────────────────────────────────────

SERVER_URL = os.getenv('SHIELDFLOW_SERVER', 'https://shieldflow-rfzv.onrender.com').rstrip('/')
API_TOKEN  = os.getenv('SHIELDFLOW_TOKEN', '')
INTERVAL   = int(os.getenv('SHIELDFLOW_INTERVAL', '30'))

# Persist device ID across restarts
DEVICE_ID_FILE = Path.home() / '.shieldflow_device_id'

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%H:%M:%S',
)
logger = logging.getLogger('shieldflow.agent')


# ─── DEVICE ID ───────────────────────────────────────────────────────────────

def get_device_id() -> str:
    if DEVICE_ID_FILE.exists():
        return DEVICE_ID_FILE.read_text().strip()
    device_id = str(uuid.uuid4())
    DEVICE_ID_FILE.write_text(device_id)
    return device_id


# ─── BASIC SYSTEM INFO ───────────────────────────────────────────────────────

def collect_basic_info() -> dict:
    """Collect the basic system metrics (always available, no psutil required)."""
    info = {
        'device_id':  get_device_id(),
        'hostname':   socket.gethostname(),
        'platform':   platform.system(),
        'os_version': platform.platform(),
        'arch':       platform.machine(),
        'python':     platform.python_version(),
        'timestamp':  datetime.utcnow().isoformat() + 'Z',
        'agent_version': '2.0.0',
    }

    # Try psutil for richer metrics
    try:
        import psutil

        mem = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        cpu  = psutil.cpu_percent(interval=1)
        boot = psutil.boot_time()

        info.update({
            'cpu_percent':         round(cpu, 1),
            'cpu_count':           psutil.cpu_count(),
            'memory_total':        mem.total,
            'memory_used':         mem.used,
            'memory_percent':      round(mem.percent, 1),
            'disk_total':          disk.total,
            'disk_used':           disk.used,
            'disk_usage_percent':  round(disk.percent, 1),
            'uptime_seconds':      int(time.time() - boot),
        })
    except ImportError:
        logger.warning('psutil not installed — basic metrics only. Run: pip3 install psutil')

    return info


# ─── SEND REPORT ─────────────────────────────────────────────────────────────

def send_report(payload: dict) -> bool:
    """Send analysis payload to ShieldFlow server."""
    headers = {
        'Content-Type': 'application/json',
        'x-agent-key': os.getenv('SHIELDFLOW_KEY', 'shieldflow-secret-key-change-in-prod'),
        'User-Agent': f'ShieldFlow-Agent/2.0 ({platform.system()})',
    }

    # Step 1: Register device
    try:
        reg = requests.post(
            f'{SERVER_URL}/api/agent/{SHIELDFLOW_TENANT}/register' if SHIELDFLOW_TENANT else f'{SERVER_URL}/api/agent/register',
            json={
                'hostname': payload.get('hostname', 'unknown'),
                'platform': payload.get('platform', 'unknown'),
                'name': payload.get('hostname', 'unknown'),
                'agent_version': '2.0.0'
            },
            headers=headers, timeout=10
        )
        device_id = reg.json().get('device_id', '')
    except Exception as e:
        logger.error(f'Register failed: {e}')
        return False

    # Step 2: Send heartbeat with expert data
    try:
        heartbeat = {
            'device_id': device_id,
            'cpu_percent': payload.get('cpu_percent', 0),
            'ram_gb': round((payload.get('memory_total', 0) or 0) / 1024**3, 1),
            'disk_gb': round((payload.get('disk_total', 0) or 0) / 1024**3, 1),
            'uptime_seconds': payload.get('uptime_seconds', 0),
            'process_count': len(payload.get('processes') or []),
            "running_processes": len(payload.get("processes") or []),
            "uptime_hours": round((payload.get("uptime_seconds") or 0) / 3600, 1),
            'ram_total_gb': round((payload.get('memory_total', 0) or 0) / 1024**3, 1),
            'disk_total_gb': round((payload.get('disk_total', 0) or 0) / 1024**3, 1),
            'uptime_seconds': payload.get('uptime_seconds', 0),
            'os_version': payload.get('os_version', ''),
            'platform': payload.get('platform', 'Darwin'),
            'memory_total': payload.get('memory_total', 0),
            'disk_total': payload.get('disk_total', 0),
            'uptime_seconds': payload.get('uptime_seconds', 0),
            'process_count': len(payload.get('processes') or []),
            "running_processes": len(payload.get("processes") or []),
            "uptime_hours": round((payload.get("uptime_seconds") or 0) / 3600, 1),
            'ram_total_gb': round((payload.get('memory_total', 0) or 0) / 1024**3, 1),
            'disk_total_gb': round((payload.get('disk_total', 0) or 0) / 1024**3, 1),
            'uptime_seconds': payload.get('uptime_seconds', 0),
            'ram_percent': payload.get('memory_percent', 0),
            'disk_percent': payload.get('disk_usage_percent', 0),
            'open_ports': [p.get('local_port') for p in (payload.get('open_ports') or []) if p.get('local_port')],
            'network_connections': len(payload.get('open_ports') or []),
            'processes': payload.get('processes', []),
            'firewall_enabled': payload.get('firewall_enabled'),
            'disk_encrypted': payload.get('disk_encrypted'),
            'pending_updates': payload.get('pending_updates', 0),
            'antivirus_status': payload.get('antivirus_status', 'unknown'),
            'users': payload.get('users', []),
            'logs': payload.get('logs', []),
        }
        resp = requests.post(
            f'{SERVER_URL}/api/agent/{SHIELDFLOW_TENANT}/heartbeat' if SHIELDFLOW_TENANT else f'{SERVER_URL}/api/agent/heartbeat',
            json=heartbeat, headers=headers, timeout=15
        )
        resp.raise_for_status()
        data = resp.json()
        logger.info(f'🟢 Heartbeat envoyé — CPU: {heartbeat["cpu_percent"]}% | RAM: {heartbeat["ram_percent"]}% | Disque: {heartbeat["disk_percent"]}%')
        return True

    except requests.exceptions.HTTPError as e:
        logger.error(f'HTTP {e.response.status_code}: {e.response.text[:200]}')
    except Exception as e:
        logger.error(f'Unexpected error: {e}')

    return False

def main():
    logger.info('=' * 55)
    logger.info('  ShieldFlow Agent v2 — Expert Mode')
    logger.info(f'  Server  : {SERVER_URL}')
    logger.info(f'  Interval: {INTERVAL}s')
    logger.info(f'  Expert  : {"enabled" if EXPERT_AVAILABLE else "disabled (install psutil)"}')
    logger.info('=' * 55)

    # Quick connectivity check
    try:
        resp = requests.get(f'{SERVER_URL}/', timeout=5)
        logger.info(f'Server reachable (HTTP {resp.status_code})')
    except Exception:
        logger.warning(f'Server not reachable at startup — will retry')

    iteration = 0
    while True:
        iteration += 1
        logger.info(f'--- Collecting (iteration {iteration}) ---')

        try:
            payload = collect_basic_info()

            if EXPERT_AVAILABLE:
                logger.info('Running expert security checks...')
                expert_data = collect_expert_data()
                payload.update(expert_data)
                logger.info(f'Expert data: {len(payload.get("processes", []))} processes, '
                            f"{len(payload.get("open_ports") or [])} ports, "
                            f'{len(payload.get("logs", []))} log lines')

            success = send_report(payload)
            if not success:
                logger.warning('Report failed — will retry next cycle')

        except KeyboardInterrupt:
            logger.info('Agent stopped by user.')
            sys.exit(0)
        except Exception as e:
            logger.error(f'Collection error: {e}', exc_info=True)

        logger.info(f'Next report in {INTERVAL}s...\n')
        
        # Verifier les commandes de remediation
        try:
            from remediation import execute as remediate
            import os as _os
            r = requests.get(
                f'{SERVER_URL}/api/agent/{SHIELDFLOW_TENANT}/commands',
                headers={'x-agent-key': _os.getenv('SHIELDFLOW_KEY', SECRET_KEY)},
                timeout=10
            )
            if r.status_code == 200:
                commands = r.json().get('commands', [])
                for cmd in commands:
                    logger.info(f'[Remediation] {cmd["alert_type"]}')
                    result = remediate(cmd['alert_type'], cmd.get('params', {}))
                    requests.post(
                        f'{SERVER_URL}/api/agent/{SHIELDFLOW_TENANT}/remediation-result',
                        json={'command_id': cmd['id'], 'result': result},
                        headers={'x-agent-key': _os.getenv('SHIELDFLOW_KEY', SECRET_KEY)},
                        timeout=10
                    )
                    logger.info(f'[Remediation] {result.get("output", result.get("error",""))}')
        
        # Threat Intelligence — vérifier les connexions réseau
        try:
            from expert_checks import check_threat_intelligence
            connections = snap.get('network_connections_detail', [])
            threat_alerts = check_threat_intelligence(connections)
            if threat_alerts:
                for ta in threat_alerts:
                    logger.warning(f'[ThreatIntel] {ta["title"]}')
        except Exception as e:
            logger.debug(f'ThreatIntel: {e}')
        except Exception as e:
            logger.debug(f'Remediation: {e}')
        time.sleep(INTERVAL)


if __name__ == '__main__':
    main()
