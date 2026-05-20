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
    url = f'{SERVER_URL}/api/agent/report'
    headers = {
        'Content-Type': 'application/json',
        'User-Agent': f'ShieldFlow-Agent/2.0 ({platform.system()})',
    }
    if API_TOKEN:
        headers['Authorization'] = f'Bearer {API_TOKEN}'

    try:
        resp = requests.post(url, json=payload, headers=headers, timeout=15)
        resp.raise_for_status()
        data = resp.json()

        score    = data.get('score', '?')
        alerts   = data.get('alert_count', '?')
        critical = data.get('critical_count', 0)

        status_emoji = '🔴' if critical > 0 else ('🟡' if int(alerts or 0) > 0 else '🟢')
        logger.info(f'{status_emoji} Score: {score}/100 | Alertes: {alerts} | Critiques: {critical}')

        return True

    except requests.exceptions.ConnectionError:
        logger.error(f'Cannot reach server at {SERVER_URL}')
    except requests.exceptions.Timeout:
        logger.error('Request timed out after 15s')
    except requests.exceptions.HTTPError as e:
        logger.error(f'HTTP {e.response.status_code}: {e.response.text[:200]}')
    except Exception as e:
        logger.error(f'Unexpected error: {e}')

    return False


# ─── MAIN LOOP ───────────────────────────────────────────────────────────────

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
        time.sleep(INTERVAL)


if __name__ == '__main__':
    main()
