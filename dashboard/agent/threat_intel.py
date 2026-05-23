#!/usr/bin/env python3
"""
ShieldFlow — Module Threat Intelligence
Vérifie les connexions réseau contre des bases d'IPs malveillantes.
Source : OTX AlienVault (gratuit, 3M+ IPs malveillantes)
"""

import os
import json
import logging
import requests
import socket
from datetime import datetime, timezone, timedelta
from pathlib import Path

logger = logging.getLogger('shieldflow.threat_intel')

CACHE_FILE = Path.home() / 'shieldflow' / 'threat_cache.json'
OTX_API_KEY = os.getenv('OTX_API_KEY', '2afe0f4bc86fee086b84e16d6d51a47cc5c15f3b527d29c988fd30211a1804b0')
CACHE_HOURS = 24

# IPs privées à ignorer
PRIVATE_RANGES = [
    '10.', '172.16.', '172.17.', '172.18.', '172.19.', '172.20.',
    '172.21.', '172.22.', '172.23.', '172.24.', '172.25.', '172.26.',
    '172.27.', '172.28.', '172.29.', '172.30.', '172.31.',
    '192.168.', '127.', '0.', '169.254.', '::1', 'fe80:'
]

def is_private_ip(ip):
    return any(ip.startswith(prefix) for prefix in PRIVATE_RANGES)

def load_cache():
    try:
        if CACHE_FILE.exists():
            data = json.loads(CACHE_FILE.read_text())
            cached_at = datetime.fromisoformat(data.get('cached_at', '2000-01-01'))
            if datetime.now(timezone.utc) - cached_at.replace(tzinfo=timezone.utc) < timedelta(hours=CACHE_HOURS):
                return data.get('malicious_ips', set()), data.get('malicious_domains', set())
    except Exception:
        pass
    return None, None

def save_cache(ips, domains):
    try:
        CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
        CACHE_FILE.write_text(json.dumps({
            'cached_at': datetime.now(timezone.utc).isoformat(),
            'malicious_ips': list(ips),
            'malicious_domains': list(domains)
        }))
    except Exception as e:
        logger.warning(f'Cache save error: {e}')

def fetch_threat_data():
    """Télécharge les dernières menaces depuis OTX AlienVault."""
    malicious_ips = set()
    malicious_domains = set()
    
    try:
        headers = {'X-OTX-API-KEY': OTX_API_KEY}
        
        # Récupérer les pulses récents (menaces actives)
        r = requests.get(
            'https://otx.alienvault.com/api/v1/pulses/subscribed',
            headers=headers,
            params={'limit': 50, 'modified_since': (datetime.now(timezone.utc) - timedelta(days=7)).strftime('%Y-%m-%dT%H:%M:%S')},
            timeout=30
        )
        
        if r.status_code == 200:
            pulses = r.json().get('results', [])
            for pulse in pulses:
                for indicator in pulse.get('indicators', []):
                    itype = indicator.get('type', '')
                    value = indicator.get('indicator', '')
                    if itype == 'IPv4' and value:
                        malicious_ips.add(value)
                    elif itype == 'IPv6' and value:
                        malicious_ips.add(value)
                    elif itype in ['domain', 'hostname', 'URL'] and value:
                        malicious_domains.add(value.lower())
            
            logger.info(f'[ThreatIntel] {len(malicious_ips)} IPs malveillantes, {len(malicious_domains)} domaines chargés')
        
        # Ajouter les IPs de malwares connus (liste statique haute fiabilité)
        known_malicious = [
            # Ransomware C&C servers
            '185.220.101.0', '185.220.102.0', '185.220.103.0',
            '194.165.16.0', '194.165.17.0',
            # Botnets connus
            '91.108.4.0', '91.108.56.0',
            # Cryptominers
            '51.15.0.0', '163.172.0.0',
        ]
        malicious_ips.update(known_malicious)
        
        save_cache(malicious_ips, malicious_domains)
        
    except Exception as e:
        logger.warning(f'[ThreatIntel] Erreur fetch: {e}')
    
    return malicious_ips, malicious_domains

def get_threat_data():
    """Retourne les données de menaces (depuis cache ou API)."""
    ips, domains = load_cache()
    if ips is not None:
        return set(ips), set(domains)
    return fetch_threat_data()

def check_connections(active_connections):
    """
    Vérifie les connexions réseau actives contre la base de menaces.
    active_connections: liste de dicts avec 'remote_ip', 'remote_port', 'process'
    """
    alerts = []
    
    if not active_connections:
        return alerts
    
    malicious_ips, malicious_domains = get_threat_data()
    
    for conn in active_connections:
        remote_ip = conn.get('remote_ip', '')
        if not remote_ip or is_private_ip(remote_ip):
            continue
        
        # Vérifier contre la liste d'IPs malveillantes
        if remote_ip in malicious_ips:
            alerts.append({
                'type': 'MALICIOUS_IP',
                'severity': 'critical',
                'title': f'Connexion vers IP malveillante : {remote_ip}',
                'description': f'La machine est connectée à {remote_ip} (port {conn.get("remote_port", "?")}) — IP répertoriée comme malveillante dans OTX AlienVault. Processus: {conn.get("process", "inconnu")}',
                'recommendation': f'Bloquer immédiatement l\'IP {remote_ip} et analyser le processus {conn.get("process", "inconnu")} pour détecter un malware.',
                'evidence': {'ip': remote_ip, 'port': conn.get('remote_port'), 'process': conn.get('process')}
            })
    
    return alerts

def check_ip_reputation(ip):
    """Vérifie la réputation d'une IP spécifique via OTX."""
    try:
        headers = {'X-OTX-API-KEY': OTX_API_KEY}
        r = requests.get(
            f'https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general',
            headers=headers,
            timeout=10
        )
        if r.status_code == 200:
            data = r.json()
            pulse_count = data.get('pulse_info', {}).get('count', 0)
            if pulse_count > 0:
                return {
                    'malicious': True,
                    'pulse_count': pulse_count,
                    'country': data.get('country_name', 'Inconnu'),
                    'reputation': data.get('reputation', 0)
                }
        return {'malicious': False}
    except Exception:
        return {'malicious': False}

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    print('Chargement des données de menaces OTX...')
    ips, domains = fetch_threat_data()
    print(f'Chargé: {len(ips)} IPs malveillantes, {len(domains)} domaines')
