#!/usr/bin/env python3
"""
ShieldFlow — Module CVE Scanner
Detecte les vulnerabilites connues sur les logiciels installes.
Source : NVD (National Vulnerability Database) - GRATUIT
"""

import os
import json
import logging
import requests
import subprocess
import platform
from datetime import datetime, timezone, timedelta
from pathlib import Path

logger = logging.getLogger('shieldflow.cve')

CACHE_FILE = Path.home() / 'shieldflow' / 'cve_cache.json'
NVD_API_KEY = os.getenv('NVD_API_KEY', '')
CACHE_HOURS = 12

OS = platform.system()

def get_installed_software():
    """Detecte les logiciels installes et leurs versions."""
    software = []
    
    try:
        if OS == 'Darwin':
            # Applications macOS
            r = subprocess.run(
                ['system_profiler', 'SPApplicationsDataType', '-json'],
                capture_output=True, text=True, timeout=30
            )
            if r.returncode == 0:
                data = json.loads(r.stdout)
                apps = data.get('SPApplicationsDataType', [])
                for app in apps[:50]:  # Limiter aux 50 premieres
                    name = app.get('_name', '')
                    version = app.get('version', '')
                    if name and version:
                        software.append({
                            'name': name,
                            'version': version,
                            'type': 'application'
                        })
            
            # Packages Homebrew
            r2 = subprocess.run(['brew', 'list', '--versions'],
                               capture_output=True, text=True, timeout=15)
            if r2.returncode == 0:
                for line in r2.stdout.strip().split('\n'):
                    parts = line.split()
                    if len(parts) >= 2:
                        software.append({
                            'name': parts[0],
                            'version': parts[1],
                            'type': 'brew'
                        })

        elif OS == 'Linux':
            # Packages dpkg
            r = subprocess.run(['dpkg', '-l'],
                              capture_output=True, text=True, timeout=15)
            if r.returncode == 0:
                for line in r.stdout.split('\n'):
                    if line.startswith('ii'):
                        parts = line.split()
                        if len(parts) >= 3:
                            software.append({
                                'name': parts[1],
                                'version': parts[2],
                                'type': 'dpkg'
                            })
            
            # Packages rpm
            r2 = subprocess.run(['rpm', '-qa', '--queryformat', '%{NAME} %{VERSION}\n'],
                               capture_output=True, text=True, timeout=15)
            if r2.returncode == 0:
                for line in r2.stdout.strip().split('\n'):
                    parts = line.split()
                    if len(parts) >= 2:
                        software.append({
                            'name': parts[0],
                            'version': parts[1],
                            'type': 'rpm'
                        })

        elif OS == 'Windows':
            r = subprocess.run(
                ['powershell', 'Get-WmiObject -Class Win32_Product | Select-Object Name,Version | ConvertTo-Json'],
                capture_output=True, text=True, timeout=30, shell=True
            )
            if r.returncode == 0:
                try:
                    apps = json.loads(r.stdout)
                    if isinstance(apps, dict):
                        apps = [apps]
                    for app in apps:
                        if app.get('Name') and app.get('Version'):
                            software.append({
                                'name': app['Name'],
                                'version': app['Version'],
                                'type': 'windows'
                            })
                except Exception:
                    pass

    except Exception as e:
        logger.warning(f'[CVE] Erreur detection logiciels: {e}')
    
    return software

def check_cve_for_software(name, version, max_results=5):
    """Verifie les CVE pour un logiciel specifique via NVD API."""
    try:
        headers = {}
        if NVD_API_KEY:
            headers['apiKey'] = NVD_API_KEY
        
        # Recherche par nom de produit
        params = {
            'keywordSearch': name,
            'resultsPerPage': max_results,
            'cvssV3Severity': 'HIGH',
        }
        
        r = requests.get(
            'https://services.nvd.nist.gov/rest/json/cves/2.0',
            params=params,
            headers=headers,
            timeout=10
        )
        
        if r.status_code == 200:
            data = r.json()
            cves = []
            for item in data.get('vulnerabilities', []):
                cve = item.get('cve', {})
                cve_id = cve.get('id', '')
                
                # Score CVSS
                metrics = cve.get('metrics', {})
                cvss_score = 0
                severity = 'UNKNOWN'
                
                for metric_type in ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']:
                    metric_list = metrics.get(metric_type, [])
                    if metric_list:
                        cvss_data = metric_list[0].get('cvssData', {})
                        cvss_score = cvss_data.get('baseScore', 0)
                        severity = metric_list[0].get('baseSeverity', 
                                   cvss_data.get('baseSeverity', 'UNKNOWN'))
                        break
                
                if cvss_score >= 7.0:  # HIGH et CRITICAL uniquement
                    descriptions = cve.get('descriptions', [])
                    desc = next((d['value'] for d in descriptions if d['language'] == 'en'), '')
                    
                    cves.append({
                        'cve_id': cve_id,
                        'score': cvss_score,
                        'severity': severity,
                        'description': desc[:300],
                        'published': cve.get('published', ''),
                        'software': name,
                        'version': version
                    })
            
            return cves
    
    except Exception as e:
        logger.debug(f'[CVE] Erreur check {name}: {e}')
    
    return []

def load_cache():
    """Charge le cache CVE local."""
    try:
        if CACHE_FILE.exists():
            data = json.loads(CACHE_FILE.read_text())
            cached_at = datetime.fromisoformat(data.get('cached_at', '2000-01-01'))
            if (datetime.now(timezone.utc) - cached_at.replace(tzinfo=timezone.utc)) < timedelta(hours=CACHE_HOURS):
                return data.get('results', {})
    except Exception:
        pass
    return None

def save_cache(results):
    """Sauvegarde les resultats en cache."""
    try:
        CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
        CACHE_FILE.write_text(json.dumps({
            'cached_at': datetime.now(timezone.utc).isoformat(),
            'results': results
        }))
    except Exception as e:
        logger.warning(f'[CVE] Cache save error: {e}')

# Logiciels prioritaires a scanner - les plus utilises en entreprise
PRIORITY_SOFTWARE = [
    'chrome', 'firefox', 'safari', 'edge',
    'office', 'word', 'excel', 'outlook', 'teams',
    'zoom', 'slack', 'discord',
    'java', 'python', 'node', 'php',
    'apache', 'nginx', 'mysql', 'postgresql',
    'openssl', 'openssh',
    'adobe', 'acrobat',
    'filezilla', 'putty', 'winscp',
    'wordpress', 'drupal',
    'docker', 'kubernetes',
    'citrix', 'vmware',
]

def scan_cve(software_list=None):
    """
    Scan CVE complet sur les logiciels installes.
    Retourne une liste d alertes ShieldFlow.
    """
    alerts = []
    
    # Verifier le cache
    cached = load_cache()
    if cached:
        logger.info(f'[CVE] Cache valide - {len(cached)} resultats')
        return _build_alerts_from_cache(cached)
    
    # Detecter les logiciels si non fournis
    if software_list is None:
        software_list = get_installed_software()
    
    logger.info(f'[CVE] Scan de {len(software_list)} logiciels installes...')
    
    # Filtrer les logiciels prioritaires
    priority = [s for s in software_list 
                if any(p in s['name'].lower() for p in PRIORITY_SOFTWARE)]
    
    # Si pas de prioritaire, prendre les 10 premiers
    to_scan = priority[:10] if priority else software_list[:10]
    
    results = {}
    for sw in to_scan:
        name = sw['name']
        version = sw['version']
        
        logger.info(f'[CVE] Verification: {name} {version}')
        cves = check_cve_for_software(name, version)
        
        if cves:
            results[name] = {
                'version': version,
                'cves': cves
            }
            logger.warning(f'[CVE] {name}: {len(cves)} vulnerabilites trouvees !')
    
    # Sauvegarder en cache
    save_cache(results)
    
    return _build_alerts_from_cache(results)

def _build_alerts_from_cache(results):
    """Construit les alertes ShieldFlow a partir des resultats CVE."""
    alerts = []
    
    for software_name, data in results.items():
        cves = data.get('cves', [])
        if not cves:
            continue
        
        # Trouver la CVE la plus critique
        max_score = max(c['score'] for c in cves)
        critical_cves = [c for c in cves if c['score'] >= 9.0]
        high_cves = [c for c in cves if 7.0 <= c['score'] < 9.0]
        
        severity = 'critical' if critical_cves else 'high'
        worst_cves = (critical_cves or high_cves)[:3]
        cve_ids = ', '.join(c['cve_id'] for c in worst_cves)
        
        alerts.append({
            'type': f'CVE_{software_name.upper().replace(" ","_").replace(".","_")[:20]}',
            'severity': severity,
            'title': f'Vulnerabilite critique: {software_name} ({len(cves)} CVE)',
            'description': f'{software_name} version {data["version"]} contient {len(cves)} vulnerabilite(s) connue(s). Score max: {max_score}/10. CVE: {cve_ids}',
            'recommendation': f'Mettez a jour {software_name} immediatement vers la derniere version disponible.',
            'evidence': {
                'software': software_name,
                'version': data['version'],
                'cve_count': len(cves),
                'max_score': max_score,
                'cves': worst_cves
            }
        })
    
    return alerts

if __name__ == '__main__':
    import sys
    logging.basicConfig(level=logging.INFO)
    
    print('Scan CVE en cours...')
    software = get_installed_software()
    print(f'{len(software)} logiciels detectes')
    
    alerts = scan_cve(software)
    if alerts:
        print(f'\nALERTES CVE ({len(alerts)}):')
        for a in alerts:
            print(f'  [{a["severity"].upper()}] {a["title"]}')
    else:
        print('Aucune vulnerabilite critique detectee')
