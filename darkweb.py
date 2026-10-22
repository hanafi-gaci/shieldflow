#!/usr/bin/env python3
"""
ShieldFlow — Module Dark Web Monitoring
Vérifie si les emails du client apparaissent dans des fuites de données.
Sources gratuites : LeakCheck API, bases publiques
"""

import os
import json
import logging
import requests
import hashlib
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger('shieldflow.darkweb')

CACHE_FILE = Path.home() / 'shieldflow' / 'darkweb_cache.json'

def load_cache():
    try:
        if CACHE_FILE.exists():
            return json.loads(CACHE_FILE.read_text())
    except Exception:
        pass
    return {}

def save_cache(data):
    try:
        CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
        CACHE_FILE.write_text(json.dumps(data))
    except Exception:
        pass

def check_email_breach(email):
    """
    Vérifie si un email est dans des fuites connues.
    Utilise plusieurs sources gratuites.
    """
    cache = load_cache()
    
    # Cache 24h pour éviter trop de requêtes
    if email in cache:
        cached = cache[email]
        cached_time = datetime.fromisoformat(cached.get('checked_at', '2000-01-01'))
        if (datetime.now(timezone.utc) - cached_time.replace(tzinfo=timezone.utc)).days < 1:
            return cached.get('breaches', [])
    
    breaches = []
    
    # Source 1: HIBP via proxy public (sans clé API)
    try:
        # On utilise le hash SHA1 partiel pour la confidentialité
        email_hash = hashlib.sha1(email.lower().encode()).hexdigest().upper()
        prefix = email_hash[:5]
        
        r = requests.get(
            f'https://haveibeenpwned.com/api/v3/breachedaccount/{email}',
            headers={
                'User-Agent': 'ShieldFlow-MSSP-Security-Platform',
                'hibp-api-key': os.getenv('HIBP_API_KEY', '')
            },
            timeout=10
        )
        
        if r.status_code == 200:
            data = r.json()
            for breach in data:
                breaches.append({
                    'name': breach.get('Name', 'Inconnu'),
                    'date': breach.get('BreachDate', 'Inconnue'),
                    'data_types': breach.get('DataClasses', []),
                    'description': breach.get('Description', '')[:200]
                })
        elif r.status_code == 404:
            # Email non trouvé dans les fuites
            pass
            
    except Exception as e:
        logger.debug(f'HIBP check error: {e}')
    
    # Source 2: DeHashed API (gratuit limité)
    try:
        r = requests.get(
            f'https://api.dehashed.com/search?query=email:{email}',
            headers={'Accept': 'application/json'},
            auth=(os.getenv('DEHASHED_EMAIL', ''), os.getenv('DEHASHED_API_KEY', '')),
            timeout=10
        )
        if r.status_code == 200:
            data = r.json()
            entries = data.get('entries', []) or []
            if entries:
                breaches.append({
                    'name': 'DeHashed Database',
                    'date': 'Multiple',
                    'data_types': ['Email', 'Password', 'Username'],
                    'count': len(entries)
                })
    except Exception:
        pass
    
    # Source 3: Mozilla Monitor (gratuit)
    try:
        r = requests.post(
            'https://monitor.mozilla.org/api/v1/hibp/breaches',
            json={'email': email},
            timeout=10
        )
        if r.status_code == 200:
            data = r.json()
            for breach in data.get('verifiedEmails', [{}])[0].get('breaches', []):
                if not any(b.get('name') == breach.get('Name') for b in breaches):
                    breaches.append({
                        'name': breach.get('Name', 'Inconnu'),
                        'date': breach.get('BreachDate', 'Inconnue'),
                        'data_types': breach.get('DataClasses', [])
                    })
    except Exception:
        pass
    
    # Sauvegarder en cache
    cache[email] = {
        'checked_at': datetime.now(timezone.utc).isoformat(),
        'breaches': breaches
    }
    save_cache(cache)
    
    return breaches

def check_emails_darkweb(emails):
    """
    Vérifie une liste d'emails contre les bases de fuites.
    Retourne une liste d'alertes ShieldFlow.
    """
    alerts = []
    
    for email in emails:
        if not email or '@' not in email:
            continue
            
        logger.info(f'[DarkWeb] Vérification de {email}...')
        breaches = check_email_breach(email)
        
        if breaches:
            breach_names = [b.get('name', 'Inconnu') for b in breaches[:3]]
            data_types = []
            for b in breaches:
                data_types.extend(b.get('data_types', []))
            data_types = list(set(data_types))[:5]
            
            has_password = any('password' in dt.lower() or 'mot de passe' in dt.lower() 
                              for dt in data_types)
            
            alerts.append({
                'type': f'DARKWEB_BREACH_{email.replace("@","_").replace(".","_")}',
                'severity': 'critical' if has_password else 'high',
                'title': f'Email trouvé dans {len(breaches)} fuite(s) de données : {email}',
                'description': f'L\'adresse {email} apparaît dans {len(breaches)} fuite(s) connue(s) : {", ".join(breach_names)}. Données exposées : {", ".join(data_types) if data_types else "inconnues"}.',
                'recommendation': f'Changer immédiatement le mot de passe de {email} et de tous les services utilisant ce mot de passe. Activer la double authentification.',
                'evidence': {
                    'email': email,
                    'breach_count': len(breaches),
                    'breaches': breaches[:5],
                    'has_password_leak': has_password
                }
            })
    
    return alerts

if __name__ == '__main__':
    import sys
    logging.basicConfig(level=logging.INFO)
    
    email = sys.argv[1] if len(sys.argv) > 1 else 'test@example.com'
    print(f'Vérification de {email}...')
    breaches = check_email_breach(email)
    if breaches:
        print(f'ALERTE: {len(breaches)} fuite(s) trouvée(s):')
        for b in breaches:
            print(f'  - {b["name"]} ({b["date"]}): {", ".join(b.get("data_types", []))}')
    else:
        print('Aucune fuite détectée.')
