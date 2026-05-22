#!/usr/bin/env python3
"""
ShieldFlow — Agent Cloud Google Workspace
Surveille la sécurité Google Workspace d'un client.
Nécessite : pip3 install google-auth google-auth-httplib2 google-api-python-client
"""

import os
import sys
import logging
from datetime import datetime, timezone, timedelta

logger = logging.getLogger('shieldflow.cloud.gworkspace')

def check_gworkspace_security(credentials_json, admin_email):
    """
    Analyse complète de la sécurité Google Workspace.
    credentials_json : chemin vers le fichier JSON du compte de service
    admin_email : email de l'administrateur (pour impersonation)
    """
    alerts = []
    
    try:
        from google.oauth2 import service_account
        from googleapiclient.discovery import build
        
        SCOPES = [
            'https://www.googleapis.com/auth/admin.directory.user.readonly',
            'https://www.googleapis.com/auth/admin.directory.domain.readonly',
            'https://www.googleapis.com/auth/admin.reports.audit.readonly',
        ]
        
        credentials = service_account.Credentials.from_service_account_file(
            credentials_json, scopes=SCOPES
        ).with_subject(admin_email)
        
        service = build('admin', 'directory_v1', credentials=credentials)
        reports = build('admin', 'reports_v1', credentials=credentials)
        
        alerts.extend(_check_users_2fa(service))
        alerts.extend(_check_inactive_users(service))
        alerts.extend(_check_external_apps(service))
        alerts.extend(_check_suspicious_activity(reports, admin_email))
        
    except ImportError:
        logger.error("google-auth non installé")
        alerts.append({
            'type': 'CONFIG_ERROR',
            'severity': 'medium',
            'title': 'Module Google Workspace non installé',
            'description': 'google-auth requis pour la surveillance Google Workspace.',
            'recommendation': 'pip3 install google-auth google-auth-httplib2 google-api-python-client'
        })
    except Exception as e:
        logger.error(f"Erreur Google Workspace: {e}")
    
    return alerts


def _check_users_2fa(service):
    """Vérifie les utilisateurs sans 2FA."""
    alerts = []
    try:
        result = service.users().list(
            customer='my_customer',
            maxResults=200,
            orderBy='email',
            projection='full'
        ).execute()
        
        for user in result.get('users', []):
            email = user.get('primaryEmail', '')
            is_enrolled = user.get('isEnrolledIn2Sv', False)
            is_enforced = user.get('isEnforcedIn2Sv', False)
            suspended = user.get('suspended', False)
            
            if suspended:
                continue
                
            if not is_enrolled:
                alerts.append({
                    'type': f'GWS_NO_2FA_{email}',
                    'severity': 'high',
                    'title': f'Utilisateur Google Workspace sans 2FA : {email}',
                    'description': f'Le compte "{email}" n\'a pas activé la double authentification.',
                    'recommendation': 'Forcer la 2FA dans Google Admin > Sécurité > Authentification.',
                    'evidence': {'email': email, '2fa': False}
                })
                
    except Exception as e:
        logger.warning(f"2FA check error: {e}")
    return alerts


def _check_inactive_users(service):
    """Vérifie les utilisateurs inactifs."""
    alerts = []
    try:
        result = service.users().list(
            customer='my_customer',
            maxResults=200,
            orderBy='lastLoginTime',
            projection='full'
        ).execute()
        
        cutoff = datetime.now(timezone.utc) - timedelta(days=90)
        
        for user in result.get('users', []):
            email = user.get('primaryEmail', '')
            last_login = user.get('lastLoginTime', '')
            suspended = user.get('suspended', False)
            is_admin = user.get('isAdmin', False)
            
            if suspended or is_admin:
                continue
            
            if last_login:
                last_login_dt = datetime.fromisoformat(last_login.replace('Z', '+00:00'))
                if last_login_dt < cutoff:
                    days_inactive = (datetime.now(timezone.utc) - last_login_dt).days
                    alerts.append({
                        'type': f'GWS_INACTIVE_{email}',
                        'severity': 'low',
                        'title': f'Compte Google inactif : {email} ({days_inactive}j)',
                        'description': f'Le compte "{email}" n\'est pas connecté depuis {days_inactive} jours.',
                        'recommendation': 'Désactiver ou supprimer ce compte. Risque RGPD Art.25.',
                        'evidence': {'email': email, 'days_inactive': days_inactive}
                    })
                    
    except Exception as e:
        logger.warning(f"Inactive users error: {e}")
    return alerts


def _check_external_apps(service):
    """Vérifie les applications tierces avec accès aux données."""
    alerts = []
    try:
        result = service.users().list(
            customer='my_customer',
            maxResults=50,
            projection='basic'
        ).execute()
        
        for user in result.get('users', [])[:10]:
            email = user.get('primaryEmail', '')
            try:
                tokens = service.tokens().list(userKey=email).execute()
                risky_apps = []
                
                for token in tokens.get('items', []):
                    scopes = token.get('scopes', [])
                    app_name = token.get('displayText', 'Unknown App')
                    
                    risky_scopes = [s for s in scopes if any(risk in s for risk in [
                        'mail.google.com',
                        'drive',
                        'admin',
                        'contacts',
                        'calendar'
                    ])]
                    
                    if risky_scopes:
                        risky_apps.append(app_name)
                
                if len(risky_apps) > 5:
                    alerts.append({
                        'type': f'GWS_TOO_MANY_APPS_{email}',
                        'severity': 'medium',
                        'title': f'Trop d\'apps tierces : {email} ({len(risky_apps)} apps)',
                        'description': f'{len(risky_apps)} applications tierces ont accès aux données Google de "{email}".',
                        'recommendation': 'Révoquer les accès inutiles dans Google Account > Sécurité > Apps tierces.',
                        'evidence': {'email': email, 'app_count': len(risky_apps), 'apps': risky_apps[:5]}
                    })
            except Exception:
                continue
                
    except Exception as e:
        logger.warning(f"External apps error: {e}")
    return alerts


def _check_suspicious_activity(reports, admin_email):
    """Vérifie les activités suspectes dans les logs Google."""
    alerts = []
    try:
        from datetime import datetime, timezone, timedelta
        start_time = (datetime.now(timezone.utc) - timedelta(days=7)).strftime('%Y-%m-%dT%H:%M:%SZ')
        
        result = reports.activities().list(
            userKey='all',
            applicationName='login',
            eventName='login_failure',
            startTime=start_time,
            maxResults=100
        ).execute()
        
        failures = result.get('items', [])
        
        # Regrouper par utilisateur
        failure_counts = {}
        for item in failures:
            actor = item.get('actor', {}).get('email', 'unknown')
            failure_counts[actor] = failure_counts.get(actor, 0) + 1
        
        for email, count in failure_counts.items():
            if count > 10:
                alerts.append({
                    'type': f'GWS_BRUTE_FORCE_{email}',
                    'severity': 'high' if count > 50 else 'medium',
                    'title': f'Tentatives de connexion échouées : {email} ({count})',
                    'description': f'{count} tentatives de connexion échouées sur "{email}" ces 7 derniers jours.',
                    'recommendation': 'Vérifier si le compte est ciblé. Forcer MFA et changer le mot de passe.',
                    'evidence': {'email': email, 'failure_count': count}
                })
                
    except Exception as e:
        logger.warning(f"Suspicious activity error: {e}")
    return alerts


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    
    creds = os.getenv('GWS_CREDENTIALS_FILE', '')
    admin = os.getenv('GWS_ADMIN_EMAIL', '')
    
    if not creds or not admin:
        print("Usage: GWS_CREDENTIALS_FILE=/path/to/creds.json GWS_ADMIN_EMAIL=admin@domain.com python3 cloud_gworkspace.py")
        sys.exit(1)
    
    print("Analyse Google Workspace en cours...")
    alerts = check_gworkspace_security(creds, admin)
    print(f"\n{len(alerts)} alerte(s) trouvée(s):")
    for a in alerts:
        print(f"  [{a['severity'].upper()}] {a['title']}")
