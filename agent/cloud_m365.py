#!/usr/bin/env python3
"""
ShieldFlow — Agent Cloud Microsoft 365
Surveille la sécurité Microsoft 365 d'un client.
Nécessite : pip3 install msal requests
"""

import os
import sys
import logging
import requests
from datetime import datetime, timezone, timedelta

logger = logging.getLogger('shieldflow.cloud.m365')

def check_m365_security(tenant_id, client_id, client_secret):
    """
    Analyse complète de la sécurité Microsoft 365.
    """
    alerts = []
    
    try:
        token = _get_token(tenant_id, client_id, client_secret)
        if not token:
            return [{'type': 'AUTH_ERROR', 'severity': 'medium',
                    'title': 'Authentification M365 échouée',
                    'description': 'Impossible de se connecter à Microsoft 365.',
                    'recommendation': 'Vérifier les credentials Azure AD.'}]
        
        alerts.extend(_check_users_mfa(token))
        alerts.extend(_check_risky_signins(token))
        alerts.extend(_check_external_sharing(token))
        alerts.extend(_check_admin_accounts(token))
        alerts.extend(_check_inactive_users(token))
        
    except Exception as e:
        logger.error(f"Erreur M365: {e}")
    
    return alerts


def _get_token(tenant_id, client_id, client_secret):
    """Obtenir un token Microsoft Graph."""
    url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    data = {
        'grant_type': 'client_credentials',
        'client_id': client_id,
        'client_secret': client_secret,
        'scope': 'https://graph.microsoft.com/.default'
    }
    try:
        r = requests.post(url, data=data, timeout=10)
        return r.json().get('access_token')
    except Exception as e:
        logger.error(f"Token error: {e}")
        return None


def _graph_get(token, endpoint, params=None):
    """Appel Microsoft Graph API."""
    headers = {'Authorization': f'Bearer {token}', 'Content-Type': 'application/json'}
    try:
        r = requests.get(f"https://graph.microsoft.com/v1.0/{endpoint}",
                        headers=headers, params=params, timeout=15)
        if r.status_code == 200:
            return r.json()
        return None
    except Exception:
        return None


def _check_users_mfa(token):
    """Vérifie les utilisateurs sans MFA."""
    alerts = []
    try:
        users = _graph_get(token, 'users', {'$select': 'displayName,userPrincipalName,accountEnabled'})
        if not users:
            return alerts
            
        for user in users.get('value', []):
            if not user.get('accountEnabled'):
                continue
            upn = user['userPrincipalName']
            
            # Vérifier méthodes d'auth
            auth = _graph_get(token, f"users/{upn}/authentication/methods")
            if auth:
                methods = auth.get('value', [])
                has_mfa = any(
                    m.get('@odata.type', '') not in [
                        '#microsoft.graph.passwordAuthenticationMethod'
                    ] for m in methods
                )
                if not has_mfa:
                    alerts.append({
                        'type': f'M365_NO_MFA_{upn}',
                        'severity': 'high',
                        'title': f'Utilisateur M365 sans MFA : {user["displayName"]}',
                        'description': f'Le compte "{upn}" n\'a pas de double authentification activée.',
                        'recommendation': 'Activer MFA dans Azure AD > Sécurité > Authentification multifacteur.',
                        'evidence': {'user': upn, 'mfa': False}
                    })
    except Exception as e:
        logger.warning(f"MFA check error: {e}")
    return alerts


def _check_risky_signins(token):
    """Vérifie les connexions à risque."""
    alerts = []
    try:
        signins = _graph_get(token, 'identityProtection/riskyUsers',
                            {'$filter': "riskLevel eq 'high' or riskLevel eq 'medium'"})
        if not signins:
            return alerts
            
        for user in signins.get('value', []):
            risk = user.get('riskLevel', 'unknown')
            alerts.append({
                'type': f'M365_RISKY_USER_{user["id"]}',
                'severity': 'critical' if risk == 'high' else 'high',
                'title': f'Compte M365 à risque : {user.get("userDisplayName", "Unknown")}',
                'description': f'Connexion suspecte détectée (risque: {risk}). Possible compromission de compte.',
                'recommendation': 'Forcer la réinitialisation du mot de passe et activer MFA immédiatement.',
                'evidence': {'user': user.get('userPrincipalName'), 'risk_level': risk}
            })
    except Exception as e:
        logger.warning(f"Risky signins error: {e}")
    return alerts


def _check_external_sharing(token):
    """Vérifie les partages externes SharePoint/OneDrive."""
    alerts = []
    try:
        sites = _graph_get(token, 'sites', {'$select': 'id,displayName,webUrl'})
        if not sites:
            return alerts
            
        for site in sites.get('value', [])[:10]:
            site_id = site['id']
            permissions = _graph_get(token, f"sites/{site_id}/permissions")
            if not permissions:
                continue
                
            for perm in permissions.get('value', []):
                roles = perm.get('roles', [])
                granted_to = perm.get('grantedToIdentitiesV2', [])
                
                for identity in granted_to:
                    user = identity.get('user', {})
                    if user and 'external' in user.get('displayName', '').lower():
                        alerts.append({
                            'type': f'M365_EXTERNAL_SHARE_{site_id}',
                            'severity': 'medium',
                            'title': f'Partage externe détecté : {site["displayName"]}',
                            'description': f'Le site SharePoint "{site["displayName"]}" est partagé avec des utilisateurs externes.',
                            'recommendation': 'Vérifier et restreindre les partages externes dans SharePoint Admin.',
                            'evidence': {'site': site['displayName'], 'url': site['webUrl']}
                        })
                        break
    except Exception as e:
        logger.warning(f"External sharing error: {e}")
    return alerts


def _check_admin_accounts(token):
    """Vérifie les comptes administrateurs."""
    alerts = []
    try:
        admins = _graph_get(token, 'directoryRoles/roleTemplateId=62e90394-69f5-4237-9190-012177145e10/members')
        if not admins:
            return alerts
            
        admin_list = admins.get('value', [])
        if len(admin_list) > 3:
            alerts.append({
                'type': 'M365_TOO_MANY_ADMINS',
                'severity': 'medium',
                'title': f'Trop de comptes admin M365 : {len(admin_list)}',
                'description': f'{len(admin_list)} comptes ont les droits Global Administrator. Principe du moindre privilège non respecté.',
                'recommendation': 'Réduire le nombre d\'admins globaux à 2-3 maximum.',
                'evidence': {'admin_count': len(admin_list)}
            })
    except Exception as e:
        logger.warning(f"Admin check error: {e}")
    return alerts


def _check_inactive_users(token):
    """Vérifie les utilisateurs inactifs depuis 90 jours."""
    alerts = []
    try:
        cutoff = (datetime.now(timezone.utc) - timedelta(days=90)).strftime('%Y-%m-%dT%H:%M:%SZ')
        users = _graph_get(token, 'users',
                          {'$filter': f"signInActivity/lastSignInDateTime le {cutoff}",
                           '$select': 'displayName,userPrincipalName,signInActivity'})
        if not users:
            return alerts
            
        for user in users.get('value', [])[:10]:
            upn = user['userPrincipalName']
            last_signin = user.get('signInActivity', {}).get('lastSignInDateTime', 'Jamais')
            alerts.append({
                'type': f'M365_INACTIVE_{upn}',
                'severity': 'low',
                'title': f'Compte M365 inactif : {user["displayName"]}',
                'description': f'"{upn}" ne s\'est pas connecté depuis plus de 90 jours (dernière connexion: {last_signin}).',
                'recommendation': 'Désactiver ou supprimer ce compte. Risque RGPD Art.25.',
                'evidence': {'user': upn, 'last_signin': last_signin}
            })
    except Exception as e:
        logger.warning(f"Inactive users error: {e}")
    return alerts


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    tenant_id = os.getenv('M365_TENANT_ID', '')
    client_id = os.getenv('M365_CLIENT_ID', '')
    client_secret = os.getenv('M365_CLIENT_SECRET', '')
    
    if not all([tenant_id, client_id, client_secret]):
        print("Usage: M365_TENANT_ID=xxx M365_CLIENT_ID=yyy M365_CLIENT_SECRET=zzz python3 cloud_m365.py")
        sys.exit(1)
    
    print("Analyse Microsoft 365 en cours...")
    alerts = check_m365_security(tenant_id, client_id, client_secret)
    print(f"\n{len(alerts)} alerte(s) trouvée(s):")
    for a in alerts:
        print(f"  [{a['severity'].upper()}] {a['title']}")
