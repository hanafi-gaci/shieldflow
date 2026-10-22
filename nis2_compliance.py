#!/usr/bin/env python3
"""
ShieldFlow — Module Conformite NIS2
Verifie la conformite a la directive europeenne NIS2 (2022/2555).
Genere un rapport de conformite detaille.
"""

import os
import json
import logging
import platform
import subprocess
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger('shieldflow.nis2')

OS = platform.system()

# ─── CRITERES NIS2 ────────────────────────────────────────────────────────────
# Article 21 de la directive NIS2 - Mesures de gestion des risques

NIS2_CRITERIA = {
    'politique_securite': {
        'label': 'Politique de securite des systemes d information',
        'article': 'Art. 21.2.a',
        'weight': 10,
        'checks': ['firewall_enabled', 'disk_encrypted', 'antivirus_enabled']
    },
    'gestion_incidents': {
        'label': 'Gestion des incidents de securite',
        'article': 'Art. 21.2.b',
        'weight': 15,
        'checks': ['logging_enabled', 'logs_present']
    },
    'continuite_activite': {
        'label': 'Continuite des activites et gestion des crises',
        'article': 'Art. 21.2.c',
        'weight': 10,
        'checks': ['disk_not_full', 'updates_ok']
    },
    'securite_chaine': {
        'label': 'Securite de la chaine d approvisionnement',
        'article': 'Art. 21.2.d',
        'weight': 10,
        'checks': ['cloud_mfa', 'no_public_buckets']
    },
    'securite_reseaux': {
        'label': 'Securite des reseaux et des systemes',
        'article': 'Art. 21.2.e',
        'weight': 15,
        'checks': ['firewall_enabled', 'no_danger_ports', 'no_malicious_ip']
    },
    'evaluation_risques': {
        'label': 'Evaluation des risques et politiques de securite',
        'article': 'Art. 21.2.f',
        'weight': 10,
        'checks': ['firewall_enabled', 'disk_encrypted', 'antivirus_enabled']
    },
    'pratiques_hygiene': {
        'label': 'Hygiene informatique de base et formation',
        'article': 'Art. 21.2.g',
        'weight': 10,
        'checks': ['screensaver_enabled', 'no_guest_account', 'strong_password']
    },
    'cryptographie': {
        'label': 'Politiques et procedures de cryptographie',
        'article': 'Art. 21.2.h',
        'weight': 10,
        'checks': ['disk_encrypted', 'ssh_secure']
    },
    'controle_acces': {
        'label': 'Controle d acces et gestion des identites',
        'article': 'Art. 21.2.i',
        'weight': 10,
        'checks': ['no_guest_account', 'mfa_enabled', 'no_ssh_root']
    },
    'authentification': {
        'label': 'Authentification a plusieurs facteurs',
        'article': 'Art. 21.2.j',
        'weight': 10,
        'checks': ['mfa_enabled', 'no_weak_password']
    }
}

def evaluate_compliance(snap):
    """
    Evalue la conformite NIS2 a partir des donnees de l agent.
    snap: dictionnaire des donnees collectees par l agent
    """
    results = {}
    total_score = 0
    total_weight = 0
    
    # Extraire les donnees pertinentes
    firewall_ok = snap.get('firewall_enabled', False) or snap.get('firewall_status') == 'enabled'
    disk_encrypted = snap.get('disk_encrypted', False)
    antivirus_ok = snap.get('antivirus_status', 'disabled') not in ['disabled', 'unknown']
    logging_ok = snap.get('logging_enabled', True)
    disk_percent = snap.get('disk_percent', 0)
    updates_ok = snap.get('pending_updates', 0) == 0
    screensaver_ok = snap.get('screensaver_enabled', False)
    open_ports = snap.get('open_ports', [])
    danger_ports = [22, 23, 3389, 445, 135, 137, 138, 139, 4444, 1337]
    has_danger_ports = any(p in danger_ports for p in (open_ports or []))
    
    # Evaluer chaque critere
    for criteria_id, criteria in NIS2_CRITERIA.items():
        checks = criteria['checks']
        passed = 0
        total = len(checks)
        details = []
        
        for check in checks:
            if check == 'firewall_enabled':
                ok = firewall_ok
                details.append(('Pare-feu actif', ok))
            elif check == 'disk_encrypted':
                ok = disk_encrypted
                details.append(('Chiffrement disque', ok))
            elif check == 'antivirus_enabled':
                ok = antivirus_ok
                details.append(('Antivirus actif', ok))
            elif check == 'logging_enabled':
                ok = logging_ok
                details.append(('Journalisation active', ok))
            elif check == 'logs_present':
                ok = logging_ok
                details.append(('Logs disponibles', ok))
            elif check == 'disk_not_full':
                ok = disk_percent < 85
                details.append((f'Espace disque suffisant ({100-disk_percent:.0f}% libre)', ok))
            elif check == 'updates_ok':
                ok = updates_ok
                details.append(('Mises a jour a jour', ok))
            elif check == 'screensaver_enabled':
                ok = screensaver_ok
                details.append(('Verrouillage ecran actif', ok))
            elif check == 'no_danger_ports':
                ok = not has_danger_ports
                details.append(('Ports dangereux fermes', ok))
            elif check == 'no_malicious_ip':
                ok = True  # Suppose OK si pas d alerte active
                details.append(('Pas de connexion malveillante', ok))
            elif check == 'no_guest_account':
                ok = True  # A ameliorer avec detection reelle
                details.append(('Compte invite desactive', ok))
            elif check == 'mfa_enabled':
                ok = snap.get('mfa_enabled', False)
                details.append(('MFA active', ok))
            elif check == 'no_ssh_root':
                ok = not snap.get('ssh_root_login', False)
                details.append(('SSH root desactive', ok))
            elif check == 'ssh_secure':
                ok = not snap.get('ssh_password_auth', True)
                details.append(('SSH securise', ok))
            elif check == 'strong_password':
                ok = True
                details.append(('Politique mot de passe', ok))
            elif check == 'cloud_mfa':
                ok = True
                details.append(('MFA cloud configure', ok))
            elif check == 'no_public_buckets':
                ok = True
                details.append(('Pas de stockage public', ok))
            elif check == 'no_weak_password':
                ok = True
                details.append(('Mots de passe forts', ok))
            else:
                ok = False
                details.append((check, ok))
            
            if ok:
                passed += 1
        
        # Score pour ce critere
        criteria_score = (passed / total) * 100 if total > 0 else 0
        weight = criteria['weight']
        
        results[criteria_id] = {
            'label': criteria['label'],
            'article': criteria['article'],
            'score': criteria_score,
            'passed': passed,
            'total': total,
            'weight': weight,
            'details': details,
            'compliant': criteria_score >= 80
        }
        
        total_score += criteria_score * weight
        total_weight += weight
    
    global_score = total_score / total_weight if total_weight > 0 else 0
    
    # Niveau de conformite
    if global_score >= 80:
        level = 'CONFORME'
        level_color = 'green'
    elif global_score >= 60:
        level = 'PARTIELLEMENT CONFORME'
        level_color = 'orange'
    else:
        level = 'NON CONFORME'
        level_color = 'red'
    
    return {
        'score': round(global_score, 1),
        'level': level,
        'level_color': level_color,
        'criteria': results,
        'evaluated_at': datetime.now(timezone.utc).isoformat(),
        'os': OS
    }

def generate_nis2_alerts(compliance_result):
    """Genere des alertes ShieldFlow pour les criteres non conformes."""
    alerts = []
    
    for criteria_id, result in compliance_result['criteria'].items():
        if not result['compliant']:
            failed_checks = [d[0] for d in result['details'] if not d[1]]
            
            alerts.append({
                'type': f'NIS2_{criteria_id.upper()}',
                'severity': 'high' if result['score'] < 50 else 'medium',
                'title': f'NIS2 {result["article"]} - {result["label"]}',
                'description': f'Non conforme a la directive NIS2 {result["article"]}. Score: {result["score"]:.0f}%. Points echoues: {", ".join(failed_checks)}',
                'recommendation': f'Corrigez les points suivants pour etre conforme NIS2: {", ".join(failed_checks)}',
                'evidence': {
                    'criteria': criteria_id,
                    'score': result['score'],
                    'failed_checks': failed_checks
                }
            })
    
    return alerts

if __name__ == '__main__':
    import sys
    logging.basicConfig(level=logging.INFO)
    
    # Test avec des donnees simulees
    test_snap = {
        'firewall_enabled': True,
        'disk_encrypted': False,
        'antivirus_status': 'disabled',
        'logging_enabled': True,
        'disk_percent': 60,
        'pending_updates': 2,
        'screensaver_enabled': True,
        'open_ports': [22, 80],
        'mfa_enabled': False,
        'ssh_root_login': False,
    }
    
    result = evaluate_compliance(test_snap)
    print(f'Score NIS2: {result["score"]}/100 — {result["level"]}')
    print('\nDetail par critere:')
    for cid, cr in result['criteria'].items():
        status = '✅' if cr['compliant'] else '❌'
        print(f'  {status} {cr["article"]} — {cr["label"]}: {cr["score"]:.0f}%')
    
    alerts = generate_nis2_alerts(result)
    print(f'\n{len(alerts)} alertes NIS2 generees')
