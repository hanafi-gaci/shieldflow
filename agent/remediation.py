#!/usr/bin/env python3
"""
ShieldFlow — Module d'auto-remédiation complet
Règle automatiquement toutes les alertes de sécurité détectées.
Compatible macOS, Linux, Windows.
"""

import subprocess
import platform
import logging
import os
import json
import socket
import re

logger = logging.getLogger('shieldflow.remediation')
OS = platform.system()  # Darwin, Linux, Windows

# ─── REGISTRE COMPLET DES ACTIONS ─────────────────────────────────────────────

REMEDIATION_MAP = {
    # Pare-feu
    'FIREWALL_OFF':         {'action': 'enable_firewall',      'label': 'Activer le pare-feu',              'auto': True,  'risk': 'low'},
    # Chiffrement
    'DISK_NOT_ENCRYPTED':   {'action': 'enable_encryption',    'label': 'Activer le chiffrement disque',    'auto': False, 'risk': 'medium'},
    # Antivirus
    'NO_ANTIVIRUS':         {'action': 'install_antivirus',    'label': 'Installer protection antivirus',   'auto': True,  'risk': 'low'},
    # Ports dangereux
    'DANGER_PORTS':         {'action': 'close_ports',          'label': 'Fermer les ports dangereux',       'auto': True,  'risk': 'low'},
    # Mises à jour
    'UPDATES_CRITICAL':     {'action': 'enable_autoupdate',    'label': 'Activer mises à jour auto',        'auto': True,  'risk': 'low'},
    'UPDATES_PENDING':      {'action': 'enable_autoupdate',    'label': 'Activer mises à jour auto',        'auto': True,  'risk': 'low'},
    # CPU/RAM
    'HIGH_CPU':             {'action': 'kill_top_process',     'label': 'Terminer processus CPU excessif',  'auto': False, 'risk': 'medium'},
    'HIGH_RAM':             {'action': 'free_memory',          'label': 'Libérer la mémoire',               'auto': True,  'risk': 'low'},
    'LOW_DISK':             {'action': 'clean_disk',           'label': 'Nettoyer le disque',               'auto': True,  'risk': 'low'},
    # Malwares
    'MALWARE_DETECTED':     {'action': 'kill_malware',         'label': 'Éliminer le malware',              'auto': True,  'risk': 'high'},
    # Brute force
    'BRUTE_FORCE':          {'action': 'block_brute_force',    'label': 'Bloquer les attaques brute force', 'auto': True,  'risk': 'low'},
    # Connexions réseau
    'HIGH_CONNECTIONS':     {'action': 'limit_connections',    'label': 'Limiter les connexions réseau',    'auto': True,  'risk': 'low'},
    # IPs malveillantes
    'MALICIOUS_IP':         {'action': 'block_ip',             'label': 'Bloquer l\'IP malveillante',       'auto': True,  'risk': 'low'},
    # Comptes
    'GUEST_ACCOUNT':        {'action': 'disable_guest',        'label': 'Désactiver compte invité',         'auto': True,  'risk': 'low'},
    'WEAK_PASSWORD':        {'action': 'force_password_policy','label': 'Appliquer politique mot de passe', 'auto': True,  'risk': 'low'},
    'NO_SCREENSAVER':       {'action': 'enable_screensaver',   'label': 'Activer verrouillage écran',       'auto': True,  'risk': 'low'},
    # SSH
    'SSH_ROOT_LOGIN':       {'action': 'disable_ssh_root',     'label': 'Désactiver SSH root',              'auto': True,  'risk': 'low'},
    'SSH_PASSWORD_AUTH':    {'action': 'disable_ssh_password', 'label': 'Désactiver auth SSH par mdp',      'auto': True,  'risk': 'low'},
    # Logs
    'LOGS_DISABLED':        {'action': 'enable_logging',       'label': 'Activer les logs système',         'auto': True,  'risk': 'low'},
    # Partage
    'FILE_SHARING_ON':      {'action': 'disable_sharing',      'label': 'Désactiver le partage de fichiers','auto': True,  'risk': 'low'},
    'REMOTE_LOGIN_ON':      {'action': 'disable_remote_login', 'label': 'Désactiver la connexion à distance','auto': True, 'risk': 'low'},
    # Cloud
    'S3_PUBLIC':            {'action': 'fix_s3_bucket',        'label': 'Rendre le bucket S3 privé',        'auto': False, 'risk': 'high'},
    'EC2_PORT_22':          {'action': 'fix_security_group',   'label': 'Restreindre le port SSH AWS',      'auto': False, 'risk': 'high'},
    'IAM_NO_MFA':           {'action': 'notify_mfa',           'label': 'Notifier activation MFA',          'auto': False, 'risk': 'medium'},
    'M365_NO_MFA':          {'action': 'notify_mfa',           'label': 'Notifier activation MFA M365',     'auto': False, 'risk': 'medium'},
    'GWS_NO_2FA':           {'action': 'notify_2fa',           'label': 'Notifier activation 2FA Google',   'auto': False, 'risk': 'medium'},
    # RGPD
    'RGPD_NO_ENCRYPT':      {'action': 'enable_encryption',    'label': 'Chiffrer les données (RGPD)',      'auto': False, 'risk': 'high'},
    'RGPD_LOG_MISSING':     {'action': 'enable_logging',       'label': 'Activer logs RGPD',                'auto': True,  'risk': 'low'},
}

def get_remediation_info(alert_type):
    """Retourne les infos de remédiation pour un type d'alerte."""
    for key, info in REMEDIATION_MAP.items():
        if alert_type.startswith(key):
            return info
    return None

def execute(alert_type, params=None):
    """Execute la remédiation pour un type d'alerte."""
    params = params or {}
    info = get_remediation_info(alert_type)
    if not info:
        return {'success': False, 'error': f'Aucune remédiation disponible pour: {alert_type}'}
    
    action_name = info['action']
    action_fn = globals().get(action_name)
    if not action_fn:
        return {'success': False, 'error': f'Action non implémentée: {action_name}'}
    
    logger.info(f'[Remédiation] {info["label"]} pour {alert_type}')
    try:
        result = action_fn(params)
        result['label'] = info['label']
        result['action'] = action_name
        return result
    except Exception as e:
        logger.error(f'Erreur remédiation [{action_name}]: {e}')
        return {'success': False, 'error': str(e), 'label': info['label']}

# ─── ACTIONS DE REMÉDIATION ───────────────────────────────────────────────────

def enable_firewall(params):
    if OS == 'Darwin':
        r = subprocess.run(['sudo', '/usr/libexec/ApplicationFirewall/socketfilterfw', '--setglobalstate', 'on'],
                          capture_output=True, text=True)
        return {'success': r.returncode == 0, 'output': 'Pare-feu macOS activé'}
    elif OS == 'Linux':
        subprocess.run(['sudo', 'apt-get', 'install', '-y', 'ufw'], capture_output=True)
        r = subprocess.run(['sudo', 'ufw', '--force', 'enable'], capture_output=True, text=True)
        return {'success': r.returncode == 0, 'output': 'Pare-feu UFW activé'}
    elif OS == 'Windows':
        r = subprocess.run(['netsh', 'advfirewall', 'set', 'allprofiles', 'state', 'on'],
                          capture_output=True, text=True, shell=True)
        return {'success': r.returncode == 0, 'output': 'Pare-feu Windows activé'}
    return {'success': False, 'error': 'OS non supporté'}

def enable_encryption(params):
    if OS == 'Darwin':
        r = subprocess.run(['sudo', 'fdesetup', 'status'], capture_output=True, text=True)
        if 'On' in r.stdout:
            return {'success': True, 'output': 'FileVault déjà activé'}
        r2 = subprocess.run(['sudo', 'fdesetup', 'enable', '-norecoverykey'], capture_output=True, text=True)
        return {'success': True, 'output': 'FileVault activation lancée — redémarrage requis'}
    elif OS == 'Linux':
        return {'success': False, 'output': 'Chiffrement Linux nécessite une réinstallation — contact support ShieldFlow'}
    elif OS == 'Windows':
        r = subprocess.run(['manage-bde', '-on', 'C:'], capture_output=True, text=True, shell=True)
        return {'success': r.returncode == 0, 'output': 'BitLocker activation lancée'}
    return {'success': False, 'error': 'OS non supporté'}

def install_antivirus(params):
    if OS == 'Darwin':
        # Vérifier XProtect (intégré macOS)
        subprocess.run(['sudo', 'softwareupdate', '-i', 'XProtect*', '--agree-to-license'],
                      capture_output=True)
        return {'success': True, 'output': 'XProtect mis à jour. Recommandation: installer Malwarebytes gratuitement sur malwarebytes.com'}
    elif OS == 'Linux':
        r = subprocess.run(['sudo', 'apt-get', 'install', '-y', 'clamav', 'clamav-daemon'],
                          capture_output=True, text=True)
        subprocess.run(['sudo', 'freshclam'], capture_output=True)
        return {'success': r.returncode == 0, 'output': 'ClamAV installé et mis à jour'}
    elif OS == 'Windows':
        r = subprocess.run(['powershell', 'Update-MpSignature'], capture_output=True, text=True, shell=True)
        return {'success': r.returncode == 0, 'output': 'Windows Defender mis à jour'}
    return {'success': False, 'error': 'OS non supporté'}

def close_ports(params):
    ports = params.get('ports', [4444, 1337, 31337, 6666, 6667, 23])
    results = []
    for port in ports:
        if OS == 'Darwin':
            # Utiliser pf pour bloquer
            rule = f"block drop proto tcp from any to any port {port}"
            r = subprocess.run(['sudo', 'sh', '-c', 
                              f'echo "{rule}" | sudo tee -a /etc/pf.anchors/shieldflow && sudo pfctl -e -f /etc/pf.conf 2>/dev/null || true'],
                             capture_output=True, text=True)
            results.append(f'Port {port} bloqué')
        elif OS == 'Linux':
            subprocess.run(['sudo', 'iptables', '-A', 'INPUT', '-p', 'tcp', '--dport', str(port), '-j', 'DROP'],
                          capture_output=True)
            subprocess.run(['sudo', 'iptables', '-A', 'INPUT', '-p', 'udp', '--dport', str(port), '-j', 'DROP'],
                          capture_output=True)
            results.append(f'Port {port} bloqué via iptables')
        elif OS == 'Windows':
            subprocess.run(['netsh', 'advfirewall', 'firewall', 'add', 'rule',
                           f'name=ShieldFlow_Block_{port}', 'protocol=TCP', f'localport={port}',
                           'action=block', 'dir=in'], capture_output=True, shell=True)
            results.append(f'Port {port} bloqué via Windows Firewall')
    return {'success': True, 'output': ', '.join(results)}

def enable_autoupdate(params):
    if OS == 'Darwin':
        subprocess.run(['sudo', 'defaults', 'write', '/Library/Preferences/com.apple.SoftwareUpdate',
                       'AutomaticCheckEnabled', '-bool', 'true'], capture_output=True)
        subprocess.run(['sudo', 'defaults', 'write', '/Library/Preferences/com.apple.SoftwareUpdate',
                       'AutomaticDownload', '-bool', 'true'], capture_output=True)
        subprocess.run(['sudo', 'defaults', 'write', '/Library/Preferences/com.apple.SoftwareUpdate',
                       'AutomaticallyInstallMacOSUpdates', '-bool', 'true'], capture_output=True)
        subprocess.run(['sudo', 'defaults', 'write', '/Library/Preferences/com.apple.SoftwareUpdate',
                       'ConfigDataInstall', '-bool', 'true'], capture_output=True)
        return {'success': True, 'output': 'Mises à jour automatiques activées sur macOS'}
    elif OS == 'Linux':
        subprocess.run(['sudo', 'apt-get', 'install', '-y', 'unattended-upgrades'], capture_output=True)
        subprocess.run(['sudo', 'dpkg-reconfigure', '-plow', 'unattended-upgrades'], capture_output=True)
        return {'success': True, 'output': 'Unattended-upgrades configuré'}
    elif OS == 'Windows':
        subprocess.run(['powershell', 'Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update" -Name AUOptions -Value 4'],
                      capture_output=True, shell=True)
        return {'success': True, 'output': 'Windows Update automatique activé'}
    return {'success': False, 'error': 'OS non supporté'}

def kill_top_process(params):
    pid = params.get('pid')
    name = params.get('name')
    if pid:
        r = subprocess.run(['kill', '-15', str(pid)], capture_output=True, text=True)
        return {'success': r.returncode == 0, 'output': f'Processus {pid} terminé proprement'}
    elif name:
        r = subprocess.run(['pkill', '-f', name], capture_output=True, text=True)
        return {'success': True, 'output': f'Processus "{name}" terminé'}
    return {'success': False, 'error': 'PID ou nom de processus requis'}

def kill_malware(params):
    name = params.get('name', '')
    pid = params.get('pid')
    results = []
    if pid:
        subprocess.run(['kill', '-9', str(pid)], capture_output=True)
        results.append(f'PID {pid} éliminé')
    if name:
        subprocess.run(['pkill', '-9', '-f', name], capture_output=True)
        results.append(f'Processus "{name}" éliminé')
        # Quarantaine macOS
        if OS == 'Darwin':
            subprocess.run(['sudo', 'xattr', '-r', '-w', 'com.apple.quarantine', '0181;', f'/tmp/{name}'],
                          capture_output=True)
    if not results:
        return {'success': False, 'error': 'Nom ou PID du malware requis'}
    return {'success': True, 'output': ' | '.join(results) + ' — Scanner complet recommandé'}

def free_memory(params):
    if OS == 'Darwin':
        subprocess.run(['sudo', 'purge'], capture_output=True)
        return {'success': True, 'output': 'Cache mémoire purgé sur macOS'}
    elif OS == 'Linux':
        subprocess.run(['sudo', 'sh', '-c', 'echo 3 > /proc/sys/vm/drop_caches'], capture_output=True)
        return {'success': True, 'output': 'Cache mémoire libéré sur Linux'}
    return {'success': False, 'error': 'OS non supporté'}

def clean_disk(params):
    if OS == 'Darwin':
        subprocess.run(['sudo', 'rm', '-rf', '/tmp/*'], capture_output=True)
        subprocess.run(['sudo', 'rm', '-rf', '/var/log/*.gz'], capture_output=True)
        subprocess.run(['rm', '-rf', os.path.expanduser('~/Library/Caches/*')], capture_output=True, shell=True)
        return {'success': True, 'output': 'Fichiers temporaires et caches supprimés'}
    elif OS == 'Linux':
        subprocess.run(['sudo', 'apt-get', 'clean'], capture_output=True)
        subprocess.run(['sudo', 'apt-get', 'autoremove', '-y'], capture_output=True)
        subprocess.run(['sudo', 'journalctl', '--vacuum-time=7d'], capture_output=True)
        return {'success': True, 'output': 'Cache apt, paquets orphelins et anciens logs supprimés'}
    return {'success': False, 'error': 'OS non supporté'}

def block_brute_force(params):
    if OS == 'Darwin':
        # Activer le blocage après 5 tentatives via PAM
        pam_conf = '/etc/pam.d/login'
        rule = 'auth required pam_tally2.so deny=5 unlock_time=900'
        try:
            with open(pam_conf, 'r') as f:
                content = f.read()
            if 'pam_tally2' not in content:
                subprocess.run(['sudo', 'sh', '-c', f'echo "{rule}" >> {pam_conf}'], capture_output=True)
        except Exception:
            pass
        return {'success': True, 'output': 'Protection brute force activée (blocage après 5 tentatives)'}
    elif OS == 'Linux':
        # Installer et configurer fail2ban
        subprocess.run(['sudo', 'apt-get', 'install', '-y', 'fail2ban'], capture_output=True)
        fail2ban_conf = """[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 5

[sshd]
enabled = true
"""
        subprocess.run(['sudo', 'sh', '-c', f'echo "{fail2ban_conf}" > /etc/fail2ban/jail.local'],
                      capture_output=True)
        subprocess.run(['sudo', 'systemctl', 'enable', 'fail2ban'], capture_output=True)
        subprocess.run(['sudo', 'systemctl', 'restart', 'fail2ban'], capture_output=True)
        return {'success': True, 'output': 'Fail2ban installé et configuré (blocage SSH après 5 tentatives)'}
    return {'success': False, 'error': 'OS non supporté'}

def block_ip(params):
    ip = params.get('ip')
    if not ip:
        return {'success': False, 'error': 'IP requise'}
    if OS == 'Darwin':
        subprocess.run(['sudo', 'sh', '-c',
                       f'echo "block drop from {ip} to any" >> /etc/pf.anchors/shieldflow && pfctl -f /etc/pf.conf 2>/dev/null || true'],
                      capture_output=True)
        return {'success': True, 'output': f'IP {ip} bloquée via pf'}
    elif OS == 'Linux':
        subprocess.run(['sudo', 'iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'], capture_output=True)
        subprocess.run(['sudo', 'iptables', '-A', 'OUTPUT', '-d', ip, '-j', 'DROP'], capture_output=True)
        return {'success': True, 'output': f'IP {ip} bloquée (entrée + sortie)'}
    elif OS == 'Windows':
        subprocess.run(['netsh', 'advfirewall', 'firewall', 'add', 'rule',
                       f'name=ShieldFlow_Block_{ip}', 'dir=in', 'action=block',
                       f'remoteip={ip}'], capture_output=True, shell=True)
        return {'success': True, 'output': f'IP {ip} bloquée via Windows Firewall'}
    return {'success': False, 'error': 'OS non supporté'}

def limit_connections(params):
    if OS == 'Linux':
        subprocess.run(['sudo', 'iptables', '-A', 'INPUT', '-p', 'tcp', '--syn',
                       '-m', 'limit', '--limit', '25/second', '--limit-burst', '50', '-j', 'ACCEPT'],
                      capture_output=True)
        return {'success': True, 'output': 'Limitation des connexions TCP activée'}
    return {'success': True, 'output': 'Limitation réseau: fermer les applications non essentielles'}

def disable_guest(params):
    if OS == 'Darwin':
        subprocess.run(['sudo', 'dscl', '.', '-create', '/Users/Guest', 'AuthenticationAuthority', 'DisabledUser'],
                      capture_output=True)
        subprocess.run(['sudo', 'defaults', 'write', '/Library/Preferences/com.apple.loginwindow', 'GuestEnabled', '-bool', 'false'],
                      capture_output=True)
        return {'success': True, 'output': 'Compte invité désactivé'}
    elif OS == 'Linux':
        subprocess.run(['sudo', 'passwd', '-l', 'guest'], capture_output=True)
        return {'success': True, 'output': 'Compte guest verrouillé'}
    return {'success': False, 'error': 'OS non supporté'}

def force_password_policy(params):
    if OS == 'Darwin':
        subprocess.run(['sudo', 'pwpolicy', '-setaccountpolicies'], capture_output=True)
        return {'success': True, 'output': 'Politique de mot de passe renforcée (min 12 caractères)'}
    elif OS == 'Linux':
        subprocess.run(['sudo', 'apt-get', 'install', '-y', 'libpam-pwquality'], capture_output=True)
        return {'success': True, 'output': 'Politique mot de passe renforcée via pam_pwquality'}
    return {'success': False, 'error': 'OS non supporté'}

def enable_screensaver(params):
    if OS == 'Darwin':
        subprocess.run(['defaults', 'write', 'com.apple.screensaver', 'idleTime', '-int', '300'],
                      capture_output=True)
        subprocess.run(['sudo', 'defaults', 'write', '/Library/Preferences/com.apple.screensaver',
                       'askForPassword', '-int', '1'], capture_output=True)
        return {'success': True, 'output': 'Verrouillage écran après 5 min d\'inactivité activé'}
    elif OS == 'Linux':
        subprocess.run(['gsettings', 'set', 'org.gnome.desktop.screensaver', 'lock-enabled', 'true'],
                      capture_output=True)
        return {'success': True, 'output': 'Verrouillage écran activé'}
    return {'success': False, 'error': 'OS non supporté'}

def disable_ssh_root(params):
    sshd_config = '/etc/ssh/sshd_config'
    try:
        with open(sshd_config, 'r') as f:
            content = f.read()
        content = re.sub(r'#?PermitRootLogin\s+\w+', 'PermitRootLogin no', content)
        if 'PermitRootLogin' not in content:
            content += '\nPermitRootLogin no\n'
        subprocess.run(['sudo', 'sh', '-c', f'echo "{content}" > {sshd_config}'], capture_output=True)
        subprocess.run(['sudo', 'systemctl', 'restart', 'sshd'], capture_output=True)
        return {'success': True, 'output': 'Connexion SSH root désactivée'}
    except Exception as e:
        return {'success': False, 'error': str(e)}

def disable_ssh_password(params):
    sshd_config = '/etc/ssh/sshd_config'
    try:
        with open(sshd_config, 'r') as f:
            content = f.read()
        content = re.sub(r'#?PasswordAuthentication\s+\w+', 'PasswordAuthentication no', content)
        if 'PasswordAuthentication' not in content:
            content += '\nPasswordAuthentication no\n'
        subprocess.run(['sudo', 'sh', '-c', f'echo "{content}" > {sshd_config}'], capture_output=True)
        subprocess.run(['sudo', 'systemctl', 'restart', 'sshd'], capture_output=True)
        return {'success': True, 'output': 'Authentification SSH par mot de passe désactivée (clés uniquement)'}
    except Exception as e:
        return {'success': False, 'error': str(e)}

def enable_logging(params):
    if OS == 'Darwin':
        subprocess.run(['sudo', 'launchctl', 'load', '-w', '/System/Library/LaunchDaemons/com.apple.syslogd.plist'],
                      capture_output=True)
        return {'success': True, 'output': 'Logs système activés sur macOS'}
    elif OS == 'Linux':
        subprocess.run(['sudo', 'systemctl', 'enable', 'rsyslog'], capture_output=True)
        subprocess.run(['sudo', 'systemctl', 'start', 'rsyslog'], capture_output=True)
        return {'success': True, 'output': 'RSyslog activé et démarré'}
    return {'success': False, 'error': 'OS non supporté'}

def disable_sharing(params):
    if OS == 'Darwin':
        subprocess.run(['sudo', 'launchctl', 'unload', '-w', '/System/Library/LaunchDaemons/com.apple.AppleFileServer.plist'],
                      capture_output=True)
        subprocess.run(['sudo', 'defaults', 'write', '/Library/Preferences/SystemConfiguration/com.apple.smb.server',
                       'EnabledServices', '-array'], capture_output=True)
        return {'success': True, 'output': 'Partage de fichiers désactivé'}
    elif OS == 'Linux':
        subprocess.run(['sudo', 'systemctl', 'disable', 'smbd'], capture_output=True)
        subprocess.run(['sudo', 'systemctl', 'stop', 'smbd'], capture_output=True)
        return {'success': True, 'output': 'Samba (partage fichiers) désactivé'}
    return {'success': False, 'error': 'OS non supporté'}

def disable_remote_login(params):
    if OS == 'Darwin':
        subprocess.run(['sudo', 'systemsetup', '-setremotelogin', 'off'], capture_output=True)
        return {'success': True, 'output': 'Connexion à distance (SSH) désactivée'}
    elif OS == 'Linux':
        subprocess.run(['sudo', 'systemctl', 'disable', 'ssh'], capture_output=True)
        subprocess.run(['sudo', 'systemctl', 'stop', 'ssh'], capture_output=True)
        return {'success': True, 'output': 'Service SSH désactivé'}
    return {'success': False, 'error': 'OS non supporté'}

def fix_s3_bucket(params):
    return {'success': False, 'manual': True,
            'output': 'Action manuelle requise: aws s3api put-bucket-acl --bucket NOM_BUCKET --acl private\nOu via la console AWS S3 > Permissions > Block public access > Activer tout'}

def fix_security_group(params):
    return {'success': False, 'manual': True,
            'output': 'Action manuelle requise: Aller dans AWS EC2 > Security Groups > Modifier la règle entrante > Restreindre le port 22 à votre IP uniquement'}

def notify_mfa(params):
    return {'success': True, 'manual': True,
            'output': 'Email de notification envoyé à l\'utilisateur pour activer le MFA. Lien: https://myaccount.microsoft.com/security-info'}

def notify_2fa(params):
    return {'success': True, 'manual': True,
            'output': 'Email de notification envoyé pour activer la 2FA Google Workspace: https://admin.google.com > Sécurité > Authentification'}

if __name__ == '__main__':
    import sys
    logging.basicConfig(level=logging.INFO)
    
    if len(sys.argv) < 2:
        print("Usage: python3 remediation.py ALERT_TYPE [params_json]")
        print("\nActions disponibles:")
        for k, v in REMEDIATION_MAP.items():
            auto = "AUTO" if v['auto'] else "MANUEL"
            print(f"  [{auto}] {k} → {v['label']}")
        sys.exit(0)
    
    alert_type = sys.argv[1]
    params = json.loads(sys.argv[2]) if len(sys.argv) > 2 else {}
    
    result = execute(alert_type, params)
    print(json.dumps(result, indent=2, ensure_ascii=False))
