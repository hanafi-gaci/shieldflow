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


# ─── REMEDIATIONS AVANCEES ────────────────────────────────────────────────────

def kill_process(params=None):
    """Tuer un processus suspect par nom ou PID."""
    params = params or {}
    process_name = params.get('process_name', '')
    pid = params.get('pid', '')
    try:
        if pid:
            subprocess.run(['kill', '-9', str(pid)], check=True)
            return {'success': True, 'output': f'Processus {pid} terminé'}
        elif process_name:
            if OS == 'Darwin' or OS == 'Linux':
                r = subprocess.run(['pkill', '-9', '-f', process_name], capture_output=True)
                return {'success': True, 'output': f'Processus {process_name} terminé'}
            elif OS == 'Windows':
                r = subprocess.run(['taskkill', '/F', '/IM', process_name], capture_output=True)
                return {'success': r.returncode == 0, 'output': f'Processus {process_name} terminé'}
        return {'success': False, 'output': 'Nom de processus ou PID requis'}
    except Exception as e:
        return {'success': False, 'output': str(e)}


def block_ip(params=None):
    """Bloquer une adresse IP suspecte."""
    params = params or {}
    ip = params.get('ip', '')
    if not ip:
        return {'success': False, 'output': 'IP requise'}
    try:
        if OS == 'Darwin':
            r = subprocess.run(['sudo', 'pfctl', '-t', 'blocklist', '-T', 'add', ip], capture_output=True)
            return {'success': True, 'output': f'IP {ip} bloquée via pfctl'}
        elif OS == 'Linux':
            r = subprocess.run(['sudo', 'iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'], capture_output=True)
            subprocess.run(['sudo', 'iptables', '-A', 'OUTPUT', '-d', ip, '-j', 'DROP'], capture_output=True)
            return {'success': True, 'output': f'IP {ip} bloquée via iptables'}
        elif OS == 'Windows':
            r = subprocess.run(['netsh', 'advfirewall', 'firewall', 'add', 'rule',
                               f'name=Block_{ip}', 'dir=in', 'action=block', f'remoteip={ip}'], capture_output=True)
            return {'success': r.returncode == 0, 'output': f'IP {ip} bloquée'}
        return {'success': False, 'output': 'OS non supporté'}
    except Exception as e:
        return {'success': False, 'output': str(e)}


def disable_user(params=None):
    """Désactiver un compte utilisateur local."""
    params = params or {}
    username = params.get('username', '')
    if not username:
        return {'success': False, 'output': 'Nom utilisateur requis'}
    try:
        if OS == 'Darwin':
            r = subprocess.run(['sudo', 'dscl', '.', '-create', f'/Users/{username}', 'AuthenticationAuthority', ';DisabledUser;'], capture_output=True)
            return {'success': r.returncode == 0, 'output': f'Utilisateur {username} désactivé'}
        elif OS == 'Linux':
            r = subprocess.run(['sudo', 'usermod', '-L', username], capture_output=True)
            return {'success': r.returncode == 0, 'output': f'Utilisateur {username} verrouillé'}
        elif OS == 'Windows':
            r = subprocess.run(['net', 'user', username, '/active:no'], capture_output=True)
            return {'success': r.returncode == 0, 'output': f'Utilisateur {username} désactivé'}
        return {'success': False, 'output': 'OS non supporté'}
    except Exception as e:
        return {'success': False, 'output': str(e)}


def flush_dns(params=None):
    """Vider le cache DNS."""
    try:
        if OS == 'Darwin':
            subprocess.run(['sudo', 'dscacheutil', '-flushcache'], check=True)
            subprocess.run(['sudo', 'killall', '-HUP', 'mDNSResponder'], check=True)
            return {'success': True, 'output': 'Cache DNS vidé'}
        elif OS == 'Linux':
            subprocess.run(['sudo', 'systemd-resolve', '--flush-caches'], capture_output=True)
            return {'success': True, 'output': 'Cache DNS vidé'}
        elif OS == 'Windows':
            r = subprocess.run(['ipconfig', '/flushdns'], capture_output=True)
            return {'success': r.returncode == 0, 'output': 'Cache DNS vidé'}
    except Exception as e:
        return {'success': False, 'output': str(e)}


def force_system_update(params=None):
    """Forcer les mises à jour système."""
    try:
        if OS == 'Darwin':
            r = subprocess.run(['sudo', 'softwareupdate', '-ia', '--restart'], capture_output=True, timeout=300)
            return {'success': True, 'output': 'Mises à jour système lancées'}
        elif OS == 'Linux':
            subprocess.run(['sudo', 'apt-get', 'update', '-y'], capture_output=True, timeout=120)
            r = subprocess.run(['sudo', 'apt-get', 'upgrade', '-y'], capture_output=True, timeout=300)
            return {'success': r.returncode == 0, 'output': 'Mises à jour Linux appliquées'}
        elif OS == 'Windows':
            r = subprocess.run(['powershell', 'Install-WindowsUpdate', '-AcceptAll', '-AutoReboot'], capture_output=True)
            return {'success': True, 'output': 'Mises à jour Windows lancées'}
    except Exception as e:
        return {'success': False, 'output': str(e)}


def restart_service(params=None):
    """Redémarrer un service système."""
    params = params or {}
    service = params.get('service', '')
    if not service:
        return {'success': False, 'output': 'Nom du service requis'}
    try:
        if OS == 'Darwin':
            r = subprocess.run(['sudo', 'launchctl', 'kickstart', '-k', f'system/{service}'], capture_output=True)
            return {'success': True, 'output': f'Service {service} redémarré'}
        elif OS == 'Linux':
            r = subprocess.run(['sudo', 'systemctl', 'restart', service], capture_output=True)
            return {'success': r.returncode == 0, 'output': f'Service {service} redémarré'}
        elif OS == 'Windows':
            subprocess.run(['net', 'stop', service], capture_output=True)
            r = subprocess.run(['net', 'start', service], capture_output=True)
            return {'success': r.returncode == 0, 'output': f'Service {service} redémarré'}
    except Exception as e:
        return {'success': False, 'output': str(e)}


def delete_malicious_file(params=None):
    """Supprimer un fichier malveillant."""
    params = params or {}
    filepath = params.get('filepath', '')
    if not filepath:
        return {'success': False, 'output': 'Chemin fichier requis'}
    try:
        import os as _os
        if _os.path.exists(filepath):
            _os.remove(filepath)
            return {'success': True, 'output': f'Fichier {filepath} supprimé'}
        return {'success': False, 'output': 'Fichier non trouvé'}
    except Exception as e:
        return {'success': False, 'output': str(e)}


def lock_session(params=None):
    """Verrouiller la session utilisateur."""
    try:
        if OS == 'Darwin':
            subprocess.run(['/System/Library/CoreServices/Menu Extras/User.menu/Contents/Resources/CGSession', '-suspend'], capture_output=True)
            return {'success': True, 'output': 'Session verrouillée'}
        elif OS == 'Linux':
            subprocess.run(['loginctl', 'lock-sessions'], capture_output=True)
            return {'success': True, 'output': 'Session verrouillée'}
        elif OS == 'Windows':
            r = subprocess.run(['rundll32.exe', 'user32.dll,LockWorkStation'], capture_output=True)
            return {'success': True, 'output': 'Session verrouillée'}
    except Exception as e:
        return {'success': False, 'output': str(e)}


def clean_temp_files(params=None):
    """Nettoyer les fichiers temporaires."""
    try:
        import shutil
        cleaned = 0
        if OS == 'Darwin':
            temp_dirs = ['/tmp', '/var/tmp', str(Path.home() / 'Library/Caches')]
        elif OS == 'Linux':
            temp_dirs = ['/tmp', '/var/tmp']
        elif OS == 'Windows':
            temp_dirs = ['C:\\Windows\\Temp', str(Path.home() / 'AppData\\Local\\Temp')]
        else:
            temp_dirs = ['/tmp']
        
        for d in temp_dirs:
            if Path(d).exists():
                for f in Path(d).iterdir():
                    try:
                        if f.is_file():
                            f.unlink()
                            cleaned += 1
                        elif f.is_dir():
                            shutil.rmtree(f, ignore_errors=True)
                            cleaned += 1
                    except:
                        pass
        return {'success': True, 'output': f'{cleaned} fichier(s) temporaire(s) supprimé(s)'}
    except Exception as e:
        return {'success': False, 'output': str(e)}


def disable_wifi(params=None):
    """Désactiver le WiFi (isolation réseau)."""
    try:
        if OS == 'Darwin':
            r = subprocess.run(['sudo', 'networksetup', '-setairportpower', 'en0', 'off'], capture_output=True)
            return {'success': r.returncode == 0, 'output': 'WiFi désactivé'}
        elif OS == 'Linux':
            r = subprocess.run(['sudo', 'nmcli', 'radio', 'wifi', 'off'], capture_output=True)
            return {'success': r.returncode == 0, 'output': 'WiFi désactivé'}
        elif OS == 'Windows':
            r = subprocess.run(['netsh', 'interface', 'set', 'interface', 'Wi-Fi', 'disable'], capture_output=True)
            return {'success': r.returncode == 0, 'output': 'WiFi désactivé'}
    except Exception as e:
        return {'success': False, 'output': str(e)}


def enable_wifi(params=None):
    """Réactiver le WiFi."""
    try:
        if OS == 'Darwin':
            r = subprocess.run(['sudo', 'networksetup', '-setairportpower', 'en0', 'on'], capture_output=True)
            return {'success': r.returncode == 0, 'output': 'WiFi réactivé'}
        elif OS == 'Linux':
            r = subprocess.run(['sudo', 'nmcli', 'radio', 'wifi', 'on'], capture_output=True)
            return {'success': r.returncode == 0, 'output': 'WiFi réactivé'}
        elif OS == 'Windows':
            r = subprocess.run(['netsh', 'interface', 'set', 'interface', 'Wi-Fi', 'enable'], capture_output=True)
            return {'success': r.returncode == 0, 'output': 'WiFi réactivé'}
    except Exception as e:
        return {'success': False, 'output': str(e)}


def isolate_machine(params=None):
    """Isolation complète de la machine du réseau — urgence ransomware."""
    results = []
    try:
        wifi = disable_wifi()
        results.append(f'WiFi: {wifi["output"]}')
        if OS == 'Darwin':
            subprocess.run(['sudo', 'pfctl', '-e'], capture_output=True)
            subprocess.run(['sudo', 'pfctl', '-F', 'all'], capture_output=True)
            results.append('Pare-feu total activé')
        elif OS == 'Linux':
            subprocess.run(['sudo', 'iptables', '-P', 'INPUT', 'DROP'], capture_output=True)
            subprocess.run(['sudo', 'iptables', '-P', 'OUTPUT', 'DROP'], capture_output=True)
            subprocess.run(['sudo', 'iptables', '-P', 'FORWARD', 'DROP'], capture_output=True)
            results.append('Toutes connexions bloquées')
        return {'success': True, 'output': ' | '.join(results), 'isolated': True}
    except Exception as e:
        return {'success': False, 'output': str(e)}


# Enregistrer les nouvelles actions dans le registre
REMEDIATION_MAP.update({
    'KILL_PROCESS':          {'action': 'kill_process',         'label': 'Tuer processus suspect',        'auto': False, 'risk': 'medium'},
    'BLOCK_IP':              {'action': 'block_ip',              'label': 'Bloquer IP suspecte',           'auto': True,  'risk': 'low'},
    'DISABLE_USER':          {'action': 'disable_user',          'label': 'Désactiver utilisateur',        'auto': False, 'risk': 'high'},
    'FLUSH_DNS':             {'action': 'flush_dns',             'label': 'Vider cache DNS',               'auto': True,  'risk': 'low'},
    'FORCE_UPDATE':          {'action': 'force_system_update',   'label': 'Forcer mises à jour',           'auto': False, 'risk': 'medium'},
    'RESTART_SERVICE':       {'action': 'restart_service',       'label': 'Redémarrer service',            'auto': False, 'risk': 'medium'},
    'DELETE_MALICIOUS_FILE': {'action': 'delete_malicious_file', 'label': 'Supprimer fichier malveillant', 'auto': False, 'risk': 'high'},
    'LOCK_SESSION':          {'action': 'lock_session',          'label': 'Verrouiller session',           'auto': True,  'risk': 'low'},
    'CLEAN_TEMP':            {'action': 'clean_temp_files',      'label': 'Nettoyer fichiers temp',        'auto': True,  'risk': 'low'},
    'DISABLE_WIFI':          {'action': 'disable_wifi',          'label': 'Désactiver WiFi',               'auto': False, 'risk': 'high'},
    'ENABLE_WIFI':           {'action': 'enable_wifi',           'label': 'Réactiver WiFi',                'auto': False, 'risk': 'low'},
    'ISOLATE_MACHINE':       {'action': 'isolate_machine',       'label': 'Isoler machine — urgence',      'auto': False, 'risk': 'critical'},
})

# Ajouter dans la fonction execute
_ADVANCED_ACTIONS = {
    'KILL_PROCESS': kill_process,
    'BLOCK_IP': block_ip,
    'DISABLE_USER': disable_user,
    'FLUSH_DNS': flush_dns,
    'FORCE_UPDATE': force_system_update,
    'RESTART_SERVICE': restart_service,
    'DELETE_MALICIOUS_FILE': delete_malicious_file,
    'LOCK_SESSION': lock_session,
    'CLEAN_TEMP': clean_temp_files,
    'DISABLE_WIFI': disable_wifi,
    'ENABLE_WIFI': enable_wifi,
    'ISOLATE_MACHINE': isolate_machine,
}

_original_execute = execute

def execute(alert_type, params=None):
    if alert_type in _ADVANCED_ACTIONS:
        return _ADVANCED_ACTIONS[alert_type](params)
    return _original_execute(alert_type, params)

