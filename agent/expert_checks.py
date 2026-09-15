#!/usr/bin/env python3
"""
ShieldFlow — Expert Agent Checks (macOS + Linux)
Collecte étendue pour l'analyse de sécurité.

Ce module s'ajoute à l'agent existant. Il collecte :
- Processus détaillés (CPU, path, args)
- Connexions réseau et ports ouverts
- Comptes utilisateurs et statuts
- Informations disque/chiffrement/pare-feu
- Logs système récents (auth, sudo, syslog)
- Variables d'environnement sensibles
- Mises à jour disponibles
"""

import os
import sys
import json
import subprocess
import platform
import re
import socket
import time
import logging
from datetime import datetime, timedelta
from pathlib import Path

logger = logging.getLogger('shieldflow.expert')

SYSTEM = platform.system()  # 'Darwin' (Mac) | 'Linux' | 'Windows'


# ─── MAIN COLLECTOR ──────────────────────────────────────────────────────────

def collect_expert_data() -> dict:
    if SYSTEM == 'Windows':
        try:
            win_data = check_windows_security()
            win_data['platform'] = 'Windows'
            return win_data
        except Exception as e:
            return {'error': str(e), 'platform': 'Windows'}
    return _collect_expert_data_unix()

def _collect_expert_data_unix() -> dict:
    """
    Collecte toutes les données de sécurité étendues.
    Retourne un dict prêt à être mergé dans le payload principal.
    """
    data = {}

    collectors = [
        ('processes',         collect_processes),
        ('open_ports',        collect_open_ports),
        ('users',             collect_users),
        ('firewall_status',   check_firewall),
        ('disk_encrypted',    check_disk_encryption),
        ('pending_updates',   check_pending_updates),
        ('antivirus_status',  check_antivirus),
        ('logs',              collect_recent_logs),
        ('open_files',        collect_sensitive_open_files),
        ('env_vars',          collect_sensitive_env_vars),
        ('network_stats',     collect_network_stats),
        ('startup_items',     collect_startup_items),
    ]

    for key, fn in collectors:
        try:
            result = fn()
            if isinstance(result, dict):
                data.update(result)
            else:
                data[key] = result
        except Exception as e:
            logger.warning(f'Expert collector "{key}" failed: {e}')
            data[key] = None

    data['expert_version'] = '1.0.0'
    data['collected_at']   = datetime.utcnow().isoformat() + 'Z'

    return data


# ─── PROCESSES ───────────────────────────────────────────────────────────────

def collect_processes() -> list:
    """Returns list of running processes with security-relevant fields."""
    try:
        import psutil
        procs = []
        for p in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'cpu_percent',
                                       'memory_percent', 'username', 'status', 'create_time']):
            try:
                info = p.info
                # Skip processes we can't inspect
                if not info.get('name'):
                    continue

                procs.append({
                    'pid':            info['pid'],
                    'name':           info['name'],
                    'path':           info.get('exe') or '',
                    'cmd':            ' '.join(info.get('cmdline') or [])[:200],
                    'cpu_percent':    round(info.get('cpu_percent') or 0.0, 2),
                    'memory_percent': round(info.get('memory_percent') or 0.0, 2),
                    'username':       info.get('username') or '',
                    'status':         info.get('status') or '',
                    'started':        datetime.fromtimestamp(
                                        info.get('create_time') or 0
                                      ).isoformat() if info.get('create_time') else '',
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        return procs

    except ImportError:
        return _collect_processes_fallback()


def _collect_processes_fallback() -> list:
    """Fallback using ps command when psutil is unavailable."""
    try:
        if SYSTEM == 'Darwin':
            cmd = ['ps', 'aux']
        else:
            cmd = ['ps', 'auxf']

        out = subprocess.check_output(cmd, timeout=10, stderr=subprocess.DEVNULL).decode(errors='ignore')
        procs = []
        for line in out.strip().split('\n')[1:]:
            parts = line.split(None, 10)
            if len(parts) < 11:
                continue
            procs.append({
                'pid':         parts[1],
                'username':    parts[0],
                'cpu_percent': parts[2],
                'name':        parts[10].split('/')[-1][:50],
                'cmd':         parts[10][:200],
                'path':        parts[10][:200],
            })
        return procs
    except Exception as e:
        logger.error(f'Fallback process collection failed: {e}')
        return []


# ─── OPEN PORTS / CONNECTIONS ────────────────────────────────────────────────

def collect_open_ports() -> list:
    """Returns listening ports and active network connections."""
    try:
        import psutil
        conns = []
        for c in psutil.net_connections(kind='all'):
            try:
                conns.append({
                    'local_port':  c.laddr.port if c.laddr else None,
                    'local_ip':    c.laddr.ip   if c.laddr else None,
                    'remote_port': c.raddr.port  if c.raddr else None,
                    'remote_ip':   c.raddr.ip    if c.raddr else None,
                    'status':      c.status or '',
                    'pid':         c.pid or 0,
                    'type':        'TCP' if c.type == socket.SOCK_STREAM else 'UDP',
                })
            except Exception:
                continue
        return conns

    except ImportError:
        return _collect_ports_fallback()


def _collect_ports_fallback() -> list:
    """Fallback using netstat."""
    try:
        if SYSTEM == 'Darwin':
            cmd = ['netstat', '-an', '-p', 'tcp']
        else:
            cmd = ['ss', '-tlnup']

        out = subprocess.check_output(cmd, timeout=10, stderr=subprocess.DEVNULL).decode(errors='ignore')
        ports = []
        for line in out.strip().split('\n'):
            m = re.search(r'[\.:]([\d]+)\s+.*(LISTEN|ESTABLISHED)', line, re.I)
            if m:
                ports.append({
                    'local_port': int(m.group(1)),
                    'status': m.group(2).upper(),
                })
        return ports
    except Exception as e:
        logger.error(f'Port collection fallback failed: {e}')
        return []


# ─── USER ACCOUNTS ───────────────────────────────────────────────────────────

def collect_users() -> list:
    """Returns local user accounts with security-relevant metadata."""
    users = []

    if SYSTEM in ('Darwin', 'Linux'):
        try:
            import pwd
            import spwd

            for entry in pwd.getpwall():
                if entry.pw_uid < 500 and entry.pw_name not in ('root',):
                    continue  # skip system accounts except root
                if entry.pw_shell in ('/usr/bin/false', '/sbin/nologin', '/bin/false'):
                    continue  # no-login accounts

                user_info = {
                    'name':               entry.pw_name,
                    'uid':                entry.pw_uid,
                    'home':               entry.pw_dir,
                    'shell':              entry.pw_shell,
                    'is_admin':           _is_admin_user(entry.pw_name),
                    'is_system_account':  entry.pw_uid < 1000,
                    'logged_in':          _is_logged_in(entry.pw_name),
                    'days_since_last_login': _days_since_last_login(entry.pw_name),
                }

                # Check password hash (Linux only, requires root)
                try:
                    shadow = spwd.getspnam(entry.pw_name)
                    user_info['has_password'] = shadow.sp_pwdp not in ('', '!', '*', '!!', 'x')
                    user_info['password_hash'] = shadow.sp_pwdp if shadow.sp_pwdp in ('!', '') else '***'
                except (KeyError, AttributeError, PermissionError):
                    user_info['has_password'] = True  # assume yes if can't check

                users.append(user_info)

        except ImportError:
            # Minimal fallback
            try:
                out = subprocess.check_output(['dscl', '.', 'list', '/Users'],
                                               timeout=5, stderr=subprocess.DEVNULL).decode(errors='ignore')
                for name in out.strip().split('\n'):
                    if name.startswith('_') or name in ('nobody', 'daemon'):
                        continue
                    users.append({
                        'name':      name,
                        'is_admin':  _is_admin_user(name),
                        'logged_in': _is_logged_in(name),
                    })
            except Exception as e:
                logger.warning(f'User collection failed: {e}')

    return users


def _is_admin_user(username: str) -> bool:
    """Check if user is in admin/sudo group."""
    try:
        if SYSTEM == 'Darwin':
            out = subprocess.check_output(
                ['dsmemberutil', 'checkmembership', '-U', username, '-G', 'admin'],
                timeout=3, stderr=subprocess.DEVNULL).decode()
            return 'is a member' in out
        else:
            import grp
            for g in grp.getgrall():
                if g.gr_name in ('sudo', 'wheel', 'admin') and username in g.gr_mem:
                    return True
    except Exception:
        pass
    return False


def _is_logged_in(username: str) -> bool:
    try:
        out = subprocess.check_output(['who'], timeout=3, stderr=subprocess.DEVNULL).decode()
        return username in out
    except Exception:
        return False


def _days_since_last_login(username: str) -> int:
    try:
        out = subprocess.check_output(['last', '-1', username],
                                       timeout=3, stderr=subprocess.DEVNULL).decode()
        if 'Never logged in' in out or 'wtmp begins' in out.split('\n')[0]:
            return 9999
        # Parse date from last output — simplified
        return 0  # placeholder; real parsing would extract date
    except Exception:
        return 0


# ─── FIREWALL ────────────────────────────────────────────────────────────────

def check_system_security() -> dict:
    """Verifie screensaver, partage de fichiers, acces distant, logs."""
    import platform
    OS = platform.system()
    result = {
        'screensaver_enabled': None,
        'file_sharing': None,
        'remote_login': None,
        'logging_enabled': None
    }
    
    try:
        if OS == 'Darwin':
            import subprocess
            # Screensaver
            r = subprocess.run(['defaults', 'read', 'com.apple.screensaver', 'idleTime'],
                              capture_output=True, text=True)
            idle = int(r.stdout.strip()) if r.stdout.strip().isdigit() else 0
            result['screensaver_enabled'] = idle > 0 and idle <= 600
            
            # Partage de fichiers
            r2 = subprocess.run(['launchctl', 'list', 'com.apple.AppleFileServer'],
                               capture_output=True, text=True)
            result['file_sharing'] = r2.returncode == 0
            
            # Acces distant SSH
            r3 = subprocess.run(['systemsetup', '-getremotelogin'],
                               capture_output=True, text=True)
            result['remote_login'] = 'On' in r3.stdout
            
            # Logs
            r4 = subprocess.run(['log', 'show', '--last', '1m'],
                               capture_output=True, text=True, timeout=5)
            result['logging_enabled'] = r4.returncode == 0
            
        elif OS == 'Linux':
            import subprocess
            # Partage fichiers
            r = subprocess.run(['systemctl', 'is-active', 'smbd'],
                              capture_output=True, text=True)
            result['file_sharing'] = r.stdout.strip() == 'active'
            
            # SSH
            r2 = subprocess.run(['systemctl', 'is-active', 'ssh'],
                               capture_output=True, text=True)
            result['remote_login'] = r2.stdout.strip() == 'active'
            
            # Logs
            r3 = subprocess.run(['systemctl', 'is-active', 'rsyslog'],
                               capture_output=True, text=True)
            result['logging_enabled'] = r3.stdout.strip() == 'active'
            result['screensaver_enabled'] = True  # Supposé OK sur serveur Linux
            
        elif OS == 'Windows':
            import subprocess
            result['screensaver_enabled'] = True
            result['file_sharing'] = False
            result['remote_login'] = False
            result['logging_enabled'] = True
            
    except Exception as e:
        pass
    
    return result

def check_firewall() -> dict:
    """Check if the system firewall is enabled."""
    enabled = None

    try:
        if SYSTEM == 'Darwin':
            out = subprocess.check_output(
                ['/usr/libexec/ApplicationFirewall/socketfilterfw', '--getglobalstate'],
                timeout=5, stderr=subprocess.DEVNULL).decode()
            enabled = 'enabled' in out.lower() or 'active' in out.lower()

        elif SYSTEM == 'Linux':
            for cmd in [['ufw', 'status'], ['firewall-cmd', '--state'], ['iptables', '-L', '-n']]:
                try:
                    out = subprocess.check_output(cmd, timeout=5, stderr=subprocess.DEVNULL).decode()
                    if 'active' in out.lower() or 'ACCEPT' in out:
                        enabled = True
                        break
                except FileNotFoundError:
                    continue

    except Exception as e:
        logger.warning(f'Firewall check failed: {e}')

    return {
        'firewall_enabled': enabled,
        'firewall_status': ('enabled' if enabled else 'disabled') if enabled is not None else 'unknown',
    }


# ─── DISK ENCRYPTION ─────────────────────────────────────────────────────────

def check_disk_encryption() -> dict:
    """Check if disk encryption (FileVault/LUKS) is active."""
    encrypted = None

    try:
        if SYSTEM == 'Darwin':
            out = subprocess.check_output(
                ['fdesetup', 'status'], timeout=5, stderr=subprocess.DEVNULL).decode()
            encrypted = 'FileVault is On' in out
            return {
                'disk_encrypted':    encrypted,
                'filevault_enabled': encrypted,
                'encryption_type':   'FileVault' if encrypted else None,
            }

        elif SYSTEM == 'Linux':
            out = subprocess.check_output(
                ['lsblk', '-o', 'NAME,TYPE'], timeout=5, stderr=subprocess.DEVNULL).decode()
            encrypted = 'crypt' in out.lower()
            return {
                'disk_encrypted':  encrypted,
                'encryption_type': 'LUKS' if encrypted else None,
            }

    except Exception as e:
        logger.warning(f'Disk encryption check failed: {e}')

    return {'disk_encrypted': None, 'encryption_type': 'unknown'}


# ─── PENDING UPDATES ─────────────────────────────────────────────────────────

def check_pending_updates() -> int:
    """Returns the number of pending system updates."""
    try:
        if SYSTEM == 'Darwin':
            out = subprocess.check_output(
                ['softwareupdate', '-l'], timeout=30, stderr=subprocess.STDOUT).decode()
            count = out.count('*')
            return count

        elif SYSTEM == 'Linux':
            for cmd in [
                ['apt-get', '-s', 'upgrade'],
                ['dnf', 'check-update', '--quiet'],
                ['yum', 'check-update', '--quiet'],
            ]:
                try:
                    result = subprocess.run(cmd, timeout=20, capture_output=True, text=True)
                    lines = [l for l in result.stdout.split('\n')
                             if l and not l.startswith(' ') and not l.startswith('Listing')]
                    return max(0, len(lines) - 2)
                except FileNotFoundError:
                    continue

    except subprocess.TimeoutExpired:
        logger.warning('Update check timed out')
    except Exception as e:
        logger.warning(f'Update check failed: {e}')

    return 0


# ─── ANTIVIRUS ───────────────────────────────────────────────────────────────

def check_antivirus() -> dict:
    """Check for active antivirus/EDR presence."""
    known_av = {
        'Darwin': [
            ('com.malwarebytes.antimalware', 'Malwarebytes'),
            ('com.sentinelone.sentineld',    'SentinelOne'),
            ('com.crowdstrike.falcon',       'CrowdStrike Falcon'),
            ('com.carbonblack.cbsecurity',   'VMware Carbon Black'),
            ('com.sophos.endpoint',          'Sophos'),
            ('com.trendmicro',               'Trend Micro'),
        ],
        'Linux': [
            ('clamd',        'ClamAV'),
            ('falcond',      'CrowdStrike Falcon'),
            ('sentineld',    'SentinelOne'),
            ('cbsensor',     'Carbon Black'),
        ]
    }

    detected = []

    try:
        if SYSTEM == 'Darwin':
            for launchd_id, name in known_av.get('Darwin', []):
                out = subprocess.check_output(
                    ['launchctl', 'list', launchd_id],
                    timeout=3, stderr=subprocess.DEVNULL).decode()
                if '"PID"' in out or 'PID' in out:
                    detected.append(name)
        elif SYSTEM == 'Linux':
            for proc_name, name in known_av.get('Linux', []):
                try:
                    subprocess.check_output(['pgrep', '-x', proc_name],
                                             timeout=3, stderr=subprocess.DEVNULL)
                    detected.append(name)
                except subprocess.CalledProcessError:
                    pass

    except Exception as e:
        logger.warning(f'Antivirus check failed: {e}')

    return {
        'antivirus_enabled': len(detected) > 0,
        'antivirus_status':  'enabled' if detected else 'disabled',
        'antivirus_products': detected,
    }


# ─── LOGS ────────────────────────────────────────────────────────────────────

def collect_recent_logs(max_lines: int = 200) -> list:
    """Collect recent auth/security log lines for anomaly detection."""
    logs = []

    log_sources = {
        'Darwin': [
            # macOS unified log — last 15 minutes, auth category
            ['log', 'show', '--predicate',
             'subsystem == "com.apple.securityd" OR category == "Authorization"',
             '--style', 'syslog', '--last', '15m'],
        ],
        'Linux': [
            ['journalctl', '-u', 'sshd', '-u', 'sudo', '--since', '15 minutes ago', '-q'],
            ['tail', '-n', str(max_lines), '/var/log/auth.log'],
            ['tail', '-n', str(max_lines), '/var/log/secure'],
        ],
    }

    sources = log_sources.get(SYSTEM, [])
    for cmd in sources:
        try:
            out = subprocess.check_output(cmd, timeout=10, stderr=subprocess.DEVNULL).decode(errors='ignore')
            for line in out.strip().split('\n')[-max_lines:]:
                if line.strip():
                    logs.append({'line': line.strip(), 'source': cmd[0]})
            if logs:
                break  # Use first successful source
        except Exception:
            continue

    return logs


# ─── SENSITIVE OPEN FILES ────────────────────────────────────────────────────

def collect_sensitive_open_files() -> list:
    """List open files that may contain credentials or sensitive data."""
    sensitive = []
    SENSITIVE_PATTERNS = [
        r'\.pem$', r'\.key$', r'id_rsa', r'id_ed25519',
        r'\.pfx$', r'\.p12$', r'\.env$', r'credentials',
        r'secret', r'password', r'\.aws/credentials',
        r'\.ssh/', r'kubeconfig', r'\.kube/config',
    ]
    combined = re.compile('|'.join(SENSITIVE_PATTERNS), re.I)

    try:
        import psutil
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                for f in proc.open_files():
                    if combined.search(f.path):
                        sensitive.append({
                            'path': f.path,
                            'pid':  proc.pid,
                            'process': proc.name(),
                        })
                        if len(sensitive) >= 20:
                            return sensitive
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                continue

    except ImportError:
        pass  # Skip if psutil unavailable

    return sensitive


# ─── SENSITIVE ENV VARS ──────────────────────────────────────────────────────

def collect_sensitive_env_vars() -> list:
    """Check current process env for exposed credentials (keys only, no values)."""
    SENSITIVE_KEY_PATTERNS = re.compile(
        r'(password|passwd|secret|api.?key|token|credential|private.?key|auth)', re.I
    )
    exposed = []
    for key in os.environ:
        if SENSITIVE_KEY_PATTERNS.search(key):
            exposed.append({'key': key, 'value': '***REDACTED***'})
    return exposed


# ─── NETWORK STATS ───────────────────────────────────────────────────────────

def collect_network_stats() -> dict:
    """Basic network interface statistics."""
    try:
        import psutil
        stats = psutil.net_io_counters()
        return {
            'bytes_sent':    stats.bytes_sent,
            'bytes_recv':    stats.bytes_recv,
            'packets_sent':  stats.packets_sent,
            'packets_recv':  stats.packets_recv,
            'errin':         stats.errin,
            'errout':        stats.errout,
            'dropin':        stats.dropin,
            'dropout':       stats.dropout,
        }
    except Exception:
        return {}


# ─── STARTUP ITEMS ───────────────────────────────────────────────────────────

def collect_startup_items() -> list:
    """List startup/launch agents that run automatically — common persistence mechanism."""
    items = []

    if SYSTEM == 'Darwin':
        launch_dirs = [
            Path('/Library/LaunchDaemons'),
            Path('/Library/LaunchAgents'),
            Path.home() / 'Library' / 'LaunchAgents',
        ]
        for d in launch_dirs:
            try:
                for f in d.iterdir():
                    if f.suffix == '.plist':
                        items.append({
                            'name': f.stem,
                            'path': str(f),
                            'location': str(d),
                        })
            except (PermissionError, FileNotFoundError):
                continue

    elif SYSTEM == 'Linux':
        try:
            out = subprocess.check_output(
                ['systemctl', 'list-units', '--type=service', '--state=enabled', '--no-pager', '-q'],
                timeout=5, stderr=subprocess.DEVNULL).decode()
            for line in out.strip().split('\n'):
                parts = line.split()
                if parts:
                    items.append({'name': parts[0], 'path': '', 'location': 'systemd'})
        except Exception:
            pass

    return items


# ─── STANDALONE TEST ─────────────────────────────────────────────────────────

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    print('[ShieldFlow] Running expert checks...\n')
    data = collect_expert_data()

    # Pretty print summary
    print(f"Processes collected:  {len(data.get('processes', []))}")
    print(f"Open ports:           {len(data.get('open_ports', []))}")
    print(f"Users:                {len(data.get('users', []))}")
    print(f"Firewall:             {data.get('firewall_status', 'unknown')}")
    print(f"Disk encrypted:       {data.get('disk_encrypted', 'unknown')}")
    print(f"Pending updates:      {data.get('pending_updates', 0)}")
    print(f"Antivirus:            {data.get('antivirus_status', 'unknown')}")
    print(f"Recent log lines:     {len(data.get('logs', []))}")
    print(f"Sensitive open files: {len(data.get('open_files', []))}")
    print(f"Sensitive env vars:   {len(data.get('env_vars', []))}")
    print(f"Startup items:        {len(data.get('startup_items', []))}")
    print('\nFull JSON:')
    print(json.dumps(data, indent=2, default=str))

def check_threat_intelligence(connections):
    """Vérifie les connexions contre la base Threat Intelligence OTX."""
    try:
        import sys, os
        sys.path.insert(0, os.path.dirname(__file__))
        from threat_intel import check_connections
        return check_connections(connections)
    except Exception as e:
        return []

def check_darkweb(emails):
    """Vérifie les emails contre les bases de fuites dark web."""
    try:
        import sys, os
        sys.path.insert(0, os.path.dirname(__file__))
        from darkweb import check_emails_darkweb
        return check_emails_darkweb(emails)
    except Exception as e:
        return []

def check_cve_vulnerabilities(software_list=None):
    """Scan CVE sur les logiciels installes."""
    try:
        import sys, os
        sys.path.insert(0, os.path.dirname(__file__))
        from cve_scanner import scan_cve, get_installed_software
        if software_list is None:
            software_list = get_installed_software()
        return scan_cve(software_list)
    except Exception as e:
        return []

def check_nis2_compliance(snap):
    """Evalue la conformite NIS2."""
    try:
        import sys, os
        sys.path.insert(0, os.path.dirname(__file__))
        from nis2_compliance import evaluate_compliance, generate_nis2_alerts
        result = evaluate_compliance(snap)
        alerts = generate_nis2_alerts(result)
        return result, alerts
    except Exception as e:
        return None, []


# ─── NOUVEAUX CHECKS ─────────────────────────────────────────────────────────

def check_ransomware_behavior() -> dict:
    """Détecte un chiffrement massif de fichiers (comportement ransomware)."""
    try:
        suspicious = []
        extensions = ['.locked','.encrypted','.crypto','.crypt','.enc','.ransom','.wnry','.wncry']
        home = Path.home()
        count = 0
        for ext in extensions:
            found = list(home.rglob(f'*{ext}'))[:10]
            count += len(found)
            suspicious.extend([str(f) for f in found])
        return {
            'ransomware_files_count': count,
            'ransomware_detected': count > 0,
            'suspicious_files': suspicious[:20]
        }
    except Exception as e:
        return {'ransomware_detected': False, 'error': str(e)}


def check_network_connections() -> dict:
    """Surveille les connexions réseau actives et détecte les anomalies."""
    try:
        if SYSTEM == 'Darwin':
            result = subprocess.run(['netstat', '-an', '-p', 'tcp'], capture_output=True, text=True)
        else:
            result = subprocess.run(['ss', '-tunp'], capture_output=True, text=True)
        
        lines = result.stdout.splitlines()
        established = [l for l in lines if 'ESTABLISHED' in l]
        listening = [l for l in lines if 'LISTEN' in l]
        
        # Ports suspects
        dangerous = [4444, 5555, 6666, 7777, 8888, 9999, 1337, 31337]
        suspicious_conns = []
        for line in established:
            for port in dangerous:
                if f'.{port} ' in line or f':{port} ' in line:
                    suspicious_conns.append(line.strip())
        
        return {
            'established_connections': len(established),
            'listening_ports': len(listening),
            'suspicious_connections': suspicious_conns,
            'has_suspicious_connections': len(suspicious_conns) > 0
        }
    except Exception as e:
        return {'established_connections': 0, 'error': str(e)}


def get_system_inventory() -> dict:
    """Inventaire complet du système — matériel et logiciels."""
    try:
        inventory = {
            'os': platform.platform(),
            'hostname': socket.gethostname(),
            'cpu_model': '',
            'ram_total_gb': 0,
            'disk_total_gb': 0,
            'installed_software': [],
        }
        
        if SYSTEM == 'Darwin':
            # CPU
            r = subprocess.run(['sysctl', '-n', 'machdep.cpu.brand_string'], capture_output=True, text=True)
            inventory['cpu_model'] = r.stdout.strip()
            # RAM
            r = subprocess.run(['sysctl', '-n', 'hw.memsize'], capture_output=True, text=True)
            inventory['ram_total_gb'] = round(int(r.stdout.strip()) / (1024**3), 1)
            # Disk
            r = subprocess.run(['df', '-h', '/'], capture_output=True, text=True)
            lines = r.stdout.splitlines()
            if len(lines) > 1:
                inventory['disk_total_gb'] = lines[1].split()[1]
            # Software (top 20)
            r = subprocess.run(['system_profiler', 'SPApplicationsDataType', '-json'], capture_output=True, text=True, timeout=30)
            try:
                data = json.loads(r.stdout)
                apps = data.get('SPApplicationsDataType', [])
                inventory['installed_software'] = [{'name': a.get('_name',''), 'version': a.get('version','')} for a in apps[:50]]
            except:
                pass
        elif SYSTEM == 'Linux':
            r = subprocess.run(['cat', '/proc/cpuinfo'], capture_output=True, text=True)
            for line in r.stdout.splitlines():
                if 'model name' in line:
                    inventory['cpu_model'] = line.split(':')[1].strip()
                    break
            r = subprocess.run(['free', '-g'], capture_output=True, text=True)
            lines = r.stdout.splitlines()
            if len(lines) > 1:
                inventory['ram_total_gb'] = lines[1].split()[1]
            # Logiciels Linux
            r = subprocess.run(['dpkg', '--list'], capture_output=True, text=True)
            pkgs = [l.split()[1] for l in r.stdout.splitlines() if l.startswith('ii')]
            inventory['installed_software'] = [{'name': p, 'version': ''} for p in pkgs[:50]]
        
        return inventory
    except Exception as e:
        return {'error': str(e)}


def check_backup_status() -> dict:
    """Vérifie si des sauvegardes récentes existent."""
    try:
        backup_found = False
        last_backup = None
        backup_dirs = []
        
        if SYSTEM == 'Darwin':
            # Time Machine
            r = subprocess.run(['tmutil', 'latestbackup'], capture_output=True, text=True)
            if r.returncode == 0 and r.stdout.strip():
                backup_found = True
                last_backup = r.stdout.strip()
            # Dossiers backup communs
            for d in ['/Volumes/Backup', Path.home() / 'Backup', Path.home() / 'backups']:
                if Path(str(d)).exists():
                    backup_dirs.append(str(d))
                    backup_found = True
        elif SYSTEM == 'Linux':
            for d in ['/backup', '/mnt/backup', '/var/backup', Path.home() / 'backup']:
                if Path(str(d)).exists():
                    backup_dirs.append(str(d))
                    backup_found = True
        
        return {
            'backup_found': backup_found,
            'last_backup': last_backup,
            'backup_dirs': backup_dirs,
            'backup_warning': not backup_found
        }
    except Exception as e:
        return {'backup_found': False, 'backup_warning': True, 'error': str(e)}


def check_new_users() -> dict:
    """Détecte les nouveaux comptes utilisateurs créés récemment."""
    try:
        recent_users = []
        if SYSTEM == 'Darwin':
            r = subprocess.run(['dscl', '.', '-list', '/Users'], capture_output=True, text=True)
            users = [u for u in r.stdout.splitlines() if not u.startswith('_') and u not in ['nobody','daemon','root']]
            recent_users = users
        elif SYSTEM == 'Linux':
            with open('/etc/passwd') as f:
                lines = f.readlines()
            users = [l.split(':')[0] for l in lines if int(l.split(':')[2]) >= 1000]
            recent_users = users
        return {'local_users': recent_users, 'user_count': len(recent_users)}
    except Exception as e:
        return {'local_users': [], 'error': str(e)}


def check_disk_health() -> dict:
    """Vérifie la santé du disque et l'espace disponible."""
    try:
        result = {}
        if SYSTEM == 'Darwin':
            r = subprocess.run(['df', '-h'], capture_output=True, text=True)
            lines = r.stdout.splitlines()
            disks = []
            for line in lines[1:]:
                parts = line.split()
                if len(parts) >= 5 and parts[0].startswith('/dev/'):
                    used_pct = int(parts[4].replace('%','')) if parts[4].endswith('%') else 0
                    disks.append({
                        'device': parts[0],
                        'size': parts[1],
                        'used': parts[2],
                        'available': parts[3],
                        'used_pct': used_pct,
                        'critical': used_pct > 85
                    })
            result['disks'] = disks
            result['any_critical'] = any(d['critical'] for d in disks)
        return result
    except Exception as e:
        return {'error': str(e)}



# ─── ZERO TRUST BEHAVIORAL MONITORING ────────────────────────────────────────

def collect_user_behavior() -> dict:
    """Surveille le comportement des utilisateurs — heure, localisation, fichiers accédés."""
    try:
        import datetime
        now = datetime.datetime.now()
        
        behavior = {
            'timestamp': now.isoformat(),
            'hour': now.hour,
            'day_of_week': now.weekday(),  # 0=lundi, 6=dimanche
            'is_business_hours': 8 <= now.hour <= 19 and now.weekday() < 5,
            'is_night_access': now.hour < 6 or now.hour >= 22,
            'is_weekend': now.weekday() >= 5,
        }

        # Utilisateur connecté actuellement
        if SYSTEM == 'Darwin' or SYSTEM == 'Linux':
            r = subprocess.run(['who'], capture_output=True, text=True)
            behavior['logged_users'] = [l.split()[0] for l in r.stdout.splitlines() if l]
            
            # Dernières connexions
            r2 = subprocess.run(['last', '-n', '10'], capture_output=True, text=True)
            behavior['recent_logins'] = r2.stdout.splitlines()[:10]

        # Localisation IP publique
        try:
            import urllib.request
            with urllib.request.urlopen('https://ipapi.co/json/', timeout=5) as resp:
                geo = json.loads(resp.read())
                behavior['ip'] = geo.get('ip','')
                behavior['country'] = geo.get('country_name','')
                behavior['city'] = geo.get('city','')
                behavior['org'] = geo.get('org','')
        except:
            behavior['ip'] = ''
            behavior['country'] = ''
            behavior['city'] = ''

        # Fichiers récemment accédés (dernière heure)
        suspicious_paths = []
        sensitive_keywords = ['password', 'mdp', 'secret', 'credential', 'bank', 'compta', 'facture', 'rh', 'salaire']
        try:
            if SYSTEM == 'Darwin':
                r = subprocess.run(['mdfind', '-onlyin', str(Path.home()), 
                    'kMDItemLastUsedDate >= $time.now(-3600)'], 
                    capture_output=True, text=True, timeout=10)
                recent_files = r.stdout.splitlines()[:20]
                for f in recent_files:
                    if any(kw in f.lower() for kw in sensitive_keywords):
                        suspicious_paths.append(f)
        except:
            pass
        behavior['sensitive_files_accessed'] = suspicious_paths
        behavior['suspicious_file_access'] = len(suspicious_paths) > 0

        return behavior
    except Exception as e:
        return {'error': str(e), 'is_business_hours': True}


def detect_behavioral_anomaly(current: dict, baseline: dict) -> dict:
    """Compare le comportement actuel avec la baseline habituelle."""
    anomalies = []
    risk_score = 0

    # Accès hors heures de bureau
    if not current.get('is_business_hours') and baseline.get('usually_business_hours', True):
        anomalies.append('Connexion hors heures de bureau inhabituelles')
        risk_score += 30

    # Accès de nuit
    if current.get('is_night_access'):
        anomalies.append('Connexion nocturne détectée')
        risk_score += 40

    # Accès le weekend
    if current.get('is_weekend') and not baseline.get('works_weekends', False):
        anomalies.append('Connexion weekend inhabituelle')
        risk_score += 20

    # Changement de pays
    current_country = current.get('country', '')
    baseline_country = baseline.get('usual_country', '')
    if current_country and baseline_country and current_country != baseline_country:
        anomalies.append(f'Connexion depuis pays inhabituel: {current_country} (habituel: {baseline_country})')
        risk_score += 80

    # Accès fichiers sensibles
    if current.get('suspicious_file_access'):
        anomalies.append(f'Accès à des fichiers sensibles détecté')
        risk_score += 25

    return {
        'anomalies': anomalies,
        'risk_score': risk_score,
        'has_anomaly': len(anomalies) > 0,
        'is_critical': risk_score >= 70
    }



# ─── SOC — COLLECTE DES LOGS SYSTÈME ─────────────────────────────────────────

def collect_system_logs() -> dict:
    """Collecte et analyse les logs système pour le SOC."""
    try:
        logs = {
            'auth_events': [],
            'failed_logins': [],
            'sudo_events': [],
            'network_events': [],
            'process_events': [],
            'critical_events': [],
        }

        if SYSTEM == 'Darwin':
            # Logs d'authentification
            r = subprocess.run(
                ['log', 'show', '--predicate',
                 'eventMessage contains "authentication" OR eventMessage contains "login" OR eventMessage contains "sudo" OR eventMessage contains "failed"',
                 '--last', '1h', '--style', 'compact'],
                capture_output=True, text=True, timeout=15
            )
            lines = r.stdout.splitlines()[-100:]
            for line in lines:
                line_l = line.lower()
                if 'failed' in line_l or 'error' in line_l:
                    logs['failed_logins'].append(line[:200])
                elif 'sudo' in line_l:
                    logs['sudo_events'].append(line[:200])
                elif 'auth' in line_l or 'login' in line_l:
                    logs['auth_events'].append(line[:200])

            # Logs kernel/sécurité
            r2 = subprocess.run(
                ['log', 'show', '--predicate',
                 'subsystem == "com.apple.securityd" OR eventMessage contains "denied" OR eventMessage contains "blocked"',
                 '--last', '1h', '--style', 'compact'],
                capture_output=True, text=True, timeout=15
            )
            for line in r2.stdout.splitlines()[-50:]:
                if any(kw in line.lower() for kw in ['denied', 'blocked', 'reject']):
                    logs['critical_events'].append(line[:200])

        elif SYSTEM == 'Linux':
            # Auth log
            for logfile in ['/var/log/auth.log', '/var/log/secure']:
                if Path(logfile).exists():
                    r = subprocess.run(['tail', '-n', '500', logfile],
                                      capture_output=True, text=True)
                    for line in r.stdout.splitlines():
                        line_l = line.lower()
                        if 'failed' in line_l or 'invalid' in line_l:
                            logs['failed_logins'].append(line[:200])
                        elif 'sudo' in line_l:
                            logs['sudo_events'].append(line[:200])
                        elif 'accepted' in line_l or 'opened' in line_l:
                            logs['auth_events'].append(line[:200])

            # Syslog
            if Path('/var/log/syslog').exists():
                r = subprocess.run(['tail', '-n', '200', '/var/log/syslog'],
                                  capture_output=True, text=True)
                for line in r.stdout.splitlines():
                    if any(kw in line.lower() for kw in ['error', 'crit', 'alert', 'emerg']):
                        logs['critical_events'].append(line[:200])

        elif SYSTEM == 'Windows':
            # Event logs via PowerShell
            r = subprocess.run([
                'powershell', '-Command',
                'Get-EventLog -LogName Security -Newest 100 | Where-Object {$_.EventID -in @(4625,4624,4648,4720,4732)} | Select-Object -ExpandProperty Message'
            ], capture_output=True, text=True, timeout=15)
            for line in r.stdout.splitlines():
                if line.strip():
                    logs['auth_events'].append(line[:200])

        # Statistiques
        logs['stats'] = {
            'failed_logins_count': len(logs['failed_logins']),
            'sudo_events_count': len(logs['sudo_events']),
            'auth_events_count': len(logs['auth_events']),
            'critical_events_count': len(logs['critical_events']),
            'has_suspicious_activity': len(logs['failed_logins']) > 5 or len(logs['critical_events']) > 0,
            'brute_force_suspected': len(logs['failed_logins']) > 10,
        }

        return logs
    except Exception as e:
        return {'error': str(e), 'stats': {'has_suspicious_activity': False}}



# ─── SUPPORT WINDOWS COMPLET ─────────────────────────────────────────────────

def check_windows_security() -> dict:
    """Checks de sécurité complets pour Windows."""
    if SYSTEM != 'Windows':
        return {}
    try:
        result = {}

        # Pare-feu Windows
        r = subprocess.run(['netsh', 'advfirewall', 'show', 'allprofiles', 'state'],
                          capture_output=True, text=True)
        result['firewall_enabled'] = 'ON' in r.stdout.upper()

        # Windows Defender / Antivirus
        r = subprocess.run(['powershell', '-Command',
            'Get-MpComputerStatus | Select-Object AntivirusEnabled,RealTimeProtectionEnabled | ConvertTo-Json'],
            capture_output=True, text=True, timeout=15)
        try:
            import json
            av = json.loads(r.stdout)
            result['antivirus_enabled'] = av.get('AntivirusEnabled', False)
            result['antivirus_status'] = 'enabled' if av.get('AntivirusEnabled') else 'disabled'
            result['realtime_protection'] = av.get('RealTimeProtectionEnabled', False)
        except:
            result['antivirus_enabled'] = False
            result['antivirus_status'] = 'unknown'

        # BitLocker
        r = subprocess.run(['manage-bde', '-status', 'C:'],
                          capture_output=True, text=True)
        result['disk_encrypted'] = 'Protection On' in r.stdout or 'Fully Encrypted' in r.stdout

        # Mises à jour Windows
        r = subprocess.run(['powershell', '-Command',
            '(New-Object -ComObject Microsoft.Update.AutoUpdate).Settings.NotificationLevel'],
            capture_output=True, text=True, timeout=10)
        result['auto_update_enabled'] = r.stdout.strip() == '4'

        # Screensaver et verrouillage
        r = subprocess.run(['reg', 'query',
            'HKCU\\Control Panel\\Desktop', '/v', 'ScreenSaveActive'],
            capture_output=True, text=True)
        result['screensaver_enabled'] = '0x1' in r.stdout or '1' in r.stdout

        # Utilisateurs locaux Windows
        r = subprocess.run(['net', 'user'], capture_output=True, text=True)
        users = [u for u in r.stdout.split() if u and not u.startswith('-') and '\\\\' not in u]
        result['local_users'] = users[:20]

        # Ports dangereux Windows
        r = subprocess.run(['netstat', '-an'], capture_output=True, text=True)
        dangerous = [4444, 1337, 5555, 6666, 7777, 8888, 9999, 31337]
        open_dangerous = []
        for port in dangerous:
            if f':{port} ' in r.stdout or f':{port}\t' in r.stdout:
                open_dangerous.append(port)
        result['dangerous_ports'] = open_dangerous
        result['has_dangerous_ports'] = len(open_dangerous) > 0

        # Connexions réseau actives
        established = [l for l in r.stdout.splitlines() if 'ESTABLISHED' in l]
        result['established_connections'] = len(established)

        # Ransomware — fichiers chiffrés
        import os
        suspicious = []
        extensions = ['.locked', '.encrypted', '.crypto', '.crypt', '.enc', '.wncry', '.wnry']
        home = os.path.expanduser('~')
        for ext in extensions:
            try:
                for root, dirs, files in os.walk(home):
                    dirs[:] = [d for d in dirs if not d.startswith('.')][:5]
                    for f in files:
                        if f.endswith(ext):
                            suspicious.append(os.path.join(root, f))
                            if len(suspicious) >= 20:
                                break
                    if len(suspicious) >= 20:
                        break
            except:
                pass
        result['ransomware_detected'] = len(suspicious) > 0
        result['ransomware_files_count'] = len(suspicious)

        # Logs Windows — tentatives connexion échouées
        r = subprocess.run(['powershell', '-Command',
            '(Get-EventLog -LogName Security -InstanceId 4625 -Newest 50 -ErrorAction SilentlyContinue).Count'],
            capture_output=True, text=True, timeout=15)
        try:
            failed = int(r.stdout.strip())
            result['soc_failed_logins'] = failed
            result['soc_brute_force'] = failed > 10
        except:
            result['soc_failed_logins'] = 0
            result['soc_brute_force'] = False

        # Inventaire logiciels Windows
        r = subprocess.run(['powershell', '-Command',
            'Get-ItemProperty HKLM:\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | Select-Object DisplayName,DisplayVersion | ConvertTo-Json'],
            capture_output=True, text=True, timeout=20)
        try:
            import json
            apps = json.loads(r.stdout)
            if isinstance(apps, list):
                result['installed_software'] = [{'name': a.get('DisplayName',''), 'version': a.get('DisplayVersion','')} for a in apps[:50] if a.get('DisplayName')]
        except:
            result['installed_software'] = []

        # Backup Windows
        r = subprocess.run(['powershell', '-Command',
            'Get-WBSummary -ErrorAction SilentlyContinue | Select-Object LastSuccessfulBackupTime'],
            capture_output=True, text=True, timeout=10)
        result['backup_found'] = 'LastSuccessfulBackupTime' in r.stdout and 'NULL' not in r.stdout
        result['backup_warning'] = not result['backup_found']

        # CPU et RAM Windows
        r = subprocess.run(['powershell', '-Command',
            '(Get-Counter "\\Processor(_Total)\\% Processor Time").CounterSamples.CookedValue'],
            capture_output=True, text=True, timeout=10)
        try:
            result['cpu_percent'] = float(r.stdout.strip())
        except:
            result['cpu_percent'] = 0

        r2 = subprocess.run(['powershell', '-Command',
            '$mem = Get-CimInstance Win32_OperatingSystem; [math]::Round(($mem.TotalVisibleMemorySize - $mem.FreePhysicalMemory) / $mem.TotalVisibleMemorySize * 100, 1)'],
            capture_output=True, text=True, timeout=10)
        try:
            result['ram_percent'] = float(r2.stdout.strip())
        except:
            result['ram_percent'] = 0

        result['platform'] = 'Windows'
        
        # Ajouter détections avancées Windows
        try:
            persistence = check_windows_persistence()
            result.update(persistence)
        except: pass
        
        try:
            lolbins = check_windows_living_off_land()
            result.update(lolbins)
        except: pass
        
        return result

    except Exception as e:
        return {'error': str(e), 'platform': 'Windows'}


def check_disk_encryption_windows() -> dict:
    """Vérifie BitLocker sur Windows."""
    if SYSTEM != 'Windows':
        return {}
    try:
        r = subprocess.run(['manage-bde', '-status'], capture_output=True, text=True)
        encrypted = 'Protection On' in r.stdout
        return {
            'disk_encrypted': encrypted,
            'encryption_type': 'BitLocker' if encrypted else 'None'
        }
    except:
        return {'disk_encrypted': False, 'encryption_type': 'Unknown'}



# ─── DÉTECTIONS WINDOWS AVANCÉES ─────────────────────────────────────────────

def check_windows_persistence() -> dict:
    """Détecte les footholds persistants Windows — comme Huntress."""
    if SYSTEM != 'Windows':
        return {}
    try:
        result = {'persistent_threats': [], 'suspicious_tasks': [], 'suspicious_services': []}

        # 1. Clés de registre de démarrage suspectes
        startup_keys = [
            r'HKCU\Software\Microsoft\Windows\CurrentVersion\Run',
            r'HKLM\Software\Microsoft\Windows\CurrentVersion\Run',
            r'HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce',
        ]
        for key in startup_keys:
            r = subprocess.run(['reg', 'query', key], capture_output=True, text=True)
            for line in r.stdout.splitlines():
                if any(sus in line.lower() for sus in ['temp', 'appdata\\roaming', 'public', 'programdata', '.vbs', '.ps1', '.bat', 'powershell', 'cmd /c', 'wscript', 'cscript']):
                    result['persistent_threats'].append(f'Registre suspect: {line.strip()[:150]}')

        # 2. Tâches planifiées suspectes
        r = subprocess.run(['schtasks', '/query', '/fo', 'LIST', '/v'], capture_output=True, text=True, timeout=15)
        current_task = ''
        for line in r.stdout.splitlines():
            if 'Nom de la tâche' in line or 'Task Name' in line:
                current_task = line
            if any(sus in line.lower() for sus in ['powershell', 'cmd', 'wscript', 'mshta', 'regsvr32', 'rundll32', 'certutil']) and current_task:
                result['suspicious_tasks'].append(f'{current_task.strip()} — {line.strip()[:100]}')

        # 3. Services Windows suspects
        r = subprocess.run(['sc', 'query', 'type=', 'all', 'state=', 'all'], capture_output=True, text=True, timeout=15)
        services = re.findall(r'SERVICE_NAME: (\S+)', r.stdout)
        for svc in services[:50]:
            r2 = subprocess.run(['sc', 'qc', svc], capture_output=True, text=True)
            if any(sus in r2.stdout.lower() for sus in ['temp\\', 'appdata\\', '%temp%', 'powershell', 'cmd /c']):
                result['suspicious_services'].append(f'Service suspect: {svc}')

        # 4. PowerShell execution policy
        r = subprocess.run(['powershell', '-Command', 'Get-ExecutionPolicy'], capture_output=True, text=True)
        policy = r.stdout.strip().lower()
        result['powershell_policy'] = policy
        result['powershell_unrestricted'] = policy in ['unrestricted', 'bypass']

        # 5. WMI subscriptions suspectes (vecteur d'attaque courant)
        r = subprocess.run(['powershell', '-Command',
            'Get-WMIObject -Namespace root\\subscription -Class __EventFilter | Select-Object Name,Query | ConvertTo-Json'],
            capture_output=True, text=True, timeout=15)
        if r.stdout.strip() and r.stdout.strip() != 'null':
            result['wmi_subscriptions'] = True
            result['persistent_threats'].append('Abonnements WMI détectés — vecteur d attaque courant')
        else:
            result['wmi_subscriptions'] = False

        # 6. Ransomware canaries — fichiers leurres
        import os
        canary_dirs = [
            os.path.expanduser('~/Documents'),
            os.path.expanduser('~/Desktop'),
            'C:\\Users\\Public\\Documents',
        ]
        result['canary_triggered'] = False
        for d in canary_dirs:
            canary_path = os.path.join(d, '.shieldflow_canary.txt')
            try:
                if not os.path.exists(canary_path):
                    with open(canary_path, 'w') as f:
                        f.write('ShieldFlow Canary File — Do not delete')
                else:
                    # Vérifier si le fichier a été modifié (signe de ransomware)
                    mtime = os.path.getmtime(canary_path)
                    if mtime > (subprocess.time.time() - 300):  # modifié dans les 5 dernières minutes
                        result['canary_triggered'] = True
                        result['persistent_threats'].append(f'CANARY MODIFIÉ: {canary_path} — ransomware potentiel')
            except: pass

        # 7. Connexions réseau suspectes Windows
        r = subprocess.run(['netstat', '-ano'], capture_output=True, text=True)
        dangerous_ports = [4444, 1337, 5555, 6666, 7777, 8888, 9999, 31337, 4445, 1234]
        suspicious_conns = []
        for line in r.stdout.splitlines():
            if 'ESTABLISHED' in line:
                for port in dangerous_ports:
                    if f':{port} ' in line or f':{port}\t' in line:
                        suspicious_conns.append(line.strip()[:100])
        result['suspicious_connections'] = suspicious_conns
        result['has_suspicious_connections'] = len(suspicious_conns) > 0

        # 8. WSL détection (Linux dans Windows — surveiller)
        r = subprocess.run(['wsl', '--list', '--quiet'], capture_output=True, text=True, timeout=10)
        result['wsl_installed'] = r.returncode == 0 and bool(r.stdout.strip())
        result['wsl_distributions'] = r.stdout.strip().splitlines() if result['wsl_installed'] else []

        result['has_persistent_threats'] = len(result['persistent_threats']) > 0
        result['has_suspicious_tasks'] = len(result['suspicious_tasks']) > 0
        result['has_suspicious_services'] = len(result['suspicious_services']) > 0

        return result
    except Exception as e:
        return {'error': str(e)}


def check_windows_living_off_land() -> dict:
    """Détecte l'utilisation malveillante d'outils Windows légitimes (LOLBins)."""
    if SYSTEM != 'Windows':
        return {}
    try:
        result = {'lolbin_alerts': []}

        # Processus LOLBins suspects en cours
        r = subprocess.run(['tasklist', '/v', '/fo', 'csv'], capture_output=True, text=True)
        lolbins = ['certutil.exe', 'mshta.exe', 'wscript.exe', 'cscript.exe',
                   'regsvr32.exe', 'rundll32.exe', 'msiexec.exe', 'bitsadmin.exe']
        for line in r.stdout.splitlines():
            for lol in lolbins:
                if lol.lower() in line.lower():
                    result['lolbin_alerts'].append(f'LOLBin actif: {lol} — vérifiez son utilisation')

        # Historique PowerShell
        ps_history = os.path.expanduser('~\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt')
        if os.path.exists(ps_history):
            try:
                with open(ps_history, 'r', errors='ignore') as f:
                    history = f.read()
                suspicious_cmds = ['invoke-expression', 'iex', 'downloadstring', 'webclient',
                                   'base64', 'bypass', 'hidden', 'encodedcommand', '-enc']
                for cmd in suspicious_cmds:
                    if cmd.lower() in history.lower():
                        result['lolbin_alerts'].append(f'PowerShell suspect dans historique: {cmd}')
            except: pass

        result['has_lolbin_activity'] = len(result['lolbin_alerts']) > 0
        return result
    except Exception as e:
        return {'error': str(e)}



# ─── DÉTECTIONS LINUX COMPLÈTES ──────────────────────────────────────────────

def check_linux_complete() -> dict:
    """Détections Linux complètes — réseau, inventaire, processus, persistence."""
    if SYSTEM != 'Linux':
        return {}
    try:
        result = {}

        # 1. Connexions réseau actives
        r = subprocess.run(['ss', '-tupn'], capture_output=True, text=True)
        established = [l for l in r.stdout.splitlines() if 'ESTAB' in l]
        dangerous_ports = [4444, 1337, 5555, 6666, 7777, 8888, 9999, 31337]
        suspicious = [l for l in established if any(f':{p}' in l for p in dangerous_ports)]
        result['established_connections'] = len(established)
        result['suspicious_connections'] = suspicious
        result['has_suspicious_connections'] = len(suspicious) > 0

        # 2. Inventaire logiciels
        installed = []
        for cmd in [['dpkg', '--get-selections'], ['rpm', '-qa']]:
            r2 = subprocess.run(cmd, capture_output=True, text=True)
            if r2.returncode == 0:
                pkgs = [l.split()[0] for l in r2.stdout.splitlines() if l.strip()]
                installed = [{'name': p, 'version': ''} for p in pkgs[:100]]
                break
        result['installed_software'] = installed

        # 3. Santé disques
        r3 = subprocess.run(['df', '-h'], capture_output=True, text=True)
        disks = []
        for line in r3.stdout.splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 5:
                try:
                    pct = int(parts[4].replace('%',''))
                    disks.append({'mount': parts[5], 'percent': pct})
                    if pct > 85:
                        result['disk_critical'] = True
                except: pass
        result['disk_usage'] = disks

        # 4. Processus suspects
        r4 = subprocess.run(['ps', 'aux', '--sort=-%cpu'], capture_output=True, text=True)
        procs = []
        for line in r4.stdout.splitlines()[1:11]:
            parts = line.split(None, 10)
            if len(parts) >= 11:
                try:
                    cpu = float(parts[2])
                    procs.append({'user': parts[0], 'cpu': cpu, 'cmd': parts[10][:80]})
                except: pass
        result['top_processes'] = procs
        result['high_cpu'] = any(p['cpu'] > 85 for p in procs)

        # 5. Persistence Linux — crontabs suspects
        suspicious_crons = []
        r5 = subprocess.run(['crontab', '-l'], capture_output=True, text=True)
        for line in r5.stdout.splitlines():
            if any(s in line.lower() for s in ['curl', 'wget', 'bash', '/tmp', 'python', 'nc ']):
                suspicious_crons.append(line.strip()[:100])
        result['suspicious_crons'] = suspicious_crons
        result['has_suspicious_crons'] = len(suspicious_crons) > 0

        # 6. SUID suspects
        r6 = subprocess.run(['find', '/usr/bin', '/usr/local/bin', '-perm', '-4000', '-type', 'f'],
                           capture_output=True, text=True, timeout=10)
        known_suid = ['sudo', 'su', 'passwd', 'ping', 'mount', 'umount', 'newgrp', 'chsh', 'chfn']
        suspicious_suid = [f for f in r6.stdout.splitlines() 
                          if not any(k in f for k in known_suid)]
        result['suspicious_suid'] = suspicious_suid
        result['has_suspicious_suid'] = len(suspicious_suid) > 0

        # 7. SSH config
        ssh_config = Path('/etc/ssh/sshd_config')
        if ssh_config.exists():
            cfg = ssh_config.read_text(errors='ignore')
            result['ssh_root_login'] = 'PermitRootLogin yes' in cfg
            result['ssh_password_auth'] = 'PasswordAuthentication yes' in cfg
        
        return result
    except Exception as e:
        return {'error': str(e)}

