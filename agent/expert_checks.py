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

