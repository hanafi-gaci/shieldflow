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
