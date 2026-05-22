#!/usr/bin/env python3
"""
ShieldFlow — Agent Cloud AWS
Surveille la sécurité de l'infrastructure AWS d'un client.
"""

import json
import os
import sys
import logging
from datetime import datetime, timezone, timedelta

logger = logging.getLogger('shieldflow.cloud.aws')

def check_aws_security(aws_access_key, aws_secret_key, aws_region='eu-west-1'):
    """
    Analyse complète de la sécurité AWS.
    Retourne une liste d'alertes.
    """
    alerts = []
    
    try:
        import boto3
        from botocore.exceptions import ClientError, NoCredentialsError
        
        session = boto3.Session(
            aws_access_key_id=aws_access_key,
            aws_secret_access_key=aws_secret_key,
            region_name=aws_region
        )
        
        # 1. Vérifier les buckets S3 publics
        alerts.extend(_check_s3_buckets(session))
        
        # 2. Vérifier les groupes de sécurité EC2
        alerts.extend(_check_security_groups(session))
        
        # 3. Vérifier les comptes IAM
        alerts.extend(_check_iam_users(session))
        
        # 4. Vérifier CloudTrail
        alerts.extend(_check_cloudtrail(session))
        
        # 5. Vérifier les clés d'accès
        alerts.extend(_check_access_keys(session))
        
    except ImportError:
        logger.error("boto3 non installé. Lancez: pip3 install boto3")
        alerts.append({
            'type': 'CONFIG_ERROR',
            'severity': 'medium',
            'title': 'Module AWS non installé',
            'description': 'boto3 requis pour la surveillance AWS.',
            'recommendation': 'pip3 install boto3'
        })
    except Exception as e:
        logger.error(f"Erreur AWS: {e}")
    
    return alerts


def _check_s3_buckets(session):
    """Vérifie les buckets S3 accessibles publiquement."""
    alerts = []
    try:
        s3 = session.client('s3')
        buckets = s3.list_buckets().get('Buckets', [])
        
        for bucket in buckets:
            name = bucket['Name']
            try:
                # Vérifier ACL public
                acl = s3.get_bucket_acl(Bucket=name)
                for grant in acl.get('Grants', []):
                    grantee = grant.get('Grantee', {})
                    if grantee.get('URI', '') == 'http://acs.amazonaws.com/groups/global/AllUsers':
                        alerts.append({
                            'type': f'S3_PUBLIC_{name}',
                            'severity': 'critical',
                            'title': f'Bucket S3 public : {name}',
                            'description': f'Le bucket S3 "{name}" est accessible publiquement. Toutes les données sont exposées sur internet.',
                            'recommendation': f'Désactiver l\'accès public : aws s3api put-bucket-acl --bucket {name} --acl private',
                            'evidence': {'bucket': name, 'access': 'public'}
                        })
                        break
                
                # Vérifier Block Public Access
                try:
                    bpa = s3.get_public_access_block(Bucket=name)
                    config = bpa.get('PublicAccessBlockConfiguration', {})
                    if not all([
                        config.get('BlockPublicAcls', False),
                        config.get('BlockPublicPolicy', False),
                        config.get('RestrictPublicBuckets', False)
                    ]):
                        alerts.append({
                            'type': f'S3_NO_BLOCK_{name}',
                            'severity': 'high',
                            'title': f'Protection S3 insuffisante : {name}',
                            'description': f'Le bucket "{name}" n\'a pas toutes les protections "Block Public Access" activées.',
                            'recommendation': f'Activer Block Public Access sur {name}',
                            'evidence': {'bucket': name, 'block_public_access': config}
                        })
                except Exception:
                    pass
                    
            except Exception:
                continue
                
    except Exception as e:
        logger.warning(f"Erreur S3: {e}")
    
    return alerts


def _check_security_groups(session):
    """Vérifie les groupes de sécurité EC2 avec ports dangereux ouverts."""
    alerts = []
    DANGEROUS_PORTS = {
        22: 'SSH',
        3389: 'RDP',
        3306: 'MySQL',
        5432: 'PostgreSQL',
        27017: 'MongoDB',
        6379: 'Redis',
        9200: 'Elasticsearch'
    }
    
    try:
        ec2 = session.client('ec2')
        sgs = ec2.describe_security_groups().get('SecurityGroups', [])
        
        for sg in sgs:
            sg_id = sg['GroupId']
            sg_name = sg.get('GroupName', sg_id)
            
            for rule in sg.get('IpPermissions', []):
                from_port = rule.get('FromPort', 0)
                to_port = rule.get('ToPort', 65535)
                
                # Vérifier si ouvert à tout internet (0.0.0.0/0)
                is_open = any(
                    r.get('CidrIp') == '0.0.0.0/0' or r.get('CidrIpv6') == '::/0'
                    for r in rule.get('IpRanges', []) + rule.get('Ipv6Ranges', [])
                )
                
                if is_open:
                    for port, service in DANGEROUS_PORTS.items():
                        if from_port <= port <= to_port:
                            alerts.append({
                                'type': f'EC2_PORT_{port}_{sg_id}',
                                'severity': 'critical' if port in [22, 3389] else 'high',
                                'title': f'Port {service} ({port}) exposé sur internet',
                                'description': f'Le groupe de sécurité "{sg_name}" expose le port {port} ({service}) à tout internet (0.0.0.0/0).',
                                'recommendation': f'Restreindre le port {port} aux IPs autorisées uniquement.',
                                'evidence': {'security_group': sg_name, 'port': port, 'service': service}
                            })
                            
    except Exception as e:
        logger.warning(f"Erreur EC2 Security Groups: {e}")
    
    return alerts


def _check_iam_users(session):
    """Vérifie les utilisateurs IAM sans MFA et avec des permissions excessives."""
    alerts = []
    try:
        iam = session.client('iam')
        users = iam.list_users().get('Users', [])
        
        for user in users:
            username = user['UserName']
            
            # Vérifier MFA
            mfa_devices = iam.list_mfa_devices(UserName=username).get('MFADevices', [])
            if not mfa_devices:
                alerts.append({
                    'type': f'IAM_NO_MFA_{username}',
                    'severity': 'high',
                    'title': f'Utilisateur AWS sans MFA : {username}',
                    'description': f'Le compte IAM "{username}" n\'a pas de double authentification activée.',
                    'recommendation': f'Activer MFA pour {username} dans la console AWS IAM.',
                    'evidence': {'username': username, 'mfa': False}
                })
            
            # Vérifier accès console sans MFA
            try:
                login_profile = iam.get_login_profile(UserName=username)
                if login_profile and not mfa_devices:
                    alerts.append({
                        'type': f'IAM_CONSOLE_NO_MFA_{username}',
                        'severity': 'critical',
                        'title': f'Accès console AWS sans MFA : {username}',
                        'description': f'"{username}" peut se connecter à la console AWS sans MFA.',
                        'recommendation': 'Forcer le MFA via une politique IAM.',
                        'evidence': {'username': username}
                    })
            except Exception:
                pass
                
    except Exception as e:
        logger.warning(f"Erreur IAM: {e}")
    
    return alerts


def _check_cloudtrail(session):
    """Vérifie si CloudTrail (audit logs) est activé."""
    alerts = []
    try:
        ct = session.client('cloudtrail')
        trails = ct.describe_trails().get('trailList', [])
        
        if not trails:
            alerts.append({
                'type': 'CLOUDTRAIL_DISABLED',
                'severity': 'high',
                'title': 'CloudTrail désactivé',
                'description': 'CloudTrail n\'est pas configuré. Aucune trace des actions AWS n\'est conservée.',
                'recommendation': 'Activer CloudTrail dans toutes les régions pour l\'audit de conformité.',
                'evidence': {'cloudtrail': False}
            })
        else:
            for trail in trails:
                if not trail.get('IsMultiRegionTrail', False):
                    alerts.append({
                        'type': f'CLOUDTRAIL_SINGLE_REGION_{trail["Name"]}',
                        'severity': 'medium',
                        'title': f'CloudTrail mono-région : {trail["Name"]}',
                        'description': 'CloudTrail n\'est pas activé sur toutes les régions AWS.',
                        'recommendation': 'Configurer CloudTrail multi-région.',
                        'evidence': {'trail': trail['Name']}
                    })
                    
    except Exception as e:
        logger.warning(f"Erreur CloudTrail: {e}")
    
    return alerts


def _check_access_keys(session):
    """Vérifie les clés d'accès AWS trop anciennes."""
    alerts = []
    try:
        iam = session.client('iam')
        users = iam.list_users().get('Users', [])
        
        for user in users:
            username = user['UserName']
            keys = iam.list_access_keys(UserName=username).get('AccessKeyMetadata', [])
            
            for key in keys:
                created = key['CreateDate']
                age_days = (datetime.now(timezone.utc) - created).days
                
                if age_days > 90:
                    alerts.append({
                        'type': f'IAM_OLD_KEY_{key["AccessKeyId"][:8]}',
                        'severity': 'high' if age_days > 180 else 'medium',
                        'title': f'Clé AWS ancienne : {username} ({age_days} jours)',
                        'description': f'La clé d\'accès de "{username}" a {age_days} jours. Les clés doivent être renouvelées tous les 90 jours.',
                        'recommendation': f'Créer une nouvelle clé pour {username} et supprimer l\'ancienne.',
                        'evidence': {'username': username, 'key_age_days': age_days}
                    })
                    
    except Exception as e:
        logger.warning(f"Erreur Access Keys: {e}")
    
    return alerts


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    
    # Test avec variables d'environnement
    key = os.getenv('AWS_ACCESS_KEY_ID', '')
    secret = os.getenv('AWS_SECRET_ACCESS_KEY', '')
    region = os.getenv('AWS_REGION', 'eu-west-1')
    
    if not key or not secret:
        print("Usage: AWS_ACCESS_KEY_ID=xxx AWS_SECRET_ACCESS_KEY=yyy python3 cloud_aws.py")
        sys.exit(1)
    
    print("Analyse AWS en cours...")
    alerts = check_aws_security(key, secret, region)
    print(f"\n{len(alerts)} alerte(s) trouvée(s):")
    for a in alerts:
        print(f"  [{a['severity'].upper()}] {a['title']}")
