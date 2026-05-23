// ShieldFlow — Base complète des instructions de remédiation
// Pour chaque alerte : auto-remédiation possible + instructions humaines par OS

const MANUAL_INSTRUCTIONS = {

  // ─── PARE-FEU ──────────────────────────────────────────────────────────────
  FIREWALL_OFF: {
    auto: true,
    label: 'Pare-feu désactivé',
    Darwin: [
      '1. Menu Apple → Réglages Système → Réseau',
      '2. Cliquez sur Pare-feu dans la barre latérale',
      '3. Activez le pare-feu',
      '4. Cliquez sur Options pour configurer les règles avancées'
    ],
    Windows: [
      '1. Panneau de configuration → Système et sécurité',
      '2. Pare-feu Windows Defender → Activer ou désactiver',
      '3. Activez pour les réseaux privés ET publics',
      '4. Confirmez et fermez'
    ],
    Linux: [
      '1. L\'agent active UFW automatiquement',
      '2. Vérifiez : sudo ufw status',
      '3. Si inactif : sudo ufw enable',
      '4. Règles de base : sudo ufw allow ssh && sudo ufw default deny incoming'
    ]
  },

  // ─── CHIFFREMENT ───────────────────────────────────────────────────────────
  DISK_NOT_ENCRYPTED: {
    auto: false,
    label: 'Disque non chiffré',
    Darwin: [
      '1. Menu Apple → Réglages Système → cliquez sur votre nom',
      '2. Cliquez sur FileVault',
      '3. Cliquez sur Activer FileVault',
      '4. Choisissez comment déverrouiller le disque (compte iCloud recommandé)',
      '5. IMPORTANT : Notez la clé de récupération dans un endroit sûr',
      '6. Redémarrez le Mac — le chiffrement prend quelques heures'
    ],
    Windows: [
      '1. Panneau de configuration → Chiffrement de lecteur BitLocker',
      '2. Cliquez sur Activer BitLocker sur le lecteur C:',
      '3. Choisissez comment déverrouiller (mot de passe recommandé)',
      '4. Sauvegardez la clé de récupération sur votre compte Microsoft',
      '5. Lancez le chiffrement et redémarrez le PC'
    ],
    Linux: [
      '1. Le chiffrement Linux (LUKS) nécessite une réinstallation du système',
      '2. Sauvegardez toutes les données importantes sur un disque externe',
      '3. Lors de l\'installation Ubuntu : cochez "Chiffrer la nouvelle installation"',
      '4. Contactez le support ShieldFlow pour planifier cette opération sans perte de données'
    ]
  },

  // ─── ANTIVIRUS ─────────────────────────────────────────────────────────────
  NO_ANTIVIRUS: {
    auto: false,
    label: 'Antivirus absent',
    Darwin: [
      '1. L\'agent met à jour XProtect (antivirus Apple intégré) automatiquement',
      '2. Pour une protection renforcée : allez sur https://malwarebytes.com',
      '3. Cliquez sur Télécharger gratuitement',
      '4. Ouvrez le fichier .pkg téléchargé et suivez l\'installation',
      '5. Lancez un scan complet après installation (environ 30 min)'
    ],
    Windows: [
      '1. L\'agent active et met à jour Windows Defender automatiquement',
      '2. Vérifiez : Sécurité Windows → Protection virus et menaces',
      '3. Cliquez sur Rechercher les mises à jour',
      '4. Lancez une Analyse complète pour vérifier le système',
      '5. Activez la protection en temps réel si désactivée'
    ],
    Linux: [
      '1. L\'agent installe ClamAV automatiquement',
      '2. Vérifiez : systemctl status clamav-daemon',
      '3. Lancez un scan : sudo clamscan -r /home --bell -i',
      '4. Mettez à jour les définitions : sudo freshclam'
    ]
  },

  // ─── MISES À JOUR ──────────────────────────────────────────────────────────
  UPDATES_CRITICAL: {
    auto: true,
    label: 'Mises à jour critiques manquantes',
    Darwin: [
      '1. L\'agent active les mises à jour automatiques',
      '2. Pour mettre à jour maintenant : Menu Apple → Réglages Système → Général → Mise à jour de logiciels',
      '3. Cliquez sur Mettre à jour maintenant',
      '4. Redémarrez si demandé — les mises à jour de sécurité sont critiques'
    ],
    Windows: [
      '1. L\'agent active Windows Update automatiquement',
      '2. Pour mettre à jour maintenant : Paramètres → Windows Update → Rechercher les mises à jour',
      '3. Installez toutes les mises à jour marquées "Critique" et "Important"',
      '4. Redémarrez le PC pour finaliser'
    ],
    Linux: [
      '1. L\'agent configure unattended-upgrades automatiquement',
      '2. Pour mettre à jour maintenant : sudo apt-get update && sudo apt-get upgrade -y',
      '3. Pour les mises à jour de sécurité uniquement : sudo apt-get install -y unattended-upgrades',
      '4. Redémarrez si le kernel a été mis à jour : sudo reboot'
    ]
  },

  UPDATES_PENDING: {
    auto: true,
    label: 'Mises à jour disponibles',
    Darwin: ['1. Menu Apple → Réglages Système → Général → Mise à jour de logiciels', '2. Installez les mises à jour disponibles', '3. Planifiez un redémarrage en dehors des heures de travail'],
    Windows: ['1. Paramètres → Windows Update → Rechercher les mises à jour', '2. Planifiez l\'installation pour la nuit'],
    Linux: ['1. sudo apt-get update && sudo apt-get upgrade -y', '2. Planifiez via cron si nécessaire']
  },

  // ─── CPU/RAM/DISQUE ────────────────────────────────────────────────────────
  HIGH_CPU: {
    auto: false,
    label: 'CPU anormalement élevé',
    Darwin: [
      '1. Ouvrez le Moniteur d\'activité (Applications → Utilitaires)',
      '2. Triez par % CPU en cliquant sur la colonne CPU',
      '3. Identifiez le processus qui consomme le plus',
      '4. Si suspect : sélectionnez-le → cliquez sur X → Forcer à quitter',
      '5. Notez le nom du processus et signalez-le à ShieldFlow si inconnu',
      '6. Si le problème persiste après redémarrage → possible malware'
    ],
    Windows: [
      '1. Ctrl+Shift+Échap → Gestionnaire des tâches',
      '2. Onglet Processus → triez par CPU',
      '3. Clic droit sur le processus suspect → Fin de tâche',
      '4. Vérifiez dans Démarrage si le processus se relance au boot',
      '5. Lancez un scan antivirus complet si suspect'
    ],
    Linux: [
      '1. Terminal : htop (installez avec sudo apt install htop)',
      '2. Triez par CPU avec F6 → percent_cpu',
      '3. Sélectionnez le processus suspect et appuyez sur F9 → Signal 9',
      '4. Vérifiez les services : systemctl list-units --state=running'
    ]
  },

  HIGH_RAM: {
    auto: true,
    label: 'RAM saturée',
    Darwin: [
      '1. L\'agent purge le cache mémoire automatiquement',
      '2. Fermez les applications inutilisées',
      '3. Moniteur d\'activité → Mémoire → identifiez les plus gourmands',
      '4. Redémarrez le Mac si le problème persiste',
      '5. Envisagez d\'augmenter la RAM si récurrent'
    ],
    Windows: [
      '1. L\'agent libère la mémoire automatiquement',
      '2. Gestionnaire des tâches → Mémoire → fermez les processus inutiles',
      '3. Désactivez les programmes au démarrage : onglet Démarrage → Désactiver',
      '4. Redémarrez le PC la nuit pour libérer la mémoire'
    ],
    Linux: [
      '1. L\'agent libère le cache automatiquement',
      '2. Vérifiez : free -h',
      '3. Identifiez les processus : ps aux --sort=-%mem | head -10',
      '4. Tuez les processus inutiles : sudo kill -9 PID'
    ]
  },

  LOW_DISK: {
    auto: true,
    label: 'Espace disque critique',
    Darwin: [
      '1. L\'agent nettoie les fichiers temporaires automatiquement',
      '2. Menu Apple → À propos de ce Mac → Stockage → Gérer',
      '3. Activez Optimiser le stockage',
      '4. Supprimez les grandes pièces jointes et les films déjà vus',
      '5. Videz la Corbeille',
      '6. Désinstallez les applications inutilisées',
      '7. Déplacez les photos/vidéos sur un disque externe ou iCloud'
    ],
    Windows: [
      '1. L\'agent nettoie les fichiers temporaires automatiquement',
      '2. Explorateur → clic droit sur C: → Propriétés → Nettoyage de disque',
      '3. Cochez tous les éléments → OK → Supprimer les fichiers',
      '4. Désinstallez les programmes inutiles : Paramètres → Applications',
      '5. Déplacez les fichiers volumineux sur un disque externe'
    ],
    Linux: [
      '1. L\'agent nettoie le cache apt automatiquement',
      '2. Vérifiez l\'espace : df -h',
      '3. Trouvez les gros fichiers : du -sh /* 2>/dev/null | sort -rh | head -20',
      '4. Nettoyez les logs : sudo journalctl --vacuum-time=7d',
      '5. Supprimez les anciens kernels : sudo apt autoremove'
    ]
  },

  // ─── PORTS DANGEREUX ───────────────────────────────────────────────────────
  DANGER_PORTS: {
    auto: true,
    label: 'Ports dangereux ouverts',
    Darwin: [
      '1. L\'agent ferme les ports dangereux automatiquement via pf',
      '2. Vérifiez quelles applications utilisent ces ports : sudo lsof -i :PORT',
      '3. Désinstallez ou désactivez l\'application concernée',
      '4. Réglages Système → Réseau → Pare-feu → Options → bloquez l\'application'
    ],
    Windows: [
      '1. L\'agent bloque les ports via Windows Firewall automatiquement',
      '2. Identifiez l\'application : netstat -ano | findstr :PORT',
      '3. Tasklist /fi "PID eq PID_TROUVÉ" pour identifier le programme',
      '4. Désinstallez ou désactivez le programme concerné'
    ],
    Linux: [
      '1. L\'agent ferme les ports via iptables automatiquement',
      '2. Identifiez l\'application : sudo ss -tlnp | grep :PORT',
      '3. Arrêtez le service : sudo systemctl stop SERVICE',
      '4. Désactivez au démarrage : sudo systemctl disable SERVICE'
    ]
  },

  // ─── BRUTE FORCE ───────────────────────────────────────────────────────────
  BRUTE_FORCE: {
    auto: true,
    label: 'Tentatives de connexion échouées',
    Darwin: [
      '1. L\'agent active la protection brute force automatiquement',
      '2. Vérifiez les tentatives : sudo log show --predicate \'process == "sshd"\' --last 1h',
      '3. Bloquez l\'IP source dans Réglages Système → Réseau → Pare-feu',
      '4. Désactivez SSH si non nécessaire : Réglages Système → Partage → désactivez Accès à distance',
      '5. Activez la double authentification sur tous les comptes'
    ],
    Windows: [
      '1. L\'agent configure le verrouillage de compte automatiquement',
      '2. Observateur d\'événements → Journaux Windows → Sécurité → filtrez ID 4625',
      '3. Notez les IPs sources et bloquez-les dans le pare-feu',
      '4. Politique de verrouillage : gpedit.msc → Stratégies de compte → Stratégie de verrouillage',
      '5. Activez la MFA sur tous les comptes Microsoft/Azure'
    ],
    Linux: [
      '1. L\'agent installe et configure fail2ban automatiquement',
      '2. Vérifiez : sudo fail2ban-client status sshd',
      '3. Les IPs sont automatiquement bloquées après 5 tentatives pendant 1h',
      '4. Renforcez SSH : éditez /etc/ssh/sshd_config → PasswordAuthentication no',
      '5. Utilisez des clés SSH uniquement'
    ]
  },

  // ─── MALWARES ──────────────────────────────────────────────────────────────
  MALWARE_DETECTED: {
    auto: true,
    label: 'Malware détecté',
    Darwin: [
      '1. L\'agent tente d\'éliminer le malware automatiquement',
      '2. URGENT : Déconnectez la machine d\'internet immédiatement',
      '3. Téléchargez Malwarebytes sur un autre appareil : malwarebytes.com',
      '4. Transférez via USB et lancez un scan complet',
      '5. Changez TOUS les mots de passe depuis un autre appareil',
      '6. Contactez ShieldFlow immédiatement pour une analyse forensique'
    ],
    Windows: [
      '1. L\'agent tente d\'éliminer le malware automatiquement',
      '2. URGENT : Déconnectez la machine d\'internet (débranchez le câble/désactivez WiFi)',
      '3. Démarrez en Mode sans échec : F8 au démarrage → Sécurité Windows → Analyse complète',
      '4. Utilisez Malwarebytes Anti-Malware en mode sans échec',
      '5. Changez TOUS les mots de passe depuis un autre appareil propre',
      '6. Si le malware persiste : réinstallation complète de Windows recommandée'
    ],
    Linux: [
      '1. L\'agent tente d\'éliminer le malware automatiquement',
      '2. URGENT : sudo systemctl isolate rescue.target pour isoler le système',
      '3. Lancez ClamAV : sudo clamscan -r / --bell -i --remove',
      '4. Vérifiez les crontabs suspects : crontab -l && sudo crontab -l',
      '5. Vérifiez les connexions sortantes : sudo netstat -tulpn',
      '6. Contactez ShieldFlow pour une analyse forensique complète'
    ]
  },

  // ─── CONNEXIONS RÉSEAU ─────────────────────────────────────────────────────
  HIGH_CONNECTIONS: {
    auto: true,
    label: 'Connexions réseau excessives',
    Darwin: [
      '1. L\'agent limite les connexions automatiquement',
      '2. Vérifiez les connexions : sudo netstat -an | grep ESTABLISHED | wc -l',
      '3. Identifiez les applications : sudo lsof -i | grep ESTABLISHED',
      '4. Fermez les applications non nécessaires',
      '5. Si connexions vers IPs inconnues : possible malware → lancez un scan'
    ],
    Windows: [
      '1. L\'agent limite les connexions automatiquement',
      '2. Gestionnaire des tâches → onglet Performances → Ouvrir le Moniteur de ressources',
      '3. Onglet Réseau → identifiez les processus avec beaucoup de connexions',
      '4. Fermez les applications non nécessaires',
      '5. Vérifiez les connexions suspectes vers des IPs inconnues'
    ],
    Linux: [
      '1. L\'agent limite les connexions via iptables automatiquement',
      '2. Vérifiez : sudo ss -s',
      '3. Identifiez les processus : sudo nethogs',
      '4. Bloquez une IP suspecte : sudo iptables -A OUTPUT -d IP_SUSPECTE -j DROP'
    ]
  },

  // ─── IP MALVEILLANTE ───────────────────────────────────────────────────────
  MALICIOUS_IP: {
    auto: true,
    label: 'Connexion vers IP malveillante',
    Darwin: [
      '1. L\'agent bloque l\'IP malveillante automatiquement',
      '2. Identifiez le processus connecté : sudo lsof -i | grep IP_MALVEILLANTE',
      '3. Fermez immédiatement l\'application concernée',
      '4. Changez les mots de passe si des données ont pu être exfiltrées',
      '5. Vérifiez les emails envoyés récemment pour détecter une fuite'
    ],
    Windows: [
      '1. L\'agent bloque l\'IP malveillante automatiquement',
      '2. Moniteur de ressources → Réseau → identifiez le processus',
      '3. Terminez le processus suspect dans le Gestionnaire des tâches',
      '4. Lancez un scan antivirus complet immédiatement',
      '5. Vérifiez si des données sensibles ont pu être transmises'
    ],
    Linux: [
      '1. L\'agent bloque l\'IP via iptables automatiquement',
      '2. Vérifiez : sudo netstat -an | grep IP_MALVEILLANTE',
      '3. Identifiez le processus : sudo lsof -i | grep IP_MALVEILLANTE',
      '4. Tuez le processus : sudo kill -9 PID',
      '5. Vérifiez les logs : sudo tail -100 /var/log/syslog'
    ]
  },

  // ─── SSH ───────────────────────────────────────────────────────────────────
  SSH_ROOT_LOGIN: {
    auto: true,
    label: 'Connexion SSH root activée',
    Darwin: ['1. L\'agent désactive SSH root automatiquement', '2. Vérifiez : sudo grep PermitRootLogin /etc/ssh/sshd_config', '3. Utilisez un compte utilisateur normal avec sudo'],
    Windows: ['1. Windows n\'utilise pas SSH root par défaut', '2. Vérifiez la configuration OpenSSH si installé', '3. Désactivez les connexions admin à distance'],
    Linux: ['1. L\'agent modifie /etc/ssh/sshd_config automatiquement', '2. Vérifiez : sudo grep PermitRootLogin /etc/ssh/sshd_config', '3. Redémarrez SSH : sudo systemctl restart sshd']
  },

  // ─── COMPTE INVITÉ ─────────────────────────────────────────────────────────
  GUEST_ACCOUNT: {
    auto: true,
    label: 'Compte invité actif',
    Darwin: [
      '1. L\'agent désactive le compte invité automatiquement',
      '2. Vérifiez : Réglages Système → Utilisateurs et groupes',
      '3. Assurez-vous que Utilisateur invité est désactivé',
      '4. Activez un mot de passe de connexion obligatoire'
    ],
    Windows: [
      '1. L\'agent désactive le compte invité automatiquement',
      '2. Vérifiez : gestion de l\'ordinateur → Utilisateurs locaux → Utilisateurs → Invité',
      '3. Double-cliquez → cochez Le compte est désactivé',
      '4. Supprimez le compte si inutile'
    ],
    Linux: ['1. L\'agent verrouille le compte guest automatiquement', '2. Vérifiez : sudo passwd -S guest', '3. Si actif : sudo passwd -l guest']
  },

  // ─── CLOUD AWS ─────────────────────────────────────────────────────────────
  S3_PUBLIC: {
    auto: false,
    label: 'Bucket S3 accessible publiquement',
    Darwin: [
      '1. Connectez-vous à la console AWS : https://console.aws.amazon.com',
      '2. Allez dans S3 → sélectionnez le bucket concerné',
      '3. Onglet Autorisations → Bloquer l\'accès public → Modifier',
      '4. Cochez toutes les cases → Enregistrer',
      '5. OU via AWS CLI : aws s3api put-bucket-acl --bucket NOM_BUCKET --acl private',
      '6. Vérifiez que les données sensibles n\'ont pas été exposées'
    ],
    Windows: [
      '1. Connectez-vous à la console AWS : https://console.aws.amazon.com',
      '2. Allez dans S3 → sélectionnez le bucket concerné',
      '3. Onglet Autorisations → Bloquer l\'accès public → Modifier',
      '4. Cochez toutes les cases → Enregistrer les modifications'
    ],
    Linux: [
      '1. Via AWS CLI : aws s3api put-public-access-block --bucket NOM_BUCKET --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true',
      '2. Vérifiez : aws s3api get-public-access-block --bucket NOM_BUCKET'
    ]
  },

  EC2_PORT_22: {
    auto: false,
    label: 'Port SSH AWS exposé à internet',
    Darwin: [
      '1. Console AWS → EC2 → Groupes de sécurité',
      '2. Trouvez le groupe de sécurité concerné',
      '3. Règles entrantes → Modifier → trouvez la règle port 22',
      '4. Changez la source de 0.0.0.0/0 à votre IP : https://monip.org',
      '5. Enregistrez les règles — accès SSH limité à votre IP uniquement'
    ],
    Windows: ['1. Console AWS → EC2 → Groupes de sécurité', '2. Règles entrantes → port 22 → changez source de 0.0.0.0/0 à votre IP'],
    Linux: ['1. aws ec2 authorize-security-group-ingress --group-id sg-xxx --protocol tcp --port 22 --cidr VOTRE_IP/32', '2. Supprimez la règle 0.0.0.0/0 pour le port 22']
  },

  IAM_NO_MFA: {
    auto: false,
    label: 'Compte AWS sans MFA',
    Darwin: [
      '1. Console AWS → IAM → Utilisateurs → sélectionnez l\'utilisateur',
      '2. Onglet Informations d\'identification de sécurité',
      '3. Appareil MFA → Attribuer un appareil MFA',
      '4. Choisissez Application d\'authentification (Google Authenticator)',
      '5. Scannez le QR code et entrez 2 codes consécutifs pour valider'
    ],
    Windows: ['1. Console AWS → IAM → Utilisateurs → Informations d\'identification', '2. Appareil MFA → Attribuer → Application d\'authentification', '3. Installez Google Authenticator sur votre téléphone et scannez le QR'],
    Linux: ['1. aws iam enable-mfa-device --user-name NOM_UTILISATEUR --serial-number arn:aws:iam::COMPTE:mfa/NOM --authentication-code-1 CODE1 --authentication-code-2 CODE2']
  },

  // ─── CLOUD M365 ────────────────────────────────────────────────────────────
  M365_NO_MFA: {
    auto: false,
    label: 'Compte Microsoft 365 sans MFA',
    Darwin: [
      '1. Allez sur https://aka.ms/mfasetup avec le compte concerné',
      '2. Cliquez sur Ajouter une méthode',
      '3. Choisissez Application d\'authentification (Microsoft Authenticator)',
      '4. Scannez le QR code avec votre téléphone',
      '5. Validez avec un code — MFA activé pour ce compte'
    ],
    Windows: ['1. Portail M365 : https://portal.microsoft.com → Mon compte → Informations de sécurité', '2. Ajoutez Microsoft Authenticator comme méthode de vérification', '3. Scannez le QR et validez'],
    Linux: ['1. Navigateur : https://aka.ms/mfasetup', '2. Ajoutez l\'application Microsoft Authenticator', '3. Scannez le QR code avec votre téléphone']
  },

  M365_RISKY_USER: {
    auto: false,
    label: 'Compte M365 à risque — possible compromission',
    Darwin: [
      '1. URGENT : Portail Azure → Azure AD → Utilisateurs à risque',
      '2. Sélectionnez l\'utilisateur → Réinitialiser le mot de passe',
      '3. Révoquez toutes les sessions : Révoquer les sessions',
      '4. Activez le MFA immédiatement',
      '5. Vérifiez les emails envoyés récemment pour détecter une fuite',
      '6. Vérifiez les règles de transfert d\'email créées'
    ],
    Windows: ['1. https://portal.azure.com → Azure AD → Utilisateurs à risque', '2. Réinitialisez le mot de passe et révoquez les sessions', '3. Activez MFA et vérifiez les activités suspectes'],
    Linux: ['1. Accédez au portail Azure depuis un navigateur', '2. Suivez les mêmes étapes que pour Windows/Mac']
  },

  // ─── CLOUD GOOGLE WORKSPACE ────────────────────────────────────────────────
  GWS_NO_2FA: {
    auto: false,
    label: 'Compte Google Workspace sans 2FA',
    Darwin: [
      '1. Allez sur https://myaccount.google.com/security avec le compte concerné',
      '2. Section Connexion à Google → Validation en 2 étapes',
      '3. Cliquez sur Commencer',
      '4. Choisissez l\'application Google Authenticator',
      '5. Scannez le QR code et entrez le code de validation'
    ],
    Windows: ['1. https://myaccount.google.com/security → Validation en 2 étapes', '2. Activez avec Google Authenticator ou SMS'],
    Linux: ['1. Navigateur : https://myaccount.google.com/security', '2. Activez la validation en 2 étapes']
  },

  GWS_BRUTE_FORCE: {
    auto: false,
    label: 'Tentatives de connexion Google suspectes',
    Darwin: [
      '1. Google Admin : https://admin.google.com → Rapports → Audit → Connexion',
      '2. Identifiez les IPs sources des tentatives échouées',
      '3. Forcez la réinitialisation du mot de passe : Admin → Utilisateurs → sélectionnez → Réinitialiser le mot de passe',
      '4. Activez la 2FA immédiatement',
      '5. Vérifiez si des applications tierces ont eu accès au compte'
    ],
    Windows: ['1. https://admin.google.com → Rapports → Audit', '2. Réinitialisez le mot de passe et activez la 2FA'],
    Linux: ['1. Accédez à https://admin.google.com depuis un navigateur', '2. Suivez les mêmes étapes']
  },

  // ─── RGPD ──────────────────────────────────────────────────────────────────
  RGPD_NO_ENCRYPT: {
    auto: false,
    label: 'Non-conformité RGPD — données non chiffrées',
    Darwin: [
      '1. Activez FileVault (voir instructions DISK_NOT_ENCRYPTED)',
      '2. Chiffrez les fichiers sensibles : clic droit → Compresser avec mot de passe',
      '3. Utilisez un gestionnaire de mots de passe chiffré (Bitwarden gratuit)',
      '4. Documentez les mesures prises pour le registre de traitement RGPD',
      '5. Article 32 RGPD exige le chiffrement des données personnelles'
    ],
    Windows: ['1. Activez BitLocker (voir instructions DISK_NOT_ENCRYPTED)', '2. Chiffrez les dossiers sensibles avec BitLocker To Go', '3. Documentez les mesures pour conformité RGPD Art. 32'],
    Linux: ['1. Chiffrez les données avec GPG : gpg --symmetric fichier_sensible', '2. Activez LUKS pour le chiffrement complet du disque', '3. Documentez les mesures pour conformité RGPD']
  },

  RGPD_LOG_MISSING: {
    auto: true,
    label: 'Logs de traçabilité absents (RGPD)',
    Darwin: ['1. L\'agent active les logs système automatiquement', '2. Vérifiez : sudo log show --last 1h', '3. Les logs sont conservés 30 jours minimum pour conformité RGPD'],
    Windows: ['1. L\'agent active l\'Observateur d\'événements automatiquement', '2. Vérifiez : Observateur d\'événements → Journaux Windows', '3. Configurez la rétention à 90 jours minimum'],
    Linux: ['1. L\'agent active rsyslog automatiquement', '2. Vérifiez : sudo systemctl status rsyslog', '3. Configurez logrotate pour conserver 90 jours de logs']
  },

  // ─── PARTAGE ET ACCÈS DISTANT ──────────────────────────────────────────────
  FILE_SHARING_ON: {
    auto: true,
    label: 'Partage de fichiers exposé',
    Darwin: ['1. L\'agent désactive le partage automatiquement', '2. Vérifiez : Réglages Système → Général → Partage', '3. Désactivez tous les partages non nécessaires', '4. Si partage nécessaire : activez uniquement pour les utilisateurs autorisés'],
    Windows: ['1. L\'agent désactive Samba automatiquement', '2. Panneau de configuration → Réseau et Internet → Centre Réseau et partage', '3. Modifier les paramètres de partage avancés → Désactiver le partage de fichiers'],
    Linux: ['1. L\'agent arrête Samba automatiquement', '2. Vérifiez : sudo systemctl status smbd', '3. Configurez des permissions strictes si partage nécessaire']
  },

  REMOTE_LOGIN_ON: {
    auto: true,
    label: 'Accès à distance activé',
    Darwin: ['1. L\'agent désactive SSH automatiquement', '2. Vérifiez : Réglages Système → Général → Partage → Accès à distance désactivé', '3. N\'activez l\'accès à distance que quand nécessaire'],
    Windows: ['1. L\'agent désactive RDP si non nécessaire', '2. Paramètres → Système → Bureau à distance → Désactiver', '3. Si nécessaire : limitez l\'accès aux utilisateurs autorisés uniquement'],
    Linux: ['1. L\'agent désactive SSH automatiquement', '2. Si SSH nécessaire : configurez avec clés uniquement (no password)', '3. Limitez via /etc/ssh/sshd_config : AllowUsers votre_user']
  },

  // ─── CLOUDTRAIL / AUDIT ────────────────────────────────────────────────────
  M365_AUTH_ERROR: {
    auto: false,
    label: 'Authentification Microsoft 365 echouee',
    Darwin: [
      '1. Allez sur https://portal.azure.com',
      '2. Cherchez App registrations et selectionnez ShieldFlow',
      '3. Cliquez sur API permissions → Add a permission → Microsoft Graph',
      '4. Choisissez Application permissions et ajoutez : User.Read.All, Directory.Read.All, AuditLog.Read.All',
      '5. Cliquez sur Grant admin consent for votre organisation',
      '6. Retournez dans ShieldFlow et cliquez sur Scanner pour verifier'
    ],
    Windows: [
      '1. Allez sur https://portal.azure.com',
      '2. App registrations → ShieldFlow → API permissions',
      '3. Add a permission → Microsoft Graph → Application permissions',
      '4. Ajoutez : User.Read.All, Directory.Read.All, AuditLog.Read.All',
      '5. Grant admin consent → Yes',
      '6. Retournez dans ShieldFlow et relancez le scan'
    ],
    Linux: [
      '1. Ouvrez un navigateur et allez sur https://portal.azure.com',
      '2. Suivez les memes etapes que Windows ci-dessus'
    ]
  },

  AWS_INVALID_KEY: {
    auto: false,
    label: 'Cle AWS invalide ou expiree',
    Darwin: [
      '1. Connectez-vous sur https://console.aws.amazon.com',
      '2. Cliquez sur votre nom en haut a droite → Security credentials',
      '3. Section Access keys → Create access key',
      '4. Copiez le nouvel Access Key ID et Secret Access Key',
      '5. Dans ShieldFlow → client → Connecter un cloud → AWS → entrez les nouvelles cles',
      '6. Supprimez lancienne cle dans AWS pour securite'
    ],
    Windows: [
      '1. https://console.aws.amazon.com → Security credentials',
      '2. Access keys → Create access key → copiez les credentials',
      '3. Mettez a jour dans ShieldFlow'
    ],
    Linux: [
      '1. aws configure dans le terminal pour verifier les credentials',
      '2. Generez une nouvelle cle dans la console AWS',
      '3. Mettez a jour dans ShieldFlow'
    ]
  },

  GWS_CREDENTIALS_CHECK: {
    auto: false,
    label: 'Google Workspace - verification manuelle requise',
    Darwin: [
      '1. Allez sur https://admin.google.com',
      '2. Securite → Controle des API → Gerer la delegation a lechelle du domaine',
      '3. Ajoutez le Client ID du compte de service ShieldFlow',
      '4. Scopes requis : https://www.googleapis.com/auth/admin.directory.user.readonly',
      '5. Retournez dans ShieldFlow et relancez le scan cloud',
      '6. Les alertes apparaitront automatiquement'
    ],
    Windows: [
      '1. https://admin.google.com → Securite → Controle des API',
      '2. Delegation a lechelle du domaine → Ajouter',
      '3. Entrez le Client ID et les scopes requis',
      '4. Relancez le scan dans ShieldFlow'
    ],
    Linux: [
      '1. Meme procedure que Windows via un navigateur',
      '2. https://admin.google.com → Securite → Controle des API'
    ]
  },

  CLOUDTRAIL_DISABLED: {
    auto: false,
    label: 'Audit AWS désactivé',
    Darwin: [
      '1. Console AWS → CloudTrail → Créer un journal',
      '2. Nom : shieldflow-audit',
      '3. Activez Multi-région',
      '4. Stockage S3 : créez un nouveau bucket cloudtrail-logs-VOTRE_COMPTE',
      '5. Activez la validation de l\'intégrité des fichiers journaux',
      '6. Coût estimé : environ 2€/mois pour une PME'
    ],
    Windows: ['1. Console AWS depuis votre navigateur', '2. Suivez les mêmes étapes que Mac'],
    Linux: ['1. aws cloudtrail create-trail --name shieldflow-audit --s3-bucket-name votre-bucket --is-multi-region-trail', '2. aws cloudtrail start-logging --name shieldflow-audit']
  },

  WEAK_PASSWORD: {
    auto: true,
    label: 'Politique de mot de passe faible',
    Darwin: [
      '1. L agent applique la politique de mot de passe automatiquement',
      '2. Verifiez : Reglages Systeme → Confidentialite et securite → Mot de passe',
      '3. Activez le mot de passe obligatoire apres verrouillage',
      '4. Utilisez un gestionnaire de mots de passe : Bitwarden (gratuit) ou 1Password',
      '5. Mot de passe recommande : 12+ caracteres, majuscules, chiffres, symboles'
    ],
    Windows: [
      '1. L agent configure la politique automatiquement',
      '2. Verifiez via gpedit.msc → Strategies de compte → Strategie de mot de passe',
      '3. Longueur minimale : 12 caracteres',
      '4. Complexite : activee',
      '5. Historique : 10 mots de passe'
    ],
    Linux: [
      '1. L agent installe et configure pam_pwquality automatiquement',
      '2. Verifiez : cat /etc/security/pwquality.conf',
      '3. minlen = 12, minclass = 3 recommandes'
    ]
  },

  NO_SCREENSAVER: {
    auto: true,
    label: 'Verrouillage ecran absent',
    Darwin: [
      '1. L agent active le verrouillage automatiquement',
      '2. Verifiez : Reglages Systeme → Ecran de veille → Demarrer apres : 5 min',
      '3. Reglages Systeme → Touch ID et mot de passe → Exiger le mot de passe : immediatement',
      '4. Raccourci de verrouillage : Ctrl+Cmd+Q'
    ],
    Windows: [
      '1. L agent configure le verrouillage automatiquement',
      '2. Parametres → Personnalisation → Ecran de veille → 5 minutes',
      '3. Cochez : A la reprise, afficher l ecran de connexion',
      '4. Raccourci : Windows+L pour verrouiller manuellement'
    ],
    Linux: [
      '1. L agent active gsettings pour le verrouillage automatiquement',
      '2. Verifiez : gsettings get org.gnome.desktop.screensaver lock-enabled',
      '3. Si desactive : gsettings set org.gnome.desktop.screensaver lock-enabled true'
    ]
  },

  SSH_PASSWORD_AUTH: {
    auto: true,
    label: 'Authentification SSH par mot de passe activee',
    Darwin: [
      '1. L agent desactive l authentification SSH par mot de passe automatiquement',
      '2. Seules les cles SSH seront acceptees - plus securise',
      '3. Pour generer une cle SSH : ssh-keygen -t ed25519 -C votre@email.com',
      '4. Copiez la cle publique : ssh-copy-id utilisateur@serveur',
      '5. Verifiez : sudo grep PasswordAuthentication /etc/ssh/sshd_config'
    ],
    Windows: [
      '1. Modifiez C:\ProgramData\ssh\sshd_config',
      '2. Changez PasswordAuthentication yes en PasswordAuthentication no',
      '3. Redemarrez le service : Restart-Service sshd',
      '4. Generez une cle SSH : ssh-keygen dans PowerShell'
    ],
    Linux: [
      '1. L agent modifie /etc/ssh/sshd_config automatiquement',
      '2. Verifiez : sudo grep PasswordAuthentication /etc/ssh/sshd_config',
      '3. Doit afficher : PasswordAuthentication no',
      '4. Redemarrage SSH : sudo systemctl restart sshd'
    ]
  },

  LOGS_DISABLED: {
    auto: true,
    label: 'Journalisation systeme desactivee',
    Darwin: [
      '1. L agent active les logs systeme automatiquement',
      '2. Verifiez : sudo log show --last 1h | head -20',
      '3. Les logs sont stockes dans /var/log/ et via le systeme unifie Apple',
      '4. Conservation recommandee : 90 jours minimum (conformite RGPD)',
      '5. Consultez les logs : Applications → Utilitaires → Console'
    ],
    Windows: [
      '1. L agent active l Observateur d evenements automatiquement',
      '2. Verifiez : eventvwr.msc → Journaux Windows',
      '3. Configurez la retention : clic droit → Proprietes → 90 jours minimum',
      "4. Activez l'audit : gpedit.msc → Parametres de securite → Strategies d'audit"
    ],
    Linux: [
      '1. L agent active et configure rsyslog automatiquement',
      '2. Verifiez : sudo systemctl status rsyslog',
      '3. Logs dans /var/log/syslog et /var/log/auth.log',
      '4. Configurez logrotate pour 90 jours : /etc/logrotate.conf'
    ]
  },

  M365_RISKY_USER: {
    auto: false,
    label: 'Compte Microsoft 365 compromis ou a risque',
    Darwin: [
      '1. URGENT : Allez sur https://portal.azure.com → Azure AD → Securite → Utilisateurs a risque',
      '2. Selectionnez l utilisateur concerne',
      '3. Cliquez sur Reinitialiser le mot de passe',
      '4. Cliquez sur Revoquer les sessions (deconnecte toutes les sessions actives)',
      '5. Activez le MFA immediatement sur ce compte',
      '6. Verifiez les regles de transfert d email : Outlook → Parametres → Courrier → Transfert',
      '7. Verifiez les connexions recentes : Azure AD → Journaux de connexion',
      '8. Signalez l incident a votre DPO si des donnees ont pu etre consultees (obligation RGPD 72h)'
    ],
    Windows: [
      '1. https://portal.azure.com → Azure AD → Securite → Utilisateurs a risque',
      '2. Reinitialiser le mot de passe et revoquer les sessions',
      '3. Activer MFA et verifier les regles de transfert email',
      '4. Notifier le DPO si violation de donnees'
    ],
    Linux: [
      '1. Acces via navigateur : https://portal.azure.com',
      '2. Suivez les memes etapes que ci-dessus'
    ]
  },

  DARKWEB_BREACH: {
    auto: false,
    label: 'Email trouve dans une fuite de donnees dark web',
    Darwin: [
      '1. URGENT : Changez immediatement le mot de passe du compte email concerne',
      '2. Changez le mot de passe sur TOUS les services utilisant ce meme mot de passe',
      '3. Activez la double authentification sur tous les comptes importants',
      '4. Verifiez les activites recentes : emails envoyes, connexions inhabituelles',
      '5. Utilisez un gestionnaire de mots de passe : Bitwarden (gratuit) sur bitwarden.com',
      '6. Verifiez regulierement sur https://haveibeenpwned.com',
      '7. Informez votre banque si des coordonnees bancaires ont pu etre exposees',
      '8. Deposez une alerte aupres de votre banque en cas de risque fraude'
    ],
    Windows: [
      '1. Changez immediatement tous les mots de passe concernes',
      '2. Activez la 2FA sur tous les comptes importants',
      '3. Installez Bitwarden : https://bitwarden.com',
      '4. Surveillez vos comptes bancaires les prochaines semaines'
    ],
    Linux: [
      '1. Changez tous les mots de passe depuis un terminal securise',
      '2. Generez des mots de passe forts : openssl rand -base64 20',
      '3. Activez la 2FA sur tous les comptes importants'
    ]
  },

  EC2_PORT_3389: {
    auto: false,
    label: 'Port RDP AWS expose a internet',
    Darwin: [
      '1. Console AWS → EC2 → Groupes de securite',
      '2. Trouvez la regle autorisant le port 3389 depuis 0.0.0.0/0',
      '3. Modifiez la regle : source → Votre IP uniquement (https://monip.org)',
      '4. OU utilisez AWS Systems Manager Session Manager pour acceder aux instances sans RDP expose',
      '5. Considerez un VPN AWS (AWS Client VPN) pour l acces distant securise'
    ],
    Windows: ['1. Console AWS → EC2 → Groupes de securite → modifiez le port 3389', '2. Limitez a votre IP uniquement'],
    Linux: ['1. aws ec2 revoke-security-group-ingress --group-id sg-xxx --protocol tcp --port 3389 --cidr 0.0.0.0/0', '2. aws ec2 authorize-security-group-ingress --group-id sg-xxx --protocol tcp --port 3389 --cidr VOTRE_IP/32']
  },

  EC2_PORT_3306: {
    auto: false,
    label: 'Port MySQL/MariaDB expose a internet',
    Darwin: [
      '1. Console AWS → EC2 → Groupes de securite',
      '2. Supprimez la regle autorisant le port 3306 depuis 0.0.0.0/0',
      '3. La base de donnees ne doit jamais etre accessible depuis internet',
      '4. Autorisez uniquement les connexions depuis les instances EC2 de votre application',
      '5. Utilisez un Security Group prive pour la base de donnees'
    ],
    Windows: ['1. Supprimez la regle port 3306 ouverte a internet dans AWS Security Groups', '2. Autorisez uniquement le Security Group de votre application'],
    Linux: ['1. aws ec2 revoke-security-group-ingress --group-id sg-xxx --protocol tcp --port 3306 --cidr 0.0.0.0/0']
  },


};

module.exports = MANUAL_INSTRUCTIONS;
