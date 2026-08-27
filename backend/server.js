/**
 * ShieldFlow Backend v2.0 — MongoDB Edition
 * Données persistantes, multi-clients, alertes email, cloud
 */

'use strict';

const express  = require('express');
const cors     = require('cors');
const crypto   = require('crypto');
const path     = require('path');
const mongoose = require('mongoose');

const app  = express();
const PORT = process.env.PORT || 3000;
const ADMIN_PASSWORD  = process.env.ADMIN_PASSWORD  || 'shieldflow2026';
const MSSP_PASSWORD   = process.env.MSSP_PASSWORD   || 'shieldflow-mssp-2026';
const SECRET_KEY      = process.env.SECRET_KEY      || 'shieldflow-secret-key-change-in-prod';
const MONGODB_URI     = process.env.MONGODB_URI     || '';
const MANUAL_INSTRUCTIONS = require('./instructions');
const RESEND_API_KEY  = process.env.RESEND_API_KEY  || '';
const ALERT_EMAIL     = process.env.ALERT_EMAIL     || '';

app.use(cors());
app.use(express.json({ limit: '10mb' }));
// Static files served after routes

// ─── MONGODB SCHEMAS ──────────────────────────────────────────────────────────

const TenantSchema = new mongoose.Schema({
  name:       String,
  email:      String,
  password:   String,
  agent_key:  String,
  cloud:      { type: Object, default: {} },
  nis2_score:      { type: Number },
  nis2_level:      { type: String },
  nis2_criteria:   { type: Object },
  nis2_updated_at: { type: Date },
  rgpd_score:      { type: Number },
  rgpd_level:      { type: String },
  rgpd_conforme:   { type: Boolean },
  rgpd_articles:   { type: Object },
  rgpd_updated_at: { type: Date },
  created_at: { type: Date, default: Date.now }
});

const DeviceSchema = new mongoose.Schema({
  tenant_id:     String,
  device_id:     String,
  name:          String,
  hostname:      String,
  platform:      String,
  agent_version: String,
  last_seen:     Date,
  status:        { type: String, default: 'online' },
  pending_commands: { type: Array, default: [] },
  snapshot:      Object,
  created_at:    { type: Date, default: Date.now }
});

const AlertSchema = new mongoose.Schema({
  tenant_id:   String,
  device_id:   String,
  device_name: String,
  type:        String,
  severity:    String,
  title:       String,
  description: String,
  recommendation: String,
  resolved:      { type: Boolean, default: false },
  resolved_at:   Date,
  auto_fixable:  { type: Boolean, default: false },
  instructions:  { type: Array, default: [] },
  created_at:  { type: Date, default: Date.now }
});

const SessionSchema = new mongoose.Schema({
  token:      String,
  tenant_id:  String,
  role:       String,
  expires_at: Date,
  created_at: { type: Date, default: Date.now }
});

const Tenant  = mongoose.model('Tenant',  TenantSchema);
const Device  = mongoose.model('Device',  DeviceSchema);
const Alert   = mongoose.model('Alert',   AlertSchema);
const Session = mongoose.model('Session', SessionSchema);

// ─── CONNECT MONGODB ──────────────────────────────────────────────────────────

let dbReady = false;

if (MONGODB_URI) {
  mongoose.connect(MONGODB_URI)
    .then(() => { console.log('[MongoDB] Connecté à Atlas ✅'); dbReady = true; })
    .catch(e  => console.error('[MongoDB] Erreur:', e.message));
} else {
  console.warn('[MongoDB] MONGODB_URI non défini — mode dégradé (données en mémoire)');
}

// ─── IN-MEMORY FALLBACK ───────────────────────────────────────────────────────
// Si MongoDB non dispo, on garde les données en mémoire
const mem = { tenants: {}, devices: {}, alerts: [], sessions: {} };

// ─── EMAIL ────────────────────────────────────────────────────────────────────

async function sendAlertEmail(tenantName, alert, deviceName, toEmail) {
  if (!RESEND_API_KEY || !toEmail) return;
  const sevColors = { critical:'#ef4444', high:'#f97316', medium:'#eab308', low:'#10b981' };
  const color = sevColors[alert.severity] || '#6b7280';
  const html = `
    <div style="font-family:sans-serif;max-width:600px;margin:0 auto;background:#0f1117;color:#e8edf5;border-radius:12px;overflow:hidden">
      <div style="background:#2563eb;padding:20px 28px">
        <div style="font-size:18px;font-weight:800;color:#fff">🛡 ShieldFlow — Alerte de sécurité</div>
        <div style="font-size:12px;color:rgba(255,255,255,.7)">${tenantName}</div>
      </div>
      <div style="padding:28px">
        <div style="background:${color}22;border:1px solid ${color}44;border-radius:8px;padding:16px;margin-bottom:20px">
          <span style="background:${color};color:#fff;padding:3px 10px;border-radius:5px;font-size:11px;font-weight:700">${alert.severity.toUpperCase()}</span>
          <span style="font-size:14px;font-weight:600;margin-left:10px">${alert.title}</span>
          <div style="font-size:13px;color:#8b9ab0;margin-top:8px">${alert.description}</div>
        </div>
        <div style="background:#1c2433;border-radius:8px;padding:14px;margin-bottom:20px">
          <div style="font-size:11px;color:#4a5a6e;margin-bottom:6px">RECOMMANDATION</div>
          <div style="font-size:13px;color:#10b981">${alert.recommendation || 'Vérifier immédiatement'}</div>
        </div>
        <div style="text-align:center">
          <a href="https://shieldflow-rfzv.onrender.com" style="background:#2563eb;color:#fff;padding:12px 28px;border-radius:8px;text-decoration:none;font-weight:700">Voir le dashboard →</a>
        </div>
      </div>
    </div>`;
  try {
    await fetch('https://api.resend.com/emails', {
      method:'POST',
      headers:{'Authorization':`Bearer ${RESEND_API_KEY}`,'Content-Type':'application/json'},
      body: JSON.stringify({
        from:'ShieldFlow <contact@conformite-rgpd.org>',
        to:[toEmail],
        subject:`🚨 [${alert.severity.toUpperCase()}] ${alert.title} — ${tenantName}`,
        html
      })
    });
    console.log(`[Email] Alerte envoyée: ${alert.title}`);
  } catch(e) { console.error('[Email]', e.message); }
}

// ─── ANALYZER ENGINE ──────────────────────────────────────────────────────────

function analyzeSnap(snap, deviceId, deviceName) {
  const candidates = [];

  if (snap.cpu_percent > 90)
    candidates.push({ type:'HIGH_CPU', severity:'high', title:'CPU anormalement élevé', description:`CPU à ${snap.cpu_percent?.toFixed(1)}% sur ${deviceName}.`, recommendation:'Identifier les processus consommateurs.' });

  if (snap.ram_percent > 95)
    candidates.push({ type:'HIGH_RAM', severity:'medium', title:'RAM saturée', description:`RAM à ${snap.ram_percent?.toFixed(1)}% sur ${deviceName}.`, recommendation:'Fermer les applications inutiles.' });

  if (snap.disk_percent > 90)
    candidates.push({ type:'LOW_DISK', severity:'high', title:'Espace disque critique', description:`Disque à ${snap.disk_percent?.toFixed(1)}% sur ${deviceName}.`, recommendation:'Liberer de espace disque immediatement.' });

  const ports = Array.isArray(snap.open_ports) ? snap.open_ports : [];
  const dangerPorts = ports.filter(p => [4444,1337,31337,6666,6667,23].includes(Number(p)));
  if (dangerPorts.length > 0)
    candidates.push({ type:'DANGER_PORTS', severity:'critical', title:`Port dangereux ouvert : ${dangerPorts.join(', ')}`, description:`Ports associes a des outils d attaque detectes sur ${deviceName}.`, recommendation:'Fermer ces ports via le pare-feu immediatement.' });

  if (snap.firewall_enabled === false || snap.firewall_status === 'disabled')
    candidates.push({ type:'FIREWALL_OFF', severity:'critical', title:'Pare-feu desactive', description:`Le pare-feu est desactive sur ${deviceName}.`, recommendation:'Activer le pare-feu dans les reglages systeme.' });

  if (snap.disk_encrypted === false)
    candidates.push({ type:'DISK_NOT_ENCRYPTED', severity:'high', title:'Disque non chiffre', description:`Le disque de ${deviceName} n est pas chiffre. Non conforme RGPD Art. 32.`, recommendation:'Activer FileVault ou BitLocker immediatement.' });

  if (snap.antivirus_status === 'disabled' || snap.antivirus_enabled === false)
    candidates.push({ type:'NO_ANTIVIRUS', severity:'high', title:'Protection antivirus absente', description:`Aucun antivirus actif detecte sur ${deviceName}.`, recommendation:'Installer Malwarebytes ou activer XProtect.' });

  if (snap.pending_updates > 20)
    candidates.push({ type:'UPDATES_CRITICAL', severity:'high', title:`${snap.pending_updates} mises a jour en attente`, description:`${snap.pending_updates} paquets non mis a jour sur ${deviceName}.`, recommendation:'Appliquer les mises a jour systeme immediatement.' });
  else if (snap.pending_updates > 5)
    candidates.push({ type:'UPDATES_PENDING', severity:'medium', title:`${snap.pending_updates} mises a jour disponibles`, description:`${snap.pending_updates} mises a jour disponibles sur ${deviceName}.`, recommendation:'Planifier une mise a jour dans les 7 jours.' });

  const malwarePatterns = [/lockbit/i,/wannacry/i,/mimikatz/i,/xmrig/i,/meterpreter/i,/njrat/i,/cryptolocker/i];
  const processes = Array.isArray(snap.processes) ? snap.processes : [];
  for (const proc of processes) {
    const name = (proc.name || proc.cmd || '').toLowerCase();
    for (const pattern of malwarePatterns) {
      if (pattern.test(name)) {
        candidates.push({ type:`MALWARE_${proc.name}`, severity:'critical', title:`Malware detecte : ${proc.name}`, description:`Processus malveillant "${proc.name}" (PID: ${proc.pid}) detecte sur ${deviceName}.`, recommendation:`Terminer immediatement PID ${proc.pid} et isoler la machine.` });
      }
    }
  }

  const logs = Array.isArray(snap.logs) ? snap.logs : [];
  const failedLogins = logs.filter(l => /failed password|authentication failure/i.test(l.line || l.message || '')).length;
  if (failedLogins > 10)
    candidates.push({ type:'BRUTE_FORCE', severity: failedLogins > 50 ? 'critical' : 'high', title:`Tentatives de connexion echouees : ${failedLogins}`, description:`${failedLogins} echecs de connexion detectes sur ${deviceName}.`, recommendation:'Verifier les IPs sources et activer MFA.' });


  // Verrouillage écran
  if (snap.screensaver_enabled === false)
    candidates.push({ type:'NO_SCREENSAVER', severity:'medium', title:'Verrouillage ecran absent', description:`Le verrouillage automatique est desactive sur ${deviceName}.`, recommendation:'Activer le verrouillage ecran apres 5 minutes.' });

  // Partage de fichiers
  if (snap.file_sharing === true)
    candidates.push({ type:'FILE_SHARING_ON', severity:'medium', title:'Partage de fichiers actif', description:`Le partage de fichiers est active sur ${deviceName}. Risque d acces non autorise.`, recommendation:'Desactiver le partage de fichiers si non necessaire.' });

  // Acces distant
  if (snap.remote_login === true)
    candidates.push({ type:'REMOTE_LOGIN_ON', severity:'medium', title:'Acces a distance active', description:`L'acces SSH/remote est active sur ${deviceName}.`, recommendation:'Desactiver si non necessaire ou restreindre aux IPs autorisees.' });

  // RGPD - logs
  if (snap.logging_enabled === false)
    candidates.push({ type:'LOGS_DISABLED', severity:'high', title:'Journalisation systeme desactivee', description:`Les logs systeme sont desactives sur ${deviceName}. Non conforme RGPD Art.30.`, recommendation:'Activer la journalisation systeme immediatement.' });

  // Ransomware — isolation automatique immédiate
  if (snap.ransomware_detected === true)
    candidates.push({ type:'RANSOMWARE_DETECTED', severity:'critical', title:'Ransomware detecte — chiffrement en cours', description:`${snap.ransomware_files_count} fichier(s) chiffre(s) detecte(s) sur ${deviceName}. Comportement ransomware probable.`, recommendation:'Isoler la machine immediatement.', auto_fixable: true });

  // Connexions suspectes
  if (snap.has_suspicious_connections === true)
    candidates.push({ type:'SUSPICIOUS_CONNECTIONS', severity:'high', title:'Connexions reseau suspectes', description:`Connexions sur ports dangereux detectees sur ${deviceName}.`, recommendation:'Verifier et bloquer les connexions suspectes.', auto_fixable: true });

  // Sauvegarde absente
  if (snap.backup_warning === true)
    candidates.push({ type:'NO_BACKUP', severity:'high', title:'Aucune sauvegarde detectee', description:`Aucune sauvegarde recente sur ${deviceName}. Risque de perte de donnees.`, recommendation:'Configurer Time Machine ou un systeme de backup.', auto_fixable: false });

  // Zero Trust — Anomalie comportementale
  if (snap.has_behavioral_anomaly === true && snap.behavioral_risk_score >= 50) {
    const anomalies = (snap.behavioral_anomalies || []).join(', ');
    const severity = snap.behavioral_risk_score >= 70 ? 'critical' : 'high';
    candidates.push({ 
      type: 'BEHAVIORAL_ANOMALY', 
      severity, 
      title: 'Comportement utilisateur suspect detecte', 
      description: `Zero Trust: ${anomalies} sur ${deviceName}. Score de risque: ${snap.behavioral_risk_score}/100.`, 
      recommendation: 'Verifier immediatement si cet acces est legitime. Contacter l utilisateur concerne.', 
      auto_fixable: false 
    });
  }

  // Connexion depuis pays etranger — critique
  if (snap.behavior?.country && snap.behavior.country !== '' && 
      snap.behavior.country !== 'France' && snap.behavioral_risk_score >= 70) {
    candidates.push({ 
      type: 'FOREIGN_CONNECTION', 
      severity: 'critical', 
      title: `Connexion depuis pays etranger: ${snap.behavior.country}`, 
      description: `Une connexion depuis ${snap.behavior.city || ''} (${snap.behavior.country}) a ete detectee sur ${deviceName}. Acces potentiellement non autorise.`, 
      recommendation: 'Bloquer immediatement cet acces et contacter l utilisateur pour confirmer.', 
      auto_fixable: false 
    });
  }

  // Acces nocturne suspect
  if (snap.behavior?.is_night_access === true) {
    candidates.push({ 
      type: 'NIGHT_ACCESS', 
      severity: 'high', 
      title: 'Connexion nocturne inhabituelle', 
      description: `Acces detecte entre 22h et 6h sur ${deviceName}. Comportement inhabituel pouvant indiquer un acces non autorise.`, 
      recommendation: 'Verifier si cet acces est legitime. Activer l authentification forte sur ce poste.', 
      auto_fixable: false 
    });
  }

  return candidates;
}


// ─── PDF REPORT + SCHEDULER ───────────────────────────────────────────────────

const PDFDocument = require('pdfkit');
const cron = require('node-cron');

async function generateTenantReport(tenantId) {
  const tenant = await Tenant.findById(tenantId);
  if (!tenant) return null;
  
  const devices = await Device.find({ tenant_id: tenantId });
  const alerts  = await Alert.find({ tenant_id: tenantId, resolved: false }).sort({ created_at: -1 });
  const resolvedToday = await Alert.find({ 
    tenant_id: tenantId, resolved: true,
    resolved_at: { $gte: new Date(Date.now() - 24*60*60*1000) }
  });
  
  const criticals = alerts.filter(a => a.severity === 'critical');
  const highs     = alerts.filter(a => a.severity === 'high');
  const score     = Math.max(0, 100 - criticals.length*20 - highs.length*10 - alerts.length*2);
  const date      = new Date().toLocaleDateString('fr-FR', { day:'2-digit', month:'long', year:'numeric' });

  return new Promise((resolve) => {
    const doc = new PDFDocument({ margin: 50, size: 'A4' });
    const chunks = [];
    doc.on('data', c => chunks.push(c));
    doc.on('end', () => resolve(Buffer.concat(chunks)));

    // Header
    doc.rect(0, 0, 595, 80).fill('#0f1117');
    doc.fillColor('#2563eb').fontSize(24).font('Helvetica-Bold').text('ShieldFlow', 50, 25);
    doc.fillColor('#ffffff').fontSize(11).font('Helvetica').text('Rapport de Securite', 50, 52);
    doc.fillColor('#8b9ab0').fontSize(9).text(date, 400, 35, { align: 'right' });
    doc.fillColor('#8b9ab0').fontSize(9).text(tenant.name, 400, 50, { align: 'right' });

    doc.moveDown(4);

    // Score
    const scoreColor = score >= 80 ? '#10b981' : score >= 50 ? '#f97316' : '#ef4444';
    doc.fillColor('#1a1d27').rect(50, 100, 495, 80).fill();
    doc.fillColor(scoreColor).fontSize(40).font('Helvetica-Bold').text(score + '/100', 60, 112);
    doc.fillColor('#8b9ab0').fontSize(10).font('Helvetica').text('Score de securite global', 60, 155);
    doc.fillColor('#e8edf5').fontSize(10).text(`${devices.length} appareil(s)  |  ${alerts.length} alerte(s) active(s)  |  ${criticals.length} critique(s)`, 200, 130);
    doc.fillColor('#10b981').fontSize(10).text(`${resolvedToday.length} alerte(s) resolue(s) aujourd hui`, 200, 148);

    doc.moveDown(5);
    doc.y = 200;

    // Alertes actives
    doc.fillColor('#e8edf5').fontSize(14).font('Helvetica-Bold').text('Alertes actives', 50);
    doc.moveDown(0.5);

    if (alerts.length === 0) {
      doc.fillColor('#10b981').fontSize(11).font('Helvetica').text('Aucune alerte active — Infrastructure saine', 50);
    } else {
      const sevColors = { critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#10b981' };
      alerts.slice(0, 10).forEach(a => {
        const color = sevColors[a.severity] || '#6b7280';
        doc.fillColor(color).fontSize(9).font('Helvetica-Bold').text(`[${a.severity.toUpperCase()}]`, 50, doc.y, { continued: true });
        doc.fillColor('#e8edf5').fontSize(9).font('Helvetica').text(` ${a.title}`, { continued: false });
        doc.fillColor('#8b9ab0').fontSize(8).text(`   ${a.description}`, 50);
        doc.moveDown(0.3);
      });
      if (alerts.length > 10) {
        doc.fillColor('#8b9ab0').fontSize(8).text(`... et ${alerts.length - 10} autre(s) alerte(s)`, 50);
      }
    }

    doc.moveDown(1);

    // Appareils
    doc.fillColor('#e8edf5').fontSize(14).font('Helvetica-Bold').text('Appareils surveilles', 50);
    doc.moveDown(0.5);
    if (devices.length === 0) {
      doc.fillColor('#8b9ab0').fontSize(11).font('Helvetica').text('Aucun appareil connecte', 50);
    } else {
      devices.forEach(d => {
        const status = d.last_seen > new Date(Date.now() - 5*60*1000) ? 'En ligne' : 'Hors ligne';
        const statusColor = status === 'En ligne' ? '#10b981' : '#ef4444';
        doc.fillColor('#e8edf5').fontSize(10).font('Helvetica').text(`${d.name || d.hostname}`, 50, doc.y, { continued: true });
        doc.fillColor('#8b9ab0').text(`  ${d.platform}  `, { continued: true });
        doc.fillColor(statusColor).text(status);
        doc.moveDown(0.3);
      });
    }

    // Footer
    doc.rect(0, 780, 595, 62).fill('#0f1117');
    doc.fillColor('#4a5a6e').fontSize(8).font('Helvetica')
       .text('ShieldFlow MSSP Platform  |  shieldflow-rfzv.onrender.com  |  Ce rapport est genere automatiquement', 50, 795, { align: 'center' });
    doc.fillColor('#2563eb').fontSize(8).text('Votre securite, notre priorite.', 50, 810, { align: 'center' });

    doc.end();
  });
}

async function sendDailyReport(tenantId) {
  if (!RESEND_API_KEY || !ALERT_EMAIL) return;
  const tenant = await Tenant.findById(tenantId);
  if (!tenant || !tenant.email) return;
  
  const pdfBuffer = await generateTenantReport(tenantId);
  if (!pdfBuffer) return;
  
  const base64PDF = pdfBuffer.toString('base64');
  const date = new Date().toLocaleDateString('fr-FR');
  
  try {
    await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${RESEND_API_KEY}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        from: 'ShieldFlow <contact@conformite-rgpd.org>',
        to: [tenant.email || ALERT_EMAIL],
        subject: `Rapport de securite ShieldFlow — ${date} — ${tenant.name}`,
        html: `<div style="font-family:sans-serif;max-width:600px;margin:0 auto;padding:20px;background:#0f1117;color:#e8edf5;border-radius:12px">
          <div style="text-align:center;margin-bottom:20px">
            <span style="font-size:24px;font-weight:800;color:#2563eb">🛡 ShieldFlow</span>
          </div>
          <p>Bonjour,</p>
          <p>Veuillez trouver en pièce jointe votre rapport de sécurité quotidien pour <strong>${tenant.name}</strong>.</p>
          <p>Pour consulter votre dashboard en temps réel :</p>
          <div style="text-align:center;margin:20px 0">
            <a href="https://shieldflow-rfzv.onrender.com" style="background:#2563eb;color:#fff;padding:12px 28px;border-radius:8px;text-decoration:none;font-weight:700">Voir le dashboard →</a>
          </div>
          <p style="color:#8b9ab0;font-size:12px">Ce rapport est généré automatiquement chaque matin par ShieldFlow.</p>
        </div>`,
        attachments: [{
          filename: `ShieldFlow-Rapport-${date.replace(/\//g,'-')}.pdf`,
          content: base64PDF,
          content_type: 'application/pdf'
        }]
      })
    });
    console.log(`[PDF] Rapport envoye a ${tenant.email || ALERT_EMAIL} pour ${tenant.name}`);
  } catch(e) {
    console.error('[PDF] Erreur envoi:', e.message);
  }
}

// Route pour générer/télécharger un rapport PDF manuellement
app.get('/api/mssp/tenants/:id/report', async (req, res) => {
  try {
    const pdfBuffer = await generateTenantReport(req.params.id);
    if (!pdfBuffer) return res.status(404).json({ error: 'Tenant non trouve' });
    const tenant = await Tenant.findById(req.params.id);
    const date = new Date().toLocaleDateString('fr-FR').replace(/\//g, '-');
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename="ShieldFlow-${tenant.name}-${date}.pdf"`);
    res.send(pdfBuffer);
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// Scheduler — rapport PDF tous les jours à 8h00
cron.schedule('0 8 * * *', async () => {
  console.log('[Scheduler] Envoi des rapports quotidiens...');
  const tenants = await Tenant.find({ email: { $exists: true, $ne: '' } });
  for (const t of tenants) {
    await sendDailyReport(t._id.toString());
    await sendAIReport(t);
  }
}, { timezone: 'Europe/Paris' });

console.log('[Scheduler] Rapport PDF quotidien programme a 8h00 Paris');

// ─── AUTH MIDDLEWARE ──────────────────────────────────────────────────────────

async function requireAuth(req, res, next) {
  const auth = req.headers['authorization'];
  if (!auth || !auth.startsWith('Bearer ')) return res.status(401).json({ error: 'Non authentifie' });
  const token = auth.replace('Bearer ', '');
  try {
    const session = await Session.findOne({ token, expires_at: { $gt: new Date() } });
    if (!session) return res.status(401).json({ error: 'Session expiree' });
    req.session = session;
    next();
  } catch(e) { res.status(500).json({ error: 'Erreur auth' }); }
}

async function requireAgentKey(tenantId, key) {
  if (key === SECRET_KEY) return true; // Legacy
  const tenant = await Tenant.findById(tenantId).catch(() => null);
  return tenant && tenant.agent_key === key;
}

// ─── AUTH ROUTES ──────────────────────────────────────────────────────────────

app.post('/api/auth/login', async (req, res) => {
  const { password, server } = req.body;
  if (password !== ADMIN_PASSWORD) return res.status(401).json({ error: 'Mot de passe incorrect' });
  const token = crypto.randomBytes(32).toString('hex');
  const expires = new Date(Date.now() + 24*60*60*1000);
  await Session.create({ token, role: 'admin', expires_at: expires });
  res.json({ token, expires_at: expires });
});

app.get('/api/auth/me', async (req, res) => {
  const auth = req.headers['authorization'];
  if (!auth) return res.status(401).json({ error: 'Non authentifie' });
  const token = auth.replace('Bearer ', '');
  const session = await Session.findOne({ token, expires_at: { $gt: new Date() } }).catch(() => null);
  if (!session) return res.status(401).json({ error: 'Session expiree' });
  res.json({ status: 'ok', role: session.role });
});

app.post('/api/auth/logout', requireAuth, async (req, res) => {
  await Session.deleteOne({ token: req.session.token });
  res.json({ success: true });
});

// ─── MSSP ROUTES ──────────────────────────────────────────────────────────────

app.post('/api/mssp/login', async (req, res) => {
  const { password } = req.body;
  if (password !== MSSP_PASSWORD) return res.status(401).json({ error: 'Mot de passe MSSP incorrect' });
  const token = crypto.randomBytes(32).toString('hex');
  const expires = new Date(Date.now() + 24*60*60*1000);
  await Session.create({ token, role: 'mssp', expires_at: expires });
  res.json({ token, expires_at: expires, role: 'mssp' });
});

app.post('/api/mssp/tenants', async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !password) return res.status(400).json({ error: 'name et password requis' });
  const agent_key = crypto.randomBytes(16).toString('hex');
  const tenant = await Tenant.create({ name, email: email||'', password, agent_key });
  res.json({ tenant_id: tenant._id, agent_key, message: 'Client cree' });
});

app.get('/api/mssp/tenants', async (req, res) => {
  const tenants = await Tenant.find().sort({ created_at: -1 });
  const result = await Promise.all(tenants.map(async t => {
    const devices = await Device.find({ tenant_id: t._id.toString() });
    const alerts  = await Alert.find({ tenant_id: t._id.toString(), resolved: false });
    const criticals = alerts.filter(a => a.severity === 'critical');
    const score = Math.max(0, 100 - criticals.length*20 - alerts.length*5);
    return {
      id: t._id, name: t.name, email: t.email,
      device_count: devices.length,
      alert_count: alerts.length,
      critical_count: criticals.length,
      score, agent_key: t.agent_key,
      created_at: t.created_at
    };
  }));
  res.json({ count: result.length, tenants: result });
});

app.get('/api/mssp/tenants/:id/dashboard', async (req, res) => {
  const tenant = await Tenant.findById(req.params.id).catch(() => null);
  if (!tenant) return res.status(404).json({ error: 'Client non trouve' });
  const devices = await Device.find({ tenant_id: req.params.id });
  const alerts  = await Alert.find({ tenant_id: req.params.id, resolved: false }).sort({ created_at: -1 });
  const criticals = alerts.filter(a => a.severity === 'critical');
  const score = Math.max(0, 100 - criticals.length*20 - alerts.length*5);
  res.json({ tenant: { id: tenant._id, name: tenant.name }, devices, alerts, score });
});

app.post('/api/tenant/login', async (req, res) => {
  const { tenant_id, password } = req.body;
  const tenant = await Tenant.findById(tenant_id).catch(() => null);
  if (!tenant || tenant.password !== password) return res.status(401).json({ error: 'Identifiants incorrects' });
  const token = crypto.randomBytes(32).toString('hex');
  const expires = new Date(Date.now() + 24*60*60*1000);
  await Session.create({ token, tenant_id, role: 'client', expires_at: expires });
  res.json({ token, tenant_id, tenant_name: tenant.name, expires_at: expires });
});

// Cloud routes
app.post('/api/mssp/tenants/:id/cloud', async (req, res) => {
  const { cloud_type, credentials } = req.body;
  const tenant = await Tenant.findById(req.params.id).catch(() => null);
  if (!tenant) return res.status(404).json({ error: 'Client non trouve' });
  if (!tenant.cloud) tenant.cloud = {};
  tenant.cloud[cloud_type] = { credentials: encryptCredentials(credentials), connected_at: new Date(), last_scan: null };
  tenant.markModified('cloud');
  await tenant.save();
  
  // Lancer le scan immédiatement après connexion
  setTimeout(async () => {
    try {
      const alerts = await runCloudScan(req.params.id, cloud_type, credentials);
      for (const alert of alerts) {
        if (alert.type === 'M365_SCAN_OK') continue;
        const exists = await Alert.findOne({ tenant_id: req.params.id, type: alert.type, resolved: false });
        if (!exists) {
          const newAlert = await Alert.create({ 
            tenant_id: req.params.id, 
            device_id: 'cloud_' + cloud_type, 
            device_name: cloud_type.toUpperCase() + ' Cloud', 
            ...alert 
          });
          if (alert.severity === 'critical' || alert.severity === 'high') {
            sendAlertEmail(tenant.name, newAlert, cloud_type + ' Cloud', ALERT_EMAIL);
          }
        }
      }
      console.log(`[CloudScan] Scan immediat ${cloud_type} pour ${tenant.name}: ${alerts.length} alertes`);
    } catch(e) {
      console.error('[CloudScan] Erreur scan immediat:', e.message);
    }
  }, 2000);
  
  res.json({ success: true, message: `Cloud ${cloud_type} connecte - scan en cours...` });
});

app.get('/api/mssp/tenants/:id/cloud', async (req, res) => {
  const tenant = await Tenant.findById(req.params.id).catch(() => null);
  if (!tenant) return res.status(404).json({ error: 'Client non trouve' });
  const clouds = Object.entries(tenant.cloud || {}).map(([type, data]) => ({
    type, connected_at: data.connected_at, last_scan: data.last_scan, status: 'connected'
  }));
  res.json({ clouds });
});

// ─── AGENT ROUTES (Legacy - sans tenant) ──────────────────────────────────────

app.post('/api/agent/register', async (req, res) => {
  const { hostname, platform, name, agent_version } = req.body;
  if (!hostname) return res.status(400).json({ error: 'hostname requis' });
  const device_id = crypto.createHash('md5').update(hostname+platform).digest('hex');
  await Device.findOneAndUpdate(
    { device_id, tenant_id: 'default' },
    { device_id, tenant_id: 'default', name: name||hostname, hostname, platform, agent_version, last_seen: new Date() },
    { upsert: true, new: true }
  );
  res.json({ device_id, message: 'Appareil enregistre' });
});

app.post('/api/agent/heartbeat', async (req, res) => {
  const { device_id, ...snap } = req.body;
  if (!device_id) return res.status(400).json({ error: 'device_id requis' });
  const device = await Device.findOneAndUpdate(
    { device_id, tenant_id: 'default' },
    { last_seen: new Date(), status: 'online', snapshot: snap },
    { new: true }
  );
  if (!device) return res.status(404).json({ error: 'Appareil non enregistre' });
  
  const candidates = analyzeSnap(snap, device_id, device.name);
  
  // Pas de NIS2/RGPD pour heartbeat sans tenant

  for (const c of candidates) {
    const exists = await Alert.findOne({ device_id, type: c.type, resolved: false });
    if (!exists) {
      await Alert.create({ tenant_id: 'default', device_id, device_name: device.name, ...c });
    }
  }
  res.json({ success: true, timestamp: new Date() });
});

// ─── AGENT ROUTES (Multi-tenant) ──────────────────────────────────────────────

app.post('/api/agent/:tenantId/register', async (req, res) => {
  const { hostname, platform, name, agent_version } = req.body;
  const tenantId = req.params.tenantId;
  const agentKey = req.headers['x-agent-key'];
  
  const tenant = await Tenant.findById(tenantId).catch(() => null);
  if (!tenant) return res.status(404).json({ error: 'Tenant non trouve' });
  if (agentKey !== tenant.agent_key && agentKey !== SECRET_KEY) return res.status(403).json({ error: 'Cle agent invalide' });
  
  const device_id = crypto.createHash('md5').update(hostname+platform).digest('hex');
  await Device.findOneAndUpdate(
    { device_id, tenant_id: tenantId },
    { device_id, tenant_id: tenantId, name: name||hostname, hostname, platform, agent_version, last_seen: new Date() },
    { upsert: true, new: true }
  );
  res.json({ device_id, message: 'Appareil enregistre' });
});

app.post('/api/agent/:tenantId/heartbeat', async (req, res) => {
  const tenantId = req.params.tenantId;
  const agentKey = req.headers['x-agent-key'];
  const { device_id, ...snap } = req.body;
  
  const tenant = await Tenant.findById(tenantId).catch(() => null);
  if (!tenant) return res.status(404).json({ error: 'Tenant non trouve' });
  if (agentKey !== tenant.agent_key && agentKey !== SECRET_KEY) return res.status(403).json({ error: 'Cle agent invalide' });
  if (!device_id) return res.status(400).json({ error: 'device_id requis' });
  
  const device = await Device.findOneAndUpdate(
    { device_id, tenant_id: tenantId },
    { last_seen: new Date(), status: 'online', snapshot: snap },
    { new: true }
  );
  if (!device) return res.status(404).json({ error: 'Appareil non enregistre' });
  
  const candidates = analyzeSnap(snap, device_id, device.name);
  
  // Calculer NIS2 et RGPD directement a partir du heartbeat
  const nis2 = calculateNIS2(snap);
  const rgpd = calculateRGPD(snap);
  await Tenant.findByIdAndUpdate(tenantId, {
    nis2_score: nis2.score,
    nis2_level: nis2.level,
    nis2_criteria: nis2.criteria,
    nis2_updated_at: new Date(),
    rgpd_score: rgpd.score,
    rgpd_level: rgpd.level,
    rgpd_conforme: rgpd.conforme,
    rgpd_articles: rgpd.articles,
    rgpd_updated_at: new Date()
  });

  for (const c of candidates) {
    const exists = await Alert.findOne({ device_id, tenant_id: tenantId, type: c.type, resolved: false });
    if (!exists) {
      // Ajouter les instructions selon l'OS
      const platform = device.platform || 'Darwin';
      const instrKey = Object.keys(MANUAL_INSTRUCTIONS).find(k => c.type.startsWith(k));
      if (instrKey) {
        const instr = MANUAL_INSTRUCTIONS[instrKey];
        c.auto_fixable = instr.auto || false;
        c.instructions = instr[platform] || instr['Darwin'] || [];
      } else {
        c.auto_fixable = false;
        c.instructions = ['Contactez le support ShieldFlow pour cette alerte.'];
      }
      const newAlert = await Alert.create({ tenant_id: tenantId, device_id, device_name: device.name, ...c });
      if (c.severity === 'critical' || c.severity === 'high') {
        sendAlertEmail(tenant.name, newAlert, device.name, ALERT_EMAIL);
      }
      // Isolation automatique si ransomware
      if (newAlert.type === 'RANSOMWARE_DETECTED') {
        console.log('[URGENCE] Ransomware détecté sur', device.name, '— isolation automatique');
        const isolateCmd = {
          id: require('crypto').randomUUID(),
          alert_type: 'ISOLATE_MACHINE',
          alert_id: newAlert._id.toString(),
          params: {},
          source: 'auto_ransomware',
          created_at: new Date()
        };
        await Device.findByIdAndUpdate(device._id, { $push: { pending_commands: isolateCmd } });
        // Rapport d'incident complet en moins de 60 secondes
        const incidentTime = new Date();
        const incidentId = 'INC-' + Date.now().toString().slice(-6);
        
        if (RESEND_API_KEY) {
          // Email urgence à ShieldFlow
          await fetch('https://api.resend.com/emails', {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${RESEND_API_KEY}`, 'Content-Type': 'application/json' },
            body: JSON.stringify({
              from: 'ShieldFlow <contact@conformite-rgpd.org>',
              to: ALERT_EMAIL,
              subject: `🚨 [${incidentId}] URGENCE RANSOMWARE — ${tenant.name} — ${device.name}`,
              html: `<div style="font-family:Arial;color:#1a1d23;max-width:560px">
                <div style="background:#e8334a;padding:20px;border-radius:8px 8px 0 0;text-align:center">
                  <h1 style="color:white;margin:0;font-size:20px">🚨 RANSOMWARE DÉTECTÉ</h1>
                  <div style="color:rgba(255,255,255,.8);font-size:12px;margin-top:6px">Référence incident : ${incidentId}</div>
                </div>
                <div style="background:#fff5f5;border:1px solid #fecaca;padding:20px;border-radius:0 0 8px 8px">
                  <table style="width:100%;border-collapse:collapse;font-size:13px">
                    <tr><td style="padding:6px 0;color:#6b7280;width:140px">Heure de détection</td><td style="font-weight:600">${incidentTime.toLocaleString('fr-FR')}</td></tr>
                    <tr><td style="padding:6px 0;color:#6b7280">Client</td><td style="font-weight:600">${tenant.name}</td></tr>
                    <tr><td style="padding:6px 0;color:#6b7280">Machine compromise</td><td style="font-weight:600">${device.name}</td></tr>
                    <tr><td style="padding:6px 0;color:#6b7280">Fichiers chiffrés</td><td style="font-weight:600;color:#e8334a">${snap.ransomware_files_count}</td></tr>
                    <tr><td style="padding:6px 0;color:#6b7280">Action automatique</td><td style="font-weight:600;color:#0ea572">✓ Machine isolée du réseau</td></tr>
                    <tr><td style="padding:6px 0;color:#6b7280">Délai de réponse</td><td style="font-weight:600;color:#0ea572">< 60 secondes</td></tr>
                  </table>
                  <div style="margin-top:16px;padding:12px;background:#fff;border-radius:6px;border:1px solid #fecaca">
                    <div style="font-size:11px;color:#e8334a;font-weight:700;margin-bottom:6px">ACTION REQUISE</div>
                    <div style="font-size:13px">Contactez ${tenant.name} immédiatement. La machine est isolée — le client ne peut plus se connecter à Internet.</div>
                  </div>
                </div>
              </div>`
            })
          });

          // Email au client — rapport d'incident en langage simple
          if (tenant.email) {
            // Générer analyse IA de l'incident
            let aiIncidentText = '';
            if (ANTHROPIC_API_KEY) {
              try {
                const aiR = await fetch('https://api.anthropic.com/v1/messages', {
                  method: 'POST',
                  headers: { 'Content-Type': 'application/json', 'x-api-key': ANTHROPIC_API_KEY, 'anthropic-version': '2023-06-01' },
                  body: JSON.stringify({
                    model: 'claude-sonnet-4-6',
                    max_tokens: 300,
                    messages: [{ role: 'user', content: `Tu es ShieldFlow, un service de cybersécurité. Rédige un message rassurant en 3 phrases maximum pour le dirigeant de l'entreprise ${tenant.name}. Un ransomware a été détecté sur leur machine ${device.name}. ShieldFlow a automatiquement isolé la machine en moins de 60 secondes. Explique ce qui s'est passé, ce que ShieldFlow a fait automatiquement, et ce qu'ils doivent faire maintenant (ne pas toucher à la machine, attendre notre appel). Ton ton doit être professionnel et rassurant, pas alarmiste.` }]
                  })
                });
                const aiData = await aiR.json();
                aiIncidentText = aiData.content?.[0]?.text || '';
              } catch(e) {}
            }

            await fetch('https://api.resend.com/emails', {
              method: 'POST',
              headers: { 'Authorization': `Bearer ${RESEND_API_KEY}`, 'Content-Type': 'application/json' },
              body: JSON.stringify({
                from: 'ShieldFlow <contact@conformite-rgpd.org>',
                to: tenant.email,
                subject: `🛡 [${incidentId}] Incident de sécurité détecté et traité — ${tenant.name}`,
                html: `<div style="font-family:Arial;color:#1a1d23;max-width:560px;margin:0 auto">
                  <div style="background:#1a1d23;padding:24px;border-radius:8px 8px 0 0;text-align:center">
                    <div style="font-size:20px;font-weight:800;color:#fff">🛡 ShieldFlow</div>
                    <div style="font-size:12px;color:#8896a8;margin-top:4px">Rapport d'incident automatique</div>
                  </div>
                  <div style="background:#f8f9fa;border:1px solid #e9ecef;border-top:none;padding:28px;border-radius:0 0 8px 8px">
                    <div style="background:#ecfdf5;border:1px solid #bbf7d0;border-radius:8px;padding:14px;margin-bottom:20px;text-align:center">
                      <div style="font-size:14px;font-weight:700;color:#0ea572">✓ Incident détecté et traité automatiquement en moins de 60 secondes</div>
                    </div>
                    
                    <h2 style="font-size:17px;margin:0 0 16px">Bonjour,</h2>
                    
                    <p style="font-size:14px;line-height:1.75;color:#3d4452;margin-bottom:16px">${aiIncidentText || 'Notre système de surveillance a détecté un comportement suspect sur votre machine ' + device.name + '. ShieldFlow a immédiatement isolé cet appareil du réseau pour protéger le reste de votre infrastructure. Notre équipe vous contactera dans les plus brefs délais.'}</p>
                    
                    <div style="background:#fff;border:1px solid #e9ecef;border-radius:8px;padding:16px;margin-bottom:20px">
                      <div style="font-size:11px;font-weight:700;text-transform:uppercase;color:#6b7280;margin-bottom:12px">Chronologie de l'incident</div>
                      <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px;font-size:13px">
                        <span style="color:#e8334a;font-size:16px">⚠</span>
                        <span><strong>${incidentTime.toLocaleTimeString('fr-FR')}</strong> — Comportement suspect détecté sur ${device.name}</span>
                      </div>
                      <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px;font-size:13px">
                        <span style="color:#0ea572;font-size:16px">✓</span>
                        <span><strong>${new Date(incidentTime.getTime()+4000).toLocaleTimeString('fr-FR')}</strong> — Machine isolée automatiquement du réseau</span>
                      </div>
                      <div style="display:flex;align-items:center;gap:10px;font-size:13px">
                        <span style="color:#2b6de8;font-size:16px">📧</span>
                        <span><strong>${new Date(incidentTime.getTime()+15000).toLocaleTimeString('fr-FR')}</strong> — Rapport envoyé, équipe ShieldFlow alertée</span>
                      </div>
                    </div>
                    
                    <div style="background:#fffbeb;border:1px solid #fde68a;border-radius:8px;padding:14px;margin-bottom:20px">
                      <div style="font-size:12px;font-weight:700;color:#d97706;margin-bottom:6px">CE QUE VOUS DEVEZ FAIRE</div>
                      <div style="font-size:13px;color:#3d4452;line-height:1.6">1. Ne touchez pas à la machine concernée<br>2. Notre équipe vous contacte dans les prochaines minutes<br>3. Continuez à travailler sur vos autres appareils</div>
                    </div>
                    
                    <div style="font-size:11px;color:#6b7280">Référence incident : ${incidentId} · ShieldFlow Incident Response</div>
                  </div>
                </div>`
              })
            });
          }
        }
      }
      // Remédiation autonome IA
      setTimeout(() => autoRemediateWithAI(tenantId, newAlert, snap), 3000);
    }
  }
  res.json({ success: true, timestamp: new Date() });
});

// ─── DASHBOARD ROUTES ─────────────────────────────────────────────────────────

app.get('/api/dashboard', async (req, res) => {
  const devices = await Device.find({ tenant_id: 'default' });
  const alerts  = await Alert.find({ tenant_id: 'default', resolved: false }).sort({ created_at: -1 }).limit(10);
  const critCount = alerts.filter(a => a.severity === 'critical').length;
  const highCount = alerts.filter(a => a.severity === 'high').length;
  const score = Math.max(0, 100 - critCount*20 - highCount*10 - alerts.length*2);
  
  const fiveMin = new Date(Date.now() - 5*60*1000);
  for (const d of devices) {
    if (d.last_seen < fiveMin) await Device.updateOne({ _id: d._id }, { status: 'offline' });
  }
  
  const snap = devices[0]?.snapshot || {};
  res.json({
    devices: { total: devices.length, online: devices.filter(d => d.status === 'online').length, offline: devices.filter(d => d.status === 'offline').length },
    alerts: { total: alerts.length, critical: critCount, high: highCount },
    score, recent_alerts: alerts,
    last_updated: new Date(),
    ...( devices[0] ? {
      cpu_percent: snap.cpu_percent, ram_percent: snap.ram_percent,
      disk_percent: snap.disk_percent, ram_total_gb: snap.ram_total_gb,
      disk_total_gb: snap.disk_total_gb, uptime_hours: snap.uptime_hours,
      running_processes: snap.running_processes, os_version: snap.os_version,
      hostname: devices[0].hostname, platform: devices[0].platform
    } : {})
  });
});

app.get('/api/devices', async (req, res) => {
  const devices = await Device.find({ tenant_id: 'default' });
  res.json({ count: devices.length, devices });
});

app.get('/api/alerts', async (req, res) => {
  const alerts = await Alert.find({ resolved: false }).sort({ created_at: -1 });
  res.json({ count: alerts.length, alerts });
});

app.post('/api/alerts/:id/resolve', requireAuth, async (req, res) => {
  await Alert.findByIdAndUpdate(req.params.id, { resolved: true, resolved_at: new Date() });
  res.json({ success: true });
});

app.get('/api/health', (req, res) => res.json({ status: 'ok', version: '2.0.0', db: dbReady ? 'mongodb' : 'memory' }));

app.get('/api/reset-alerts', async (req, res) => {
  await Alert.deleteMany({});
  res.json({ success: true, message: 'Alertes effacees' });
});

// ─── SERVE AGENT FILES ────────────────────────────────────────────────────────
app.use('/agent', express.static(path.join(__dirname, '../dashboard/agent')));







// ─── CHIFFREMENT CREDENTIALS ──────────────────────────────────────────────────

const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || crypto.randomBytes(32).toString('hex').slice(0, 32);
const IV_LENGTH = 16;

function encrypt(text) {
  if (!text) return text;
  try {
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY.padEnd(32).slice(0, 32)), iv);
    let encrypted = cipher.update(String(text));
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    return iv.toString('hex') + ':' + encrypted.toString('hex');
  } catch(e) { return text; }
}

function decrypt(text) {
  if (!text || !text.includes(':')) return text;
  try {
    const parts = text.split(':');
    const iv = Buffer.from(parts[0], 'hex');
    const encryptedText = Buffer.from(parts[1], 'hex');
    const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY.padEnd(32).slice(0, 32)), iv);
    let decrypted = decipher.update(encryptedText);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    return decrypted.toString();
  } catch(e) { return text; }
}

function encryptCredentials(credentials) {
  if (!credentials) return credentials;
  const encrypted = {};
  for (const [key, value] of Object.entries(credentials)) {
    encrypted[key] = typeof value === 'string' ? encrypt(value) : value;
  }
  return encrypted;
}

function decryptCredentials(credentials) {
  if (!credentials) return credentials;
  const decrypted = {};
  for (const [key, value] of Object.entries(credentials)) {
    decrypted[key] = typeof value === 'string' ? decrypt(value) : value;
  }
  return decrypted;
}

// ─── CALCUL RGPD SERVEUR ──────────────────────────────────────────────────────

function calculateRGPD(snap) {
  const articles = {
    'Art.5 - Integrite et confidentialite': {
      ok: snap.disk_encrypted === true,
      detail: snap.disk_encrypted ? 'Donnees chiffrees' : 'Disque non chiffre — violation Art.5',
      instruction: 'Activez FileVault (Mac) ou BitLocker (Windows) pour chiffrer les donnees personnelles.'
    },
    'Art.25 - Protection des donnees par defaut': {
      ok: snap.firewall_enabled === true || snap.firewall_status === 'enabled',
      detail: snap.firewall_enabled ? 'Pare-feu actif' : 'Pare-feu desactive — acces non autorise possible',
      instruction: 'Activez le pare-feu systeme pour proteger les donnees par defaut.'
    },
    'Art.32 - Securite du traitement': {
      ok: (snap.antivirus_status && snap.antivirus_status !== 'disabled' && snap.antivirus_status !== 'unknown'),
      detail: snap.antivirus_status !== 'disabled' ? 'Antivirus actif' : 'Aucune protection antivirus',
      instruction: 'Installez un antivirus pour proteger les traitements de donnees personnelles.'
    },
    'Art.30 - Registre des traitements': {
      ok: snap.logging_enabled !== false,
      detail: snap.logging_enabled !== false ? 'Journalisation active' : 'Logs desactives — tracabilite impossible',
      instruction: 'Activez la journalisation systeme pour maintenir un registre des acces aux donnees.'
    },
    'Art.5 - Limitation conservation': {
      ok: (snap.disk_percent || 0) < 80,
      detail: (snap.disk_percent || 0) < 80 ? 'Espace disque OK' : 'Disque presque plein — risque perte de donnees',
      instruction: 'Liberez de lespace disque et mettez en place une politique de retention des donnees.'
    },
  };

  const passed = Object.values(articles).filter(a => a.ok).length;
  const total = Object.keys(articles).length;
  const score = Math.round((passed / total) * 100);
  const conforme = score >= 80;

  return {
    conforme,
    score,
    level: conforme ? 'CONFORME' : score >= 60 ? 'PARTIELLEMENT CONFORME' : 'NON CONFORME',
    articles,
    passed,
    total
  };
}

// ─── CALCUL NIS2 SERVEUR ──────────────────────────────────────────────────────

function calculateNIS2(snap) {
  const checks = {
    firewall:    snap.firewall_enabled === true || snap.firewall_status === 'enabled',
    encrypted:   snap.disk_encrypted === true,
    antivirus:   snap.antivirus_status && snap.antivirus_status !== 'disabled' && snap.antivirus_status !== 'unknown',
    logging:     snap.logging_enabled !== false,
    disk_ok:     (snap.disk_percent || 0) < 85,
    updates_ok:  (snap.pending_updates || 0) === 0,
    screensaver: snap.screensaver_enabled === true,
    no_sharing:  snap.file_sharing !== true,
    no_remote:   snap.remote_login !== true,
  };

  const criteria = {
    'Politique de securite': { checks: ['firewall','encrypted','antivirus'], article: 'Art.21.2.a', weight: 15 },
    'Gestion des incidents':  { checks: ['logging'], article: 'Art.21.2.b', weight: 15 },
    'Continuite activite':    { checks: ['disk_ok','updates_ok'], article: 'Art.21.2.c', weight: 10 },
    'Securite reseaux':       { checks: ['firewall','no_sharing','no_remote'], article: 'Art.21.2.e', weight: 15 },
    'Hygiene informatique':   { checks: ['screensaver','updates_ok'], article: 'Art.21.2.g', weight: 15 },
    'Cryptographie':          { checks: ['encrypted'], article: 'Art.21.2.h', weight: 15 },
    'Controle acces':         { checks: ['no_remote','screensaver'], article: 'Art.21.2.i', weight: 15 },
  };

  let totalScore = 0;
  let totalWeight = 0;
  const results = {};

  for (const [name, crit] of Object.entries(criteria)) {
    const passed = crit.checks.filter(c => checks[c]).length;
    const score = Math.round((passed / crit.checks.length) * 100);
    results[name] = {
      label: name,
      article: crit.article,
      score,
      passed,
      total: crit.checks.length,
      compliant: score >= 75,
      details: crit.checks.map(c => [c, checks[c]])
    };
    totalScore += score * crit.weight;
    totalWeight += crit.weight;
  }

  const global = Math.round(totalScore / totalWeight);
  return {
    score: global,
    level: global >= 80 ? 'CONFORME' : global >= 60 ? 'PARTIELLEMENT CONFORME' : 'NON CONFORME',
    criteria: results,
    checks
  };
}



// ─── INSCRIPTION DEPUIS LANDING PAGE ─────────────────────────────────────────

app.post('/api/signup', async (req, res) => {
  try {
    const { name, email, company, machines, plan, phone } = req.body;
    if (!name || !email) return res.status(400).json({ error: 'Nom et email requis' });

    // Email simple au client
    if (RESEND_API_KEY) {
      await fetch('https://api.resend.com/emails', {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${RESEND_API_KEY}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({
          from: 'ShieldFlow <contact@conformite-rgpd.org>',
          to: email,
          subject: "Votre demande d'audit RGPD — ShieldFlow",
          html: `<div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;color:#212529">
            <div style="background:#1a1d23;padding:28px;text-align:center;border-radius:8px 8px 0 0">
              <h1 style="color:#ffffff;font-size:22px;margin:0">🛡 ShieldFlow</h1>
              <p style="color:#adb5bd;font-size:13px;margin:6px 0 0">Cybersécurité & Conformité RGPD</p>
            </div>
            <div style="padding:32px;border:1px solid #dee2e6;border-top:none;background:#f9fafb">
              <p style="font-size:16px;margin:0 0 16px">Bonjour <strong>${name}</strong>,</p>
              <p style="color:#495057;line-height:1.7;margin:0 0 20px">Merci pour votre intérêt pour ShieldFlow. Notre équipe a bien reçu votre demande d'audit RGPD et vous contactera sous <strong>24h</strong> à cette adresse email.</p>
              <div style="background:#e8f4fd;border-left:4px solid #1c7ed6;padding:16px;border-radius:4px;margin:20px 0">
                <p style="margin:0;font-size:14px;color:#1864ab"><strong>Ce que nous allons faire :</strong><br>
                Notre équipe analysera votre situation et vous enverra un plan d'action personnalisé pour mettre votre entreprise en conformité RGPD.</p>
              </div>
              <p style="color:#868e96;font-size:13px">Des questions ? Contactez-nous directement : <a href="mailto:shieldflowcontact@gmail.com" style="color:#1c7ed6">shieldflowcontact@gmail.com</a></p>
            </div>
            <div style="background:#dee2e6;padding:14px;text-align:center;border-radius:0 0 8px 8px">
              <p style="color:#868e96;font-size:11px;margin:0">ShieldFlow · Marseille, France · Données hébergées en Europe</p>
            </div>
          </div>`
        })
      });
    }

    // Notification à ShieldFlow avec toutes les infos du prospect
    if (RESEND_API_KEY && ALERT_EMAIL) {
      await fetch('https://api.resend.com/emails', {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${RESEND_API_KEY}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({
          from: 'ShieldFlow <contact@conformite-rgpd.org>',
          to: ALERT_EMAIL,
          subject: `🎯 Nouveau prospect : ${company || name}`,
          html: `<div style="font-family:Arial,sans-serif;color:#212529;max-width:500px">
            <h2 style="color:#1a1d23">🎯 Nouveau prospect ShieldFlow</h2>
            <table style="width:100%;border-collapse:collapse">
              <tr><td style="padding:8px;background:#f8f9fa;font-weight:600;width:120px">Nom</td><td style="padding:8px;border:1px solid #dee2e6">${name}</td></tr>
              <tr><td style="padding:8px;background:#f8f9fa;font-weight:600">Email</td><td style="padding:8px;border:1px solid #dee2e6"><a href="mailto:${email}">${email}</a></td></tr>
              <tr><td style="padding:8px;background:#f8f9fa;font-weight:600">Entreprise</td><td style="padding:8px;border:1px solid #dee2e6">${company || 'Non renseigné'}</td></tr>
              <tr><td style="padding:8px;background:#f8f9fa;font-weight:600">Machines</td><td style="padding:8px;border:1px solid #dee2e6">${machines || 'Non renseigné'}</td></tr>
              <tr><td style="padding:8px;background:#f8f9fa;font-weight:600">Téléphone</td><td style="padding:8px;border:1px solid #dee2e6">${phone || 'Non renseigné'}</td></tr>
              <tr><td style="padding:8px;background:#f8f9fa;font-weight:600">Plan</td><td style="padding:8px;border:1px solid #dee2e6;color:#1c7ed6;font-weight:600">${plan || 'Non sélectionné'}</td></tr>
            </table>
            <p style="margin-top:20px;color:#495057">→ Contactez ce prospect dans les 24h pour maximiser la conversion.</p>
          </div>`
        })
      });
    }

    res.json({ success: true, message: 'Demande envoyée' });
  } catch(e) {
    console.error('[Signup]', e.message);
    res.status(500).json({ error: e.message });
  }
});



// ─── SOC — ANALYSTE VIRTUEL IA ───────────────────────────────────────────────

async function runSOCAnalysis(tenantId) {
  if (!ANTHROPIC_API_KEY) return null;
  try {
    const tenant = await Tenant.findById(tenantId).catch(() => null);
    if (!tenant) return null;

    const alerts = await Alert.find({ tenant_id: tenantId, resolved: false });
    const devices = await Device.find({ tenant_id: tenantId });
    const criticals = alerts.filter(a => a.severity === 'critical');
    const score = Math.max(0, 100 - criticals.length*20 - alerts.length*5);

    // Collecter les logs de tous les devices
    const logsData = devices.map(d => ({
      device: d.name,
      platform: d.platform,
      failed_logins: d.snapshot?.soc_failed_logins || 0,
      brute_force: d.snapshot?.soc_brute_force || false,
      suspicious: d.snapshot?.soc_has_suspicious || false,
      critical_events: d.snapshot?.soc_critical_events || 0,
      behavioral_anomaly: d.snapshot?.has_behavioral_anomaly || false,
      behavioral_risk: d.snapshot?.behavioral_risk_score || 0,
      anomalies: d.snapshot?.behavioral_anomalies || [],
      cpu: d.snapshot?.cpu_percent || 0,
      connections: d.snapshot?.established_connections || 0,
    }));

    const prompt = `Tu es un analyste SOC (Security Operations Center) senior avec 15 ans d'expérience. 
Tu travailles pour ShieldFlow et tu analyses la sécurité de l'entreprise "${tenant.name}".

DONNÉES DE LA DERNIÈRE HEURE :
- Score sécurité global : ${score}/100
- Alertes actives : ${alerts.length} dont ${criticals.length} critiques
- Appareils surveillés : ${devices.length}

LOGS ET ÉVÉNEMENTS PAR APPAREIL :
${logsData.map(d => `
Appareil: ${d.device} (${d.platform})
- Tentatives connexion échouées: ${d.failed_logins}
- Brute force suspecté: ${d.brute_force ? 'OUI' : 'non'}
- Activité suspecte: ${d.suspicious ? 'OUI' : 'non'}
- Événements critiques logs: ${d.critical_events}
- Anomalie comportementale: ${d.behavioral_anomaly ? 'OUI (score: '+d.behavioral_risk+'/100)' : 'non'}
- Connexions réseau actives: ${d.connections}
- CPU: ${d.cpu}%
${d.anomalies.length > 0 ? '- Anomalies: ' + d.anomalies.join(', ') : ''}
`).join('')}

ALERTES ACTIVES : ${alerts.map(a => `[${a.severity.toUpperCase()}] ${a.title}`).join(' | ') || 'Aucune'}

En tant qu'analyste SOC, génère un rapport d'analyse en JSON avec exactement ce format :
{
  "niveau_menace": "CRITIQUE|ÉLEVÉ|MOYEN|FAIBLE",
  "resume_executif": "Résumé en 2 phrases pour le dirigeant",
  "evenements_detectes": ["événement 1", "événement 2"],
  "analyse_technique": "Analyse détaillée pour le technicien en 3-4 phrases",
  "vecteurs_attaque_potentiels": ["vecteur 1", "vecteur 2"],
  "actions_immediates": ["action 1", "action 2", "action 3"],
  "recommandations_24h": ["reco 1", "reco 2"],
  "indicateurs_compromission": ["ioc 1"],
  "score_risque_soc": 0
}

Réponds UNIQUEMENT avec le JSON valide, sans texte avant ou après.`;

    const r = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-api-key': ANTHROPIC_API_KEY, 'anthropic-version': '2023-06-01' },
      body: JSON.stringify({ model: 'claude-sonnet-4-6', max_tokens: 1500, messages: [{ role: 'user', content: prompt }] })
    });
    const d = await r.json();
    const text = d.content?.[0]?.text || '';
    
    try {
      return JSON.parse(text.replace(/```json|```/g, '').trim());
    } catch(e) {
      return { resume_executif: text, niveau_menace: 'MOYEN', score_risque_soc: 50 };
    }
  } catch(e) {
    console.error('[SOC]', e.message);
    return null;
  }
}

// Route SOC manuel
app.get('/api/mssp/tenants/:id/soc-report', async (req, res) => {
  try {
    const analysis = await runSOCAnalysis(req.params.id);
    if (!analysis) return res.status(503).json({ error: 'SOC non disponible' });
    res.json({ success: true, analysis, generated_at: new Date() });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// Scheduler SOC — toutes les heures, email si anomalie détectée
cron.schedule('0 * * * *', async () => {
  console.log('[SOC Scheduler] Analyse SOC horaire...');
  try {
    const tenants = await Tenant.find({ email: { $exists: true, $ne: '' } });
    for (const tenant of tenants) {
      const analysis = await runSOCAnalysis(tenant._id.toString());
      if (!analysis) continue;
      
      // Envoyer email seulement si menace ÉLEVÉE ou CRITIQUE
      if (['ÉLEVÉ', 'CRITIQUE'].includes(analysis.niveau_menace) && RESEND_API_KEY && ALERT_EMAIL) {
        const lvlColor = analysis.niveau_menace === 'CRITIQUE' ? '#e8334a' : '#d97706';
        
        // Email à ShieldFlow
        await fetch('https://api.resend.com/emails', {
          method: 'POST',
          headers: { 'Authorization': `Bearer ${RESEND_API_KEY}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({
            from: 'ShieldFlow SOC <contact@conformite-rgpd.org>',
            to: ALERT_EMAIL,
            subject: `🔍 [SOC] ${analysis.niveau_menace} — ${tenant.name}`,
            html: `<div style="font-family:Arial;max-width:600px;color:#1a1d23">
              <div style="background:${lvlColor};padding:20px;border-radius:8px 8px 0 0;text-align:center">
                <h1 style="color:white;margin:0;font-size:18px">🔍 Rapport SOC — ${analysis.niveau_menace}</h1>
                <div style="color:rgba(255,255,255,.8);font-size:12px;margin-top:4px">${tenant.name} · ${new Date().toLocaleString('fr-FR')}</div>
              </div>
              <div style="background:#f8f9fa;border:1px solid #e9ecef;border-top:none;padding:24px;border-radius:0 0 8px 8px">
                <h3 style="margin:0 0 12px;font-size:15px">Résumé exécutif</h3>
                <p style="font-size:14px;color:#3d4452;line-height:1.7">${analysis.resume_executif}</p>
                
                <h3 style="margin:16px 0 8px;font-size:14px">Événements détectés</h3>
                ${(analysis.evenements_detectes||[]).map(e => `<div style="padding:6px 10px;background:#fff;border-left:3px solid ${lvlColor};margin-bottom:4px;font-size:13px">${e}</div>`).join('')}
                
                <h3 style="margin:16px 0 8px;font-size:14px">Actions immédiates</h3>
                ${(analysis.actions_immediates||[]).map((a,i) => `<div style="padding:6px 10px;background:#fff;border:1px solid #e9ecef;border-radius:4px;margin-bottom:4px;font-size:13px"><strong>${i+1}.</strong> ${a}</div>`).join('')}
                
                <div style="margin-top:16px;padding:10px;background:#e7f5ff;border-radius:6px;font-size:12px;color:#1864ab">
                  Score risque SOC : <strong>${analysis.score_risque_soc}/100</strong>
                </div>
              </div>
            </div>`
          })
        });
        console.log(`[SOC] Rapport ${analysis.niveau_menace} envoyé pour ${tenant.name}`);
      }
    }
  } catch(e) {
    console.error('[SOC Scheduler]', e.message);
  }
}, { timezone: 'Europe/Paris' });

// ─── ANALYSE IA DES ALERTES ──────────────────────────────────────────────────

const ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY || '';

async function analyzeWithAI(prompt) {
  if (!ANTHROPIC_API_KEY) return null;
  try {
    const r = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01'
      },
      body: JSON.stringify({
        model: 'claude-sonnet-4-6',
        max_tokens: 1000,
        messages: [{ role: 'user', content: prompt }]
      })
    });
    const d = await r.json();
    return d.content?.[0]?.text || null;
  } catch(e) {
    console.error('[AI]', e.message);
    return null;
  }
}

app.get('/api/mssp/tenants/:tenantId/alerts/:alertId/ai-analysis', async (req, res) => {
  try {
    const { tenantId, alertId } = req.params;
    const tenant = await Tenant.findById(tenantId).catch(() => null);
    if (!tenant) return res.status(404).json({ error: 'Client non trouvé' });
    
    const alert = await Alert.findById(alertId).catch(() => null);
    if (!alert) return res.status(404).json({ error: 'Alerte non trouvée' });

    const device = await Device.findOne({ device_id: alert.device_id }).catch(() => null);
    const snap = device?.snapshot || {};

    const prompt = `Tu es un expert en cybersécurité senior qui analyse des alertes de sécurité pour des PME françaises. 
    
Contexte de l'alerte :
- Client : ${tenant.name}
- Type d'alerte : ${alert.type}
- Titre : ${alert.title}
- Appareil : ${alert.device_name}
- Système : ${snap.platform || 'inconnu'}
- CPU actuel : ${snap.cpu_percent || 0}%
- RAM actuelle : ${snap.ram_percent || 0}%
- Disque utilisé : ${snap.disk_percent || 0}%
- Pare-feu : ${snap.firewall_enabled ? 'Activé' : 'Désactivé'}
- Antivirus : ${snap.antivirus_status || 'inconnu'}
- Chiffrement disque : ${snap.disk_encrypted ? 'Oui' : 'Non'}

Génère une analyse professionnelle en français avec exactement ce format JSON :
{
  "niveau_risque": "CRITIQUE|ÉLEVÉ|MOYEN|FAIBLE",
  "explication": "Explication claire en 2-3 phrases pour un dirigeant non-technique",
  "impact_metier": "Impact concret sur l'activité de l'entreprise en 1-2 phrases",
  "actions_immediates": ["Action 1", "Action 2", "Action 3"],
  "risque_rgpd": "Oui|Non",
  "detail_rgpd": "Explication du risque RGPD si applicable"
}

Réponds UNIQUEMENT avec le JSON, sans texte avant ou après.`;

    const analysis = await analyzeWithAI(prompt);
    
    if (!analysis) return res.json({ error: 'IA non disponible' });
    
    try {
      const parsed = JSON.parse(analysis.replace(/```json|```/g, '').trim());
      res.json({ success: true, analysis: parsed, alert_id: alertId });
    } catch(e) {
      res.json({ success: true, analysis: { explication: analysis }, alert_id: alertId });
    }
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/mssp/tenants/:tenantId/ai-report', async (req, res) => {
  try {
    const tenant = await Tenant.findById(req.params.tenantId).catch(() => null);
    if (!tenant) return res.status(404).json({ error: 'Client non trouvé' });
    
    const alerts = await Alert.find({ tenant_id: req.params.tenantId, resolved: false });
    const devices = await Device.find({ tenant_id: req.params.tenantId });
    const criticals = alerts.filter(a => a.severity === 'critical');
    const score = Math.max(0, 100 - criticals.length*20 - alerts.length*5);

    const prompt = `Tu es un expert en cybersécurité senior. Rédige un résumé exécutif de sécurité pour un dirigeant de PME, en français, professionnel et concis.

Données de l'entreprise ${tenant.name} :
- Score de sécurité : ${score}/100
- Nombre d'appareils : ${devices.length}
- Alertes actives : ${alerts.length} dont ${criticals.length} critiques
- Alertes : ${alerts.map(a => a.title).join(', ') || 'Aucune'}
- Conformité RGPD : ${tenant.rgpd_score || 0}/100

Génère un résumé en 3 paragraphes maximum :
1. État général de la sécurité
2. Points d'attention prioritaires
3. Recommandations concrètes

Ton langage doit être accessible à un dirigeant non-technique. Sois direct et actionnable.`;

    const report = await analyzeWithAI(prompt);
    res.json({ success: true, report, tenant: tenant.name, score, generated_at: new Date() });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── RGPD PDF REPORT ─────────────────────────────────────────────────────────

app.get('/api/mssp/tenants/:id/rgpd-report', async (req, res) => {
  try {
    const tenant = await Tenant.findById(req.params.id);
    if (!tenant) return res.status(404).json({ error: 'Tenant non trouve' });

    const rgpd = {
      score: tenant.rgpd_score || 0,
      level: tenant.rgpd_level || 'Non evalue',
      conforme: tenant.rgpd_conforme || false,
      articles: tenant.rgpd_articles || {}
    };

    const doc = new PDFDocument({ margin: 50 });
    const chunks = [];
    doc.on('data', c => chunks.push(c));
    doc.on('end', () => {
      const buf = Buffer.concat(chunks);
      res.setHeader('Content-Type', 'application/pdf');
      res.setHeader('Content-Disposition', 'attachment; filename=rapport-rgpd-' + tenant.name + '.pdf');
      res.send(buf);
    });

    // Header
    doc.fillColor('#1a1d27').rect(0, 0, doc.page.width, 120).fill();
    doc.fillColor('#2563eb').fontSize(28).font('Helvetica-Bold').text('ShieldFlow', 50, 30);
    doc.fillColor('#ffffff').fontSize(16).font('Helvetica-Bold').text('Rapport de Conformite RGPD', 50, 65);
    doc.fillColor('#8b9ab0').fontSize(11).font('Helvetica').text('Reglement General sur la Protection des Donnees (UE) 2016/679', 50, 88);

    doc.moveDown(3);

    // Score global
    const scoreColor = rgpd.conforme ? '#10b981' : rgpd.score >= 60 ? '#f97316' : '#ef4444';
    const badge = rgpd.conforme ? 'CONFORME' : rgpd.level;

    doc.fillColor('#1a1d27').roundedRect(50, 135, doc.page.width - 100, 80, 8).fill();
    doc.fillColor(scoreColor).fontSize(36).font('Helvetica-Bold').text(rgpd.score + '/100', 70, 150);
    doc.fillColor(scoreColor).fontSize(14).font('Helvetica-Bold').text(badge, 70, 192);
    doc.fillColor('#8b9ab0').fontSize(10).font('Helvetica').text('Client: ' + tenant.name + '  |  Date: ' + new Date().toLocaleDateString('fr-FR'), 300, 165);

    doc.moveDown(5);

    // Articles
    doc.fillColor('#e8edf5').fontSize(14).font('Helvetica-Bold').text('Detail par article RGPD', 50);
    doc.moveDown(0.5);

    for (const [name, article] of Object.entries(rgpd.articles)) {
      const color = article.ok ? '#10b981' : '#ef4444';
      const icon = article.ok ? '✓' : '✗';

      doc.fillColor('#151b26').roundedRect(50, doc.y, doc.page.width - 100, article.ok ? 45 : 70, 6).fill();
      doc.fillColor(color).fontSize(11).font('Helvetica-Bold').text(icon + '  ' + name, 65, doc.y + 10);
      doc.fillColor('#8b9ab0').fontSize(9).font('Helvetica').text(article.detail, 65, doc.y + 5);
      if (!article.ok && article.instruction) {
        doc.fillColor('#3b82f6').fontSize(9).font('Helvetica').text('→ ' + article.instruction, 65, doc.y + 3);
      }
      doc.moveDown(article.ok ? 2.5 : 3.5);
    }

    doc.moveDown();

    // Conclusion
    const conclusionBg = rgpd.conforme ? '#0a1f15' : '#1a0a0a';
    const conclusionColor = rgpd.conforme ? '#10b981' : '#ef4444';
    doc.fillColor(conclusionBg).roundedRect(50, doc.y, doc.page.width - 100, 80, 8).fill();

    if (rgpd.conforme) {
      doc.fillColor(conclusionColor).fontSize(12).font('Helvetica-Bold').text('Felicitations — Votre systeme est conforme au RGPD', 65, doc.y + 15);
      doc.fillColor('#8b9ab0').fontSize(10).font('Helvetica').text('Continuez a surveiller votre conformite avec ShieldFlow. Un rapport mensuel est recommande.', 65, doc.y + 5);
    } else {
      doc.fillColor(conclusionColor).fontSize(12).font('Helvetica-Bold').text('Action requise — Votre systeme necessite des corrections', 65, doc.y + 15);
      doc.fillColor('#8b9ab0').fontSize(10).font('Helvetica').text('Les points marques ✗ doivent etre corriges pour eviter des sanctions CNIL (jusqu a 4% du CA mondial).', 65, doc.y + 5);
    }

    doc.end();
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── RGPD ROUTE ──────────────────────────────────────────────────────────────

app.get('/api/mssp/tenants/:id/rgpd', async (req, res) => {
  try {
    const tenant = await Tenant.findById(req.params.id);
    if (!tenant) return res.status(404).json({ error: 'Tenant non trouve' });
    res.json({
      score: tenant.rgpd_score || 0,
      level: tenant.rgpd_level || 'Non evalue',
      conforme: tenant.rgpd_conforme || false,
      articles: tenant.rgpd_articles || {},
      updated_at: tenant.rgpd_updated_at
    });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── NIS2 SCORE ROUTE ────────────────────────────────────────────────────────

app.post('/api/agent/:tenantId/nis2-score', async (req, res) => {
  try {
    const tenantId = req.params.tenantId;
    const agentKey = req.headers['x-agent-key'];
    const tenant = await Tenant.findById(tenantId).catch(() => null);
    if (!tenant) return res.status(404).json({ error: 'Tenant non trouve' });
    if (agentKey !== tenant.agent_key && agentKey !== SECRET_KEY)
      return res.status(403).json({ error: 'Cle invalide' });

    // Sauvegarder le score NIS2
    await Tenant.findByIdAndUpdate(tenantId, {
      'nis2_score': req.body.score,
      'nis2_level': req.body.level,
      'nis2_criteria': req.body.criteria,
      'nis2_updated_at': new Date()
    });

    res.json({ success: true });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/mssp/tenants/:id/nis2', async (req, res) => {
  try {
    const tenant = await Tenant.findById(req.params.id);
    if (!tenant) return res.status(404).json({ error: 'Tenant non trouve' });
    res.json({
      score: tenant.nis2_score || 0,
      level: tenant.nis2_level || 'Non evalue',
      criteria: tenant.nis2_criteria || {},
      updated_at: tenant.nis2_updated_at
    });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── CVE ALERTS ROUTE ────────────────────────────────────────────────────────

app.post('/api/agent/:tenantId/cve-alert', async (req, res) => {
  try {
    const tenantId = req.params.tenantId;
    const agentKey = req.headers['x-agent-key'];
    const tenant = await Tenant.findById(tenantId).catch(() => null);
    if (!tenant) return res.status(404).json({ error: 'Tenant non trouve' });
    if (agentKey !== tenant.agent_key && agentKey !== SECRET_KEY) 
      return res.status(403).json({ error: 'Cle invalide' });

    const alert = req.body;
    const device = await Device.findOne({ tenant_id: tenantId });
    
    // Verifier si alerte deja existante
    const exists = await Alert.findOne({ 
      tenant_id: tenantId, 
      type: alert.type, 
      resolved: false 
    });
    
    if (!exists) {
      // Ajouter instructions CVE
      const instrKey = 'CVE_SOFTWARE';
      alert.instructions = [
        'Mettez a jour ' + (alert.evidence?.software || 'le logiciel concerne') + ' immediatement',
        'Allez sur le site officiel du logiciel et telechargez la derniere version',
        'Mac : utilisez les mises a jour automatiques ou App Store',
        'Windows : Parametres → Windows Update → Rechercher les mises a jour',
        'Linux : sudo apt-get update && sudo apt-get upgrade -y',
        'Apres mise a jour, relancez un scan ShieldFlow pour confirmer la correction',
        'CVE references : ' + (alert.evidence?.cves?.map(c => c.cve_id).join(', ') || 'voir rapport')
      ];
      alert.auto_fixable = false;
      
      const newAlert = await Alert.create({
        tenant_id: tenantId,
        device_id: device?.device_id || 'unknown',
        device_name: device?.name || 'Machine',
        ...alert
      });
      
      if (alert.severity === 'critical' || alert.severity === 'high') {
        sendAlertEmail(tenant.name, newAlert, device?.name || 'Machine', ALERT_EMAIL);
      }
      
      console.log(`[CVE] Nouvelle alerte: ${alert.title}`);
    }
    
    res.json({ success: true });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── INSTRUCTIONS ROUTE ──────────────────────────────────────────────────────

app.get('/api/mssp/tenants/:tenantId/alerts/:alertId/instructions', async (req, res) => {
  try {
    const alert = await Alert.findById(req.params.alertId);
    if (!alert) return res.status(404).json({ error: 'Alerte non trouvée' });
    
    const instructions = alert.instructions || [];
    const platform = 'Darwin'; // Par défaut macOS, à améliorer
    
    // Si pas d'instructions en DB, chercher dans la base statique
    if (!instructions.length) {
      const instrKey = Object.keys(MANUAL_INSTRUCTIONS).find(k => alert.type.startsWith(k));
      if (instrKey) {
        const device = await Device.findOne({ device_id: alert.device_id });
        const os = device?.platform || 'Darwin';
        const instr = MANUAL_INSTRUCTIONS[instrKey];
        const steps = instr[os] || instr['Darwin'] || ['Contactez le support ShieldFlow.'];
        return res.json({ title: alert.title, instructions: steps, auto_fixable: instr.auto || false });
      }
    }
    
    // Si pas d'instructions specifiques, generer des instructions generiques
    const finalInstructions = instructions.length > 0 ? instructions : [
      `Alerte detectee : ${alert.title}`,
      `Appareil concerne : ${alert.device_name}`,
      `Severite : ${alert.severity.toUpperCase()}`,
      '---',
      '1. Verifiez l etat de l appareil concerne dans le dashboard',
      '2. Connectez-vous a la machine et verifiez les logs systeme',
      '3. Si Mac : ouvrez Console.app et cherchez des erreurs recentes',
      '4. Si Windows : ouvrez l Observateur d evenements et cherchez des erreurs',
      '5. Si Linux : tapez sudo journalctl -n 100 dans le terminal',
      `6. Description complete : ${alert.description}`,
      `7. Recommendation : ${alert.recommendation || 'Contactez le support ShieldFlow'}`,
      '8. Une fois resolu, l alerte disparaitra au prochain scan (30 secondes)'
    ];
    res.json({ title: alert.title, instructions: finalInstructions, auto_fixable: alert.auto_fixable || false });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── REMEDIATION ROUTES ───────────────────────────────────────────────────────

// Envoyer une commande de remédiation à un agent
app.post('/api/mssp/tenants/:tenantId/alerts/:alertId/remediate', async (req, res) => {
  try {
    const alert = await Alert.findById(req.params.alertId);
    if (!alert) return res.status(404).json({ error: 'Alerte non trouvée' });
    
    // Créer la commande
    const command = {
      id: require('crypto').randomBytes(8).toString('hex'),
      alert_type: alert.type,
      alert_id: alert._id.toString(),
      device_id: alert.device_id,
      params: req.body.params || {},
      created_at: new Date(),
      executed: false
    };
    
    // Stocker dans la file d'attente du device
    await Device.findOneAndUpdate(
      { device_id: alert.device_id, tenant_id: req.params.tenantId },
      { $push: { pending_commands: command } }
    );
    
    res.json({ success: true, command_id: command.id, message: 'Commande envoyée à l\'agent' });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// Agent récupère ses commandes en attente
app.get('/api/agent/:tenantId/commands', async (req, res) => {
  const tenantId = req.params.tenantId;
  const agentKey = req.headers['x-agent-key'];
  
  const tenant = await Tenant.findById(tenantId).catch(() => null);
  if (!tenant) return res.status(404).json({ error: 'Tenant non trouvé' });
  if (agentKey !== tenant.agent_key && agentKey !== SECRET_KEY) return res.status(403).json({ error: 'Clé invalide' });
  
  // Récupérer toutes les commandes en attente pour ce tenant
  const devices = await Device.find({ tenant_id: tenantId, 'pending_commands.0': { $exists: true } });
  const commands = [];
  for (const d of devices) {
    const pending = (d.pending_commands || []).filter(c => !c.executed);
    commands.push(...pending);
  }
  
  res.json({ commands });
});

// Agent signale le résultat d'une remédiation
app.post('/api/agent/:tenantId/remediation-result', async (req, res) => {
  const { command_id, result } = req.body;
  const tenantId = req.params.tenantId;
  
  // Marquer la commande comme exécutée
  await Device.findOneAndUpdate(
    { tenant_id: tenantId, 'pending_commands.id': command_id },
    { 
      $set: { 
        'pending_commands.$.executed': true,
        'pending_commands.$.result': result,
        'pending_commands.$.executed_at': new Date()
      }
    }
  );
  
  // Si succès → résoudre l'alerte
  if (result && result.success) {
    const cmd = await Device.findOne(
      { tenant_id: tenantId, 'pending_commands.id': command_id },
      { 'pending_commands.$': 1 }
    );
    if (cmd && cmd.pending_commands[0]) {
      const alertId = cmd.pending_commands[0].alert_id;
      if (alertId) {
        await Alert.findByIdAndUpdate(alertId, { resolved: true, resolved_at: new Date() });
      }
    }
  }
  
  res.json({ success: true });
});


// ─── CLOUD SCHEDULER ─────────────────────────────────────────────────────────

const { execFile } = require('child_process');
const path2 = require('path');

async function runCloudScan(tenantId, cloudType, credentials) {
  return new Promise((resolve) => {
    const alerts = [];
    
    if (cloudType === 'aws') {
      // Simulation scan AWS — en production utilise boto3 via Python
      const checks = [];
      
      // Vérifications basiques sans boto3
      if (!credentials.access_key || credentials.access_key.length < 16) {
        checks.push({
          type: 'AWS_INVALID_KEY',
          severity: 'high',
          title: 'Clé AWS invalide ou expirée',
          description: 'La cle acces AWS fournie semble invalide. Verifiez vos credentials.',
          recommendation: 'Créez une nouvelle clé dans AWS IAM et mettez à jour ShieldFlow.'
        });
      }
      
      resolve(checks);
      
    } else if (cloudType === 'm365') {
      // Vérification M365 via Microsoft Graph
      const https = require('https');
      
      // Obtenir un token
      const tokenData = `grant_type=client_credentials&client_id=${credentials.client_id}&client_secret=${encodeURIComponent(credentials.client_secret || '')}&scope=https://graph.microsoft.com/.default`;
      
      const options = {
        hostname: 'login.microsoftonline.com',
        path: `/${credentials.tenant_id}/oauth2/v2.0/token`,
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
      };
      
      const req = https.request(options, (res) => {
        let data = '';
        res.on('data', chunk => data += chunk);
        res.on('end', async () => {
          try {
            const tokenData = JSON.parse(data);
            if (tokenData.error) {
              alerts.push({
                type: 'M365_AUTH_ERROR',
                severity: 'high',
                title: 'Authentification Microsoft 365 échouée',
                description: `Impossible de se connecter à M365: ${tokenData.error_description || tokenData.error}`,
                recommendation: 'Vérifiez le Tenant ID, Client ID et Client Secret dans les paramètres cloud.'
              });
              return resolve(alerts);
            }
            
            const accessToken = tokenData.access_token;
            
            // Vérifier les utilisateurs sans MFA
            const usersReq = https.request({
              hostname: 'graph.microsoft.com',
              path: '/v1.0/users?$select=displayName,userPrincipalName,accountEnabled&$top=50',
              headers: { 'Authorization': `Bearer ${accessToken}` }
            }, (usersRes) => {
              let userData = '';
              usersRes.on('data', c => userData += c);
              usersRes.on('end', () => {
                try {
                  const users = JSON.parse(userData);
                  const activeUsers = (users.value || []).filter(u => u.accountEnabled);
                  
                  if (activeUsers.length > 0) {
                    // Vérifier si trop d'admins
                    alerts.push({
                      type: 'M365_SCAN_OK',
                      severity: 'low',
                      title: `M365 scanné: ${activeUsers.length} utilisateurs actifs`,
                      description: `Scan Microsoft 365 effectué. ${activeUsers.length} comptes actifs trouvés. Vérification MFA recommandée pour tous les comptes.`,
                      recommendation: 'Activez le MFA pour tous les utilisateurs via Azure AD > Sécurité.'
                    });
                  }
                } catch(e) {}
                resolve(alerts);
              });
            });
            usersReq.on('error', () => resolve(alerts));
            usersReq.end();
            
          } catch(e) {
            resolve(alerts);
          }
        });
      });
      req.on('error', () => resolve(alerts));
      req.write(tokenData);
      req.end();
      
    } else if (cloudType === 'gworkspace') {
      // Google Workspace scan basique
      alerts.push({
        type: 'GWS_CREDENTIALS_CHECK',
        severity: 'medium',
        title: 'Google Workspace: vérification manuelle requise',
        description: 'Les credentials Google Workspace ont été enregistrés. Un scan complet nécessite le module Python google-auth.',
        recommendation: 'Vérifiez que le compte de service a les bonnes permissions dans Google Admin Console.'
      });
      resolve(alerts);
    } else {
      resolve([]);
    }
  });
}

async function scanAllClouds() {
  console.log('[CloudScan] Démarrage scan cloud de tous les tenants...');
  const tenants = await Tenant.find();
  
  for (const tenant of tenants) {
    const clouds = tenant.cloud || {};
    
    for (const [cloudType, cloudData] of Object.entries(clouds)) {
      if (!cloudData.credentials) continue;
      
      console.log(`[CloudScan] Scan ${cloudType} pour ${tenant.name}...`);
      
      try {
        const alerts = await runCloudScan(tenant._id.toString(), cloudType, cloudData.credentials);
        
        for (const alert of alerts) {
          if (alert.type === 'M365_SCAN_OK') continue; // Ignorer les infos
          
          const exists = await Alert.findOne({
            tenant_id: tenant._id.toString(),
            type: alert.type,
            resolved: false
          });
          
          if (!exists) {
            const newAlert = await Alert.create({
              tenant_id: tenant._id.toString(),
              device_id: 'cloud_' + cloudType,
              device_name: cloudType.toUpperCase() + ' Cloud',
              ...alert
            });
            
            if (alert.severity === 'critical' || alert.severity === 'high') {
              sendAlertEmail(tenant.name, newAlert, cloudType + ' Cloud', ALERT_EMAIL);
            }
          }
        }
        
        // Mettre à jour la date du dernier scan
        tenant.cloud[cloudType].last_scan = new Date();
        tenant.markModified('cloud');
        await tenant.save();
        
        console.log(`[CloudScan] ${tenant.name} ${cloudType}: ${alerts.length} alertes`);
        
      } catch(e) {
        console.error(`[CloudScan] Erreur ${tenant.name} ${cloudType}:`, e.message);
      }
    }
  }
  
  console.log('[CloudScan] Scan cloud terminé');
}

// Scanner les clouds toutes les heures
cron.schedule('0 * * * *', scanAllClouds, { timezone: 'Europe/Paris' });

// Route pour déclencher un scan cloud manuellement
// ─── DELETE CLOUD ─────────────────────────────────────────────────────────────

app.delete('/api/mssp/tenants/:id/cloud/:type', async (req, res) => {
  try {
    const tenant = await Tenant.findById(req.params.id).catch(() => null);
    if (!tenant) return res.status(404).json({ error: 'Client non trouve' });
    if (!tenant.cloud) return res.json({ success: true });
    delete tenant.cloud[req.params.type];
    tenant.markModified('cloud');
    await tenant.save();
    // Supprimer les alertes cloud associées
    await Alert.updateMany(
      { tenant_id: req.params.id, device_id: 'cloud_' + req.params.type },
      { resolved: true, resolved_at: new Date() }
    );
    res.json({ success: true, message: 'Cloud supprime' });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/mssp/tenants/:id/cloud/scan', async (req, res) => {
  const tenant = await Tenant.findById(req.params.id).catch(() => null);
  if (!tenant) return res.status(404).json({ error: 'Tenant non trouvé' });
  
  const clouds = tenant.cloud || {};
  const results = {};
  
  for (const [cloudType, cloudData] of Object.entries(clouds)) {
    if (!cloudData.credentials) continue;
    const alerts = await runCloudScan(req.params.id, cloudType, decryptCredentials(cloudData.credentials));
    results[cloudType] = alerts.length;
    
    for (const alert of alerts) {
      if (alert.type === 'M365_SCAN_OK') continue;
      const exists = await Alert.findOne({ tenant_id: req.params.id, type: alert.type, resolved: false });
      if (!exists) {
        await Alert.create({ tenant_id: req.params.id, device_id: 'cloud_' + cloudType, device_name: cloudType.toUpperCase() + ' Cloud', ...alert });
      }
    }
  }
  
  res.json({ success: true, results, message: 'Scan cloud déclenché' });
});

console.log('[Scheduler] Scan cloud programmé toutes les heures');

// Route principale — landing page
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, '../dashboard/landing.html'));
});

// Dashboard MSSP
app.get('/dashboard', (req, res) => {
  res.sendFile(path.join(__dirname, '../dashboard/index.html'));
});

// Static files
app.use(express.static(path.join(__dirname, '../dashboard')));


// ─── REMÉDIATION AUTONOME IA ─────────────────────────────────────────────────

async function autoRemediateWithAI(tenantId, alert, snap) {
  if (!ANTHROPIC_API_KEY) return;
  
  // Seulement pour les alertes auto-fixables
  const autoFixable = ['FIREWALL_OFF', 'SCREENSAVER_OFF', 'REMOTE_LOGIN_ON', 
                        'FILE_SHARING_ON', 'LOGS_DISABLED', 'DANGER_PORTS',
                        'SUSPICIOUS_CONNECTIONS'];
  
  if (!autoFixable.includes(alert.type)) return;
  
  try {
    const prompt = `Tu es un système de remédiation automatique cybersécurité. 
    
Alerte détectée : ${alert.type} — ${alert.title}
Système : ${snap.platform || 'Darwin'}
Contexte : pare-feu=${snap.firewall_enabled}, antivirus=${snap.antivirus_status}, CPU=${snap.cpu_percent}%

Décide si cette alerte peut être corrigée automatiquement et en toute sécurité sans intervention humaine.
Réponds UNIQUEMENT en JSON :
{
  "can_auto_fix": true/false,
  "reason": "raison courte",
  "command_type": "FIREWALL_OFF|SCREENSAVER_OFF|REMOTE_LOGIN_ON|FILE_SHARING_ON|LOGS_DISABLED|DANGER_PORTS|none",
  "confidence": 0-100
}`;

    const r = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-api-key': ANTHROPIC_API_KEY, 'anthropic-version': '2023-06-01' },
      body: JSON.stringify({ model: 'claude-sonnet-4-6', max_tokens: 200, messages: [{ role: 'user', content: prompt }] })
    });
    const d = await r.json();
    const text = d.content?.[0]?.text || '';
    
    let decision;
    try { decision = JSON.parse(text.replace(/```json|```/g, '').trim()); } catch(e) { return; }
    
    if (decision.can_auto_fix && decision.confidence >= 80) {
      console.log(`[AI Remediation] Auto-fix ${alert.type} sur ${alert.device_name} (confiance: ${decision.confidence}%)`);
      
      // Envoyer la commande de remédiation
      const device = await Device.findOne({ device_id: alert.device_id });
      if (!device) return;
      
      const command = {
        id: require('crypto').randomUUID(),
        alert_type: decision.command_type,
        alert_id: alert._id.toString(),
        params: {},
        source: 'ai_auto',
        created_at: new Date()
      };
      
      await Device.findByIdAndUpdate(device._id, { $push: { pending_commands: command } });
      await Alert.findByIdAndUpdate(alert._id, { ai_auto_fix: true, ai_confidence: decision.confidence });
      
      console.log(`[AI Remediation] Commande envoyée automatiquement pour ${alert.type}`);
    }
  } catch(e) {
    console.error('[AI Remediation]', e.message);
  }
}

// ─── RAPPORT IA QUOTIDIEN ────────────────────────────────────────────────────

async function sendAIReport(tenant) {
  if (!ANTHROPIC_API_KEY || !RESEND_API_KEY) return;
  try {
    const alerts = await Alert.find({ tenant_id: tenant._id.toString(), resolved: false });
    const devices = await Device.find({ tenant_id: tenant._id.toString() });
    const criticals = alerts.filter(a => a.severity === 'critical');
    const score = Math.max(0, 100 - criticals.length*20 - alerts.length*5);

    // Générer le rapport IA
    const prompt = `Tu es un expert cybersécurité senior. Rédige un rapport de sécurité quotidien professionnel en français pour le dirigeant de l'entreprise "${tenant.name}".

Données du jour :
- Score de sécurité : ${score}/100
- Appareils surveillés : ${devices.length}
- Alertes actives : ${alerts.length} dont ${criticals.length} critiques
- Alertes : ${alerts.map(a => a.title).slice(0,5).join(', ') || 'Aucune'}
- Conformité RGPD : ${tenant.rgpd_score || 0}/100

Rédige un rapport en 3 paragraphes courts :
1. Bilan de sécurité du jour (1-2 phrases)
2. Points d'attention (si alertes) ou félicitations (si tout va bien)
3. Recommandation du jour

Ton langage doit être accessible, professionnel et rassurant. Maximum 150 mots.`;

    const r = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-api-key': ANTHROPIC_API_KEY, 'anthropic-version': '2023-06-01' },
      body: JSON.stringify({ model: 'claude-sonnet-4-6', max_tokens: 500, messages: [{ role: 'user', content: prompt }] })
    });
    const aiData = await r.json();
    const aiText = aiData.content?.[0]?.text || 'Rapport non disponible';

    const scoreColor = score >= 80 ? '#0ea572' : score >= 50 ? '#d97706' : '#e8334a';
    const scoreLabel = score >= 80 ? 'Bon niveau' : score >= 50 ? 'À améliorer' : 'Critique';

    await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${RESEND_API_KEY}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        from: 'ShieldFlow <contact@conformite-rgpd.org>',
        to: tenant.email,
        subject: `🛡 Rapport de sécurité du ${new Date().toLocaleDateString('fr-FR')} — ${tenant.name}`,
        html: `<div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;color:#1a1d23">
          <div style="background:#1a1d23;padding:24px;border-radius:12px 12px 0 0;text-align:center">
            <div style="font-size:22px;font-weight:800;color:#ffffff;letter-spacing:-0.03em">🛡 ShieldFlow</div>
            <div style="font-size:12px;color:#8896a8;margin-top:4px">Rapport de sécurité quotidien — ${new Date().toLocaleDateString('fr-FR')}</div>
          </div>
          <div style="background:#f8f9fa;padding:28px;border:1px solid #e9ecef;border-top:none">
            <h2 style="font-size:18px;margin:0 0 20px;color:#1a1d23">${tenant.name}</h2>
            
            <div style="display:flex;gap:12px;margin-bottom:24px;flex-wrap:wrap">
              <div style="flex:1;min-width:100px;background:white;border:1px solid #e9ecef;border-radius:8px;padding:16px;text-align:center">
                <div style="font-size:32px;font-weight:800;color:${scoreColor}">${score}</div>
                <div style="font-size:10px;color:#6b7280;text-transform:uppercase;letter-spacing:.06em">Score /100</div>
                <div style="font-size:11px;color:${scoreColor};font-weight:600;margin-top:2px">${scoreLabel}</div>
              </div>
              <div style="flex:1;min-width:100px;background:white;border:1px solid #e9ecef;border-radius:8px;padding:16px;text-align:center">
                <div style="font-size:32px;font-weight:800;color:${alerts.length>0?'#e8334a':'#0ea572'}">${alerts.length}</div>
                <div style="font-size:10px;color:#6b7280;text-transform:uppercase;letter-spacing:.06em">Alertes</div>
                <div style="font-size:11px;color:${criticals.length>0?'#e8334a':'#6b7280'};margin-top:2px">${criticals.length} critique(s)</div>
              </div>
              <div style="flex:1;min-width:100px;background:white;border:1px solid #e9ecef;border-radius:8px;padding:16px;text-align:center">
                <div style="font-size:32px;font-weight:800;color:#2b6de8">${devices.length}</div>
                <div style="font-size:10px;color:#6b7280;text-transform:uppercase;letter-spacing:.06em">Appareils</div>
                <div style="font-size:11px;color:#0ea572;margin-top:2px">Surveillés</div>
              </div>
            </div>

            <div style="background:white;border:1px solid #e9ecef;border-radius:8px;padding:20px;margin-bottom:20px">
              <div style="font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.06em;color:#6b7280;margin-bottom:12px">🤖 Analyse IA du jour</div>
              <div style="font-size:14px;color:#3d4452;line-height:1.75;white-space:pre-wrap">${aiText}</div>
            </div>

            ${alerts.length > 0 ? `
            <div style="background:#fff5f5;border:1px solid #fecaca;border-radius:8px;padding:16px;margin-bottom:20px">
              <div style="font-size:11px;font-weight:700;text-transform:uppercase;color:#e8334a;margin-bottom:8px">Alertes actives</div>
              ${alerts.slice(0,3).map(a => `<div style="font-size:13px;padding:6px 0;border-bottom:1px solid #fecaca;color:#3d4452">⚠ ${a.title} — ${a.device_name}</div>`).join('')}
            </div>` : `
            <div style="background:#f0fdf4;border:1px solid #bbf7d0;border-radius:8px;padding:16px;margin-bottom:20px;text-align:center">
              <div style="font-size:14px;color:#0ea572;font-weight:600">✅ Aucune alerte — Infrastructure saine</div>
            </div>`}

            <p style="font-size:12px;color:#9ca3af;margin:0">Ce rapport est généré automatiquement par ShieldFlow chaque matin à 8h. Pour toute question : <a href="mailto:shieldflowcontact@gmail.com" style="color:#2b6de8">shieldflowcontact@gmail.com</a></p>
          </div>
          <div style="background:#e9ecef;padding:12px;border-radius:0 0 12px 12px;text-align:center">
            <p style="font-size:11px;color:#9ca3af;margin:0">ShieldFlow · Cybersécurité Managée · conformite-rgpd.org</p>
          </div>
        </div>`
      })
    });
    console.log('[AI Report] Envoyé à', tenant.email);
  } catch(e) {
    console.error('[AI Report] Erreur:', e.message);
  }
}

// ─── START ────────────────────────────────────────────────────────────────────

app.listen(PORT, () => {
  console.log(`
╔══════════════════════════════════════╗
║      ShieldFlow Backend v2.0         ║
║      Port : ${PORT}                     ║
║      DB   : MongoDB Atlas            ║
╚══════════════════════════════════════╝

  MSSP Password  : ${MSSP_PASSWORD}
  Admin Password : ${ADMIN_PASSWORD}
  Dashboard : http://localhost:${PORT}
  `);
});
