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
app.use(express.static(path.join(__dirname, '../dashboard')));

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
        from:'ShieldFlow <onboarding@resend.dev>',
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
        from: 'ShieldFlow <onboarding@resend.dev>',
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
  console.log('[Scheduler] Envoi des rapports PDF quotidiens...');
  const tenants = await Tenant.find({ email: { $exists: true, $ne: '' } });
  for (const t of tenants) {
    await sendDailyReport(t._id.toString());
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
    const { name, email, company, machines } = req.body;
    if (!name || !email) return res.status(400).json({ error: 'Nom et email requis' });

    // Créer le tenant automatiquement
    const agentKey = require('crypto').randomBytes(16).toString('hex');
    const tenant = await Tenant.create({
      name: company || name,
      email,
      contact_name: name,
      password: require('crypto').randomBytes(8).toString('hex'),
      agent_key: agentKey,
      plan: 'trial',
      trial_started_at: new Date()
    });

    const tenantId = tenant._id.toString();
    const installCmd = `curl -sSL https://shieldflow-rfzv.onrender.com/install.sh | bash -s -- ${tenantId} ${agentKey}`;

    // Email de bienvenue avec la commande d'installation
    if (RESEND_API_KEY) {
      await fetch('https://api.resend.com/emails', {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${RESEND_API_KEY}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({
          from: 'ShieldFlow <onboarding@resend.dev>',
          to: email,
          subject: 'Votre audit RGPD gratuit — ShieldFlow',
          html: `
            <div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;color:#212529">
              <div style="background:#212529;padding:28px;border-radius:8px 8px 0 0;text-align:center">
                <h1 style="color:#ffffff;font-size:24px;margin:0">🛡 ShieldFlow</h1>
                <p style="color:#adb5bd;margin:8px 0 0;font-size:14px">Cybersécurité Managée pour PME</p>
              </div>
              <div style="background:#f8f9fa;padding:32px;border:1px solid #dee2e6;border-top:none">
                <h2 style="font-size:20px;margin:0 0 16px">Bonjour ${name},</h2>
                <p style="color:#495057;line-height:1.7;margin:0 0 20px">Votre compte ShieldFlow a été créé. Voici votre commande d'installation pour analyser la conformité RGPD de vos machines :</p>
                <div style="background:#212529;border-radius:8px;padding:16px;margin:20px 0">
                  <p style="color:#adb5bd;font-size:11px;margin:0 0 8px;text-transform:uppercase;letter-spacing:.06em">Commande d'installation</p>
                  <code style="color:#69db7c;font-size:13px;word-break:break-all">${installCmd}</code>
                </div>
                <p style="color:#495057;line-height:1.7;margin:20px 0">Collez cette commande dans votre Terminal (Mac/Linux) ou PowerShell (Windows). L'installation prend moins de 5 minutes.</p>
                <div style="background:#fff3cd;border:1px solid #ffc107;border-radius:6px;padding:16px;margin:20px 0">
                  <p style="color:#856404;margin:0;font-size:14px"><strong>⏱ Votre score RGPD apparaîtra dans les 30 secondes</strong> suivant l'installation. Notre équipe vous contactera avec votre rapport complet.</p>
                </div>
                <p style="color:#868e96;font-size:13px;margin:20px 0 0">Une question ? Répondez directement à cet email ou contactez-nous à <a href="mailto:shieldflowcontact@gmail.com" style="color:#1c7ed6">shieldflowcontact@gmail.com</a></p>
              </div>
              <div style="background:#dee2e6;padding:16px;border-radius:0 0 8px 8px;text-align:center">
                <p style="color:#868e96;font-size:12px;margin:0">ShieldFlow · Marseille, France · <a href="#" style="color:#868e96">Se désabonner</a></p>
              </div>
            </div>
          `
        })
      });
    }

    // Notifier ShieldFlow (toi)
    if (RESEND_API_KEY && ALERT_EMAIL) {
      await fetch('https://api.resend.com/emails', {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${RESEND_API_KEY}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({
          from: 'ShieldFlow <onboarding@resend.dev>',
          to: ALERT_EMAIL,
          subject: `🎯 Nouveau prospect : ${company || name} (${email})`,
          html: `
            <div style="font-family:Arial,sans-serif;color:#212529">
              <h2>Nouveau prospect inscrit</h2>
              <p><strong>Nom :</strong> ${name}</p>
              <p><strong>Email :</strong> ${email}</p>
              <p><strong>Entreprise :</strong> ${company || 'Non renseigné'}</p>
              <p><strong>Machines :</strong> ${machines || 'Non renseigné'}</p>
              <p><strong>Tenant ID :</strong> ${tenantId}</p>
              <p><strong>Agent Key :</strong> ${agentKey}</p>
              <hr>
              <p>Le prospect a reçu sa commande d'installation par email. Surveillez son score RGPD dans le dashboard.</p>
            </div>
          `
        })
      });
    }

    res.json({ success: true, message: 'Compte créé — email envoyé', tenant_id: tenantId });
  } catch(e) {
    console.error('[Signup]', e.message);
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

// Route explicite pour le dashboard
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, '../dashboard/index.html'));
});

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
