/**
 * ShieldFlow Backend v1.1 — Stockage JSON pur
 * Compatible Node.js v18+ sans compilation native
 */

const express = require('express');
const cors    = require('cors');
const crypto  = require('crypto');
const fs      = require('fs');
const path    = require('path');

const app  = express();
const PORT = process.env.PORT || 3000;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'shieldflow2026';
const SECRET_KEY     = process.env.SECRET_KEY     || 'shieldflow-secret-key-change-in-prod';
const DB_FILE        = path.join(__dirname, 'db.json');

// ─── TENANTS (multi-clients) ──────────────────────────────────────────────
const TENANTS_FILE = path.join(__dirname, 'tenants.json');

function loadTenants() {
  if (!fs.existsSync(TENANTS_FILE)) return { tenants: {}, mssp_password: 'shieldflow-mssp-2026' };
  try { return JSON.parse(fs.readFileSync(TENANTS_FILE, 'utf8')); }
  catch(e) { return { tenants: {}, mssp_password: 'shieldflow-mssp-2026' }; }
}

function saveTenants(data) {
  fs.writeFileSync(TENANTS_FILE, JSON.stringify(data, null, 2));
}

function getTenantDB(tenantId) {
  const file = path.join(__dirname, `db_${tenantId}.json`);
  if (!fs.existsSync(file)) return { devices:{}, snapshots:{}, alerts:[], sessions:{}, alertIdSeq:1 };
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); }
  catch(e) { return { devices:{}, snapshots:{}, alerts:[], sessions:{}, alertIdSeq:1 }; }
}

function saveTenantDB(tenantId, db) {
  const file = path.join(__dirname, `db_${tenantId}.json`);
  fs.writeFileSync(file, JSON.stringify(db, null, 2));
}

app.use(cors());
app.use(express.json({ limit: '2mb' }));
app.use(express.static(path.join(__dirname, '../dashboard')));

function loadDB() {
  if (!fs.existsSync(DB_FILE)) return { devices:{}, snapshots:{}, alerts:[], sessions:{}, alertIdSeq:1 };
  try { return JSON.parse(fs.readFileSync(DB_FILE, 'utf8')); }
  catch(e) { return { devices:{}, snapshots:{}, alerts:[], sessions:{}, alertIdSeq:1 }; }
}
function saveDB(db) { fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2)); }

function requireAuth(req, res, next) {
  const auth = req.headers['authorization'];
  if (!auth || !auth.startsWith('Bearer ')) return res.status(401).json({ error: 'Non authentifié' });
  const token = auth.replace('Bearer ', '');
  const db = loadDB();
  const session = db.sessions[token];
  if (!session || new Date(session.expires_at) < new Date()) return res.status(401).json({ error: 'Session expirée' });
  next();
}

function requireAgentKey(req, res, next) {
  if (req.headers['x-agent-key'] !== SECRET_KEY) return res.status(403).json({ error: 'Clé agent invalide' });
  next();
}

function analyzeAndCreateAlerts(db, deviceId, deviceName, snap) {
  const now = new Date().toISOString();
  const candidates = [];

  // CPU
  if (snap.cpu_percent > 90)
    candidates.push({ type:'HIGH_CPU', severity:'high', title:'CPU anormalement élevé', description:`CPU à ${snap.cpu_percent.toFixed(1)}% sur ${deviceName}.`, recommendation:'Identifier les processus consommateurs via le Moniteur activite.' });

  // RAM
  if (snap.ram_percent > 95)
    candidates.push({ type:'HIGH_RAM', severity:'medium', title:'RAM saturée', description:`RAM à ${snap.ram_percent.toFixed(1)}% sur ${deviceName}.`, recommendation:'Fermer les applications inutiles ou augmenter la RAM.' });

  // Disque
  if (snap.disk_percent > 90)
    candidates.push({ type:'LOW_DISK', severity:'high', title:'Espace disque critique', description:`Disque à ${snap.disk_percent.toFixed(1)}% sur ${deviceName}.`, recommendation:'Liberer de espace disque immediatement.' });

  // Ports dangereux
  const ports = Array.isArray(snap.open_ports) ? snap.open_ports : [];
  const dangerPorts = ports.filter(p => [4444,1337,31337,6666,6667,23].includes(Number(p)));
  if (dangerPorts.length > 0)
    candidates.push({ type:'DANGER_PORTS', severity:'critical', title:`Port dangereux ouvert : ${dangerPorts.join(', ')}`, description:`Port(s) associé(s) à des outils d'attaque détectés sur ${deviceName}.`, recommendation:'Fermer ces ports via le pare-feu immédiatement.' });

  // Pare-feu
  if (snap.firewall_enabled === false || snap.firewall_status === 'disabled')
    candidates.push({ type:'FIREWALL_OFF', severity:'critical', title:'Pare-feu désactivé', description:`Le pare-feu est désactivé sur ${deviceName}. La machine est exposée sans protection réseau.`, recommendation:'Activer le pare-feu : Réglages Système → Réseau → Pare-feu → Activer.' });

  // Chiffrement disque
  if (snap.disk_encrypted === false)
    candidates.push({ type:'DISK_NOT_ENCRYPTED', severity:'high', title:'Disque non chiffré', description:`Le disque de ${deviceName} n'est pas chiffré. Non conforme RGPD Art. 32.`, recommendation:'Activer FileVault : Réglages Système → Confidentialité → FileVault.' });

  // Antivirus
  if (snap.antivirus_status === 'disabled' || snap.antivirus_enabled === false)
    candidates.push({ type:'NO_ANTIVIRUS', severity:'high', title:'Protection antivirus absente', description:`Aucun antivirus actif détecté sur ${deviceName}.`, recommendation:'Installer Malwarebytes ou activer XProtect.' });

  // Mises à jour
  if (snap.pending_updates > 20)
    candidates.push({ type:'UPDATES_CRITICAL', severity:'high', title:`${snap.pending_updates} mises à jour en attente`, description:`${snap.pending_updates} paquets non mis à jour sur ${deviceName}. Risque de vulnérabilités critiques.`, recommendation:'Appliquer les mises à jour système immédiatement.' });
  else if (snap.pending_updates > 5)
    candidates.push({ type:'UPDATES_PENDING', severity:'medium', title:`${snap.pending_updates} mises à jour disponibles`, description:`${snap.pending_updates} mises à jour disponibles sur ${deviceName}.`, recommendation:'Planifier une mise à jour dans les 7 jours.' });

  // Processus suspects (malwares connus)
  const malwarePatterns = [/lockbit/i, /wannacry/i, /mimikatz/i, /xmrig/i, /meterpreter/i, /njrat/i, /cryptolocker/i];
  const processes = Array.isArray(snap.processes) ? snap.processes : [];
  for (const proc of processes) {
    const name = (proc.name || proc.cmd || '').toLowerCase();
    for (const pattern of malwarePatterns) {
      if (pattern.test(name)) {
        candidates.push({ type:'MALWARE_DETECTED', severity:'critical', title:`Malware détecté : ${proc.name}`, description:`Processus malveillant "${proc.name}" (PID: ${proc.pid}) détecté sur ${deviceName}.`, recommendation:`Terminer immédiatement PID ${proc.pid} et isoler la machine.` });
      }
    }
  }

  // Logs : brute force
  const logs = Array.isArray(snap.logs) ? snap.logs : [];
  const failedLogins = logs.filter(l => /failed password|authentication failure/i.test(l.line || l.message || '')).length;
  if (failedLogins > 10)
    candidates.push({ type:'BRUTE_FORCE', severity: failedLogins > 50 ? 'critical' : 'high', title:`Tentatives de connexion échouées : ${failedLogins}`, description:`${failedLogins} échecs de connexion détectés sur ${deviceName}. Possible attaque brute force.`, recommendation:'Vérifier les IPs sources et activer fail2ban ou MFA.' });

  // Ajouter les nouvelles alertes
  for (const c of candidates) {
    const exists = db.alerts.some(a => a.device_id === deviceId && a.type === c.type && !a.resolved);
    if (!exists) db.alerts.push({
      id: db.alertIdSeq++,
      device_id: deviceId,
      device_name: deviceName,
      type: c.type,
      severity: c.severity,
      title: c.title,
      description: c.description,
      recommendation: c.recommendation || '',
      resolved: false,
      created_at: now
    });
  }
}


app.post('/api/auth/login', (req, res) => {
  if (!req.body.password || req.body.password !== ADMIN_PASSWORD) return res.status(401).json({ error: 'Mot de passe incorrect' });
  const token = crypto.randomBytes(32).toString('hex');
  const expires = new Date(Date.now()+24*3600*1000).toISOString();
  const db = loadDB();
  db.sessions[token] = { created_at: new Date().toISOString(), expires_at: expires };
  saveDB(db);
  res.json({ token, expires_at: expires });
});
app.get('/api/auth/me', requireAuth, (req, res) => { res.json({ status: 'ok' }); });
app.post('/api/auth/logout', requireAuth, (req, res) => {
  const token = req.headers['authorization'].replace('Bearer ','');
  const db = loadDB(); delete db.sessions[token]; saveDB(db);
  res.json({ success:true });
});

// Agent
app.post('/api/agent/register', requireAgentKey, (req, res) => {
  const { hostname, platform, name, agent_version } = req.body;
  if (!hostname || !platform) return res.status(400).json({ error: 'hostname et platform requis' });
  const id  = crypto.createHash('md5').update(hostname+platform).digest('hex');
  const now = new Date().toISOString();
  const db  = loadDB();
  if (db.devices[id]) {
    Object.assign(db.devices[id], { last_seen:now, name:name||hostname, agent_version:agent_version||'1.0', status:'online' });
  } else {
    db.devices[id] = { id, name:name||hostname, hostname, platform, agent_version:agent_version||'1.0', first_seen:now, last_seen:now, status:'online', ip_local:null };
    db.snapshots[id] = [];
  }
  saveDB(db);
  res.json({ device_id:id, message:'Appareil enregistré' });
});

app.post('/api/agent/heartbeat', requireAgentKey, (req, res) => {
  const { device_id, ip_local, ...snap } = req.body;
  if (!device_id) return res.status(400).json({ error: 'device_id requis' });
  const db = loadDB();
  if (!db.devices[device_id]) return res.status(404).json({ error: 'Appareil non enregistré' });
  const now = new Date().toISOString();
  Object.assign(db.devices[device_id], { last_seen:now, ip_local:ip_local||db.devices[device_id].ip_local, status:'online' });
  if (!db.snapshots[device_id]) db.snapshots[device_id] = [];
  db.snapshots[device_id].unshift({ ...snap, timestamp:now });
  if (db.snapshots[device_id].length > 100) db.snapshots[device_id] = db.snapshots[device_id].slice(0,100);
  analyzeAndCreateAlerts(db, device_id, db.devices[device_id].name, snap);
  saveDB(db);
  res.json({ success:true, timestamp:now });
});

// Dashboard
app.get('/api/health', (req, res) => res.json({ status:'ok', version:'1.1.0', timestamp:new Date().toISOString() }));

app.get('/api/dashboard', requireAuth, (req, res) => {
  const db = loadDB();
  const fiveMin = new Date(Date.now()-5*60*1000).toISOString();
  for (const id in db.devices) if (db.devices[id].last_seen < fiveMin) db.devices[id].status='offline';
  saveDB(db);
  const devices = Object.values(db.devices);
  const activeAlerts = db.alerts.filter(a=>!a.resolved);
  const today = new Date(); today.setHours(0,0,0,0);
  const resolvedToday = db.alerts.filter(a=>a.resolved&&new Date(a.resolved_at)>=today).length;
  const critCount = activeAlerts.filter(a=>a.severity==='critical').length;
  const highCount = activeAlerts.filter(a=>a.severity==='high').length;
  const score = Math.max(0, 100 - critCount*20 - highCount*10 - activeAlerts.length*2);
  res.json({
    devices: { total:devices.length, online:devices.filter(d=>d.status==='online').length, offline:devices.filter(d=>d.status!=='online').length },
    alerts:  { total:activeAlerts.length, critical:critCount, high:highCount, resolved_today:resolvedToday },
    score, recent_alerts:activeAlerts.slice(-10).reverse(), last_updated:new Date().toISOString()
  });
});

app.get('/api/devices', requireAuth, (req, res) => {
  const db = loadDB();
  const result = Object.values(db.devices).map(dev => ({
    ...dev, latest_snapshot:(db.snapshots[dev.id]||[])[0]||null,
    active_alerts: db.alerts.filter(a=>a.device_id===dev.id&&!a.resolved).length
  }));
  res.json(result.sort((a,b)=>b.last_seen.localeCompare(a.last_seen)));
});

app.get('/api/devices/:id', requireAuth, (req, res) => {
  const db = loadDB();
  const dev = db.devices[req.params.id];
  if (!dev) return res.status(404).json({ error:'Appareil non trouvé' });
  res.json({ ...dev, snapshots:(db.snapshots[req.params.id]||[]).slice(0,48), alerts:db.alerts.filter(a=>a.device_id===req.params.id).slice(-20).reverse() });
});

app.get('/api/alerts', requireAuth, (req, res) => {
  const db = loadDB();
  const resolved = req.query.resolved==='true';
  res.json(db.alerts.filter(a=>a.resolved===resolved).slice(-100).reverse());
});

app.post('/api/alerts/:id/resolve', requireAuth, (req, res) => {
  const db = loadDB();
  const alert = db.alerts.find(a=>a.id===Number(req.params.id));
  if (!alert) return res.status(404).json({ error:'Alerte non trouvée' });
  alert.resolved=true; alert.resolved_at=new Date().toISOString();
  saveDB(db);
  res.json({ success:true });
});

// ─── MSSP ROUTES ─────────────────────────────────────────────────────────────

// Login MSSP (vue globale)
app.post('/api/mssp/login', (req, res) => {
  const { password } = req.body;
  const t = loadTenants();
  if (password !== t.mssp_password) return res.status(401).json({ error: 'Mot de passe MSSP incorrect' });
  const token = require('crypto').randomBytes(32).toString('hex');
  const expires = new Date(Date.now() + 24*60*60*1000).toISOString();
  t.mssp_sessions = t.mssp_sessions || {};
  t.mssp_sessions[token] = { expires_at: expires };
  saveTenants(t);
  res.json({ token, expires_at: expires, role: 'mssp' });
});

// Créer un client
app.post('/api/mssp/tenants', (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !password) return res.status(400).json({ error: 'name et password requis' });
  const t = loadTenants();
  const id = 'tenant_' + Date.now();
  const agentKey = require('crypto').randomBytes(16).toString('hex');
  t.tenants[id] = { id, name, email: email||'', password, agent_key: agentKey, created_at: new Date().toISOString() };
  saveTenants(t);
  res.json({ tenant_id: id, agent_key: agentKey, message: 'Client créé' });
});

// Lister tous les clients (vue MSSP)
app.get('/api/mssp/tenants', (req, res) => {
  const t = loadTenants();
  const result = [];
  for (const [id, tenant] of Object.entries(t.tenants)) {
    const db = getTenantDB(id);
    const devices = Object.values(db.devices);
    const alerts = db.alerts.filter(a => !a.resolved);
    const criticals = alerts.filter(a => a.severity === 'critical');
    const score = Math.max(0, 100 - criticals.length*20 - alerts.length*5);
    result.push({
      id, name: tenant.name, email: tenant.email,
      device_count: devices.length,
      alert_count: alerts.length,
      critical_count: criticals.length,
      score,
      agent_key: tenant.agent_key,
      created_at: tenant.created_at
    });
  }
  res.json({ count: result.length, tenants: result });
});

// Dashboard d'un client spécifique
app.get('/api/mssp/tenants/:id/dashboard', (req, res) => {
  const t = loadTenants();
  const tenant = t.tenants[req.params.id];
  if (!tenant) return res.status(404).json({ error: 'Client non trouvé' });
  const db = getTenantDB(req.params.id);
  const devices = Object.values(db.devices);
  const alerts = db.alerts.filter(a => !a.resolved);
  res.json({ tenant: { id: req.params.id, name: tenant.name }, devices, alerts });
});

// Login client (avec tenant_id)
app.post('/api/tenant/login', (req, res) => {
  const { tenant_id, password } = req.body;
  const t = loadTenants();
  const tenant = t.tenants[tenant_id];
  if (!tenant || tenant.password !== password) return res.status(401).json({ error: 'Identifiants incorrects' });
  const token = require('crypto').randomBytes(32).toString('hex');
  const expires = new Date(Date.now() + 24*60*60*1000).toISOString();
  const db = getTenantDB(tenant_id);
  db.sessions = db.sessions || {};
  db.sessions[token] = { expires_at: expires, tenant_id };
  saveTenantDB(tenant_id, db);
  res.json({ token, tenant_id, tenant_name: tenant.name, expires_at: expires });
});

// Agent register avec tenant
app.post('/api/agent/:tenantId/register', (req, res) => {
  const { hostname, platform, name, agent_version } = req.body;
  const tenantId = req.params.tenantId;
  const t = loadTenants();
  const tenant = t.tenants[tenantId];
  if (!tenant) return res.status(404).json({ error: 'Tenant non trouvé' });
  const agentKey = req.headers['x-agent-key'];
  if (agentKey !== tenant.agent_key) return res.status(403).json({ error: 'Clé agent invalide' });
  const id = require('crypto').createHash('md5').update(hostname+platform).digest('hex');
  const now = new Date().toISOString();
  const db = getTenantDB(tenantId);
  if (!db.devices[id]) db.devices[id] = { id, name: name||hostname, hostname, platform, agent_version, created_at: now };
  db.devices[id].last_seen = now;
  db.snapshots = db.snapshots || {};
  saveTenantDB(tenantId, db);
  res.json({ device_id: id, message: 'Appareil enregistré' });
});

// Agent heartbeat avec tenant
app.post('/api/agent/:tenantId/heartbeat', (req, res) => {
  const tenantId = req.params.tenantId;
  const t = loadTenants();
  const tenant = t.tenants[tenantId];
  if (!tenant) return res.status(404).json({ error: 'Tenant non trouvé' });
  const agentKey = req.headers['x-agent-key'];
  if (agentKey !== tenant.agent_key) return res.status(403).json({ error: 'Clé agent invalide' });
  const { device_id, ...snap } = req.body;
  if (!device_id) return res.status(400).json({ error: 'device_id requis' });
  const db = getTenantDB(tenantId);
  if (!db.devices[device_id]) return res.status(404).json({ error: 'Appareil non enregistré' });
  const now = new Date().toISOString();
  db.devices[device_id].last_seen = now;
  db.devices[device_id].status = 'online';
  db.snapshots = db.snapshots || {};
  if (!db.snapshots[device_id]) db.snapshots[device_id] = [];
  db.snapshots[device_id].unshift({ ...snap, timestamp: now });
  if (db.snapshots[device_id].length > 100) db.snapshots[device_id] = db.snapshots[device_id].slice(0, 100);
  analyzeAndCreateAlerts(db, device_id, db.devices[device_id].name, snap);
  saveTenantDB(tenantId, db);
  res.json({ success: true, timestamp: now });
});

app.listen(PORT, () => {
  console.log(`
╔══════════════════════════════════════╗
║      ShieldFlow Backend v1.1         ║
║      Port : ${PORT}                     ║
║      Stockage : db.json              ║
╚══════════════════════════════════════╝

  Mot de passe admin : ${ADMIN_PASSWORD}
  Clé agent          : ${SECRET_KEY}

  Dashboard : http://localhost:${PORT}
  `);
});
