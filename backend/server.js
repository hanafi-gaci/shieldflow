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

  if (snap.cpu_percent > 90)
    candidates.push({ type:'HIGH_CPU', severity:'high', title:'CPU anormalement élevé', description:`CPU à ${snap.cpu_percent.toFixed(1)}% sur ${deviceName}.` });

  if (snap.ram_percent > 95)
    candidates.push({ type:'HIGH_RAM', severity:'medium', title:'RAM saturée', description:`RAM à ${snap.ram_percent.toFixed(1)}% sur ${deviceName}.` });

  if (snap.disk_percent > 90)
    candidates.push({ type:'LOW_DISK', severity:'high', title:'Espace disque critique', description:`Disque à ${snap.disk_percent.toFixed(1)}% sur ${deviceName}.` });

  const ports = Array.isArray(snap.open_ports) ? snap.open_ports : [];
  const dangerPorts = ports.filter(p => [22,23,3389,5900].includes(Number(p)));
  if (dangerPorts.length > 0) {
    const names = {22:'SSH',23:'Telnet',3389:'RDP',5900:'VNC'};
    candidates.push({ type:'OPEN_PORTS', severity: dangerPorts.includes(23)?'critical':'medium',
      title:`Port(s) sensible(s) ouvert(s) : ${dangerPorts.join(', ')}`,
      description:`Ports sur ${deviceName} : ${dangerPorts.map(p=>`${p} (${names[p]||'?'})`).join(', ')}.` });
  }

  if (snap.network_connections > 200)
    candidates.push({ type:'HIGH_CONNECTIONS', severity:'medium', title:'Connexions réseau élevées', description:`${snap.network_connections} connexions actives sur ${deviceName}.` });

  for (const c of candidates) {
    const exists = db.alerts.some(a => a.device_id===deviceId && a.type===c.type && !a.resolved);
    if (!exists) db.alerts.push({ id: db.alertIdSeq++, device_id:deviceId, device_name:deviceName, ...c, created_at:now, resolved:false, resolved_at:null });
  }
}

// Auth
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
