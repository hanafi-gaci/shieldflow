'use strict';

/**
 * ShieldFlow — Analysis Routes
 * POST /api/agent/report  — receives data from Python agent, runs analysis
 * GET  /api/alerts        — returns all alerts for a device or tenant
 * GET  /api/compliance    — returns compliance report
 */

const express  = require('express');
const router   = express.Router();
const { analyzePayload, buildComplianceReport } = require('../modules/analyzer');

// In-memory store (replace with DB in Phase 2)
const reportStore = new Map(); // key: deviceId → latest analysis result

// ─── POST /api/agent/report ───────────────────────────────────────────────
// Called by the Python agent every N seconds with raw system metrics
router.post('/agent/report', (req, res) => {
  try {
    const payload = req.body;

    if (!payload || typeof payload !== 'object') {
      return res.status(400).json({ error: 'Invalid payload' });
    }

    const deviceId = payload.device_id || payload.hostname || 'unknown';
    const result   = analyzePayload(payload);
    const compliance = buildComplianceReport(result.alerts);

    const enriched = {
      device_id:   deviceId,
      hostname:    payload.hostname || deviceId,
      platform:    payload.platform || 'unknown',
      analyzed_at: new Date().toISOString(),
      score:       result.score,
      alerts:      result.alerts,
      summary:     result.summary,
      compliance,
      raw_payload: payload,  // keep for forensics
    };

    reportStore.set(deviceId, enriched);

    // Log critical alerts to console (will go to Render logs)
    const criticals = result.alerts.filter(a => a.severity === 'CRITICAL');
    if (criticals.length > 0) {
      console.warn(`[CRITICAL] Device ${deviceId} has ${criticals.length} critical alert(s):`,
        criticals.map(a => a.title).join(', '));
    }

    console.log(`[Analyzer] ${deviceId} — score: ${result.score}/100, alerts: ${result.alerts.length}`);

    res.json({
      status:     'analyzed',
      device_id:  deviceId,
      score:      result.score,
      alert_count: result.alerts.length,
      critical_count: criticals.length,
      analyzed_at: enriched.analyzed_at,
    });

  } catch (err) {
    console.error('[/api/agent/report] Error:', err);
    res.status(500).json({ error: 'Analysis failed', details: err.message });
  }
});

// ─── GET /api/alerts ──────────────────────────────────────────────────────
router.get('/alerts', (req, res) => {
  const { device_id, severity, category } = req.query;
  let alerts = [];

  if (device_id) {
    const report = reportStore.get(device_id);
    alerts = report ? report.alerts : [];
  } else {
    // All devices
    for (const report of reportStore.values()) {
      alerts.push(...report.alerts.map(a => ({
        ...a,
        device_id: report.device_id,
        hostname:  report.hostname,
      })));
    }
  }

  // Filters
  if (severity)  alerts = alerts.filter(a => a.severity  === severity.toUpperCase());
  if (category)  alerts = alerts.filter(a => a.category  === category.toUpperCase());

  // Sort by severity weight
  const severityOrder = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
  alerts.sort((a, b) => (severityOrder[a.severity] || 9) - (severityOrder[b.severity] || 9));

  res.json({ count: alerts.length, alerts });
});

// ─── GET /api/compliance ──────────────────────────────────────────────────
router.get('/compliance', (req, res) => {
  const { device_id } = req.query;
  const results = [];

  const reports = device_id
    ? [reportStore.get(device_id)].filter(Boolean)
    : Array.from(reportStore.values());

  for (const report of reports) {
    results.push({
      device_id:  report.device_id,
      hostname:   report.hostname,
      score:      report.score,
      compliance: report.compliance,
      analyzed_at: report.analyzed_at,
    });
  }

  res.json({ count: results.length, results });
});

// ─── GET /api/devices ─────────────────────────────────────────────────────
router.get('/devices', (req, res) => {
  const devices = Array.from(reportStore.values()).map(r => ({
    device_id:    r.device_id,
    hostname:     r.hostname,
    platform:     r.platform,
    score:        r.score,
    alert_count:  r.alerts.length,
    critical_count: r.alerts.filter(a => a.severity === 'CRITICAL').length,
    analyzed_at:  r.analyzed_at,
    status:       getDeviceStatus(r),
  }));

  res.json({ count: devices.length, devices });
});

// ─── GET /api/dashboard/overview ──────────────────────────────────────────
router.get('/dashboard/overview', (req, res) => {
  const reports = Array.from(reportStore.values());
  let totalAlerts = 0;
  let totalCritical = 0;
  let avgScore = 0;

  for (const r of reports) {
    totalAlerts   += r.alerts.length;
    totalCritical += r.alerts.filter(a => a.severity === 'CRITICAL').length;
    avgScore      += r.score;
  }

  if (reports.length > 0) avgScore = Math.round(avgScore / reports.length);

  const topThreats = [];
  for (const r of reports) {
    topThreats.push(...r.alerts
      .filter(a => a.severity === 'CRITICAL' || a.severity === 'HIGH')
      .map(a => ({ ...a, device_id: r.device_id, hostname: r.hostname })));
  }
  topThreats.sort((a, b) => {
    const w = { CRITICAL: 0, HIGH: 1 };
    return (w[a.severity] || 9) - (w[b.severity] || 9);
  });

  res.json({
    device_count:    reports.length,
    total_alerts:    totalAlerts,
    critical_alerts: totalCritical,
    average_score:   avgScore,
    top_threats:     topThreats.slice(0, 10),
    last_updated:    new Date().toISOString(),
  });
});

function getDeviceStatus(report) {
  const minutesSince = (Date.now() - new Date(report.analyzed_at).getTime()) / 60000;
  if (minutesSince > 10) return 'offline';
  if (report.alerts.some(a => a.severity === 'CRITICAL')) return 'critical';
  if (report.alerts.some(a => a.severity === 'HIGH'))     return 'warning';
  return 'healthy';
}

module.exports = router;
