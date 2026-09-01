#!/usr/bin/env node
/**
 * TraceLens — local observability proxy
 * Captures latency, status, method, path, timestamp for every proxied request.
 * Storage: SQLite (node:sqlite if available) + JSONL fallback. No distributed tracing.
 */

import http from 'node:http';
import https from 'node:https';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '..');

// ---- config ----
const PROXY_PORT = parseInt(process.env.PORT || process.env.PROXY_PORT || '3888', 10);
const TARGET = process.env.TARGET || process.env.TARGET_URL || 'http://localhost:3000';
const targetUrl = new URL(TARGET);
const DATA_DIR = process.env.DATA_DIR || path.join(ROOT, 'data');
const JSONL_PATH = path.join(DATA_DIR, 'traces.jsonl');
const SQLITE_PATH = path.join(DATA_DIR, 'traces.db');
const MAX_TRACES = parseInt(process.env.MAX_TRACES || '5000', 10);

// ---- storage ----
fs.mkdirSync(DATA_DIR, { recursive: true });

let db = null;
let useSqlite = false;
try {
  const { DatabaseSync } = await import('node:sqlite');
  db = new DatabaseSync(SQLITE_PATH);
  db.exec(`
    CREATE TABLE IF NOT EXISTS traces (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      timestamp TEXT NOT NULL,
      method TEXT NOT NULL,
      path TEXT NOT NULL,
      status INTEGER,
      latency_ms REAL NOT NULL,
      target TEXT,
      request_headers TEXT,
      response_headers TEXT,
      error TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_traces_timestamp ON traces(timestamp);
  `);
  useSqlite = true;
  console.log(`[tracelens] sqlite: ${SQLITE_PATH}`);
} catch {
  console.log('[tracelens] node:sqlite unavailable — using JSONL only');
}

const memoryTraces = [];
let jsonlCount = 0;

// load existing jsonl into memory (tail)
try {
  if (fs.existsSync(JSONL_PATH)) {
    const lines = fs.readFileSync(JSONL_PATH, 'utf8').trim().split('\n').filter(Boolean);
    for (const line of lines.slice(-1000)) {
      try { memoryTraces.push(JSON.parse(line)); } catch {}
    }
    jsonlCount = lines.length;
  }
} catch {}

function persist(trace) {
  memoryTraces.push(trace);
  if (memoryTraces.length > MAX_TRACES) memoryTraces.splice(0, memoryTraces.length - MAX_TRACES);

  // jsonl append
  try {
    fs.appendFileSync(JSONL_PATH, JSON.stringify(trace) + '\n');
    jsonlCount++;
  } catch (e) {
    console.error('[tracelens] jsonl write failed', e.message);
  }

  // sqlite
  if (useSqlite && db) {
    try {
      const stmt = db.prepare(`INSERT INTO traces (timestamp, method, path, status, latency_ms, target, request_headers, response_headers, error) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`);
      stmt.run(trace.timestamp, trace.method, trace.path, trace.status, trace.latencyMs, trace.target, JSON.stringify(trace.requestHeaders || {}), JSON.stringify(trace.responseHeaders || {}), trace.error || null);
      // prune old rows
      const count = db.prepare('SELECT COUNT(*) as c FROM traces').get().c;
      if (count > MAX_TRACES) {
        db.prepare(`DELETE FROM traces WHERE id IN (SELECT id FROM traces ORDER BY id ASC LIMIT ?)`).run(count - MAX_TRACES);
      }
    } catch (e) {
      console.error('[tracelens] sqlite write failed', e.message);
    }
  }
}

function getTraces({ limit = 100, method, status } = {}) {
  let traces = memoryTraces;
  // prefer sqlite if available and memory is empty or stale — use memory as source of truth for speed
  if (method) traces = traces.filter(t => t.method === method.toUpperCase());
  if (status) traces = traces.filter(t => String(t.status) === String(status));
  return traces.slice(-limit).reverse();
}

// ---- proxy logic ----
function proxyRequest(clientReq, clientRes) {
  const start = performance.now();
  const timestamp = new Date().toISOString();

  // viewer / api routes — not proxied
  const url = new URL(clientReq.url, `http://${clientReq.headers.host}`);
  if (url.pathname.startsWith('/__tracelens')) {
    handleInternal(url, clientReq, clientRes);
    return;
  }

  const isTargetHttps = targetUrl.protocol === 'https:';
  const lib = isTargetHttps ? https : http;

  const proxyOpts = {
    hostname: targetUrl.hostname,
    port: targetUrl.port || (isTargetHttps ? 443 : 80),
    path: clientReq.url,
    method: clientReq.method,
    headers: { ...clientReq.headers, host: targetUrl.host, 'x-tracelens-proxy': '1' },
  };

  const proxyReq = lib.request(proxyOpts, (proxyRes) => {
    const latencyMs = Math.round((performance.now() - start) * 100) / 100;

    // capture trace
    const trace = {
      timestamp,
      method: clientReq.method,
      path: url.pathname + url.search,
      status: proxyRes.statusCode,
      latencyMs,
      target: TARGET,
      requestHeaders: clientReq.headers,
      responseHeaders: proxyRes.headers,
    };
    persist(trace);
    console.log(`[tracelens] ${trace.method} ${trace.path} → ${trace.status} ${latencyMs}ms`);

    clientRes.writeHead(proxyRes.statusCode, proxyRes.headers);
    proxyRes.pipe(clientRes);
  });

  proxyReq.on('error', (err) => {
    const latencyMs = Math.round((performance.now() - start) * 100) / 100;
    const trace = {
      timestamp,
      method: clientReq.method,
      path: url.pathname + url.search,
      status: 502,
      latencyMs,
      target: TARGET,
      error: err.message,
    };
    persist(trace);
    console.error(`[tracelens] proxy error ${clientReq.method} ${trace.path}: ${err.message}`);
    if (!clientRes.headersSent) {
      clientRes.writeHead(502, { 'content-type': 'application/json' });
      clientRes.end(JSON.stringify({ error: 'Bad Gateway', target: TARGET, detail: err.message, trace }));
    }
  });

  clientReq.pipe(proxyReq);
}

function handleInternal(url, req, res) {
  // CORS for viewer
  res.setHeader('Access-Control-Allow-Origin', '*');

  if (url.pathname === '/__tracelens/traces' || url.pathname === '/__tracelens/api/traces') {
    const limit = parseInt(url.searchParams.get('limit') || '100', 10);
    const method = url.searchParams.get('method');
    const status = url.searchParams.get('status');
    const traces = getTraces({ limit: Math.min(limit, 1000), method, status });
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ target: TARGET, count: traces.length, total: memoryTraces.length, traces }, null, 2));
    return;
  }

  if (url.pathname === '/__tracelens/stats') {
    const traces = memoryTraces;
    const avg = traces.length ? traces.reduce((a, t) => a + t.latencyMs, 0) / traces.length : 0;
    const p95 = (() => {
      if (!traces.length) return 0;
      const sorted = [...traces].map(t => t.latencyMs).sort((a,b)=>a-b);
      return sorted[Math.floor(sorted.length * 0.95)] || 0;
    })();
    const byStatus = {};
    for (const t of traces) { const k = String(t.status)[0] + 'xx'; byStatus[k] = (byStatus[k]||0)+1; }
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ count: traces.length, avgMs: Math.round(avg*100)/100, p95Ms: p95, byStatus, target: TARGET, storage: useSqlite ? 'sqlite+jsonl' : 'jsonl', jsonlPath: JSONL_PATH }, null, 2));
    return;
  }

  if (url.pathname === '/__tracelens/health') {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ ok: true, proxy: 'tracelens', target: TARGET, uptime: process.uptime() }));
    return;
  }

  // serve viewer
  const viewerFile = url.pathname === '/__tracelens' || url.pathname === '/__tracelens/' ? 'index.html' : url.pathname.replace('/__tracelens/', '');
  const safeFile = path.normalize(viewerFile).replace(/^(\.\.[\/\\])+/, '');
  const viewerPath = path.join(__dirname, 'viewer', safeFile);
  if (fs.existsSync(viewerPath) && fs.statSync(viewerPath).isFile()) {
    const ext = path.extname(viewerPath);
    const mime = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.json': 'application/json' }[ext] || 'text/plain';
    res.writeHead(200, { 'content-type': mime });
    fs.createReadStream(viewerPath).pipe(res);
    return;
  }

  // fallback: redirect to viewer
  if (url.pathname === '/__tracelens' || url.pathname === '/__tracelens/') {
    res.writeHead(200, { 'content-type': 'text/html' });
    res.end(fs.readFileSync(path.join(__dirname, 'viewer', 'index.html'), 'utf8'));
    return;
  }

  res.writeHead(404, { 'content-type': 'application/json' });
  res.end(JSON.stringify({ error: 'Not found', path: url.pathname }));
}

// ---- server ----
const server = http.createServer(proxyRequest);

server.listen(PROXY_PORT, () => {
  console.log(`
  TraceLens — local observability proxy
  ─────────────────────────────────────
  Proxy:   http://localhost:${PROXY_PORT}  →  ${TARGET}
  Viewer:  http://localhost:${PROXY_PORT}/__tracelens
  API:     http://localhost:${PROXY_PORT}/__tracelens/traces
  Stats:   http://localhost:${PROXY_PORT}/__tracelens/stats
  Health:  http://localhost:${PROXY_PORT}/__tracelens/health
  Storage: ${useSqlite ? `sqlite (${SQLITE_PATH}) + jsonl` : `jsonl (${JSONL_PATH})`}
  `);
});

process.on('SIGINT', () => { console.log('\n[tracelens] shutting down'); try { db?.close(); } catch {} server.close(() => process.exit(0)); });
process.on('SIGTERM', () => { try { db?.close(); } catch {} server.close(() => process.exit(0)); });
