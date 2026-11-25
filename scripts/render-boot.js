import fs from 'node:fs';
import path from 'node:path';
import http from 'node:http';
import os from 'node:os';
import { spawn, execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { DatabaseSync } from 'node:sqlite';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.resolve(__dirname, '..');
const dataDir = path.join(rootDir, 'data');

const SUPABASE_URL = (process.env.SUPABASE_URL || '').replace(/\/+$/, '');
const SUPABASE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_SECRET_KEY || '';
const BUCKET = process.env.SUPABASE_STATE_BUCKET || 'youpi-state';
const OBJECT_NAME = process.env.SUPABASE_STATE_OBJECT || 'youpi-data.tar.gz';
const SYNC_INTERVAL_MS = Number(process.env.STATE_SYNC_INTERVAL_MS || 120000);
const PORT = Number(process.env.PORT || 10000);

function hasSupabaseConfig() {
  return Boolean(SUPABASE_URL && SUPABASE_KEY);
}

async function ensureBucket() {
  if (!hasSupabaseConfig()) return;
  try {
    await fetch(`${SUPABASE_URL}/storage/v1/bucket`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${SUPABASE_KEY}`,
        apikey: SUPABASE_KEY,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ id: BUCKET, name: BUCKET, public: false })
    });
  } catch {}
}

async function restoreState() {
  if (!hasSupabaseConfig()) {
    console.log('[RenderBoot] SUPABASE_URL/SUPABASE_SERVICE_ROLE_KEY not set; skipping state restore.');
    return;
  }
  await ensureBucket();
  const url = `${SUPABASE_URL}/storage/v1/object/${BUCKET}/${OBJECT_NAME}`;
  try {
    const res = await fetch(url, {
      headers: { Authorization: `Bearer ${SUPABASE_KEY}`, apikey: SUPABASE_KEY },
      signal: AbortSignal.timeout(20000)
    });
    if (res.status === 404 || res.status === 400) {
      console.log('[RenderBoot] No remote backup yet; starting fresh.');
      return;
    }
    if (!res.ok) {
      console.warn(`[RenderBoot] Restore returned HTTP ${res.status}; continuing with local data.`);
      return;
    }
    const tmpArchive = path.join(os.tmpdir(), `restore-${Date.now()}.tar.gz`);
    fs.writeFileSync(tmpArchive, Buffer.from(await res.arrayBuffer()));
    fs.mkdirSync(dataDir, { recursive: true });
    execFileSync('tar', ['-xzf', tmpArchive, '-C', dataDir]);
    fs.rmSync(tmpArchive, { force: true });
    console.log('[RenderBoot] Restored YouPI data/ from Supabase Storage.');
  } catch (err) {
    console.warn('[RenderBoot] Restore failed:', err.message);
  }
}

let isBackingUp = false;
async function backupState() {
  if (!hasSupabaseConfig() || isBackingUp || !fs.existsSync(dataDir)) return;
  isBackingUp = true;
  const tmpArchive = path.join(os.tmpdir(), `backup-${Date.now()}.tar.gz`);
  try {
    // Flush SQLite WAL into main DB file so the archive is crash-consistent.
    const dbPath = path.join(dataDir, 'youpi_pg.sqlite');
    if (fs.existsSync(dbPath)) {
      try {
        const db = new DatabaseSync(dbPath);
        db.exec('PRAGMA wal_checkpoint(TRUNCATE);');
        db.close();
      } catch {}
    }
    execFileSync('tar', ['-czf', tmpArchive, '-C', dataDir, '.']);
    const buf = fs.readFileSync(tmpArchive);
    const url = `${SUPABASE_URL}/storage/v1/object/${BUCKET}/${OBJECT_NAME}`;
    const res = await fetch(url, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${SUPABASE_KEY}`,
        apikey: SUPABASE_KEY,
        'Content-Type': 'application/gzip',
        'x-upsert': 'true'
      },
      body: buf,
      signal: AbortSignal.timeout(25000)
    });
    if (!res.ok) {
      console.warn(`[RenderBoot] Backup upload failed: HTTP ${res.status}`);
    } else {
      console.log(`[RenderBoot] Backed up data/ (${buf.length} bytes) to Supabase Storage.`);
    }
  } catch (err) {
    console.warn('[RenderBoot] Backup error:', err.message);
  } finally {
    fs.rmSync(tmpArchive, { force: true });
    isBackingUp = false;
  }
}

// 1. Restore persisted state before starting YouPI
await restoreState();

// 2. Expose Render / UptimeRobot health endpoint on $PORT
const healthServer = http.createServer(async (req, res) => {
  if (req.url === '/' || req.url === '/health') {
    let apiStatus = 'STARTING';
    try {
      const r = await fetch(`http://127.0.0.1:${process.env.PAYMENT_API_PORT || 6100}/health`, {
        signal: AbortSignal.timeout(2000)
      });
      if (r.ok) apiStatus = 'UP';
    } catch {}
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ status: 'UP', service: 'youpi-render-host', paymentApi: apiStatus }));
    return;
  }
  res.writeHead(404);
  res.end('Not Found');
});
healthServer.listen(PORT, '0.0.0.0', () => {
  console.log(`[RenderBoot] Health endpoint listening on 0.0.0.0:${PORT} (for Render + UptimeRobot)`);
});

// 3. Launch YouPI Production Gateway + Cloudflare Tunnel
const child = spawn(process.execPath, [path.join(__dirname, 'start.js')], {
  cwd: rootDir,
  stdio: 'inherit',
  env: { ...process.env }
});

// shortcut: periodic archive sync every 2 min; a hard SIGKILL without SIGTERM can lose up to 2 min of SQLite writes.
const syncTimer = setInterval(() => {
  backupState().catch(() => {});
}, SYNC_INTERVAL_MS);
if (syncTimer.unref) syncTimer.unref();

async function shutdown(signal) {
  console.log(`[RenderBoot] Received ${signal}; flushing state to Supabase before exit...`);
  clearInterval(syncTimer);
  try { child.kill('SIGTERM'); } catch {}
  await new Promise(r => setTimeout(r, 1500));
  await backupState();
  healthServer.close(() => process.exit(0));
  setTimeout(() => process.exit(0), 5000).unref();
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));
child.on('exit', async (code) => {
  await backupState();
  process.exit(code ?? 1);
});
