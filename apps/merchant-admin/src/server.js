import http from 'node:http';
import https from 'node:https';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { getDatabase, MerchantRepository, SupportTicketRepository } from '@youpi/db';
import { getAdminToken, safeEqual } from '@youpi/common';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

/** Security headers applied to every response served by the merchant admin. */
const BASE_SECURITY_HEADERS = Object.freeze({
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'SAMEORIGIN',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
  'Content-Security-Policy': "default-src 'self'; img-src 'self' data: https:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; frame-ancestors 'self'; base-uri 'none'; form-action 'self'; object-src 'none'"
});

const SESSION_COOKIE = 'youpi_admin_session';
const SESSION_TTL_MS = 24 * 60 * 60 * 1000;
const LOGIN_WINDOW_MS = 15 * 60 * 1000;
const LOGIN_MAX_FAILURES = 5;
const CRED_FILE_PATH = path.resolve(process.cwd(), 'data', '.secrets', 'admin_password.json');
const loginFailures = new Map();

export function hashAdminPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const derived = crypto.scryptSync(String(password), salt, 64).toString('hex');
  return `${salt}:${derived}`;
}

export function verifyAdminPassword(password, storedHash) {
  try {
    const [salt, expectedHex] = String(storedHash || '').split(':');
    if (!salt || !expectedHex) return false;
    const expected = Buffer.from(expectedHex, 'hex');
    const derived = crypto.scryptSync(String(password), salt, 64);
    if (expected.length !== derived.length) return false;
    return crypto.timingSafeEqual(expected, derived);
  } catch {
    return false;
  }
}

let cachedFallbackHash = null;
let cachedManagerHash = null;
function loadAdminCredentials() {
  const envUser = (process.env.ADMIN_USERNAME || 'dappersfit').trim().toLowerCase();
  if (process.env.ADMIN_PASSWORD_HASH && process.env.ADMIN_PASSWORD_HASH.includes(':')) {
    return { username: envUser, passwordHash: process.env.ADMIN_PASSWORD_HASH.trim() };
  }
  try {
    if (fs.existsSync(CRED_FILE_PATH)) {
      const parsed = JSON.parse(fs.readFileSync(CRED_FILE_PATH, 'utf8'));
      if (parsed && parsed.username && parsed.passwordHash) {
        return { username: String(parsed.username).trim().toLowerCase(), passwordHash: String(parsed.passwordHash) };
      }
    }
  } catch {}
  if (!cachedFallbackHash) {
    cachedFallbackHash = hashAdminPassword(process.env.ADMIN_PASSWORD || 'Dappersfit@2026!');
  }
  return { username: envUser, passwordHash: cachedFallbackHash };
}

function loadManagerCredentials() {
  const managerUser = (process.env.MANAGER_USERNAME || 'dappersfit@gmail.com').trim().toLowerCase();
  if (process.env.MANAGER_PASSWORD_HASH && process.env.MANAGER_PASSWORD_HASH.includes(':')) {
    return { username: managerUser, passwordHash: process.env.MANAGER_PASSWORD_HASH.trim() };
  }
  if (!cachedManagerHash) {
    cachedManagerHash = hashAdminPassword(process.env.MANAGER_PASSWORD || 'Jail@1974');
  }
  return { username: managerUser, passwordHash: cachedManagerHash };
}

const MANAGER_ALLOWED_GET_PATHS = new Set([
  '/api/v1/admin/payments',
  '/api/v1/admin/queue',
  '/api/v1/admin/stream',
  '/api/v1/admin/counter-pending',
  '/api/v1/admin/cod-orders',
  '/api/v1/admin/merchants'
]);

function isManagerAllowedApiRequest(method, pathname) {
  return String(method || '').toUpperCase() === 'GET' && MANAGER_ALLOWED_GET_PATHS.has(pathname);
}

function saveAdminCredentials(username, passwordHash) {
  cachedFallbackHash = passwordHash;
  fs.mkdirSync(path.dirname(CRED_FILE_PATH), { recursive: true });
  fs.writeFileSync(CRED_FILE_PATH, JSON.stringify({ username, passwordHash, updatedAt: new Date().toISOString() }, null, 2), { mode: 0o600 });
}

function parseCookies(req) {
  const out = {};
  const header = String(req.headers?.cookie || '');
  for (const part of header.split(';')) {
    const idx = part.indexOf('=');
    if (idx > 0) {
      out[part.slice(0, idx).trim()] = decodeURIComponent(part.slice(idx + 1).trim());
    }
  }
  return out;
}

function createAdminSessionToken(username, role = 'admin') {
  const payload = Buffer.from(JSON.stringify({ u: username, role, exp: Date.now() + SESSION_TTL_MS })).toString('base64url');
  const sig = crypto.createHmac('sha256', getAdminToken()).update(payload).digest('base64url');
  return `${payload}.${sig}`;
}

function verifyAdminSessionCookie(req) {
  try {
    const raw = parseCookies(req)[SESSION_COOKIE];
    if (!raw || !raw.includes('.')) return null;
    const [payload, sig] = raw.split('.');
    if (!payload || !sig) return null;
    const expected = crypto.createHmac('sha256', getAdminToken()).update(payload).digest('base64url');
    if (!safeEqual(sig, expected)) return null;
    const data = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
    if (!data || !data.u || !data.exp || Date.now() > data.exp) return null;
    const role = data.role === 'manager' ? 'manager' : 'admin';
    return { username: String(data.u), role };
  } catch {
    return null;
  }
}

function getClientIp(req) {
  const fwd = String(req.headers['x-forwarded-for'] || '').split(',')[0].trim();
  return fwd || req.socket?.remoteAddress || 'unknown';
}

function isRateLimited(ip) {
  const now = Date.now();
  const list = (loginFailures.get(ip) || []).filter(ts => now - ts < LOGIN_WINDOW_MS);
  loginFailures.set(ip, list);
  return list.length >= LOGIN_MAX_FAILURES;
}

function recordLoginFailure(ip) {
  const now = Date.now();
  const list = (loginFailures.get(ip) || []).filter(ts => now - ts < LOGIN_WINDOW_MS);
  list.push(now);
  loginFailures.set(ip, list);
}

function readJsonBody(req, maxBytes = 8192) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', chunk => {
      size += chunk.length;
      if (size > maxBytes) {
        reject(new Error('Payload too large'));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}'));
      } catch {
        resolve({});
      }
    });
    req.on('error', reject);
  });
}

function isHttpsRequest(req) {
  return req.socket?.encrypted || String(req.headers['x-forwarded-proto'] || '').toLowerCase().includes('https');
}

/** True when the caller presented the admin bearer token OR a valid full-admin HttpOnly session cookie. */
function hasAdminToken(req, url = null, pathname = '') {
  const auth = String(req.headers?.['authorization'] || '').trim();
  if (auth.toLowerCase().startsWith('bearer ')) {
    const token = auth.slice(7).trim();
    if (token && safeEqual(token, getAdminToken())) return true;
  }
  const session = verifyAdminSessionCookie(req);
  return Boolean(session && session.role === 'admin');
}

/**
 * Strips headers a browser must not be able to spoof when relaying to an internal service.
 */
function sanitizedForwardHeaders(req, targetHost) {
  const headers = { ...req.headers, host: targetHost };
  for (const name of Object.keys(headers)) {
    const lower = name.toLowerCase();
    if (lower === 'x-internal-render' || lower === 'x-internal-token') {
      delete headers[name];
    }
  }
  return headers;
}

// In production, reliably ensure environment variables from .env are loaded if not already provided
if (!process.env.BASE_PAYMENT_API_URL && typeof process.loadEnvFile === 'function') {
  try {
    const rootEnv = path.resolve(__dirname, '../../../.env');
    if (fs.existsSync(rootEnv)) {
      process.loadEnvFile(rootEnv);
    }
  } catch {}
}

export class AdminServer {
  /**
   * @param {{
   *   db?: import('@youpi/db').Database,
   *   apiBaseUrl?: string
   * }} options
   */
  constructor(options = {}) {
    this.db = options.db || getDatabase();
    this.apiBaseUrl = options.apiBaseUrl || process.env.PAYMENT_API_URL || process.env.BASE_PAYMENT_API_URL || 'http://localhost:6100';
    this.merchantRepo = new MerchantRepository(this.db);
    this.ticketRepo = new SupportTicketRepository(this.db);
    this.htmlTemplatePath = path.join(__dirname, 'views', 'admin.html');
    this.template = fs.readFileSync(this.htmlTemplatePath, 'utf8');
  }

  renderHtml() {
    try {
      this.template = fs.readFileSync(this.htmlTemplatePath, 'utf8');
    } catch {}

    const appName = (process.env.DEFAULT_APP_NAME || '').trim() || 'YOUPI PG';
    const primaryColor = (process.env.DEFAULT_PRIMARY_COLOR || '').trim() || '#2563eb';

    let html = this.template;
    // Always use empty string '' so client fetch calls hit the merchant admin's own /api proxy!
    // This completely eliminates CORS errors, tunnel downtime 530s, and cross-origin failures.
    const clientApiBase = '';
    html = html.replaceAll('{{API_BASE_URL}}', clientApiBase);
    html = html.replaceAll('{{APP_NAME}}', appName);
    html = html.replaceAll('{{DEFAULT_PRIMARY_COLOR}}', primaryColor);
    return html;
  }

  createServer() {
    return http.createServer(async (req, res) => {
      const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
      const pathname = url.pathname;

      if (req.method === 'OPTIONS') {
        res.writeHead(204, {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
          'Access-Control-Allow-Headers': 'Content-Type, Authorization'
        });
        res.end();
        return;
      }

      // Health
      if (pathname === '/health') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ status: 'UP', service: 'merchant-admin' }));
        return;
      }

      // Encrypted Password Session Auth: /api/auth/me, /api/auth/login, /api/auth/logout, /api/auth/change-password
      if (pathname === '/api/auth/me' && req.method === 'GET') {
        const session = verifyAdminSessionCookie(req);
        res.writeHead(200, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', ...BASE_SECURITY_HEADERS });
        res.end(JSON.stringify(session ? { authenticated: true, username: session.username, role: session.role } : { authenticated: false }));
        return;
      }

      if (pathname === '/api/auth/login' && req.method === 'POST') {
        const ip = getClientIp(req);
        if (isRateLimited(ip)) {
          res.writeHead(429, { 'Content-Type': 'application/json', 'Retry-After': '900', ...BASE_SECURITY_HEADERS });
          res.end(JSON.stringify({ error: 'Too many failed attempts. Please wait 15 minutes.' }));
          return;
        }
        const body = await readJsonBody(req).catch(() => ({}));
        const username = String(body.username || '').trim().toLowerCase();
        const password = String(body.password || '');
        const adminCreds = loadAdminCredentials();
        const managerCreds = loadManagerCredentials();

        let matchedRole = null;
        let matchedUser = null;
        if (safeEqual(username, adminCreds.username) && verifyAdminPassword(password, adminCreds.passwordHash)) {
          matchedRole = 'admin';
          matchedUser = adminCreds.username;
        } else if (safeEqual(username, managerCreds.username) && verifyAdminPassword(password, managerCreds.passwordHash)) {
          matchedRole = 'manager';
          matchedUser = managerCreds.username;
        }

        if (!matchedRole) {
          recordLoginFailure(ip);
          res.writeHead(401, { 'Content-Type': 'application/json', ...BASE_SECURITY_HEADERS });
          res.end(JSON.stringify({ error: 'Invalid username or password.' }));
          return;
        }
        loginFailures.delete(ip);
        const sessionVal = createAdminSessionToken(matchedUser, matchedRole);
        const secureFlag = isHttpsRequest(req) ? '; Secure' : '';
        res.writeHead(200, {
          'Content-Type': 'application/json',
          'Cache-Control': 'no-store',
          'Set-Cookie': `${SESSION_COOKIE}=${encodeURIComponent(sessionVal)}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${Math.floor(SESSION_TTL_MS / 1000)}${secureFlag}`,
          ...BASE_SECURITY_HEADERS
        });
        res.end(JSON.stringify({ ok: true, username: matchedUser, role: matchedRole }));
        return;
      }

      if (pathname === '/api/auth/logout' && req.method === 'POST') {
        const secureFlag = isHttpsRequest(req) ? '; Secure' : '';
        res.writeHead(200, {
          'Content-Type': 'application/json',
          'Set-Cookie': `${SESSION_COOKIE}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0${secureFlag}`,
          ...BASE_SECURITY_HEADERS
        });
        res.end(JSON.stringify({ ok: true }));
        return;
      }

      if (pathname === '/api/auth/change-password' && req.method === 'POST') {
        const session = verifyAdminSessionCookie(req);
        if (!session || session.role !== 'admin') {
          res.writeHead(session ? 403 : 401, { 'Content-Type': 'application/json', ...BASE_SECURITY_HEADERS });
          res.end(JSON.stringify({ error: session ? 'Admin role required to change password.' : 'Sign in required' }));
          return;
        }
        const body = await readJsonBody(req).catch(() => ({}));
        const currentPassword = String(body.currentPassword || '');
        const newPassword = String(body.newPassword || '');
        if (newPassword.length < 8 || newPassword.length > 128) {
          res.writeHead(400, { 'Content-Type': 'application/json', ...BASE_SECURITY_HEADERS });
          res.end(JSON.stringify({ error: 'New password must be 8-128 characters.' }));
          return;
        }
        const creds = loadAdminCredentials();
        if (!verifyAdminPassword(currentPassword, creds.passwordHash)) {
          res.writeHead(401, { 'Content-Type': 'application/json', ...BASE_SECURITY_HEADERS });
          res.end(JSON.stringify({ error: 'Current password is incorrect.' }));
          return;
        }
        saveAdminCredentials(creds.username, hashAdminPassword(newPassword));
        res.writeHead(200, { 'Content-Type': 'application/json', ...BASE_SECURITY_HEADERS });
        res.end(JSON.stringify({ ok: true }));
        return;
      }

      // Admin Tickets API: GET /api/admin/tickets
      if (pathname === '/api/admin/tickets') {
        if (!hasAdminToken(req)) {
          const isManager = verifyAdminSessionCookie(req)?.role === 'manager';
          res.writeHead(isManager ? 403 : 401, { 'Content-Type': 'application/json', ...BASE_SECURITY_HEADERS });
          res.end(JSON.stringify({ error: isManager ? 'Forbidden: Manager Mode is read-only' : 'Unauthorized', code: isManager ? 'FORBIDDEN' : 'AUTH_REQUIRED' }));
          return;
        }
        const merchants = this.merchantRepo.findAll();
        const mId = merchants[0]?.id || '00000000-0000-0000-0000-000000000001';
        const tickets = this.ticketRepo.findTicketsByMerchant(mId);

        res.writeHead(200, {
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': '*',
          ...BASE_SECURITY_HEADERS
        });
        res.end(JSON.stringify(tickets));
        return;
      }

      // Merged Control Center Supervisor Proxy: /api/services/* and /api/logs/stream -> Control Center on port 8090
      // Relaying this unauthenticated would republish process control and every service's
      // stdout/stderr on the internet-facing admin host, so the admin token is required.
      if (pathname.startsWith('/api/services') || pathname === '/api/logs/stream') {
        if (!hasAdminToken(req, url, pathname)) {
          const isManager = verifyAdminSessionCookie(req)?.role === 'manager';
          res.writeHead(isManager ? 403 : 401, { 'Content-Type': 'application/json', ...BASE_SECURITY_HEADERS });
          res.end(JSON.stringify({ error: isManager ? 'Forbidden: Manager Mode is read-only' : 'Unauthorized', code: isManager ? 'FORBIDDEN' : 'AUTH_REQUIRED' }));
          return;
        }
        const controlCenterUrl = process.env.CONTROL_CENTER_URL || `http://127.0.0.1:${process.env.CONTROL_CENTER_PORT || 8090}`;
        const targetUrl = new URL(req.url, controlCenterUrl);
        const requestClient = targetUrl.protocol === 'https:' ? https : http;
        const forwardHeaders = sanitizedForwardHeaders(req, targetUrl.host);
        if (!forwardHeaders.authorization && !forwardHeaders.Authorization) {
          forwardHeaders.Authorization = `Bearer ${getAdminToken()}`;
        }
        const proxyReq = requestClient.request({
          hostname: targetUrl.hostname,
          port: targetUrl.port || undefined,
          path: `${targetUrl.pathname}${targetUrl.search}`,
          method: req.method,
          headers: forwardHeaders
        }, (proxyRes) => {
          res.writeHead(proxyRes.statusCode, proxyRes.headers);
          proxyRes.pipe(res);
        });

        proxyReq.on('error', (err) => {
          if (!res.headersSent) {
            res.writeHead(502, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'Control center supervisor unavailable', details: err.message }));
          }
        });

        req.on('data', chunk => proxyReq.write(chunk));
        req.on('end', () => proxyReq.end());
        return;
      }


      // Stand Proxy: /stand, /stand/print, /stand/qr.svg -> Checkout Portal (Port 7000)
      if (pathname.startsWith('/stand')) {
        const checkoutUrl = process.env.CHECKOUT_PORTAL_URL || 'http://localhost:7000';
        const targetUrl = new URL(req.url, checkoutUrl);
        const requestClient = targetUrl.protocol === 'https:' ? https : http;
        const proxyReq = requestClient.request({
          hostname: targetUrl.hostname,
          port: targetUrl.port || undefined,
          path: `${targetUrl.pathname}${targetUrl.search}`,
          method: req.method,
          headers: sanitizedForwardHeaders(req, targetUrl.host)
        }, (proxyRes) => {
          res.writeHead(proxyRes.statusCode, proxyRes.headers);
          proxyRes.pipe(res);
        });

        proxyReq.on('error', (err) => {
          if (!res.headersSent) {
            res.writeHead(502, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'Checkout portal unavailable for stand', details: err.message }));
          }
        });

        req.on('data', chunk => proxyReq.write(chunk));
        req.on('end', () => proxyReq.end());
        return;
      }

      // Transparent API Proxy: /api/* -> Payment Core REST API
      if (pathname.startsWith('/api/')) {
        const session = verifyAdminSessionCookie(req);
        // Enforce strict read-only RBAC for Manager Mode on every /api/* call
        if (session && session.role === 'manager' && !isManagerAllowedApiRequest(req.method, pathname)) {
          res.writeHead(403, { 'Content-Type': 'application/json', ...BASE_SECURITY_HEADERS });
          res.end(JSON.stringify({ error: 'Forbidden: Manager Mode is restricted to read-only live monitor & sales.' }));
          return;
        }
        const targetUrl = new URL(req.url, this.apiBaseUrl);
        const requestClient = targetUrl.protocol === 'https:' ? https : http;
        const dappersfitMerchant = this.merchantRepo.findById('d99d66ee-1530-4c38-9872-69ecec0102a7');
        const defaultMerchant = dappersfitMerchant || (this.merchantRepo.getDefault ? this.merchantRepo.getDefault() : (this.merchantRepo.findById('00000000-0000-0000-0000-000000000001') || this.merchantRepo.findAll()[0]));
        const defaultMerchantId = defaultMerchant?.id || '00000000-0000-0000-0000-000000000001';
        const forwardHeaders = {
          ...sanitizedForwardHeaders(req, targetUrl.host),
          'x-merchant-id': session?.role === 'manager' ? defaultMerchantId : (req.headers['x-merchant-id'] || defaultMerchantId),
          'x-forwarded-host': req.headers.host || '',
          'x-forwarded-proto': req.headers['x-forwarded-proto'] || 'http'
        };
        // Inject internal admin bearer token server-side when browser holds a valid encrypted HttpOnly session
        if (!forwardHeaders.authorization && !forwardHeaders.Authorization && session) {
          forwardHeaders.Authorization = `Bearer ${getAdminToken()}`;
        }
        const proxyReq = requestClient.request({
          hostname: targetUrl.hostname,
          port: targetUrl.port || undefined,
          path: `${targetUrl.pathname}${targetUrl.search}`,
          method: req.method,
          headers: forwardHeaders
        }, (proxyRes) => {
          res.writeHead(proxyRes.statusCode, proxyRes.headers);
          proxyRes.pipe(res);
        });

        proxyReq.on('error', (err) => {
          if (!res.headersSent) {
            res.writeHead(502, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'Gateway API unavailable', details: err.message }));
          }
        });

        req.pipe(proxyReq);
        return;
      }

      // Download Android Companion APK
      if (pathname === '/youpi-sms-gateway.apk' || pathname === '/api/v1/admin/sms-gateway/download-apk') {
        const apkCandidates = [
          path.resolve(__dirname, '../public/youpi-sms-gateway.apk'),
          path.resolve(__dirname, '../../payment-api/public/youpi-sms-gateway.apk'),
          path.resolve(__dirname, '../../android-observer-app/youpi-sms-gateway.apk')
        ];
        let apkPath = null;
        for (const p of apkCandidates) {
          if (fs.existsSync(p)) {
            apkPath = p;
            break;
          }
        }
        if (apkPath) {
          const stat = fs.statSync(apkPath);
          res.writeHead(200, {
            'Content-Type': 'application/vnd.android.package-archive',
            'Content-Disposition': 'attachment; filename="youpi-sms-gateway.apk"',
            'Content-Length': stat.size,
            'Access-Control-Allow-Origin': '*'
          });
          const stream = fs.createReadStream(apkPath);
          stream.pipe(res);
          return;
        }
      }

      // Self-hosted UI fonts (CSP blocks third-party font CDNs)
      const fontMatch = /^\/fonts\/(dm-sans|sora)\.woff2$/.exec(pathname);
      if (fontMatch && req.method === 'GET') {
        const fontPath = path.resolve(__dirname, '../public/fonts', `${fontMatch[1]}.woff2`);
        if (fs.existsSync(fontPath)) {
          res.writeHead(200, {
            'Content-Type': 'font/woff2',
            'Cache-Control': 'public, max-age=31536000, immutable',
            'X-Content-Type-Options': 'nosniff'
          });
          fs.createReadStream(fontPath).pipe(res);
          return;
        }
      }

      // Dashboard View: GET / or GET /admin
      if (pathname === '/' || pathname === '/admin') {
        const html = this.renderHtml();
        res.writeHead(200, {
          'Content-Type': 'text/html; charset=utf-8',
          'Cache-Control': 'no-cache',
          ...BASE_SECURITY_HEADERS
        });
        res.end(html);
        return;
      }

      res.writeHead(404, { 'Content-Type': 'text/plain' });
      res.end('Admin Route Not Found');
    });
  }
}
