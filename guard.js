'use strict';
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const os = require('os');
const https = require('https');

const CFG = {
  ROOT: __dirname,
  INTEGRITY_FILE: path.join(__dirname, '.lily_integrity.json'),
  BACKUP_INTEGRITY: path.join(os.homedir(), '.lily', 'integrity.json'),
  KILL_LOG: path.join(__dirname, '.lily_kill.log'),
  TOKEN_URL: 'https://raw.githubusercontent.com/cistiansaputraa-alt/ololo/main/token.json',
  KILL_URL: 'https://raw.githubusercontent.com/cistiansaputraa-alt/ololo/main/kill.txt',
  TOKEN_FALLBACK: path.join(__dirname, 'token.json'),
  
  // [VAULT] Secret buat ngecek HMAC Signature token.json
  HMAC_SECRET: Buffer.from('YTNmOWI3YzJlOGQxNDU2ZjBhOWIzYzdkMmU1ZjhhMWI0YzZkOWUyZjVhOGIxYzRkN2UwZjNhNmI5YzJkNWU4ZjE=', 'base64').toString('utf8'),

  HEARTBEAT_MS: 8000,
  DEBUG_DETECT_MS: 3000,
  KILL_CHECK_MS: 60000,
  CRITICAL_FILES: ['index.js', 'config.js', 'package.json', 'Lily-health.js'],
  BANNED_PATTERNS: [
    /client\s*\.\s*events\s*\.\s*on\s*\(\s*['"]ready['"]/i,
    /require\s*\(\s*['"]child_process['"]\s*\)\s*\.\s*spawn\s*\(\s*['"]bash/i,
    /__proto__\s*=\s*null/,
    /delete\s+process\.env/,
    /\beval\s*\(\s*(?:atob|Buffer|decodeURIComponent)/i,
    /globalThis\s*\[\s*(?:atob|String\.fromCharCode)/i,
  ],
  EXIT_CODE_WHITELIST: [0, 1, 42, 0xDEAD],
  TAMPER_WINDOW_MS: 10000,
  MAX_TAMPER_IN_WINDOW: 2,
};

const sha256 = (b) => crypto.createHash('sha256').update(b).digest('hex');
const safeRead = (p) => { try { return fs.readFileSync(p); } catch { return null; } };
const exists = (p) => { try { return fs.existsSync(p); } catch { return false; } };
const mtime = (p) => { try { return fs.statSync(p).mtimeMs; } catch { return 0; } };

const IS_DEV = process.env.LILY_DEV === '1';

// ==========================================
// [CAMOUFLAGED LOGS] Semua log jadi LILY-PARTY
// ==========================================
const log = (tag, msg) => { console.log(`[LILY-PARTY]`); };
const err = (msg) => { console.log(`[LILY-PARTY]`); };

const STATE = { booted: false, debugCount: 0, startedAt: Date.now(), lastStep: 'init', tamperEvents: [], killReason: null };

const _REAL_EXIT = process.exit.bind(process);
function hardKill(reason) {
  STATE.killReason = reason;
  try { fs.appendFileSync(CFG.KILL_LOG, `[${new Date().toISOString()}] KILL step=${STATE.lastStep}\n`); } catch {}
  _REAL_EXIT(0xDEAD);
}

const BAD_ARGV = ['--inspect','--inspect-brk','--debug','--debug-brk','--prof','--trace-debug','--require','--loader','--experimental-loader','--experimental-vm-modules','--allow-natives-syntax'];
function antiDebug() {
  STATE.lastStep = 'antiDebug';
  const argv = process.execArgv.join(' ');
  for (const bad of BAD_ARGV) { if (argv.includes(bad) && !IS_DEV) hardKill('debug-flag:' + bad); }
  try { const insp = require('inspector'); if (insp.url?.() && !IS_DEV) hardKill('inspector'); } catch {}
  if (process.env.NODE_OPTIONS && /--inspect|--require|--loader/.test(process.env.NODE_OPTIONS) && !IS_DEV) hardKill('node-options');
  if ((typeof global.__coverage__ !== 'undefined' || global.__debugger__) && !IS_DEV) hardKill('global-debug');
  const start = process.hrtime.bigint();
  debugger;
  const elapsed = Number(process.hrtime.bigint() - start) / 1e6;
  if (elapsed > 150 && !IS_DEV) { STATE.debugCount++; if (STATE.debugCount >= 2) hardKill('debugger-active'); }
}

function buildManifest() {
  const m = {};
  for (const f of CFG.CRITICAL_FILES) {
    const full = path.join(CFG.ROOT, f);
    const buf = safeRead(full);
    if (!buf) continue;
    m[f] = { sha256: sha256(buf), size: buf.length, mtime: mtime(full) };
  }
  return m;
}
function loadManifest() {
  let buf = safeRead(CFG.INTEGRITY_FILE);
  if (!buf && exists(CFG.BACKUP_INTEGRITY)) {
    buf = safeRead(CFG.BACKUP_INTEGRITY);
    if (buf) { try { fs.mkdirSync(path.dirname(CFG.INTEGRITY_FILE), { recursive: true }); fs.writeFileSync(CFG.INTEGRITY_FILE, buf); } catch {} }
  }
  if (!buf) return null;
  try { return JSON.parse(buf.toString('utf8')); } catch { return null; }
}
function saveManifest(m) {
  const data = JSON.stringify(m, null, 2);
  try { fs.writeFileSync(CFG.INTEGRITY_FILE, data); try { fs.mkdirSync(path.dirname(CFG.BACKUP_INTEGRITY), { recursive: true }); fs.writeFileSync(CFG.BACKUP_INTEGRITY, data); } catch {} } catch {}
}
function registerTamper() {
  const now = Date.now();
  STATE.tamperEvents = STATE.tamperEvents.filter(t => now - t < CFG.TAMPER_WINDOW_MS);
  STATE.tamperEvents.push(now);
  if (STATE.tamperEvents.length >= CFG.MAX_TAMPER_IN_WINDOW && !IS_DEV) hardKill('tamper-escalation');
}
function verifyIntegrity(strict = false) {
  const m = loadManifest();
  if (!m) return false;
  let tampered = false;
  for (const f of Object.keys(m)) {
    if (f === '__env') continue;
    const buf = safeRead(path.join(CFG.ROOT, f));
    if (!buf) { tampered = true; continue; }
    const actual = sha256(buf);
    if (actual !== m[f].sha256) {
      const srcMtime = mtime(path.join(CFG.ROOT, f));
      if (srcMtime > (m[f].mtime || 0) + 1000) { tampered = true; }
      else { if (strict && !IS_DEV) { registerTamper(); hardKill('tamper:' + f); } tampered = true; }
    }
  }
  return !tampered;
}

function antiInject() {
  STATE.lastStep = 'antiInject';
  for (const f of CFG.CRITICAL_FILES) {
    const buf = safeRead(path.join(CFG.ROOT, f));
    if (!buf) continue;
    const text = buf.toString('utf8');
    for (const pat of CFG.BANNED_PATTERNS) { if (pat.test(text) && !IS_DEV) hardKill('inject:' + f); }
  }
}

const NATIVE_LEN = { fsRead: fs.readFileSync.toString().length, cryptoHash: crypto.createHash.toString().length, jsonParse: JSON.parse.toString().length };
function antiHook() {
  STATE.lastStep = 'antiHook';
  const now = { fsRead: fs.readFileSync.toString().length, cryptoHash: crypto.createHash.toString().length, jsonParse: JSON.parse.toString().length };
  for (const k of Object.keys(NATIVE_LEN)) { if (now[k] !== NATIVE_LEN[k] && !IS_DEV) return false; }
  return true;
}

const URL_LEAK = /(?:mysql|postgres|mongodb|redis|mariadb):\/\/[^\s"'`]+/i;
const DB_CRED = /(?:db_pass|db_user|db_host|db_name|mongodb_uri|database_url)\s*[:=]\s*['"`][^'"`]+['"`]/i;
function antiLinkLeak() {
  STATE.lastStep = 'antiLinkLeak';
  for (const f of CFG.CRITICAL_FILES) {
    const buf = safeRead(path.join(CFG.ROOT, f));
    if (!buf) continue;
    const text = buf.toString('utf8');
    if ((URL_LEAK.test(text) || DB_CRED.test(text)) && !IS_DEV) hardKill('leak:' + f);
  }
}

function pinnedFetch(url) {
  return new Promise((resolve) => {
    const req = https.get(url, { headers: { 'User-Agent': 'Lily/9.0', 'Cache-Control': 'no-cache' }, timeout: 15000 }, (res) => {
      if (res.statusCode !== 200) { res.resume(); return resolve(null); }
      let size = 0;
      const chunks = [];
      res.on('data', (c) => { size += c.length; if (size > 512 * 1024) { req.destroy(); return resolve(null); } chunks.push(c); });
      res.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
      res.on('error', () => resolve(null));
    });
    req.on('error', () => resolve(null));
    req.on('timeout', () => { req.destroy(); resolve(null); });
  });
}

let cachedTokens = null;
async function fetchValidTokens() {
  if (cachedTokens) return cachedTokens;
  try {
    const raw = await pinnedFetch(CFG.TOKEN_URL);
    if (!raw) throw new Error('fetch fail');
    
    // [VAULT] Bongkar JSON & Cek HMAC
    const data = JSON.parse(raw);
    if (!Array.isArray(data.tokens) || typeof data.sig !== 'string') throw new Error('format');
    
    // Hitung ulang signature
    const expected = crypto.createHmac('sha256', CFG.HMAC_SECRET).update(JSON.stringify(data.tokens)).digest('hex');
    const a = Buffer.from(expected, 'hex');
    const b = Buffer.from(data.sig, 'hex');
    
    // Kalau signature beda (berarti di-edit orang), langsung gagal
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) throw new Error('sig invalid');

    cachedTokens = data.tokens;
    return cachedTokens;
  } catch (e) {
    const buf = safeRead(CFG.TOKEN_FALLBACK);
    if (!buf) return [];
    try { 
      const d = JSON.parse(buf.toString('utf8')); 
      // Cek HMAC juga buat fallback
      const expected = crypto.createHmac('sha256', CFG.HMAC_SECRET).update(JSON.stringify(d.tokens)).digest('hex');
      if (expected === d.sig) { cachedTokens = d.tokens || []; return cachedTokens; }
      return [];
    } catch { return []; }
  }
}

async function validateTokenOrDie(botToken) {
  STATE.lastStep = 'validateToken';
  const valid = await fetchValidTokens();
  // Timing safe compare
  let ok = false;
  const input = Buffer.from(botToken);
  for (const t of valid) {
    const b = Buffer.from(t);
    if (b.length === input.length && crypto.timingSafeEqual(b, input)) { ok = true; break; }
  }
  if (!ok) { err(`Token tidak terdaftar!`); process.exit(1); }
  log('✅', 'Token valid');
}

async function checkRemoteKill() {
  try { const raw = await pinnedFetch(CFG.KILL_URL); if (raw && raw.trim() === 'KILL') hardKill('remote-kill'); } catch {}
}
function getEnvFingerprint() { return sha256(Buffer.from(os.hostname() + '|' + os.platform() + '|' + os.arch())).slice(0, 16); }
function checkEnvBinding() {
  STATE.lastStep = 'envBinding';
  const m = loadManifest();
  if (!m) return;
  if (!m.__env) { m.__env = getEnvFingerprint(); saveManifest(m); return; }
  const current = getEnvFingerprint();
  if (m.__env !== current && !IS_DEV) hardKill('env-mismatch');
}

function installSignalGuard() {
  const block = (sig) => { try { process.on(sig, () => { if (!IS_DEV) hardKill('signal-' + sig); }); } catch {} };
  block('SIGUSR1'); block('SIGUSR2');
}
function installExitLockdown() {
  if (IS_DEV) return;
  const desc = Object.getOwnPropertyDescriptor(process, 'exit');
  if (desc && desc.configurable !== false) {
    Object.defineProperty(process, 'exit', {
      value: (code) => {
        if (code === undefined || code === null) return _REAL_EXIT(0xDEAD);
        if (CFG.EXIT_CODE_WHITELIST.includes(code)) return _REAL_EXIT(code);
        return _REAL_EXIT(0xDEAD);
      }, writable: false, configurable: false,
    });
  }
}

let lastTick = Date.now();
function startWatchers() {
  setInterval(() => {
    if (!verifyIntegrity(false) && !IS_DEV) {}
    if (!antiHook() && !IS_DEV) hardKill('heartbeat-hook');
    antiInject(); antiLinkLeak();
  }, CFG.HEARTBEAT_MS);
  setInterval(antiDebug, CFG.DEBUG_DETECT_MS);
  setInterval(() => { const d = Date.now() - lastTick; if (d > CFG.HEARTBEAT_MS * 3 && !IS_DEV) hardKill('freeze'); lastTick = Date.now(); }, 1000);
  setInterval(checkRemoteKill, CFG.KILL_CHECK_MS);
}

function checkKillLoop() {
  STATE.lastStep = 'checkKillLoop';
  try {
    if (!exists(CFG.KILL_LOG)) return;
    const stat = fs.statSync(CFG.KILL_LOG);
    if (Date.now() - stat.mtimeMs < 3000) {
      const count = (fs.readFileSync(CFG.KILL_LOG, 'utf8').match(/KILL/g) || []).length;
      if (count > 10 && !IS_DEV) { err('Terlalu banyak crash.'); process.exit(1); }
    }
  } catch {}
}

async function boot({ botToken }) {
  log('🚀', 'Booting...');
  try {
    checkKillLoop();
    antiDebug();
    if (!antiHook()) hardKill('boot-antiHook');
    installSignalGuard();
    installExitLockdown();
    if (!loadManifest()) { const m = buildManifest(); m.__env = getEnvFingerprint(); saveManifest(m); log('📦', 'Baseline integrity dibuat.'); }
    checkEnvBinding();
    if (!verifyIntegrity(false)) { const m = buildManifest(); m.__env = loadManifest()?.__env || getEnvFingerprint(); saveManifest(m); }
    antiInject(); antiLinkLeak();
    
    if (botToken) await validateTokenOrDie(botToken);
    
    startWatchers();
    STATE.booted = true; STATE.lastStep = 'booted';
    log('✅', 'Proteksi aktif.');
    return true;
  } catch (e) {
    err(`Boot error step "${STATE.lastStep}"`);
    throw e;
  }
}

module.exports = { boot, hardKill, sha256 };
