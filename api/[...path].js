'use strict';
const crypto = require('node:crypto');
const { promisify } = require('node:util');
const { Pool, types } = require('pg');
const scrypt = promisify(crypto.scrypt);
types.setTypeParser(20, v => parseInt(v, 10)); // BIGINT -> number

const TG = process.env.TELEGRAM_CHANNEL || 'https://t.me/allverifird';
const SUP = process.env.SUPPORT_LINK || 'https://t.me/jhddddjjeeeroh';
const DAY = 864e5;

class HttpError extends Error { constructor(s, m) { super(m); this.status = s; } }
const bad = (m, s = 400) => { throw new HttpError(s, m); };

/* ---------- database ---------- */
let pool;
function P() {
  if (!pool) {
    if (!process.env.DATABASE_URL) bad('Server is not configured: DATABASE_URL is missing', 500);
    const cs = process.env.DATABASE_URL.replace(/([?&])sslmode=[^&]*&?/, '$1').replace(/[?&]$/, '');
    pool = new Pool({ connectionString: cs, max: 1, idleTimeoutMillis: 10000, ssl: { rejectUnauthorized: false } });
  }
  return pool;
}
const q = (s, a = [], c) => (c || P()).query(s, a).then(r => r.rows);
const get = async (s, a, c) => (await q(s, a, c))[0];
async function tx(fn) {
  const c = await P().connect();
  try { await c.query('BEGIN'); const r = await fn(c); await c.query('COMMIT'); return r; }
  catch (e) { try { await c.query('ROLLBACK'); } catch (_) {} throw e; }
  finally { c.release(); }
}
const SCHEMA = `
CREATE TABLE IF NOT EXISTS users(id SERIAL PRIMARY KEY, name TEXT NOT NULL, username TEXT UNIQUE NOT NULL, email TEXT UNIQUE NOT NULL, phone TEXT, pw TEXT NOT NULL, pwv INTEGER NOT NULL DEFAULT 0, is_admin INTEGER NOT NULL DEFAULT 0, ref_by INTEGER, activated INTEGER NOT NULL DEFAULT 0, tasks_bal INTEGER NOT NULL DEFAULT 0, ref_bal INTEGER NOT NULL DEFAULT 0, bank TEXT, pin TEXT, created BIGINT NOT NULL);
CREATE TABLE IF NOT EXISTS tasks(id SERIAL PRIMARY KEY, title TEXT NOT NULL, kind TEXT NOT NULL, url TEXT, body TEXT, active INTEGER NOT NULL DEFAULT 1);
CREATE TABLE IF NOT EXISTS completions(id SERIAL PRIMARY KEY, user_id INTEGER NOT NULL, task_id INTEGER NOT NULL, ts BIGINT NOT NULL);
CREATE INDEX IF NOT EXISTS ix_comp ON completions(user_id, task_id, ts);
CREATE TABLE IF NOT EXISTS proofs(id SERIAL PRIMARY KEY, user_id INTEGER NOT NULL, task_id INTEGER NOT NULL, text TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending', ts BIGINT NOT NULL);
CREATE TABLE IF NOT EXISTS withdrawals(id SERIAL PRIMARY KEY, user_id INTEGER NOT NULL, wallet TEXT NOT NULL, amount INTEGER NOT NULL, bank TEXT, status TEXT NOT NULL DEFAULT 'pending', ts BIGINT NOT NULL);
CREATE TABLE IF NOT EXISTS tx(id SERIAL PRIMARY KEY, user_id INTEGER NOT NULL, label TEXT NOT NULL, amount INTEGER NOT NULL, wallet TEXT NOT NULL, ts BIGINT NOT NULL);
CREATE INDEX IF NOT EXISTS ix_tx ON tx(user_id, ts);
CREATE TABLE IF NOT EXISTS settings(k TEXT PRIMARY KEY, v INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS resets(h TEXT PRIMARY KEY, user_id INTEGER NOT NULL, exp BIGINT NOT NULL);
CREATE TABLE IF NOT EXISTS task_starts(user_id INTEGER NOT NULL, task_id INTEGER NOT NULL, ts BIGINT NOT NULL, PRIMARY KEY(user_id, task_id));
CREATE TABLE IF NOT EXISTS config(k TEXT PRIMARY KEY, v TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS income(id SERIAL PRIMARY KEY, amount INTEGER NOT NULL, note TEXT, ts BIGINT NOT NULL);
CREATE TABLE IF NOT EXISTS rate(k TEXT PRIMARY KEY, n INTEGER NOT NULL, r BIGINT NOT NULL);
`;
const DEF = { daily: 300, minTasks: 1000, minRef: 1000, refBonus: 500 };
let ready;
function init() {
  return ready || (ready = (async () => {
    if (!process.env.SESSION_SECRET || process.env.SESSION_SECRET.length < 16) bad('Server is not configured: set a long SESSION_SECRET', 500);
    await P().query(SCHEMA);
    for (const k in DEF) await q('INSERT INTO settings(k,v) VALUES($1,$2) ON CONFLICT(k) DO NOTHING', [k, DEF[k]]);
    await q('INSERT INTO tasks(title,kind,url,body) SELECT $1::text,$2::text,$3::text,$4::text WHERE NOT EXISTS (SELECT 1 FROM tasks)',
      ['Read about our benefits', 'read', '', 'Benefix pays you for real tasks funded by brands and survey clients. Join free, finish your daily tasks, and withdraw to your bank account once you reach the minimum.']);
    await q('INSERT INTO tasks(title,kind,url,body) SELECT $1::text,$2::text,$3::text,$4::text WHERE (SELECT COUNT(*) FROM tasks)=1 AND NOT EXISTS (SELECT 1 FROM tasks WHERE kind=$2::text)',
      ['Join our Telegram channel', 'tg', TG, '']);
    if (!(await get('SELECT 1 x FROM users WHERE is_admin=1'))) {
      const email = (process.env.ADMIN_EMAIL || '').toLowerCase(), pw = process.env.ADMIN_PASSWORD || '';
      if (!email || pw.length < 8) bad('Server is not configured: set ADMIN_EMAIL and ADMIN_PASSWORD (8+ characters)', 500);
      await q('INSERT INTO users(name,username,email,phone,pw,is_admin,created) VALUES($1,$2,$3,$4,$5,1,$6) ON CONFLICT DO NOTHING', ['Admin', 'admin', email, '', await hashPw(pw), Date.now()]);
    }
  })().catch(e => { ready = null; throw e; }));
}

/* ---------- security helpers ---------- */
const sha = x => crypto.createHash('sha256').update(x).digest('hex');
async function hashPw(p) { const salt = crypto.randomBytes(16).toString('hex'); return salt + ':' + (await scrypt(p, salt, 64)).toString('hex'); }
async function checkPw(p, st) {
  if (!st) return false; const [salt, h] = st.split(':'); if (!salt || !h) return false;
  const a = Buffer.from(h, 'hex'), b = await scrypt(p, salt, 64); return a.length === b.length && crypto.timingSafeEqual(a, b);
}
const sign = s => crypto.createHmac('sha256', process.env.SESSION_SECRET).update(s).digest('base64url');
function makeToken(u) { const b = Buffer.from(JSON.stringify({ u: u.id, v: u.pwv, e: Date.now() + 30 * DAY })).toString('base64url'); return b + '.' + sign(b); }
function readToken(t) {
  if (!t) return null; const [b, s] = t.split('.'); if (!b || !s) return null;
  const x = Buffer.from(sign(b)), y = Buffer.from(s); if (x.length !== y.length || !crypto.timingSafeEqual(x, y)) return null;
  try { const d = JSON.parse(Buffer.from(b, 'base64url')); return d.e > Date.now() ? d : null; } catch { return null; }
}
async function limit(key, max, ms) {
  const now = Date.now();
  const r = await get(`INSERT INTO rate(k,n,r) VALUES($1,1,$2) ON CONFLICT(k) DO UPDATE SET n=CASE WHEN rate.r<$3 THEN 1 ELSE rate.n+1 END, r=CASE WHEN rate.r<$3 THEN $2 ELSE rate.r END RETURNING n`, [key, now + ms, now]);
  if (r.n > max) bad('Too many attempts. Try again later.', 429);
  if (Math.random() < 0.02) q('DELETE FROM rate WHERE r<$1', [now]).catch(() => {});
}
const str = (v, max) => typeof v === 'string' ? v.trim().slice(0, max) : '';
const int = v => Number.isSafeInteger(+v) && +v > 0 ? +v : 0;
const isUrl = u => { try { const x = new URL(u); return x.protocol === 'https:' || x.protocol === 'http:'; } catch { return false; } };

/* ---------- money and tasks ---------- */
async function settings(c) { return Object.fromEntries((await q('SELECT k,v FROM settings', [], c)).map(r => [r.k, r.v])); }
async function rewardPer(c) { const s = await settings(c), n = (await get('SELECT COUNT(*) c FROM tasks WHERE active=1', [], c)).c; return Math.floor(s.daily / Math.max(1, n)); }
const addTx = (c, uid, label, amount, wallet) => q('INSERT INTO tx(user_id,label,amount,wallet,ts) VALUES($1,$2,$3,$4,$5)', [uid, label, amount, wallet, Date.now()], c);
async function credit(c, uid, amount, label, wallet) {
  const col = wallet === 'r' ? 'ref_bal' : 'tasks_bal';
  await q(`UPDATE users SET ${col}=${col}+$1 WHERE id=$2`, [amount, uid], c); await addTx(c, uid, label, amount, wallet);
}
const lockUser = (c, id) => get('SELECT id FROM users WHERE id=$1 FOR UPDATE', [id], c);
async function giveReward(c, uid, task) {
  const u = await get('SELECT * FROM users WHERE id=$1', [uid], c), amt = await rewardPer(c);
  await q('INSERT INTO completions(user_id,task_id,ts) VALUES($1,$2,$3)', [uid, task.id, Date.now()], c);
  await credit(c, uid, amt, task.title, 't');
  if (!u.activated) {
    await q('UPDATE users SET activated=1 WHERE id=$1', [uid], c);
    const s = await settings(c);
    if (u.ref_by && s.refBonus > 0) await credit(c, u.ref_by, s.refBonus, 'Referral bonus: ' + u.name, 'r');
  }
}
async function taskState(uid, t, c) {
  const last = (await get('SELECT MAX(ts) ts FROM completions WHERE user_id=$1 AND task_id=$2', [uid, t.id], c)).ts;
  const pend = await get("SELECT 1 x FROM proofs WHERE user_id=$1 AND task_id=$2 AND status='pending'", [uid, t.id], c);
  let state = 'ready', nextAt = 0;
  if (t.kind === 'tg') { if (last) state = 'done'; else if (pend) state = 'review'; }
  else if (last && Date.now() - last < DAY) { state = 'wait'; nextAt = last + DAY; }
  return { id: t.id, title: t.title, kind: t.kind, url: t.kind === 'tg' ? t.url : '', body: t.kind === 'read' ? t.body : '', state, nextAt };
}
async function adCfg(c) { const m = Object.fromEntries((await q("SELECT k,v FROM config WHERE k IN ('ad_src','ad_zone')", [], c)).map(r => [r.k, r.v])); return { src: m.ad_src || '', zone: m.ad_zone || '' }; }
const userView = u => ({ id: u.id, name: u.name, username: u.username, email: u.email, phone: u.phone, activated: !!u.activated, isAdmin: !!u.is_admin, tasksBal: u.tasks_bal, refBal: u.ref_bal, bank: u.bank ? JSON.parse(u.bank) : null, hasPin: !!u.pin });

/* ---------- routes ---------- */
const routes = [];
const R = (m, p, a, h) => routes.push({ m, re: new RegExp('^' + p.replace(/:(\w+)/g, '(?<$1>[^/]+)') + '$'), a, h });

R('POST', '/api/signup', null, async (c) => {
  await limit('su:' + c.ip, 10, 36e5);
  const b = c.body, name = str(b.name, 60), un = str(b.username, 20).toLowerCase(), email = str(b.email, 120).toLowerCase(), phone = str(b.phone, 20).replace(/\s/g, ''), pw = typeof b.password === 'string' ? b.password : '', rc = str(b.invitedBy, 20).toLowerCase().replace(/^@/, '');
  if (!name) bad('Enter your full name');
  if (!/^[a-z0-9_]{3,20}$/.test(un)) bad('Username: 3-20 letters, numbers or underscore');
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) bad('Enter a valid email');
  if (!/^\+?\d{10,15}$/.test(phone)) bad('Enter a valid phone number');
  if (pw.length < 6 || pw.length > 100) bad('Password must be at least 6 characters');
  if (await get('SELECT 1 x FROM users WHERE email=$1', [email])) bad('Email already registered');
  if (await get('SELECT 1 x FROM users WHERE username=$1', [un])) bad('Username is taken');
  let inv = null;
  if (rc) { inv = await get('SELECT id FROM users WHERE username=$1 AND is_admin=0', [rc]); if (!inv) bad('Inviter username not found'); }
  const h = await hashPw(pw);
  const u = await get('INSERT INTO users(name,username,email,phone,pw,ref_by,created) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING *', [name, un, email, phone, h, inv ? inv.id : null, Date.now()]);
  return { cookie: makeToken(u), data: { ok: true } };
});
R('POST', '/api/login', null, async (c) => {
  const email = str(c.body.email, 120).toLowerCase(), pw = typeof c.body.password === 'string' ? c.body.password : '';
  await limit('li:' + c.ip, 30, 9e5); await limit('le:' + email, 8, 9e5);
  const u = await get('SELECT * FROM users WHERE email=$1', [email]);
  if (!u || !(await checkPw(pw, u.pw))) bad('Wrong email or password', 401);
  return { cookie: makeToken(u), data: { ok: true } };
});
R('POST', '/api/logout', null, async () => ({ cookie: '', data: { ok: true } }));
R('POST', '/api/forgot', null, async (c) => {
  await limit('fg:' + c.ip, 10, 36e5);
  const u = await get('SELECT * FROM users WHERE email=$1', [str(c.body.email, 120).toLowerCase()]);
  if (u) { const t = crypto.randomBytes(32).toString('hex'); await q('INSERT INTO resets(h,user_id,exp) VALUES($1,$2,$3)', [sha(t), u.id, Date.now() + 36e5]); console.log('[reset link for ' + u.email + '] ' + c.origin + '/#reset=' + t); }
  return { data: { ok: true, message: 'If this email is registered, a reset link has been prepared. Contact support if you do not receive it.' } };
});
R('POST', '/api/reset', null, async (c) => {
  await limit('rs:' + c.ip, 10, 36e5);
  const t = str(c.body.token, 100), pw = typeof c.body.password === 'string' ? c.body.password : '';
  if (pw.length < 6 || pw.length > 100) bad('Password must be at least 6 characters');
  const r = await get('SELECT * FROM resets WHERE h=$1 AND exp>$2', [sha(t), Date.now()]);
  if (!r) bad('This reset link is invalid or expired');
  const h = await hashPw(pw);
  await tx(async c2 => { await q('UPDATE users SET pw=$1, pwv=pwv+1 WHERE id=$2', [h, r.user_id], c2); await q('DELETE FROM resets WHERE user_id=$1', [r.user_id], c2); });
  return { data: { ok: true } };
});

R('GET', '/api/me', 'user', async (c) => {
  const u = c.user, s = await settings(), base = { user: userView(u), settings: s, links: { tg: TG, support: SUP } };
  if (u.is_admin) return { data: base };
  const reward = await rewardPer(), ts = await q('SELECT * FROM tasks WHERE active=1 ORDER BY id');
  const tasks = []; for (const t of ts) tasks.push({ ...(await taskState(u.id, t)), reward });
  return { data: { ...base, reward, tasks, ad: await adCfg(),
    referrals: (await q('SELECT name, activated, created FROM users WHERE ref_by=$1 ORDER BY id DESC', [u.id])).map(r => ({ name: r.name, activated: !!r.activated, joined: r.created })),
    withdrawals: await q('SELECT id,wallet,amount,status,ts FROM withdrawals WHERE user_id=$1 ORDER BY id DESC LIMIT 50', [u.id]),
    history: await q('SELECT label,amount,wallet,ts FROM tx WHERE user_id=$1 ORDER BY id DESC LIMIT 30', [u.id]) } };
});
R('POST', '/api/tasks/:id/start', 'user', async (c) => {
  const t = await get('SELECT * FROM tasks WHERE id=$1 AND active=1 AND kind=$2', [+c.p.id || 0, 'read']); if (!t) bad('Task not found', 404);
  if ((await taskState(c.user.id, t)).state !== 'ready') bad('This task is not available right now');
  await q('INSERT INTO task_starts(user_id,task_id,ts) VALUES($1,$2,$3) ON CONFLICT(user_id,task_id) DO UPDATE SET ts=$3', [c.user.id, t.id, Date.now()]);
  return { data: { ok: true } };
});
R('POST', '/api/tasks/:id/claim', 'user', async (c) => {
  const t = await get('SELECT * FROM tasks WHERE id=$1 AND active=1 AND kind=$2', [+c.p.id || 0, 'read']); if (!t) bad('Task not found', 404);
  const s = await get('SELECT ts FROM task_starts WHERE user_id=$1 AND task_id=$2', [c.user.id, t.id]);
  if (!s || Date.now() - s.ts < 5000) bad('Keep reading for 5 seconds first');
  const reward = await tx(async c2 => {
    await lockUser(c2, c.user.id);
    if ((await taskState(c.user.id, t, c2)).state !== 'ready') bad('This task is not available right now');
    await giveReward(c2, c.user.id, t); await q('DELETE FROM task_starts WHERE user_id=$1 AND task_id=$2', [c.user.id, t.id], c2);
    return rewardPer(c2);
  });
  return { data: { ok: true, reward } };
});
R('POST', '/api/tasks/:id/proof', 'user', async (c) => {
  await limit('pf:' + c.user.id, 10, 36e5);
  const t = await get('SELECT * FROM tasks WHERE id=$1 AND active=1 AND kind=$2', [+c.p.id || 0, 'tg']); if (!t) bad('Task not found', 404);
  const text = str(c.body.text, 100); if (text.length < 3) bad('Enter your Telegram username as proof');
  await tx(async c2 => {
    await lockUser(c2, c.user.id);
    if ((await taskState(c.user.id, t, c2)).state !== 'ready') bad('You already submitted or completed this task');
    await q('INSERT INTO proofs(user_id,task_id,text,ts) VALUES($1,$2,$3,$4)', [c.user.id, t.id, text, Date.now()], c2);
  });
  return { data: { ok: true } };
});
R('POST', '/api/bank', 'user', async (c) => {
  const b = str(c.body.bank, 40), a = str(c.body.account, 10), n = str(c.body.name, 60);
  if (!b || !/^\d{10}$/.test(a) || !n) bad('Enter bank, 10-digit account number and account name');
  await q('UPDATE users SET bank=$1 WHERE id=$2', [JSON.stringify({ b, a, n }), c.user.id]); return { data: { ok: true } };
});
R('POST', '/api/pin', 'user', async (c) => {
  const pin = str(c.body.pin, 4); if (!/^\d{4}$/.test(pin)) bad('PIN must be 4 digits');
  if (c.user.pin) { await limit('pc:' + c.user.id, 5, 9e5); if (!(await checkPw(str(c.body.current, 4), c.user.pin))) bad('Current PIN is wrong', 403); }
  await q('UPDATE users SET pin=$1 WHERE id=$2', [await hashPw(pin), c.user.id]); return { data: { ok: true } };
});
R('POST', '/api/withdraw', 'user', async (c) => {
  const u = c.user, w = c.body.wallet === 'r' ? 'r' : 't', amt = int(c.body.amount), s = await settings(), min = w === 'r' ? s.minRef : s.minTasks;
  if (!u.bank || !u.pin) bad('Add bank details and a PIN in Profile first');
  await limit('wp:' + u.id, 5, 9e5);
  if (!(await checkPw(str(c.body.pin, 4), u.pin))) bad('Wrong PIN', 403);
  if (!amt || amt < min) bad('Minimum withdrawal is \u20A6' + min.toLocaleString('en-NG'));
  await tx(async c2 => {
    const col = w === 'r' ? 'ref_bal' : 'tasks_bal';
    const r = await q(`UPDATE users SET ${col}=${col}-$1 WHERE id=$2 AND ${col}>=$1 RETURNING id`, [amt, u.id], c2);
    if (!r.length) bad('Amount is above this wallet balance');
    await q('INSERT INTO withdrawals(user_id,wallet,amount,bank,ts) VALUES($1,$2,$3,$4,$5)', [u.id, w, amt, u.bank, Date.now()], c2);
    await addTx(c2, u.id, 'Withdrawal requested', -amt, w);
  });
  return { data: { ok: true } };
});

R('GET', '/api/admin/overview', 'admin', async () => {
  const users = await q(`SELECT u.id,u.name,u.username,u.email,u.phone,u.activated,u.tasks_bal,u.ref_bal,u.created,i.username inviter,(SELECT COUNT(*) FROM users r WHERE r.ref_by=u.id) refs FROM users u LEFT JOIN users i ON i.id=u.ref_by WHERE u.is_admin=0 ORDER BY u.id DESC LIMIT 500`);
  return { data: { users,
    tasks: await q('SELECT id,title,kind,url,active FROM tasks ORDER BY id'),
    proofs: await q(`SELECT p.id,p.text,p.ts,u.name,u.username,t.title FROM proofs p JOIN users u ON u.id=p.user_id JOIN tasks t ON t.id=p.task_id WHERE p.status='pending' ORDER BY p.id`),
    withdrawals: (await q(`SELECT w.id,w.wallet,w.amount,w.bank,w.status,w.ts,u.name,u.username FROM withdrawals w JOIN users u ON u.id=w.user_id ORDER BY w.id DESC LIMIT 200`)).map(w => ({ ...w, bank: w.bank ? JSON.parse(w.bank) : null })),
    settings: await settings(), reward: await rewardPer(), ad: await adCfg(),
    finance: {
      income: (await get('SELECT COALESCE(SUM(amount),0) s FROM income')).s,
      paid: (await get("SELECT COALESCE(SUM(amount),0) s FROM withdrawals WHERE status='approved'")).s,
      pending: (await get("SELECT COALESCE(SUM(amount),0) s FROM withdrawals WHERE status='pending'")).s,
      owed: (await get('SELECT COALESCE(SUM(tasks_bal+ref_bal),0) s FROM users WHERE is_admin=0')).s },
    incomeLog: await q('SELECT id,amount,note,ts FROM income ORDER BY id DESC LIMIT 20') } };
});
R('POST', '/api/admin/tasks', 'admin', async (c) => {
  const title = str(c.body.title, 80), kind = c.body.kind === 'tg' ? 'tg' : 'read', url = str(c.body.url, 300), body = str(c.body.body, 1500);
  if (!title) bad('Enter a title'); if (kind === 'tg' && !isUrl(url)) bad('Enter a valid link starting with https://');
  await q('INSERT INTO tasks(title,kind,url,body) VALUES($1,$2,$3,$4)', [title, kind, kind === 'tg' ? url : '', body || 'Read this page, then claim your reward.']); return { data: { ok: true } };
});
R('POST', '/api/admin/tasks/:id/remove', 'admin', async (c) => { await q('UPDATE tasks SET active=0 WHERE id=$1', [+c.p.id || 0]); return { data: { ok: true } }; });
R('POST', '/api/admin/proofs/:id', 'admin', async (c) => {
  await tx(async c2 => {
    const p0 = await get("SELECT * FROM proofs WHERE id=$1 AND status='pending'", [+c.p.id || 0], c2); if (!p0) bad('Already handled');
    await lockUser(c2, p0.user_id);
    const p = await get("SELECT * FROM proofs WHERE id=$1 AND status='pending' FOR UPDATE", [p0.id], c2); if (!p) bad('Already handled');
    if (c.body.approve) {
      const t = await get('SELECT * FROM tasks WHERE id=$1', [p.task_id], c2);
      if (t && !(await get('SELECT 1 x FROM completions WHERE user_id=$1 AND task_id=$2', [p.user_id, t.id], c2))) await giveReward(c2, p.user_id, t);
      await q("UPDATE proofs SET status='approved' WHERE id=$1", [p.id], c2);
    } else await q("UPDATE proofs SET status='rejected' WHERE id=$1", [p.id], c2);
  }); return { data: { ok: true } };
});
R('POST', '/api/admin/withdrawals/:id', 'admin', async (c) => {
  await tx(async c2 => {
    const w = await get("SELECT * FROM withdrawals WHERE id=$1 AND status='pending' FOR UPDATE", [+c.p.id || 0], c2); if (!w) bad('Already handled');
    if (c.body.approve) await q("UPDATE withdrawals SET status='approved' WHERE id=$1", [w.id], c2);
    else { await q("UPDATE withdrawals SET status='rejected' WHERE id=$1", [w.id], c2); await credit(c2, w.user_id, w.amount, 'Withdrawal refunded', w.wallet); }
  }); return { data: { ok: true } };
});
R('POST', '/api/admin/credit', 'admin', async (c) => {
  const amt = int(c.body.amount); if (!amt || amt > 1e6) bad('Enter an amount between 1 and 1,000,000');
  const note = str(c.body.note, 60) || 'Bonus from Benefix';
  const n = await tx(async c2 => {
    const ids = c.body.all ? (await q('SELECT id FROM users WHERE is_admin=0', [], c2)).map(r => r.id)
      : (await q('SELECT id FROM users WHERE id=$1 AND is_admin=0', [int(c.body.userId)], c2)).map(r => r.id);
    for (const id of ids) await credit(c2, id, amt, note, 't'); return ids.length;
  });
  if (!n) bad('No user found'); return { data: { ok: true, count: n } };
});
R('POST', '/api/admin/settings', 'admin', async (c) => {
  const fields = ['daily', 'minTasks', 'minRef', 'refBonus'];
  await tx(async c2 => { for (const k of fields) { const v = Number(c.body[k]); if (!Number.isSafeInteger(v) || v < 0 || v > 1e7) bad('Invalid value for ' + k); await q('UPDATE settings SET v=$1 WHERE k=$2', [v, k], c2); } });
  return { data: { ok: true } };
});
R('POST', '/api/admin/ad', 'admin', async (c) => {
  const src = str(c.body.src, 300), zone = str(c.body.zone, 40);
  if (src && !/^https:\/\/[a-z0-9.-]+\/[^\s"'<>]*$/i.test(src)) bad('Ad script link must start with https://');
  if (!/^[A-Za-z0-9_-]*$/.test(zone)) bad('Zone ID can only have letters, numbers, - and _');
  for (const [k, v] of [['ad_src', src], ['ad_zone', zone]]) await q('INSERT INTO config(k,v) VALUES($1,$2) ON CONFLICT(k) DO UPDATE SET v=$2', [k, v]);
  return { data: { ok: true } };
});
R('POST', '/api/admin/income', 'admin', async (c) => {
  const amt = int(c.body.amount); if (!amt || amt > 1e9) bad('Enter an amount in naira');
  await q('INSERT INTO income(amount,note,ts) VALUES($1,$2,$3)', [amt, str(c.body.note, 80) || 'Ad income', Date.now()]); return { data: { ok: true } };
});
R('POST', '/api/admin/income/:id/delete', 'admin', async (c) => { await q('DELETE FROM income WHERE id=$1', [+c.p.id || 0]); return { data: { ok: true } }; });
R('POST', '/api/admin/users/:id/reset-link', 'admin', async (c) => {
  const u = await get('SELECT id FROM users WHERE id=$1 AND is_admin=0', [+c.p.id || 0]); if (!u) bad('User not found', 404);
  const t = crypto.randomBytes(32).toString('hex'); await q('INSERT INTO resets(h,user_id,exp) VALUES($1,$2,$3)', [sha(t), u.id, Date.now() + 36e5]);
  return { data: { link: c.origin + '/#reset=' + t } };
});
R('POST', '/api/admin/users/:id/delete', 'admin', async (c) => {
  await tx(async c2 => {
    const id = +c.p.id || 0; if (!(await get('SELECT 1 x FROM users WHERE id=$1 AND is_admin=0', [id], c2))) bad('User not found', 404);
    await q('UPDATE users SET ref_by=NULL WHERE ref_by=$1', [id], c2);
    for (const t of ['completions', 'proofs', 'withdrawals', 'tx', 'resets', 'task_starts']) await q(`DELETE FROM ${t} WHERE user_id=$1`, [id], c2);
    await q('DELETE FROM users WHERE id=$1', [id], c2);
  }); return { data: { ok: true } };
});

function dbHint(e) {
  const c = e && e.code, m = String((e && e.message) || '');
  if (c === '28P01' || /password authentication failed/i.test(m)) return 'Database password is wrong. Check DATABASE_URL.';
  if (/tenant or user not found/i.test(m)) return 'Database username or project code is wrong. Check DATABASE_URL.';
  if (c === 'ERR_INVALID_URL' || /invalid url|invalid connection/i.test(m)) return 'DATABASE_URL is not a valid link. Remove any [ ] brackets or spaces.';
  if (c === 'ENOTFOUND' || c === 'EAI_AGAIN') return 'Database address not found. Check DATABASE_URL, and that the password has no @ or spaces.';
  if (c === 'ECONNREFUSED' || c === 'ETIMEDOUT' || c === 'ENETUNREACH') return 'Cannot reach the database. Use the Transaction pooler string (port 6543).';
  if (/ssl|certificate/i.test(m)) return 'Database secure connection failed. Use the Transaction pooler string.';
  if (c && /^[0-9A-Z]{5}$/.test(c)) return 'Database error (code ' + c + ').';
  return null;
}

/* ---------- request handler ---------- */
async function bodyOf(req) {
  if (req.body && typeof req.body === 'object' && !Buffer.isBuffer(req.body)) return req.body;
  let raw = '';
  if (typeof req.body === 'string') raw = req.body;
  else if (Buffer.isBuffer(req.body)) raw = req.body.toString('utf8');
  else raw = await new Promise((res, rej) => { let n = 0; const ch = []; req.on('data', d => { n += d.length; if (n > 20000) rej(new HttpError(413, 'Request too large')); else ch.push(d); }); req.on('end', () => res(Buffer.concat(ch).toString('utf8'))); req.on('error', rej); });
  if (!raw) return {};
  try { const j = JSON.parse(raw); return j && typeof j === 'object' ? j : {}; } catch { bad('Invalid request'); }
}
function cookies(req) { const o = {}; (req.headers.cookie || '').split(';').forEach(p => { const i = p.indexOf('='); if (i > 0) o[p.slice(0, i).trim()] = p.slice(i + 1).trim(); }); return o; }

module.exports = async function handler(req, res) {
  const host = req.headers.host || 'localhost', proto = req.headers['x-forwarded-proto'] || 'https', origin = proto + '://' + host;
  const ip = (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || req.socket.remoteAddress || '?';
  const json = (s, d, extra = {}) => { res.statusCode = s; res.setHeader('Content-Type', 'application/json; charset=utf-8'); res.setHeader('Cache-Control', 'no-store'); for (const k in extra) res.setHeader(k, extra[k]); res.end(JSON.stringify(d)); };
  try {
    const url = new URL(req.url, 'http://x'), pathname = url.pathname.replace(/\/+$/, '') || '/';
    const r = routes.find(x => x.m === req.method && x.re.test(pathname));
    if (!r) return json(404, { error: 'Not found' });
    if (req.method !== 'GET') {
      if (req.headers['x-requested-with'] !== 'benefit') return json(403, { error: 'Forbidden' });
      const o = req.headers.origin; if (o && new URL(o).host !== host) return json(403, { error: 'Forbidden' });
    }
    await init();
    const c = { ip, origin, p: pathname.match(r.re).groups || {}, body: req.method === 'GET' ? {} : await bodyOf(req), user: null };
    if (r.a) {
      const t = readToken(cookies(req).sid), u = t && await get('SELECT * FROM users WHERE id=$1', [t.u]);
      if (!u || u.pwv !== t.v) return json(401, { error: 'Please log in' });
      if (r.a === 'admin' && !u.is_admin) return json(403, { error: 'Forbidden' });
      if (r.a === 'user' && u.is_admin && pathname !== '/api/me') return json(403, { error: 'Forbidden' });
      c.user = u;
    }
    const out = await r.h(c), extra = {};
    if (out.cookie !== undefined) extra['Set-Cookie'] = 'sid=' + out.cookie + '; Path=/; HttpOnly; SameSite=Lax; Secure; ' + (out.cookie ? 'Max-Age=2592000' : 'Max-Age=0');
    return json(200, out.data, extra);
  } catch (e) {
    if (e instanceof HttpError) return json(e.status, { error: e.message });
    if (e && e.code === '23505') return json(400, { error: 'That email or username is already registered' });
    console.error(e); return json(500, { error: dbHint(e) || 'Server error' });
  }
};
