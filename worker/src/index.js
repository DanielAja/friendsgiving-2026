// Friendsgiving 2026 potluck API — a small Cloudflare Worker + D1.
//
// Anyone can read the list and add a dish without an account.
// Editing or removing a dish needs proof you added it:
//   - the device that added it keeps a random edit token (only its SHA-256 is stored), or
//   - the optional password set when it was added (stored as salted PBKDF2).
// Abuse checks: per-IP rate limits on adds, edits and password guesses, a cap on the
// total number of dishes, and length checks on every field. IPs are never stored,
// only a salted hash used as a rate-limit key.

const CATEGORIES = ['main', 'side', 'dessert', 'drink', 'other'];
const MAX_ITEMS = 400;
const LIMITS = {
  create:   { max: 8,  window: 3600 },   // new dishes per IP per hour
  createDay:{ max: 20, window: 86400 },  // new dishes per IP per day
  write:    { max: 60, window: 3600 },   // edits + deletes per IP per hour
  pwItem:   { max: 5,  window: 900 },    // wrong passwords per IP per dish per 15 min
  pwAll:    { max: 20, window: 3600 },   // wrong passwords per IP per hour
};
const PBKDF2_ITER = 100000;

export default {
  async fetch(request, env) {
    const origin = request.headers.get('Origin') || '';
    const allowed = (env.ALLOWED_ORIGINS || '').split(',').map(s => s.trim()).filter(Boolean);
    const cors = {
      'Access-Control-Allow-Methods': 'GET, POST, PATCH, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, X-Edit-Token',
      'Access-Control-Max-Age': '86400',
      'Vary': 'Origin',
    };
    if (allowed.includes(origin)) cors['Access-Control-Allow-Origin'] = origin;

    if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: cors });

    try {
      if (expired(env)) {
        await purge(env);
        return json({ error: 'This potluck list has closed.' }, 410, cors);
      }
      const res = await route(request, env);
      for (const [k, v] of Object.entries(cors)) res.headers.set(k, v);
      return res;
    } catch (e) {
      if (e instanceof HttpError) return json({ error: e.message }, e.status, cors);
      console.error(e);
      return json({ error: 'Something went wrong. Try again in a moment.' }, 500, cors);
    }
  },

  async scheduled(_event, env) {
    if (expired(env)) await purge(env);
    await env.DB.prepare('DELETE FROM limits WHERE expires < ?').bind(now()).run();
  },
};

async function route(request, env) {
  const url = new URL(request.url);
  const parts = url.pathname.replace(/\/+$/, '').split('/').filter(Boolean); // api, items, :id, unlock
  if (parts[0] !== 'api' || parts[1] !== 'items') throw new HttpError(404, 'Not found');
  const id = parts[2];
  const action = parts[3];
  const ip = await ipKey(request, env);

  if (!id && request.method === 'GET') return list(env);
  if (!id && request.method === 'POST') return create(request, env, ip);
  if (id && !action && request.method === 'PATCH') return update(request, env, ip, id);
  if (id && !action && request.method === 'DELETE') return remove(request, env, ip, id);
  if (id && action === 'unlock' && request.method === 'POST') return unlock(request, env, ip, id);
  throw new HttpError(405, 'Not allowed');
}

// ---------- handlers ----------

async function list(env) {
  const { results } = await env.DB.prepare(
    'SELECT id, name, dish, category, qty, note, pw_hash IS NOT NULL AS has_pw, created_at, updated_at FROM items ORDER BY created_at'
  ).all();
  return json({
    items: results.map(publicItem),
    expiresAt: env.EXPIRES_AT || null,
  });
}

async function create(request, env, ip) {
  const body = await readJson(request);
  const fields = validate(body, true);
  const password = optionalPassword(body.password);

  const { n } = await env.DB.prepare('SELECT COUNT(*) AS n FROM items').first();
  if (n >= MAX_ITEMS) throw new HttpError(409, 'The list is full.');

  await limit(env, 'create', ip);
  await limit(env, 'createDay', ip);

  const id = randomId(12);
  const token = randomId(32);
  const t = now();
  let pwHash = null, pwSalt = null;
  if (password) ({ hash: pwHash, salt: pwSalt } = await hashPassword(password));

  await env.DB.batch([
    env.DB.prepare(
      'INSERT INTO items (id, name, dish, category, qty, note, pw_hash, pw_salt, creator, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)'
    ).bind(id, fields.name, fields.dish, fields.category, fields.qty, fields.note, pwHash, pwSalt, ip, t, t),
    env.DB.prepare('INSERT INTO tokens (token_hash, item_id, created_at) VALUES (?,?,?)').bind(await sha256(token), id, t),
  ]);

  const item = await getItem(env, id);
  return json({ item: publicItem(item), token }, 201);
}

async function update(request, env, ip, id) {
  const body = await readJson(request);
  const item = await mustGet(env, id);
  await limit(env, 'write', ip);
  await authorize(request, env, ip, item, body.password);

  const fields = validate({ ...item, ...pick(body, ['name', 'dish', 'category', 'qty', 'note']) }, false);
  let pwHash = item.pw_hash, pwSalt = item.pw_salt;
  if (body.removePassword === true) { pwHash = null; pwSalt = null; }
  if (body.newPassword !== undefined && body.newPassword !== null && body.newPassword !== '') {
    const pw = optionalPassword(body.newPassword);
    ({ hash: pwHash, salt: pwSalt } = await hashPassword(pw));
  }

  await env.DB.prepare(
    'UPDATE items SET name=?, dish=?, category=?, qty=?, note=?, pw_hash=?, pw_salt=?, updated_at=? WHERE id=?'
  ).bind(fields.name, fields.dish, fields.category, fields.qty, fields.note, pwHash, pwSalt, now(), id).run();

  return json({ item: publicItem(await getItem(env, id)) });
}

async function remove(request, env, ip, id) {
  const body = request.headers.get('Content-Type')?.includes('json') ? await readJson(request) : {};
  const item = await mustGet(env, id);
  await limit(env, 'write', ip);
  await authorize(request, env, ip, item, body.password);
  await env.DB.batch([
    env.DB.prepare('DELETE FROM items WHERE id=?').bind(id),
    env.DB.prepare('DELETE FROM tokens WHERE item_id=?').bind(id),
  ]);
  return json({ ok: true });
}

// Trade the password for an edit token, so this device can edit without retyping it.
async function unlock(request, env, ip, id) {
  const body = await readJson(request);
  const item = await mustGet(env, id);
  await checkPassword(env, ip, item, body.password);
  const token = randomId(32);
  await env.DB.prepare('INSERT INTO tokens (token_hash, item_id, created_at) VALUES (?,?,?)')
    .bind(await sha256(token), id, now()).run();
  return json({ token });
}

// ---------- auth ----------

async function authorize(request, env, ip, item, password) {
  const token = request.headers.get('X-Edit-Token');
  if (token && token.length <= 100) {
    const row = await env.DB.prepare('SELECT item_id FROM tokens WHERE token_hash=?').bind(await sha256(token)).first();
    if (row && row.item_id === item.id) return;
  }
  if (password) return checkPassword(env, ip, item, password);
  if (!item.pw_hash) throw new HttpError(403, 'Only the device that added this dish can change it.');
  throw new HttpError(401, 'Enter the password for this dish to change it.');
}

async function checkPassword(env, ip, item, password) {
  if (!item.pw_hash) throw new HttpError(403, 'This dish has no password. Only the device that added it can change it.');
  // Refuse before checking, so a locked-out guesser learns nothing.
  await peekLimit(env, 'pwItem', `${ip}:${item.id}`);
  await peekLimit(env, 'pwAll', ip);
  if (typeof password !== 'string' || password.length > 64) throw new HttpError(400, 'Wrong password.');
  const { hash } = await hashPassword(password, item.pw_salt);
  if (!timingSafeEqual(hash, item.pw_hash)) {
    await bump(env, 'pwItem', `${ip}:${item.id}`);
    await bump(env, 'pwAll', ip);
    throw new HttpError(401, 'Wrong password.');
  }
}

// ---------- rate limits (fixed windows in D1) ----------

function windowKey(kind, who) {
  const w = LIMITS[kind].window;
  const slot = Math.floor(now() / w);
  return { key: `${kind}:${who}:${slot}`, expires: (slot + 1) * w };
}

async function limit(env, kind, who) {
  const count = await bump(env, kind, who);
  if (count > LIMITS[kind].max) throw new HttpError(429, 'Too many changes from your connection. Please wait a bit and try again.');
}

async function peekLimit(env, kind, who) {
  const { key } = windowKey(kind, who);
  const row = await env.DB.prepare('SELECT count FROM limits WHERE key=?').bind(key).first();
  if (row && row.count >= LIMITS[kind].max) throw new HttpError(429, 'Too many wrong passwords. Try again later.');
}

async function bump(env, kind, who) {
  const { key, expires } = windowKey(kind, who);
  const row = await env.DB.prepare(
    'INSERT INTO limits (key, count, expires) VALUES (?, 1, ?) ON CONFLICT(key) DO UPDATE SET count = count + 1 RETURNING count'
  ).bind(key, expires).first();
  return row.count;
}

// ---------- validation ----------

function validate(body, isNew) {
  const name = clean(body.name, 40);
  const dish = clean(body.dish, 80);
  const note = clean(body.note ?? '', 140, true);
  const category = String(body.category || 'other').toLowerCase();
  const qty = Number(body.qty ?? 1);
  if (!name) throw new HttpError(400, 'Add your name.');
  if (!dish) throw new HttpError(400, 'Add what you are bringing.');
  if (!CATEGORIES.includes(category)) throw new HttpError(400, 'Pick a category.');
  if (!Number.isInteger(qty) || qty < 1 || qty > 99) throw new HttpError(400, 'How many should be between 1 and 99.');
  void isNew;
  return { name, dish, note, category, qty };
}

function clean(v, max, allowEmpty = false) {
  if (v === undefined || v === null) return allowEmpty ? '' : '';
  if (typeof v !== 'string' && typeof v !== 'number') throw new HttpError(400, 'Invalid input.');
  const s = String(v).replace(/[\u0000-\u001f\u007f​-‏‪-‮⁦-⁩]/g, ' ').replace(/\s+/g, ' ').trim();
  if (s.length > max) throw new HttpError(400, `Keep it under ${max} characters.`);
  return s;
}

function optionalPassword(pw) {
  if (pw === undefined || pw === null || pw === '') return null;
  if (typeof pw !== 'string' || pw.length < 4 || pw.length > 64) throw new HttpError(400, 'Passwords need 4 to 64 characters.');
  return pw;
}

// ---------- helpers ----------

class HttpError extends Error { constructor(status, msg) { super(msg); this.status = status; } }

function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...headers },
  });
}

async function readJson(request) {
  const text = await request.text();
  if (text.length > 4000) throw new HttpError(413, 'Too much data.');
  try { return text ? JSON.parse(text) : {}; } catch { throw new HttpError(400, 'Invalid request.'); }
}

function pick(obj, keys) {
  const out = {};
  for (const k of keys) if (obj[k] !== undefined) out[k] = obj[k];
  return out;
}

function publicItem(r) {
  return {
    id: r.id, name: r.name, dish: r.dish, category: r.category, qty: r.qty, note: r.note,
    hasPassword: !!(r.has_pw ?? r.pw_hash), createdAt: r.created_at, updatedAt: r.updated_at,
  };
}

async function getItem(env, id) {
  return env.DB.prepare('SELECT * FROM items WHERE id=?').bind(id).first();
}

async function mustGet(env, id) {
  if (!/^[A-Za-z0-9_-]{1,40}$/.test(id)) throw new HttpError(404, 'That dish is no longer on the list.');
  const item = await getItem(env, id);
  if (!item) throw new HttpError(404, 'That dish is no longer on the list.');
  return item;
}

function now() { return Math.floor(Date.now() / 1000); }
function expired(env) { return env.EXPIRES_AT && Date.now() > Date.parse(env.EXPIRES_AT); }

async function purge(env) {
  await env.DB.batch([env.DB.prepare('DELETE FROM items'), env.DB.prepare('DELETE FROM tokens')]);
}

async function ipKey(request, env) {
  const ip = request.headers.get('CF-Connecting-IP') || 'local';
  return (await sha256(`${env.IP_SALT || 'dev-salt'}:${ip}`)).slice(0, 24);
}

function randomId(bytes) {
  const b = crypto.getRandomValues(new Uint8Array(bytes));
  return btoa(String.fromCharCode(...b)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function sha256(s) {
  const d = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s));
  return hex(d);
}

async function hashPassword(password, saltHex) {
  const salt = saltHex ? fromHex(saltHex) : crypto.getRandomValues(new Uint8Array(16));
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: PBKDF2_ITER }, key, 256);
  return { hash: hex(bits), salt: hex(salt) };
}

function hex(buf) { return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join(''); }
function fromHex(h) { return new Uint8Array(h.match(/.{2}/g).map(x => parseInt(x, 16))); }

function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}
