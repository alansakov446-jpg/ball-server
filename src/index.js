import { neon } from '@neondatabase/serverless';

const enc = new TextEncoder();
const hex = (u8) => [...u8].map((x) => x.toString(16).padStart(2, '0')).join('');
const b64u = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const unb64u = (s) => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0));
const J = (o, s = 200) => new Response(JSON.stringify(o), { status: s, headers: { 'content-type': 'application/json' } });

async function hmac(keyBytes, data) {
  const k = await crypto.subtle.importKey('raw', keyBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return new Uint8Array(await crypto.subtle.sign('HMAC', k, enc.encode(data)));
}
function safeEq(a, b) {
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}

// Проверка подписи Telegram Mini App (initData). Без неё вход невозможен.
async function verifyInit(initData, botToken) {
  const p = new URLSearchParams(initData);
  const hash = p.get('hash');
  if (!hash) return null;
  p.delete('hash');
  const dcs = [...p.entries()].map(([k, v]) => k + '=' + v).sort().join('\n');
  const secret = await hmac(enc.encode('WebAppData'), botToken);
  if (!safeEq(hex(await hmac(secret, dcs)), hash)) return null;
  if (Date.now() / 1000 - Number(p.get('auth_date')) > 86400) return null;
  try { return JSON.parse(p.get('user')); } catch { return null; }
}

// Наш собственный токен сессии (подписан SESSION_SECRET).
async function sign(payload, secret) {
  const body = b64u(enc.encode(JSON.stringify(payload)));
  return body + '.' + b64u(await hmac(enc.encode(secret), body));
}
async function check(token, secret) {
  const [body, sig] = String(token || '').split('.');
  if (!body || !sig) return null;
  if (!safeEq(b64u(await hmac(enc.encode(secret), body)), sig)) return null;
  try {
    const p = JSON.parse(new TextDecoder().decode(unb64u(body)));
    return p.exp > Date.now() / 1000 ? p : null;
  } catch { return null; }
}

async function hashPw(pw, salt = crypto.getRandomValues(new Uint8Array(16))) {
  const k = await crypto.subtle.importKey('raw', enc.encode(pw), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: 100000 }, k, 256);
  return 'p1$' + b64u(salt) + '$' + b64u(bits);
}
async function verifyPw(pw, stored) {
  const parts = String(stored).split('$');
  if (parts.length !== 3) return false;
  return safeEq(await hashPw(pw, unb64u(parts[1])), stored);
}

async function profile(q, env, id) {
  const [u] = await q('select nick, nick_color, coins, (pass_hash is not null) as has_pw from users where tg_id = $1', [id]);
  return { id: String(id), nick: u.nick, nickColor: u.nick_color, coins: u.coins, hasPw: u.has_pw, isAdmin: String(id) === String(env.ADMIN_ID) };
}

async function route(req, env, url) {
  const path = url.pathname;

  if (path.startsWith('/ws/')) {
    const code = path.slice(4);
    if (!/^[A-Z0-9]{4,8}$/.test(code)) return J({ error: 'code' }, 400);
    const sess0 = await check(url.searchParams.get('t'), env.SESSION_SECRET);
    if (!sess0) return J({ error: 'auth' }, 401);
    const rows = await neon(env.DATABASE_URL).query('select nick, nick_color from users where tg_id = $1', [sess0.id]);
    const h = new Headers(req.headers);
    h.set('x-nick', encodeURIComponent((rows[0] && rows[0].nick) || 'Игрок'));
    h.set('x-color', (rows[0] && rows[0].nick_color) || '');
    h.set('x-join', url.searchParams.get('j') ? '1' : '');
    return env.ROOM.get(env.ROOM.idFromName(code)).fetch(new Request(req, { headers: h }));
  }

  const sql = neon(env.DATABASE_URL);
  const q = (t, p) => sql.query(t, p);

  if (path === '/api/auth' && req.method === 'POST') {
    const body = await req.json().catch(() => ({}));
    const u = await verifyInit(String(body.initData || ''), env.BOT_TOKEN);
    if (!u) return J({ error: 'bad_init' }, 401);
    await q('insert into users (tg_id, tg_name) values ($1, $2) on conflict (tg_id) do update set tg_name = $2', [u.id, u.first_name || '']);
    const token = await sign({ id: u.id, exp: Math.floor(Date.now() / 1000) + 7 * 86400 }, env.SESSION_SECRET);
    return J({ token, profile: await profile(q, env, u.id) });
  }

  const sess = await check((req.headers.get('authorization') || '').replace('Bearer ', ''), env.SESSION_SECRET);
  if (!sess) return J({ error: 'auth' }, 401);
  const id = sess.id;
  const isAdmin = String(id) === String(env.ADMIN_ID);
  const body = req.method === 'POST' ? await req.json().catch(() => ({})) : {};

  if (path === '/api/me') return J(await profile(q, env, id));

  if (path === '/api/nick') {
    const nick = String(body.nick || '');
    if (!/^[A-Za-z0-9_А-Яа-яЁё]{3,16}$/.test(nick)) return J({ error: 'nick_format' }, 400);
    if (!isAdmin && /^(admin|админ|moder|support|system|owner|владелец)/i.test(nick)) return J({ error: 'reserved' }, 400);
    try {
      await q('update users set nick = $1 where tg_id = $2', [nick, id]);
    } catch (e) {
      if (String(e.code) === '23505' || /duplicate|unique/i.test(String(e.message))) return J({ error: 'nick_taken' }, 409);
      throw e;
    }
    return J({ ok: true, nick });
  }

  if (path === '/api/password') {
    const pw = body.password;
    if (typeof pw !== 'string' || pw.length < 8 || pw.length > 64 || !/[A-ZА-ЯЁ]/.test(pw) || !/[^A-Za-zА-Яа-яЁё0-9]/.test(pw)) return J({ error: 'pw_rules' }, 400);
    const [u] = await q('select pass_hash from users where tg_id = $1', [id]);
    if (u.pass_hash && !(await verifyPw(String(body.old || ''), u.pass_hash))) return J({ error: 'pw_old' }, 403);
    await q('update users set pass_hash = $1 where tg_id = $2', [await hashPw(pw), id]);
    return J({ ok: true });
  }

  if (path === '/api/daily') {
    const r = await q('update users set coins = coins + 50, last_daily = current_date where tg_id = $1 and (last_daily is null or last_daily < current_date) returning coins', [id]);
    if (!r.length) return J({ error: 'already' }, 409);
    return J({ coins: r[0].coins, gain: 50 });
  }

  // Награда за победу. Клиент сам сообщает о победе, поэтому есть лимиты: 5 монет, не чаще раза в 45 сек, не больше 300 в день.
  if (path === '/api/reward') {
    if (!body.won) return J({ gain: 0 });
    const r = await q(
      `update users set coins = coins + 5,
         earned_today = case when earned_day = current_date then earned_today + 5 else 5 end,
         earned_day = current_date, last_reward = now()
       where tg_id = $1 and (last_reward is null or last_reward < now() - interval '45 seconds')
         and (earned_day is distinct from current_date or earned_today < 300)
       returning coins`, [id]);
    if (!r.length) return J({ gain: 0 });
    return J({ gain: 5, coins: r[0].coins });
  }

  if (path === '/api/admin/grant') {
    if (!isAdmin) return J({ error: 'forbidden' }, 403);
    const c = Math.max(-1e8, Math.min(1e8, Math.trunc(Number(body.coins) || 0)));
    const color = body.nickColor ? String(body.nickColor) : null;
    if (color && !/^(#[0-9a-fA-F]{6})(,#[0-9a-fA-F]{6}){0,2}$/.test(color)) return J({ error: 'color' }, 400);
    const r = body.target
      ? await q('update users set coins = greatest(0, coins + $1), nick_color = coalesce($3, nick_color) where lower(nick) = lower($2) returning nick, coins, nick_color', [c, String(body.target), color])
      : await q('update users set coins = greatest(0, coins + $1), nick_color = coalesce($3, nick_color) where tg_id = $2 returning nick, coins, nick_color', [c, id, color]);
    if (!r.length) return J({ error: 'not_found' }, 404);
    return J(r[0]);
  }

  return J({ error: 'not_found' }, 404);
}

export default {
  async fetch(req, env) {
    const cors = {
      'Access-Control-Allow-Origin': env.ALLOWED_ORIGIN,
      'Access-Control-Allow-Headers': 'content-type, authorization',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      Vary: 'Origin',
    };
    if (req.method === 'OPTIONS') return new Response(null, { headers: cors });
    try {
      const r = await route(req, env, new URL(req.url));
      if (r.status === 101) return r;
      const h = new Headers(r.headers);
      for (const [k, v] of Object.entries(cors)) h.set(k, v);
      return new Response(r.body, { status: r.status, headers: h });
    } catch (e) {
      console.error(e);
      return new Response(JSON.stringify({ error: 'server' }), { status: 500, headers: { ...cors, 'content-type': 'application/json' } });
    }
  },
};

// Комната до 5 игроков. Первый вошедший становится хостом (он считает игру), остальные шлют ему ввод.
// Каждое сообщение пересылается остальным в обёртке {"f":номер_места,"d":сообщение}.
export class Room {
  constructor(state) { this.state = state; }
  async fetch(req) {
    if (req.headers.get('Upgrade') !== 'websocket') return new Response('expected websocket', { status: 426 });
    const socks = this.state.getWebSockets();
    if (req.headers.get('x-join') && socks.length === 0) return new Response('no room', { status: 404 });
    if (socks.length >= 5) return new Response('room full', { status: 409 });
    const att = socks.map((w) => w.deserializeAttachment() || {});
    let slot = 0;
    while (att.some((a) => a.slot === slot)) slot++;
    const host = !att.some((a) => a.host);
    let nick = '';
    try { nick = decodeURIComponent(req.headers.get('x-nick') || ''); } catch { nick = ''; }
    nick = (nick || 'Игрок').slice(0, 16);
    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair);
    this.state.acceptWebSocket(server);
    server.serializeAttachment({ slot, host, nick });
    const roster = att.concat([{ slot, host, nick }]).map((a) => ({ s: a.slot, n: a.nick, h: a.host ? 1 : 0 }));
    server.send(JSON.stringify({ t: 'hello', slot, host, roster }));
    socks.forEach((o) => o.send(JSON.stringify({ t: 'join', s: slot, n: nick })));
    return new Response(null, { status: 101, webSocket: client });
  }
  webSocketMessage(ws, msg) {
    if (typeof msg !== 'string' || msg.length > 6000 || msg[0] !== '{') return;
    const a = ws.deserializeAttachment() || {};
    const out = '{"f":' + a.slot + ',"d":' + msg + '}';
    this.state.getWebSockets().forEach((o) => { if (o !== ws) o.send(out); });
  }
  webSocketClose(ws) {
    const a = ws.deserializeAttachment() || {};
    const rest = this.state.getWebSockets().filter((o) => o !== ws);
    if (a.host) rest.forEach((o) => { try { o.close(1000, 'host left'); } catch (e) {} });
    else rest.forEach((o) => o.send(JSON.stringify({ t: 'leave', s: a.slot })));
  }
  webSocketError(ws) { this.webSocketClose(ws); }
                                                                                   }
