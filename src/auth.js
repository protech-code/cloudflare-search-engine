import { createMiddleware } from 'hono/factory';
import { one, run } from './db.js';
import { randomHex } from './utils.js';

const SESSION_MS = 7 * 24 * 60 * 60 * 1000;
const encoder = new TextEncoder();

function toBase64Url(bytes) {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function fromBase64Url(value) {
  const base64 = value.replace(/-/g, '+').replace(/_/g, '/');
  const binary = atob(base64 + '='.repeat((4 - base64.length % 4) % 4));
  return Uint8Array.from(binary, char => char.charCodeAt(0));
}

async function sessionKey(secret) {
  if (!secret || secret.length < 32) throw new Error('SESSION_SECRET must contain at least 32 characters');
  return crypto.subtle.importKey('raw', encoder.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
}

async function signedId(id, secret) {
  const key = await sessionKey(secret);
  const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(id));
  return `${id}.${toBase64Url(new Uint8Array(signature))}`;
}

function readCookie(header, name) {
  const pair = header.split(';').map(part => part.trim()).find(part => part.startsWith(`${name}=`));
  return pair ? decodeURIComponent(pair.slice(name.length + 1)) : '';
}

function cookieHeader(value, secure, maxAge = SESSION_MS / 1000) {
  return `sid=${encodeURIComponent(value)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAge}${secure ? '; Secure' : ''}`;
}

async function createSession(db) {
  const id = randomHex(32);
  const csrf = randomHex(24);
  const expiresAt = Date.now() + SESSION_MS;
  await run(db, 'INSERT INTO sessions (id, csrf_token, expires_at) VALUES (?, ?, ?)', id, csrf, expiresAt);
  return { id, csrf_token: csrf, actor_type: null, actor_id: null, expires_at: expiresAt };
}

export const sessionMiddleware = createMiddleware(async (c, next) => {
  const secret = c.env.SESSION_SECRET;
  const cookie = readCookie(c.req.header('cookie') || '', 'sid');
  let session = null;
  if (cookie) {
    const [id, signature, extra] = cookie.split('.');
    if (id && signature && !extra) {
      try {
        const key = await sessionKey(secret);
        const valid = await crypto.subtle.verify('HMAC', key, fromBase64Url(signature), encoder.encode(id));
        if (valid) {
          session = await one(c.env.DB, 'SELECT * FROM sessions WHERE id = ? AND expires_at > ?', id, Date.now());
        }
      } catch (error) {
        if (error.message.includes('SESSION_SECRET')) throw error;
      }
    }
  }
  if (!session) {
    session = await createSession(c.env.DB);
    c.header('Set-Cookie', cookieHeader(await signedId(session.id, secret), new URL(c.req.url).protocol === 'https:'));
  }
  c.set('session', session);
  await next();
});

export async function rotateSession(c, actorType, actorId) {
  const current = c.get('session');
  await run(c.env.DB, 'DELETE FROM sessions WHERE id = ?', current.id);
  const session = await createSession(c.env.DB);
  await run(c.env.DB, 'UPDATE sessions SET actor_type = ?, actor_id = ? WHERE id = ?', actorType, actorId, session.id);
  const cookie = await signedId(session.id, c.env.SESSION_SECRET);
  c.header('Set-Cookie', cookieHeader(cookie, new URL(c.req.url).protocol === 'https:'));
  return { ...session, actor_type: actorType, actor_id: actorId };
}

export async function destroySession(c) {
  const session = c.get('session');
  await run(c.env.DB, 'DELETE FROM sessions WHERE id = ?', session.id);
  c.header('Set-Cookie', cookieHeader('', new URL(c.req.url).protocol === 'https:', 0));
}

export const csrfMiddleware = createMiddleware(async (c, next) => {
  if (c.req.method === 'POST') {
    const form = await c.req.raw.clone().formData();
    const supplied = form.get('csrf');
    const expected = c.get('session').csrf_token;
    if (typeof supplied !== 'string' || supplied.length !== expected.length) {
      return c.text('Invalid CSRF token', 403);
    }
    let diff = 0;
    for (let i = 0; i < expected.length; i++) diff |= expected.charCodeAt(i) ^ supplied.charCodeAt(i);
    if (diff !== 0) return c.text('Invalid CSRF token', 403);
  }
  await next();
});

export function requireActor(type) {
  return createMiddleware(async (c, next) => {
    const session = c.get('session');
    if (session.actor_type !== type || !session.actor_id) return c.redirect(type === 'admin' ? '/admin/login' : '/account/login', 303);
    const table = type === 'admin' ? 'admins' : 'users';
    const actor = await one(c.env.DB, `SELECT * FROM ${table} WHERE id = ? AND disabled = 0`, session.actor_id);
    if (!actor) {
      await destroySession(c);
      return c.redirect(type === 'admin' ? '/admin/login' : '/account/login', 303);
    }
    c.set('actor', actor);
    await next();
  });
}

export async function hashPassword(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const key = await crypto.subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: 210_000 }, key, 256);
  return `pbkdf2$210000$${toBase64Url(salt)}$${toBase64Url(new Uint8Array(bits))}`;
}

export async function verifyPassword(password, encoded) {
  const [algorithm, roundsText, saltText, hashText] = String(encoded).split('$');
  const rounds = Number(roundsText);
  if (algorithm !== 'pbkdf2' || !Number.isInteger(rounds) || rounds < 100_000 || rounds > 1_000_000 || !saltText || !hashText) return false;
  const key = await crypto.subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: fromBase64Url(saltText), iterations: rounds }, key, 256);
  const actual = new Uint8Array(bits);
  const expected = fromBase64Url(hashText);
  if (actual.length !== expected.length) return false;
  let diff = 0;
  for (let i = 0; i < actual.length; i++) diff |= actual[i] ^ expected[i];
  return diff === 0;
}

export async function hasPermission(db, admin, permission) {
  const role = await one(db, 'SELECT permissions FROM roles WHERE id = ?', admin.role_id);
  if (!role) return false;
  const permissions = JSON.parse(role.permissions);
  return permissions.includes('*') || permissions.includes(permission);
}
