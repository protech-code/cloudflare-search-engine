import { Hono } from 'hono';
import {
  csrfMiddleware, destroySession, hasPermission, hashPassword, requireActor, rotateSession,
  sessionMiddleware, verifyPassword,
} from './auth.js';
import { all, one, rateLimit, recordEvent, run } from './db.js';
import { consumeCrawlBatch, enqueueCrawl } from './crawler.js';
import { buildFtsQuery } from './search.js';
import { escapeHtml, form, htmlPage, notice } from './utils.js';

const app = new Hono();
app.use('*', sessionMiddleware);
app.use('*', csrfMiddleware);
app.use('*', async (c, next) => {
  const rows = await all(c.env.DB, 'SELECT key, value FROM settings');
  c.set('settings', Object.fromEntries(rows.map(row => [row.key, row.value])));
  await next();
});

function csrf(c) {
  return c.get('session').csrf_token;
}

function siteName(c) {
  return c.get('settings')?.siteName || c.env.SITE_NAME || 'MySearch';
}

function page(c, title, content, actor = null) {
  return c.html(htmlPage(title, content, { siteName: siteName(c), csrf: csrf(c), actor }));
}

function redirect(c, path, status = 303) {
  return c.redirect(path, status);
}

function adminPage(c, title, content, actor) {
  const nav = `<nav><a href="/admin">Dashboard</a> <a href="/admin/sources">Crawl sources</a> <a href="/admin/index">Index</a> <a href="/admin/keywords">Keywords</a> <a href="/admin/submissions">Submissions</a> <a href="/admin/roles">Roles</a> <a href="/admin/users">Accounts</a> <a href="/admin/settings">Settings</a> <a href="/admin/engine">Engine</a></nav>`;
  return c.html(htmlPage(title, `${nav}${content}`, { siteName: siteName(c), csrf: csrf(c), actor }));
}

async function turnstileOk(c, token) {
  const secret = c.env.TURNSTILE_SECRET_KEY;
  if (!secret) return true;
  if (!token || !c.env.TURNSTILE_SITE_KEY) return false;
  const body = new URLSearchParams({ secret, response: token, remoteip: c.req.header('cf-connecting-ip') || '' });
  const response = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', { method: 'POST', body });
  if (!response.ok) throw new Error(`Turnstile verification failed with HTTP ${response.status}`);
  const result = await response.json();
  return result.success === true;
}

async function searchPages(db, rawQuery, pageNumber = 1) {
  const { tokens, match } = buildFtsQuery(rawQuery);
  if (!tokens.length) return { total: 0, hits: [], tokens };
  const offset = (pageNumber - 1) * 10;
  const hits = await all(db, `
    SELECT p.url, p.domain, p.title, p.description,
      snippet(search_fts, 5, '', '', ' … ', 28) AS snippet
    FROM search_fts
    JOIN search_pages p ON p.id = search_fts.id
    WHERE search_fts MATCH ?
    ORDER BY bm25(search_fts), p.crawled_at DESC
    LIMIT 10 OFFSET ?
  `, match, offset);
  const count = await one(db, 'SELECT COUNT(*) AS total FROM search_fts WHERE search_fts MATCH ?', match);
  return { total: count.total, hits, tokens };
}

app.get('/', async c => {
  const popular = await all(c.env.DB, `
    SELECT q, COUNT(*) AS count FROM queries
    WHERE created_at >= datetime('now', '-30 days') AND length(q) BETWEEN 2 AND 60
    GROUP BY q ORDER BY count DESC LIMIT 8
  `);
  const content = `<section class="hero"><h1>${escapeHtml(siteName(c))}</h1>
    <p>Search indexed websites.</p>
    <form method="get" action="/search" class="search-form"><input name="q" aria-label="Search" placeholder="Search the web" required maxlength="200"><button>Search</button></form>
    <p><a href="/submit">Suggest a website</a></p></section>
    ${popular.length ? `<section><h2>Popular searches</h2><ul class="chips">${popular.map(row => `<li><a href="/search?q=${encodeURIComponent(row.q)}">${escapeHtml(row.q)}</a></li>`).join('')}</ul></section>` : ''}`;
  return page(c, 'Search', content);
});

app.get('/search', async c => {
  const query = (c.req.query('q') || '').trim().slice(0, 200);
  const pageNumber = Math.max(1, Math.min(50, Number.parseInt(c.req.query('page') || '1', 10) || 1));
  if (!query) return redirect(c, '/');
  try {
    const { total, hits } = await searchPages(c.env.DB, query, pageNumber);
    if (pageNumber === 1) await run(c.env.DB, 'INSERT INTO queries (q, results) VALUES (?, ?)', query.toLowerCase(), total);
    await recordEvent(c.env.DB, 'impression', hits, query);
    const results = (await Promise.all(hits.map(async hit =>
      `<article class="hit"><small>${escapeHtml(hit.domain)}</small><h2><a href="/go?u=${encodeURIComponent(hit.url)}&q=${encodeURIComponent(query)}&s=${await sign(c.env.SESSION_SECRET, `go:${hit.url}`)}">${escapeHtml(hit.title || hit.url)}</a></h2><p>${escapeHtml(hit.snippet || hit.description)}</p></article>`,
    ))).join('');
    const next = pageNumber < 50 && total > pageNumber * 10
      ? `<a href="/search?q=${encodeURIComponent(query)}&page=${pageNumber + 1}">Next page</a>` : '';
    const content = `<h1>Results for “${escapeHtml(query)}”</h1><p>${total.toLocaleString()} results</p>${results || '<p>No results yet. Add and crawl a website in the admin dashboard.</p>'}<div class="pager">${next}</div>`;
    return page(c, `Search: ${query}`, content);
  } catch (error) {
    console.error('search failed:', error);
    return page(c, 'Search unavailable', '<p class="error">Search is temporarily unavailable. Check the D1 database migration and try again.</p>');
  }
});

async function sign(secret, value) {
  if (!secret || secret.length < 32) throw new Error('SESSION_SECRET must contain at least 32 characters');
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const bytes = new Uint8Array(await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(value)));
  return [...bytes].map(byte => byte.toString(16).padStart(2, '0')).join('');
}

async function validSignature(secret, value, signature) {
  const expected = await sign(secret, value);
  if (expected.length !== signature.length) return false;
  let diff = 0;
  for (let i = 0; i < expected.length; i++) diff |= expected.charCodeAt(i) ^ signature.charCodeAt(i);
  return diff === 0;
}

app.get('/go', async c => {
  const raw = c.req.query('u') || '';
  const query = (c.req.query('q') || '').slice(0, 200);
  if (!await validSignature(c.env.SESSION_SECRET, `go:${raw}`, c.req.query('s') || '')) return c.text('Invalid result link', 400);
  let url;
  try {
    url = new URL(raw);
  } catch {
    return c.text('Invalid result link', 400);
  }
  if (!['http:', 'https:'].includes(url.protocol)) return c.text('Invalid result link', 400);
  await recordEvent(c.env.DB, 'click', [{ domain: url.hostname, url: url.href }], query);
  return c.redirect(url.href, 302);
});

app.get('/suggest', async c => {
  const query = (c.req.query('q') || '').trim().slice(0, 80);
  const { tokens, match } = buildFtsQuery(query);
  if (!tokens.length) return c.json([]);
  try {
    const suggestionMatch = tokens.slice(0, 4).map(token => `"${token.replaceAll('"', '""')}"*`).join(' AND ');
    const rows = await all(c.env.DB, 'SELECT title FROM search_fts WHERE search_fts MATCH ? LIMIT 8', suggestionMatch || match);
    return c.json(rows.map(row => row.title));
  } catch (error) {
    console.error('suggest failed:', error);
    return c.json({ error: 'Suggestions unavailable' }, 503);
  }
});

app.get('/submit', c => page(c, 'Submit a site', `<h1>Suggest a website</h1>${form('/submit', csrf(c),
  `<label>Website URL<input name="url" required maxlength="2000" placeholder="https://example.com"></label>
   <label>Contact email<input name="email" type="email" required maxlength="254"></label>
   ${c.env.TURNSTILE_SITE_KEY ? `<div class="cf-turnstile" data-sitekey="${escapeHtml(c.env.TURNSTILE_SITE_KEY)}"></div><script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>` : ''}`,
  'Submit')}`));

app.post('/submit', async c => {
  const ip = c.req.header('cf-connecting-ip') || 'unknown';
  if (!await rateLimit(c.env.DB, `site-submit:${ip}`, 5, 60 * 60 * 1000)) return c.text('Submission limit reached. Try again later.', 429);
  const body = await c.req.parseBody();
  if (!await turnstileOk(c, String(body['cf-turnstile-response'] || ''))) return page(c, 'Submit a site', notice('Captcha verification failed.', 'error'));
  const email = String(body.email || '').trim().toLowerCase();
  let url;
  try {
    url = new URL(/^https?:\/\//i.test(String(body.url || '')) ? String(body.url).trim() : `https://${String(body.url || '').trim()}`);
    if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || (url.port && !['80', '443'].includes(url.port))) throw new Error('Invalid URL');
  } catch {
    return page(c, 'Submit a site', notice('Enter a valid public website URL.', 'error'));
  }
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 254) return page(c, 'Submit a site', notice('Enter a valid email address.', 'error'));
  url.hash = '';
  const origin = url.origin;
  const existing = await one(c.env.DB, "SELECT 1 FROM sources WHERE origin = ? UNION SELECT 1 FROM submissions WHERE origin = ? AND status IN ('pending','approved') LIMIT 1", origin, origin);
  if (existing) return page(c, 'Submit a site', notice('This website has already been submitted or indexed.', 'error'));
  await run(c.env.DB, 'INSERT INTO submissions (url, origin, email, ip) VALUES (?, ?, ?, ?)', url.href, origin, email, c.req.header('cf-connecting-ip') || '');
  return page(c, 'Submit a site', notice('Thanks. Your submission is waiting for admin review.', 'success'));
});

app.get('/robots.txt', c => c.text('User-agent: *\nAllow: /\nSitemap: ' + (c.env.BASE_URL || new URL(c.req.url).origin) + '/sitemap.xml\n', 200, { 'Content-Type': 'text/plain; charset=utf-8' }));
app.get('/sitemap.xml', c => c.body(`<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc>${escapeHtml(c.env.BASE_URL || new URL(c.req.url).origin)}/</loc></url></urlset>`, 200, { 'Content-Type': 'application/xml; charset=utf-8' }));

app.get('/admin/setup', async c => {
  const count = await one(c.env.DB, 'SELECT COUNT(*) AS count FROM admins');
  if (count.count) return redirect(c, '/admin/login');
  if (!c.env.BOOTSTRAP_TOKEN) return page(c, 'Admin setup disabled', notice('Set BOOTSTRAP_TOKEN as a Worker secret to create the first administrator.', 'error'));
  return page(c, 'Create administrator', `<h1>Create the first administrator</h1>${form('/admin/setup', csrf(c),
    `<label>Setup token<input name="token" type="password" required></label>
     <label>Username<input name="username" required minlength="3" maxlength="32" pattern="[A-Za-z0-9._-]+"></label>
     <label>Password<input name="password" type="password" required minlength="12" maxlength="200"></label>`,
    'Create administrator')}`);
});

app.post('/admin/setup', async c => {
  const ip = c.req.header('cf-connecting-ip') || 'unknown';
  if (!await rateLimit(c.env.DB, `admin-setup:${ip}`, 5, 60 * 60 * 1000)) return c.text('Setup limit reached.', 429);
  const body = await c.req.parseBody();
  const count = await one(c.env.DB, 'SELECT COUNT(*) AS count FROM admins');
  if (count.count || !c.env.BOOTSTRAP_TOKEN || String(body.token || '') !== c.env.BOOTSTRAP_TOKEN) return c.text('Admin setup denied', 403);
  const username = String(body.username || '').trim();
  const password = String(body.password || '');
  if (!/^[A-Za-z0-9._-]{3,32}$/.test(username) || password.length < 12 || password.length > 200) {
    return page(c, 'Create administrator', notice('Invalid username or password. Use at least 12 characters for the password.', 'error'));
  }
  const passwordHash = await hashPassword(password);
  const role = await one(c.env.DB, "SELECT id FROM roles WHERE name = 'superadmin'");
  await run(c.env.DB, 'INSERT INTO admins (username, password_hash, role_id) VALUES (?, ?, ?)', username, passwordHash, role.id);
  return redirect(c, '/admin/login');
});

app.get('/admin/login', c => page(c, 'Admin login', `<h1>Admin login</h1>${form('/admin/login', csrf(c),
  `<label>Username<input name="username" required autocomplete="username"></label><label>Password<input type="password" name="password" required autocomplete="current-password"></label>
   ${c.env.TURNSTILE_SITE_KEY ? `<div class="cf-turnstile" data-sitekey="${escapeHtml(c.env.TURNSTILE_SITE_KEY)}"></div><script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>` : ''}`,
  'Log in')}`));

app.post('/admin/login', async c => {
  const body = await c.req.parseBody();
  const ip = c.req.header('cf-connecting-ip') || 'unknown';
  if (!await rateLimit(c.env.DB, `admin-login:${ip}`, 10, 15 * 60 * 1000)) return c.text('Too many login attempts', 429);
  if (!await turnstileOk(c, String(body['cf-turnstile-response'] || ''))) return page(c, 'Admin login', notice('Captcha verification failed.', 'error'));
  const admin = await one(c.env.DB, 'SELECT * FROM admins WHERE username = ? COLLATE NOCASE', String(body.username || '').trim());
  if (!admin || admin.disabled || !await verifyPassword(String(body.password || ''), admin.password_hash)) {
    return page(c, 'Admin login', notice('Invalid username or password.', 'error'));
  }
  await run(c.env.DB, 'UPDATE admins SET last_login_at = CURRENT_TIMESTAMP WHERE id = ?', admin.id);
  await rotateSession(c, 'admin', admin.id);
  return redirect(c, '/admin');
});

app.get('/account/login', c => page(c, 'Site owner login', `<h1>Site owner login</h1>${form('/account/login', csrf(c),
  `<label>Email<input type="email" name="email" required autocomplete="email"></label><label>Password<input type="password" name="password" required autocomplete="current-password"></label>
   ${c.env.TURNSTILE_SITE_KEY ? `<div class="cf-turnstile" data-sitekey="${escapeHtml(c.env.TURNSTILE_SITE_KEY)}"></div><script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>` : ''}`,
  'Log in')}<p><a href="/account/register">Create an account</a></p>`));

app.get('/account/register', c => page(c, 'Create account', `<h1>Create a site owner account</h1>${form('/account/register', csrf(c),
  `<label>Email<input type="email" name="email" required maxlength="254"></label><label>Password<input type="password" name="password" required minlength="10" maxlength="200"></label>
   ${c.env.TURNSTILE_SITE_KEY ? `<div class="cf-turnstile" data-sitekey="${escapeHtml(c.env.TURNSTILE_SITE_KEY)}"></div><script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>` : ''}`,
  'Register')}<p><a href="/account/login">Already registered?</a></p>`));

app.post('/account/register', async c => {
  const ip = c.req.header('cf-connecting-ip') || 'unknown';
  if (!await rateLimit(c.env.DB, `account-register:${ip}`, 10, 60 * 60 * 1000)) return c.text('Registration limit reached.', 429);
  const body = await c.req.parseBody();
  if (!await turnstileOk(c, String(body['cf-turnstile-response'] || ''))) return page(c, 'Create account', notice('Captcha verification failed.', 'error'));
  const email = String(body.email || '').trim().toLowerCase(), password = String(body.password || '');
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 254 || password.length < 10 || password.length > 200) {
    return page(c, 'Create account', notice('Enter a valid email and a password of at least 10 characters.', 'error'));
  }
  try {
    const result = await run(c.env.DB, 'INSERT INTO users (email, password_hash) VALUES (?, ?) RETURNING id', email, await hashPassword(password));
    await rotateSession(c, 'user', result.results[0].id);
    return redirect(c, '/account');
  } catch (error) {
    if (error.message.includes('UNIQUE')) return page(c, 'Create account', notice('An account with this email already exists.', 'error'));
    throw error;
  }
});

app.post('/account/login', async c => {
  const body = await c.req.parseBody();
  const ip = c.req.header('cf-connecting-ip') || 'unknown';
  if (!await rateLimit(c.env.DB, `account-login:${ip}`, 10, 15 * 60 * 1000)) return c.text('Too many login attempts', 429);
  if (!await turnstileOk(c, String(body['cf-turnstile-response'] || ''))) return page(c, 'Site owner login', notice('Captcha verification failed.', 'error'));
  const user = await one(c.env.DB, 'SELECT * FROM users WHERE email = ? COLLATE NOCASE', String(body.email || '').trim());
  if (!user || user.disabled || !await verifyPassword(String(body.password || ''), user.password_hash)) return page(c, 'Site owner login', notice('Invalid email or password.', 'error'));
  await run(c.env.DB, 'UPDATE users SET last_login_at = CURRENT_TIMESTAMP WHERE id = ?', user.id);
  await rotateSession(c, 'user', user.id);
  return redirect(c, '/account');
});

app.post('/logout', async c => {
  await destroySession(c);
  return redirect(c, '/');
});

app.use('/admin', requireActor('admin'));
app.use('/admin/*', requireActor('admin'));
app.use('/account', requireActor('user'));
app.use('/account/*', requireActor('user'));

function permission(permissionName) {
  return async (c, next) => {
    if (!await hasPermission(c.env.DB, c.get('actor'), permissionName)) return c.text('Forbidden', 403);
    await next();
  };
}

function adminForm(c, action, fields, submit) {
  return form(action, csrf(c), fields, submit);
}

app.get('/admin', permission('dashboard.view'), async c => {
  const actor = c.get('actor');
  const [sources, pages, queries, pending] = await Promise.all([
    one(c.env.DB, 'SELECT COUNT(*) AS n FROM sources'),
    one(c.env.DB, 'SELECT COUNT(*) AS n FROM search_pages'),
    one(c.env.DB, 'SELECT COUNT(*) AS n FROM queries'),
    one(c.env.DB, "SELECT COUNT(*) AS n FROM submissions WHERE status = 'pending'"),
  ]);
  const top = await all(c.env.DB, `
    SELECT q, COUNT(*) AS n FROM queries
    WHERE lower(q) NOT IN (SELECT lower(q) FROM keywords WHERE kind = 'blocked')
    GROUP BY q ORDER BY n DESC LIMIT 10
  `);
  return adminPage(c, 'Admin dashboard', `<h1>Dashboard</h1><div class="stats"><div>Sources <b>${sources.n}</b></div><div>Indexed pages <b>${pages.n}</b></div><div>Searches <b>${queries.n}</b></div><div>Pending submissions <b>${pending.n}</b></div></div><h2>Popular searches</h2><ul>${top.map(row => `<li>${escapeHtml(row.q)} (${row.n})</li>`).join('') || '<li>No searches yet.</li>'}</ul>`, actor);
});

app.get('/admin/sources', permission('sources.manage'), async c => {
  const actor = c.get('actor');
  const sources = await all(c.env.DB, 'SELECT * FROM sources ORDER BY id DESC');
  const rows = sources.map(source => `<tr><td>${escapeHtml(source.url)}</td><td>${escapeHtml(source.status)}</td><td>${source.pages_crawled}/${source.max_pages}</td><td>${escapeHtml(source.last_error || '')}</td><td>${adminForm(c, `/admin/sources/${source.id}/crawl`, '', 'Crawl / recrawl')}${adminForm(c, `/admin/sources/${source.id}/delete`, '', 'Delete')}</td></tr>`).join('');
  const fields = `<label>Website URL<input name="url" type="url" placeholder="https://example.com" required></label><label>Maximum pages<input name="max_pages" type="number" value="50" min="1" max="2000" required></label>`;
  return adminPage(c, 'Crawl sources', `<h1>Crawl sources</h1>${adminForm(c, '/admin/sources', fields, 'Add source')}<table><thead><tr><th>URL</th><th>Status</th><th>Pages</th><th>Last error</th><th>Actions</th></tr></thead><tbody>${rows}</tbody></table>`, actor);
});

app.post('/admin/sources', permission('sources.manage'), async c => {
  const body = await c.req.parseBody();
  try {
    const url = new URL(String(body.url || '').trim());
    if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || (url.port && !['80', '443'].includes(url.port))) throw new Error('Invalid URL');
    const max = Math.min(Math.max(Number.parseInt(String(body.max_pages), 10) || 50, 1), 2000);
    await run(c.env.DB, 'INSERT INTO sources (url, origin, max_pages) VALUES (?, ?, ?)', url.href, url.origin, max);
    return redirect(c, '/admin/sources');
  } catch (error) {
    if (error.message.includes('UNIQUE')) return page(c, 'Crawl sources', notice('This source is already configured.', 'error'));
    return page(c, 'Crawl sources', notice('Enter a valid HTTP or HTTPS URL.', 'error'));
  }
});

app.post('/admin/sources/:id/crawl', permission('sources.manage'), async c => {
  const source = await one(c.env.DB, 'SELECT * FROM sources WHERE id = ?', Number(c.req.param('id')));
  if (!source) return c.notFound();
  if (source.status === 'running') return redirect(c, '/admin/sources');
  await enqueueCrawl(c.env, source);
  return redirect(c, '/admin/sources');
});

app.post('/admin/sources/:id/delete', permission('sources.manage'), async c => {
  const source = await one(c.env.DB, 'SELECT * FROM sources WHERE id = ?', Number(c.req.param('id')));
  if (source) {
    const domain = new URL(source.url).hostname;
    await c.env.DB.batch([
      c.env.DB.prepare('DELETE FROM search_fts WHERE domain = ?').bind(domain),
      c.env.DB.prepare('DELETE FROM search_pages WHERE domain = ?').bind(domain),
      c.env.DB.prepare('DELETE FROM sources WHERE id = ?').bind(source.id),
    ]);
  }
  return redirect(c, '/admin/sources');
});

app.get('/admin/index', permission('index.manage'), async c => {
  const actor = c.get('actor'), query = (c.req.query('q') || '').trim().slice(0, 100);
  const pages = query
    ? await all(c.env.DB, 'SELECT id, url, title, domain FROM search_pages WHERE instr(lower(title), lower(?)) > 0 OR instr(lower(domain), lower(?)) > 0 ORDER BY crawled_at DESC LIMIT 100', query, query)
    : await all(c.env.DB, 'SELECT id, url, title, domain FROM search_pages ORDER BY crawled_at DESC LIMIT 100');
  const rows = pages.map(hit => `<tr><td>${escapeHtml(hit.title)}</td><td>${escapeHtml(hit.domain)}</td><td><a href="${escapeHtml(hit.url)}" rel="nofollow">${escapeHtml(hit.url)}</a></td><td>${adminForm(c, `/admin/index/${encodeURIComponent(hit.id)}/delete`, '', 'Delete')}</td></tr>`).join('');
  const filter = `<form method="get" action="/admin/index"><label>Filter<input name="q" value="${escapeHtml(query)}"></label><button>Filter</button></form>`;
  const clear = adminForm(c, '/admin/index/clear', '', 'Clear entire index');
  return adminPage(c, 'Search index', `<h1>Indexed pages</h1>${filter}${clear}<p class="warning">Clear deletes every indexed document.</p><table><thead><tr><th>Title</th><th>Domain</th><th>URL</th><th></th></tr></thead><tbody>${rows}</tbody></table>`, actor);
});

app.post('/admin/index/:id/delete', permission('index.manage'), async c => {
  const id = c.req.param('id');
  await c.env.DB.batch([
    c.env.DB.prepare('DELETE FROM search_fts WHERE id = ?').bind(id),
    c.env.DB.prepare('DELETE FROM search_pages WHERE id = ?').bind(id),
  ]);
  return redirect(c, '/admin/index');
});

app.post('/admin/index/clear', permission('index.manage'), async c => {
  await c.env.DB.batch([c.env.DB.prepare('DELETE FROM search_fts'), c.env.DB.prepare('DELETE FROM search_pages')]);
  return redirect(c, '/admin/index');
});

app.get('/admin/keywords', permission('keywords.manage'), async c => {
  const actor = c.get('actor'), keywords = await all(c.env.DB, 'SELECT * FROM keywords ORDER BY id DESC');
  const rows = keywords.map(row => `<li><strong>${escapeHtml(row.kind)}</strong> ${escapeHtml(row.q)} ${adminForm(c, `/admin/keywords/${row.id}/delete`, '', 'Delete')}</li>`).join('');
  const fields = `<label>Keyword<input name="q" required maxlength="60"></label><label>Type<select name="kind"><option value="pinned">Pinned</option><option value="blocked">Blocked</option></select></label>`;
  return adminPage(c, 'Keywords', `<h1>Keyword management</h1>${adminForm(c, '/admin/keywords', fields, 'Save keyword')}<ul>${rows}</ul>`, actor);
});

app.post('/admin/keywords', permission('keywords.manage'), async c => {
  const body = await c.req.parseBody(), query = String(body.q || '').trim().replace(/\s+/g, ' ').slice(0, 60);
  if (!query) return redirect(c, '/admin/keywords');
  const kind = body.kind === 'blocked' ? 'blocked' : 'pinned';
  await run(c.env.DB, 'INSERT INTO keywords (q, kind) VALUES (?, ?) ON CONFLICT(q) DO UPDATE SET kind = excluded.kind', query, kind);
  return redirect(c, '/admin/keywords');
});

app.post('/admin/keywords/:id/delete', permission('keywords.manage'), async c => {
  await run(c.env.DB, 'DELETE FROM keywords WHERE id = ?', Number(c.req.param('id')));
  return redirect(c, '/admin/keywords');
});

app.get('/admin/submissions', permission('submissions.manage'), async c => {
  const actor = c.get('actor');
  const submissions = await all(c.env.DB, "SELECT * FROM submissions ORDER BY CASE status WHEN 'pending' THEN 0 ELSE 1 END, created_at DESC LIMIT 200");
  const rows = submissions.map(row => `<tr><td>${escapeHtml(row.url)}</td><td>${escapeHtml(row.email)}</td><td>${escapeHtml(row.status)}</td><td>${row.status === 'pending' ? `${adminForm(c, `/admin/submissions/${row.id}/approve`, '', 'Approve')}${adminForm(c, `/admin/submissions/${row.id}/reject`, '', 'Reject')}` : ''}</td></tr>`).join('');
  return adminPage(c, 'Site submissions', `<h1>Site submissions</h1><table><thead><tr><th>URL</th><th>Contact</th><th>Status</th><th>Actions</th></tr></thead><tbody>${rows}</tbody></table>`, actor);
});

app.post('/admin/submissions/:id/approve', permission('submissions.manage'), async c => {
  const submission = await one(c.env.DB, "SELECT * FROM submissions WHERE id = ? AND status = 'pending'", Number(c.req.param('id')));
  if (submission) {
    const result = await run(c.env.DB, 'INSERT INTO sources (url, origin, max_pages) VALUES (?, ?, 50) ON CONFLICT(url) DO UPDATE SET origin = excluded.origin RETURNING id', submission.url, submission.origin);
    const source = await one(c.env.DB, 'SELECT * FROM sources WHERE id = ?', result.results[0].id);
    await run(c.env.DB, "UPDATE submissions SET status = 'approved' WHERE id = ?", submission.id);
    await enqueueCrawl(c.env, source);
  }
  return redirect(c, '/admin/submissions');
});

app.post('/admin/submissions/:id/reject', permission('submissions.manage'), async c => {
  await run(c.env.DB, "UPDATE submissions SET status = 'rejected' WHERE id = ? AND status = 'pending'", Number(c.req.param('id')));
  return redirect(c, '/admin/submissions');
});

app.get('/admin/engine', permission('engine.view'), async c => {
  const actor = c.get('actor');
  const [pages, index] = await Promise.all([
    one(c.env.DB, 'SELECT COUNT(*) AS n FROM search_pages'),
    one(c.env.DB, 'SELECT COUNT(*) AS n FROM search_fts'),
  ]);
  return adminPage(c, 'Search engine status', `<h1>Search engine status</h1><p>Provider: Cloudflare D1 + FTS5</p><p>Indexed records: ${pages.n}</p><p>Full-text records: ${index.n}</p>`, actor);
});

app.get('/admin/settings', permission('seo.manage'), async c => {
  const actor = c.get('actor'), settings = c.get('settings') || {};
  const fields = `<label>Site name<input name="siteName" maxlength="100" value="${escapeHtml(settings.siteName || c.env.SITE_NAME || 'MySearch')}"></label>
    <label>Description<input name="siteDescription" maxlength="300" value="${escapeHtml(settings.siteDescription || '')}"></label>
    <label>Default language<select name="defaultLang"><option value="en">English</option><option value="vi" ${settings.defaultLang === 'vi' ? 'selected' : ''}>Tiếng Việt</option></select></label>`;
  return adminPage(c, 'Settings', `<h1>Site settings</h1>${adminForm(c, '/admin/settings', fields, 'Save settings')}`, actor);
});

app.post('/admin/settings', permission('seo.manage'), async c => {
  const body = await c.req.parseBody();
  const allowed = ['siteName', 'siteDescription', 'defaultLang'];
  await c.env.DB.batch(allowed.map(key => c.env.DB.prepare('INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value').bind(key, String(body[key] || '').slice(0, 300))));
  return redirect(c, '/admin/settings');
});

app.get('/admin/roles', permission('roles.manage'), async c => {
  const actor = c.get('actor'), roles = await all(c.env.DB, 'SELECT * FROM roles ORDER BY id');
  const permissions = ['dashboard.view', 'sources.manage', 'index.manage', 'keywords.manage', 'submissions.manage', 'sites.manage', 'seo.manage', 'appearance.manage', 'engine.view', 'roles.manage', 'accounts.manage'];
  const fields = `<label>Role name<input name="name" pattern="[a-z0-9_-]+" required maxlength="32"></label>${permissions.map(item => `<label class="check"><input type="checkbox" name="permissions" value="${item}">${item}</label>`).join('')}`;
  const rows = roles.map(role => `<li>${escapeHtml(role.name)}: ${escapeHtml(role.permissions)}</li>`).join('');
  return adminPage(c, 'Roles', `<h1>Roles</h1><ul>${rows}</ul><h2>Create role</h2>${adminForm(c, '/admin/roles', fields, 'Create role')}`, actor);
});

app.post('/admin/roles', permission('roles.manage'), async c => {
  const body = await c.req.raw.clone().formData(), name = String(body.get('name') || '').trim();
  const permissions = body.getAll('permissions').map(String).filter(value => /^[a-z.]+$/.test(value));
  if (!/^[a-z0-9_-]{2,32}$/.test(name) || !permissions.length) return c.text('Invalid role', 400);
  await run(c.env.DB, 'INSERT INTO roles (name, permissions) VALUES (?, ?)', name, JSON.stringify([...new Set(permissions)]));
  return redirect(c, '/admin/roles');
});

app.get('/admin/users', permission('accounts.manage'), async c => {
  const actor = c.get('actor');
  const [admins, users, roles] = await Promise.all([
    all(c.env.DB, 'SELECT a.id, a.username, a.disabled, r.name AS role FROM admins a JOIN roles r ON r.id = a.role_id ORDER BY a.id'),
    all(c.env.DB, 'SELECT id, email, disabled FROM users ORDER BY id DESC LIMIT 200'),
    all(c.env.DB, 'SELECT id, name FROM roles ORDER BY id'),
  ]);
  const adminRows = admins.map(a => `<tr><td>${escapeHtml(a.username)}</td><td>${escapeHtml(a.role)}</td><td>${a.disabled ? 'Disabled' : 'Active'}</td><td>${a.id === actor.id ? 'Current account' : adminForm(c, `/admin/users/admin/${a.id}/toggle`, '', a.disabled ? 'Enable' : 'Disable')}</td></tr>`).join('');
  const userRows = users.map(u => `<tr><td>${escapeHtml(u.email)}</td><td>${u.disabled ? 'Disabled' : 'Active'}</td><td>${adminForm(c, `/admin/users/user/${u.id}/toggle`, '', u.disabled ? 'Enable' : 'Disable')}</td></tr>`).join('');
  const fields = `<label>Username<input name="username" required minlength="3" maxlength="32"></label><label>Password<input name="password" type="password" required minlength="12" maxlength="200"></label><label>Role<select name="role_id">${roles.map(role => `<option value="${role.id}">${escapeHtml(role.name)}</option>`).join('')}</select></label>`;
  return adminPage(c, 'Accounts', `<h1>Administrators</h1>${adminForm(c, '/admin/users/admin', fields, 'Create administrator')}<table><thead><tr><th>Username</th><th>Role</th><th>Status</th><th></th></tr></thead><tbody>${adminRows}</tbody></table><h1>Site owner accounts</h1><table><thead><tr><th>Email</th><th>Status</th><th></th></tr></thead><tbody>${userRows}</tbody></table>`, actor);
});

app.post('/admin/users/admin', permission('accounts.manage'), async c => {
  const body = await c.req.parseBody(), username = String(body.username || '').trim(), password = String(body.password || '');
  const roleId = Number(body.role_id), role = await one(c.env.DB, 'SELECT id FROM roles WHERE id = ?', roleId);
  if (!role || !/^[A-Za-z0-9._-]{3,32}$/.test(username) || password.length < 12 || password.length > 200) return c.text('Invalid administrator data', 400);
  await run(c.env.DB, 'INSERT INTO admins (username, password_hash, role_id) VALUES (?, ?, ?)', username, await hashPassword(password), roleId);
  return redirect(c, '/admin/users');
});

app.post('/admin/users/:type/:id/toggle', permission('accounts.manage'), async c => {
  const type = c.req.param('type'), id = Number(c.req.param('id'));
  if (type === 'admin' && id === c.get('actor').id) return c.text('Cannot disable your own account', 400);
  if (!['admin', 'user'].includes(type)) return c.text('Invalid account type', 400);
  await run(c.env.DB, `UPDATE ${type === 'admin' ? 'admins' : 'users'} SET disabled = CASE disabled WHEN 0 THEN 1 ELSE 0 END WHERE id = ?`, id);
  return redirect(c, '/admin/users');
});

app.get('/account', async c => {
  const actor = c.get('actor'), sites = await all(c.env.DB, 'SELECT * FROM sites WHERE user_id = ? ORDER BY id DESC', actor.id);
  const rows = sites.map(site => `<li><a href="/account/sites/${site.id}">${escapeHtml(site.origin)}</a> — ${site.verified_at ? 'Verified' : 'Not verified'}</li>`).join('');
  const fields = `<label>Website URL<input name="url" type="url" required placeholder="https://example.com"></label>`;
  return page(c, 'My sites', `<h1>Site owner dashboard</h1><p>Signed in as ${escapeHtml(actor.email)}</p>${form('/account/sites', csrf(c), fields, 'Add website')}<ul>${rows || '<li>No websites added.</li>'}</ul>`, actor);
});

app.post('/account/sites', async c => {
  const actor = c.get('actor'), body = await c.req.parseBody();
  try {
    const raw = String(body.url || '').trim(), origin = new URL(/^https?:\/\//i.test(raw) ? raw : `https://${raw}`).origin;
    const host = new URL(origin).hostname, token = crypto.randomUUID().replaceAll('-', '');
    await run(c.env.DB, 'INSERT INTO sites (user_id, origin, host, verify_token) VALUES (?, ?, ?, ?)', actor.id, origin, host, token);
    return redirect(c, '/account');
  } catch (error) {
    if (error.message.includes('UNIQUE')) return page(c, 'My sites', notice('You already added this website.', 'error'), actor);
    return page(c, 'My sites', notice('Enter a valid website URL.', 'error'), actor);
  }
});

async function ownedSite(c) {
  return one(c.env.DB, 'SELECT * FROM sites WHERE id = ? AND user_id = ?', Number(c.req.param('id')), c.get('actor').id);
}

app.get('/account/sites/:id', async c => {
  const site = await ownedSite(c);
  if (!site) return c.notFound();
  const actor = c.get('actor');
  const instructions = `<p>Add <code>&lt;meta name="mysearch-verification" content="${escapeHtml(site.verify_token)}"&gt;</code> to your home page, or create <code>mysearch-${escapeHtml(site.verify_token)}.html</code> with exactly this content: <code>mysearch-verification: ${escapeHtml(site.verify_token)}</code>.</p>`;
  const verify = site.verified_at ? '<p class="success">Website verified.</p>' : `${instructions}${form(`/account/sites/${site.id}/verify`, csrf(c), '<label>Verification method<select name="method"><option value="meta">Meta tag</option><option value="file">HTML file</option><option value="dns">DNS TXT</option></select></label>', 'Verify ownership')}`;
  const source = await one(c.env.DB, 'SELECT * FROM sources WHERE origin = ?', site.origin);
  const indexed = await one(c.env.DB, 'SELECT COUNT(*) AS n FROM search_pages WHERE domain = ?', site.host);
  const pageList = await all(c.env.DB, 'SELECT url, title FROM search_pages WHERE domain = ? ORDER BY crawled_at DESC LIMIT 50', site.host);
  const errors = await all(c.env.DB, 'SELECT url, reason FROM crawl_errors WHERE host = ? ORDER BY id DESC LIMIT 20', site.host);
  const analytics = await one(c.env.DB, `
    SELECT COUNT(*) FILTER (WHERE type = 'impression') AS impressions,
      COUNT(*) FILTER (WHERE type = 'click') AS clicks
    FROM events WHERE domain = ? AND created_at >= datetime('now', '-28 days')
  `, site.host);
  const topQueries = await all(c.env.DB, `
    SELECT q, COUNT(*) FILTER (WHERE type = 'impression') AS impressions,
      COUNT(*) FILTER (WHERE type = 'click') AS clicks
    FROM events WHERE domain = ? AND created_at >= datetime('now', '-28 days')
    GROUP BY q ORDER BY impressions DESC, clicks DESC LIMIT 10
  `, site.host);
  const actions = site.verified_at && source ? `${form(`/account/sites/${site.id}/crawl`, csrf(c), '', 'Request recrawl')}
    ${form(`/account/sites/${site.id}/sitemap`, csrf(c), '<label>Sitemap URL<input name="sitemap" type="url" placeholder="https://example.com/sitemap.xml"></label>', 'Save sitemap')}
    <p>Crawl status: ${escapeHtml(source.status)} · indexed: ${indexed.n} · pages this run: ${source.pages_crawled}/${source.max_pages}</p>` : '';
  const analyticsView = site.verified_at
    ? `<h2>Last 28 days</h2><p>Impressions: ${analytics.impressions} · Clicks: ${analytics.clicks}</p><ul>${topQueries.map(row => `<li>${escapeHtml(row.q)} — ${row.impressions} impressions / ${row.clicks} clicks</li>`).join('')}</ul>`
    : '';
  const indexedPages = pageList.length ? `<h2>Indexed pages</h2><ul>${pageList.map(row => `<li><a href="${escapeHtml(row.url)}" rel="nofollow">${escapeHtml(row.title || row.url)}</a></li>`).join('')}</ul>` : '';
  return page(c, site.origin, `<h1>${escapeHtml(site.origin)}</h1>${verify}${actions}${analyticsView}${indexedPages}<h2>Crawl errors</h2><ul>${errors.map(error => `<li>${escapeHtml(error.reason)} — ${escapeHtml(error.url)}</li>`).join('')}</ul>${form(`/account/sites/${site.id}/delete`, csrf(c), '', 'Remove site and indexed data')}`, actor);
});

app.post('/account/sites/:id/verify', async c => {
  const site = await ownedSite(c);
  if (!site || site.verified_at) return c.notFound();
  const body = await c.req.parseBody(), method = String(body.method || 'meta');
  let verified = false;
  try {
    if (method === 'dns') {
      const dnsUrl = new URL('https://cloudflare-dns.com/dns-query');
      dnsUrl.searchParams.set('name', site.host);
      dnsUrl.searchParams.set('type', 'TXT');
      const response = await fetch(dnsUrl, { headers: { accept: 'application/dns-json' } });
      if (!response.ok) throw new Error(`DNS verification HTTP ${response.status}`);
      const data = await response.json();
      verified = (data.Answer || []).some(answer => String(answer.data).replace(/^"|"$/g, '').replaceAll('" "', '') === `mysearch-verification=${site.verify_token}`);
    } else if (method === 'meta' || method === 'file') {
      const target = method === 'meta' ? `${site.origin}/` : `${site.origin}/mysearch-${site.verify_token}.html`;
      const response = await safeFetch(target, 100_000);
      if (!response.ok) throw new Error(`Verification HTTP ${response.status}`);
      if (new URL(response.headers.get('x-mysearch-final-url') || target).origin !== site.origin) throw new Error('Verification redirected to another origin');
      const text = await response.text();
      if (method === 'meta') {
        let found = false;
        await new HTMLRewriter().on('meta[name="mysearch-verification"]', {
          element(element) { if (element.getAttribute('content') === site.verify_token) found = true; },
        }).transform(new Response(text)).text();
        verified = found;
      } else {
        verified = text.trim() === `mysearch-verification: ${site.verify_token}`;
      }
    }
  } catch (error) {
    console.error('site ownership verification failed:', error);
  }
  if (!verified) return page(c, site.origin, notice('Verification failed. Check the token and try again.', 'error'), c.get('actor'));
  await run(c.env.DB, 'UPDATE sites SET verified_at = CURRENT_TIMESTAMP, verify_method = ? WHERE id = ?', method, site.id);
  const sourceUrl = `${site.origin}/`;
  const result = await run(c.env.DB, 'INSERT INTO sources (url, origin, max_pages) VALUES (?, ?, ?) ON CONFLICT(url) DO UPDATE SET origin = excluded.origin RETURNING id', sourceUrl, site.origin, Number(c.env.VERIFIED_MAX_PAGES) || 200);
  const source = await one(c.env.DB, 'SELECT * FROM sources WHERE id = ?', result.results[0].id);
  await enqueueCrawl(c.env, source);
  return redirect(c, `/account/sites/${site.id}`);
});

app.post('/account/sites/:id/crawl', async c => {
  const site = await ownedSite(c);
  if (!site || !site.verified_at) return c.notFound();
  const source = await one(c.env.DB, 'SELECT * FROM sources WHERE origin = ?', site.origin);
  if (!source) return c.notFound();
  if (source.crawl_requested_at && Date.now() - source.crawl_requested_at < 6 * 60 * 60 * 1000) {
    return page(c, site.origin, notice('Please wait before requesting another crawl.', 'error'), c.get('actor'));
  }
  if (source.status !== 'running') await enqueueCrawl(c.env, source);
  return redirect(c, `/account/sites/${site.id}`);
});

app.post('/account/sites/:id/sitemap', async c => {
  const site = await ownedSite(c);
  if (!site || !site.verified_at) return c.notFound();
  const body = await c.req.parseBody(), sitemap = String(body.sitemap || '').trim();
  try {
    if (sitemap) {
      const url = new URL(sitemap);
      if (url.hostname !== site.host || !['http:', 'https:'].includes(url.protocol)) throw new Error();
    }
  } catch {
    return page(c, site.origin, notice('Sitemap must be a valid URL on this website.', 'error'), c.get('actor'));
  }
  await run(c.env.DB, 'UPDATE sources SET sitemap_url = ? WHERE origin = ?', sitemap || null, site.origin);
  return redirect(c, `/account/sites/${site.id}`);
});

app.post('/account/sites/:id/delete', async c => {
  const site = await ownedSite(c);
  if (!site) return c.notFound();
  await c.env.DB.batch([
    c.env.DB.prepare('DELETE FROM search_fts WHERE domain = ?').bind(site.host),
    c.env.DB.prepare('DELETE FROM search_pages WHERE domain = ?').bind(site.host),
    c.env.DB.prepare('DELETE FROM sources WHERE origin = ?').bind(site.origin),
    c.env.DB.prepare('DELETE FROM sites WHERE id = ?').bind(site.id),
  ]);
  return redirect(c, '/account');
});

app.notFound(c => c.html(htmlPage('Not found', '<h1>404</h1><p>The requested page was not found.</p>', { siteName: siteName(c), csrf: csrf(c) }), 404));

app.onError((error, c) => {
  console.error('request failed:', error);
  return c.html(htmlPage('Server error', '<h1>Something went wrong</h1><p>Please try again later.</p>', { siteName: siteName(c), csrf: c.get('session')?.csrf_token || '' }), 500);
});

export default {
  fetch: app.fetch,
  async queue(batch, env) {
    await consumeCrawlBatch(batch, env);
  },
  async scheduled(event, env) {
    await env.DB.batch([
      env.DB.prepare('DELETE FROM sessions WHERE expires_at <= ?').bind(Date.now()),
      env.DB.prepare('DELETE FROM rate_limits WHERE window_start < ?').bind(Date.now() - 24 * 60 * 60 * 1000),
      env.DB.prepare("DELETE FROM events WHERE created_at < datetime('now', '-90 days')"),
    ]);
    console.log('Daily maintenance completed for scheduled event', event.cron);
  },
};
