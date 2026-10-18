import { all, one, run } from './db.js';
import { documentId, truncate } from './utils.js';

const MAX_REDIRECTS = 5;
const MAX_HTML_BYTES = 1_000_000;

function privateIpv4(value) {
  const parts = value.split('.').map(Number);
  if (parts.length !== 4 || parts.some(part => !Number.isInteger(part) || part < 0 || part > 255)) return true;
  const [a, b] = parts;
  return a === 0 || a === 10 || a === 127 || a >= 224
    || (a === 100 && b >= 64 && b <= 127)
    || (a === 169 && b === 254)
    || (a === 172 && b >= 16 && b <= 31)
    || (a === 192 && (b === 0 || b === 168 || b === 88 && parts[2] === 99))
    || (a === 198 && (b === 18 || b === 19 || b === 51 && parts[2] === 100))
    || (a === 203 && b === 0 && parts[2] === 113);
}

function isIpLiteral(host) {
  return /^\d{1,3}(?:\.\d{1,3}){3}$/.test(host) || host.includes(':');
}

function isPrivateAddress(address) {
  const value = String(address).toLowerCase();
  if (value.includes(':')) {
    if (value.startsWith('::ffff:')) return privateIpv4(value.slice(7));
    const firstSegment = Number.parseInt(value.split(':')[0], 16);
    return !Number.isInteger(firstSegment) || firstSegment < 0x2000 || firstSegment > 0x3fff
      || value.startsWith('2001:db8:');
  }
  return privateIpv4(value);
}

export async function assertPublicUrl(raw) {
  let url;
  try {
    url = new URL(raw);
  } catch {
    throw new Error('Invalid URL');
  }
  const hostname = url.hostname.replace(/^\[|\]$/g, '').toLowerCase();
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password) throw new Error('Only public HTTP(S) URLs are allowed');
  if (!hostname.includes('.') && !isIpLiteral(hostname)) throw new Error('Public domain name required');
  if (url.port && !['80', '443'].includes(url.port)) throw new Error('Non-standard ports are not crawled');
  if (isIpLiteral(hostname)) {
    if (isPrivateAddress(hostname)) throw new Error('Private network addresses are blocked');
    return url;
  }

  const records = await Promise.all(['A', 'AAAA'].map(async type => {
    const endpoint = new URL('https://cloudflare-dns.com/dns-query');
    endpoint.searchParams.set('name', hostname);
    endpoint.searchParams.set('type', type);
    const response = await fetch(endpoint, { headers: { accept: 'application/dns-json' } });
    if (!response.ok) throw new Error('Could not validate destination host');
    const data = await response.json();
    if (data.Status !== 0 && data.Status !== 3) throw new Error('Could not resolve destination host');
    return (data.Answer || []).filter(answer => answer.type === 1 || answer.type === 28).map(answer => answer.data);
  }));
  const addresses = records.flat();
  if (!addresses.length || addresses.some(isPrivateAddress)) throw new Error('Host does not resolve to public addresses');
  return url;
}

export async function safeFetch(raw, maxBytes = MAX_HTML_BYTES, userAgent = 'MySearchBot/1.0 (+https://example.com/bot)') {
  let url = new URL(raw);
  for (let redirects = 0; redirects <= MAX_REDIRECTS; redirects++) {
    await assertPublicUrl(url.href);
    const response = await fetch(url, {
      headers: {
        'user-agent': userAgent,
        accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
      },
      redirect: 'manual',
      signal: AbortSignal.timeout(15_000),
    });
    if ([301, 302, 303, 307, 308].includes(response.status)) {
      const location = response.headers.get('location');
      if (!location) return response;
      await response.body?.cancel();
      url = new URL(location, url);
      continue;
    }
    const contentLength = Number(response.headers.get('content-length') || 0);
    if (contentLength > maxBytes) throw new Error('Response exceeds size limit');
    const reader = response.body?.getReader();
    if (!reader) return response;
    const chunks = [];
    let length = 0;
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      length += value.byteLength;
      if (length > maxBytes) {
        await reader.cancel();
        throw new Error('Response exceeds size limit');
      }
      chunks.push(value);
    }
    const headers = new Headers(response.headers);
    headers.set('x-mysearch-final-url', url.href);
    return new Response(new Blob(chunks), { status: response.status, statusText: response.statusText, headers });
  }
  throw new Error('Too many redirects');
}

function isAllowedByRobots(text, pathname, userAgent) {
  const groups = [];
  let current = null;
  for (const line of text.split(/\r?\n/)) {
    const clean = line.split('#')[0].trim();
    const match = clean.match(/^([^:]+):\s*(.*)$/);
    if (!match) continue;
    const key = match[1].toLowerCase(), value = match[2].trim();
    if (key === 'user-agent') {
      if (!current || current.hasRules) {
        current = { agents: [], rules: [], hasRules: false };
        groups.push(current);
      }
      current.agents.push(value.toLowerCase());
    } else if (current && (key === 'allow' || key === 'disallow')) {
      current.hasRules = true;
      if (value) current.rules.push({ allow: key === 'allow', path: value });
    }
  }
  const matches = groups.filter(group => group.agents.some(agent => agent === '*' || userAgent.toLowerCase().includes(agent)));
  const selected = matches.filter(group => group.agents.some(agent => agent !== '*'));
  const rules = (selected.length ? selected : matches).flatMap(group => group.rules)
    .filter(rule => pathname.startsWith(rule.path))
    .sort((a, b) => b.path.length - a.path.length || Number(b.allow) - Number(a.allow));
  return !rules.length || rules[0].allow;
}

async function extractPage(response) {
  let title = '', description = '', text = '', links = [];
  const extractor = new HTMLRewriter()
    .on('title', { text(chunk) { title += chunk.text; } })
    .on('meta[name="description"]', { element(element) { description = element.getAttribute('content') || ''; } })
    .on('a[href]', { element(element) { links.push(element.getAttribute('href')); } })
    .on('script,style,noscript,nav,footer,header,form,iframe,svg', { element(element) { element.remove(); } })
    .on('body', { text(chunk) { text += chunk.text; } });
  const rewritten = await extractor.transform(response).text();
  if (!text) text = rewritten.replace(/<[^>]*>/g, ' ');
  return {
    title: truncate(title || '', 200),
    description: truncate(description, 300),
    content: truncate(text, 8000),
    links,
  };
}

function normalizeLink(link, base) {
  try {
    const url = new URL(link, base);
    if (!['http:', 'https:'].includes(url.protocol) || url.hostname !== new URL(base).hostname) return null;
    if (/\.(jpg|jpeg|png|gif|svg|webp|pdf|zip|mp4|mp3|css|js|ico|xml)$/i.test(url.pathname)) return null;
    url.hash = '';
    return url.href;
  } catch {
    return null;
  }
}

async function robotsRules(origin, userAgent) {
  try {
    const response = await safeFetch(`${origin}/robots.txt`, 250_000, userAgent);
    return response.ok ? await response.text() : '';
  } catch {
    return '';
  }
}

async function sitemapLinks(source, robotsText, userAgent) {
  const candidates = source.sitemap_url
    ? [source.sitemap_url]
    : [...robotsText.matchAll(/^sitemap:\s*(\S+)/gim)].map(match => match[1]).slice(0, 3);
  const output = new Set();
  for (const sitemap of candidates) {
    try {
      const url = new URL(sitemap);
      if (url.origin !== source.origin) continue;
      const response = await safeFetch(url.href, 2_000_000, userAgent);
      if (!response.ok) continue;
      const xml = await response.text();
      for (const match of xml.matchAll(/<loc>\s*([^<]+)\s*<\/loc>/gi)) {
        const candidate = normalizeLink(match[1].trim().replaceAll('&amp;', '&'), source.url);
        if (candidate) output.add(candidate);
        if (output.size >= 500) break;
      }
    } catch (error) {
      console.warn('sitemap fetch failed:', error.message);
    }
  }
  return [...output];
}

async function recordError(db, host, url, reason) {
  await run(db, 'INSERT INTO crawl_errors (host, url, reason) VALUES (?, ?, ?)', host, url, String(reason).slice(0, 200));
}

export async function enqueueCrawl(env, source) {
  if (source.status === 'running') return false;
  try {
    await env.DB.batch([
      env.DB.prepare('DELETE FROM crawl_seen WHERE source_id = ?').bind(source.id),
      env.DB.prepare('DELETE FROM crawl_metadata WHERE source_id = ?').bind(source.id),
      env.DB.prepare('UPDATE sources SET status = ?, pages_crawled = 0, last_error = NULL, crawl_requested_at = ? WHERE id = ?')
        .bind('running', Date.now(), source.id),
      env.DB.prepare('INSERT OR IGNORE INTO crawl_seen (source_id, url) VALUES (?, ?)').bind(source.id, source.url),
    ]);
    await env.CRAWL_QUEUE.send({ sourceId: source.id, url: source.url }, {
      delaySeconds: Math.ceil(Math.min(Math.max(Number(env.CRAWL_DELAY_MS) || 1000, 1000), 10_000) / 1000),
    });
  } catch (error) {
    await run(env.DB, "UPDATE sources SET status = 'error', last_error = ? WHERE id = ?", String(error.message).slice(0, 500), source.id);
    throw error;
  }
  return true;
}

export async function consumeCrawlBatch(batch, env) {
  for (const message of batch.messages) {
    const { sourceId, url } = message.body || {};
    const source = await one(env.DB, 'SELECT * FROM sources WHERE id = ?', sourceId);
    if (!source) {
      message.ack();
      continue;
    }
    try {
      if (source.pages_crawled >= source.max_pages) {
        await run(env.DB, "UPDATE sources SET status = 'idle', last_crawled_at = ? WHERE id = ?", Date.now(), source.id);
        message.ack();
        continue;
      }

      const target = await assertPublicUrl(url);
      if (target.origin !== source.origin) throw new Error('URL left the configured origin');
      const userAgent = env.BOT_UA || 'MySearchBot/1.0 (+https://example.com/bot)';
      let metadata = await one(env.DB, 'SELECT * FROM crawl_metadata WHERE source_id = ? AND expires_at > ?', source.id, Date.now());
      if (!metadata) {
        const rules = await robotsRules(source.origin, userAgent);
        const sitemaps = await sitemapLinks(source, rules, userAgent);
        await run(env.DB, `INSERT INTO crawl_metadata (source_id, robots_text, sitemaps_json, expires_at)
          VALUES (?, ?, ?, ?) ON CONFLICT(source_id) DO UPDATE SET robots_text = excluded.robots_text,
          sitemaps_json = excluded.sitemaps_json, expires_at = excluded.expires_at`,
        source.id, rules, JSON.stringify(sitemaps), Date.now() + 6 * 60 * 60 * 1000);
        metadata = { robots_text: rules, sitemaps_json: JSON.stringify(sitemaps) };
      }
      const rules = metadata.robots_text;
      const sitemaps = JSON.parse(metadata.sitemaps_json);
      if (!isAllowedByRobots(rules, target.pathname, env.BOT_UA || 'MySearchBot')) {
        await recordError(env.DB, target.hostname, url, 'Blocked by robots.txt');
        await run(env.DB, "UPDATE crawl_seen SET status = 'done' WHERE source_id = ? AND url = ?", source.id, url);
        const remaining = await one(env.DB, "SELECT COUNT(*) AS n FROM crawl_seen WHERE source_id = ? AND status = 'queued'", source.id);
        if (!remaining.n) await run(env.DB, "UPDATE sources SET status = 'idle', last_crawled_at = ? WHERE id = ?", Date.now(), source.id);
        message.ack();
        continue;
      }

      const response = await safeFetch(url, MAX_HTML_BYTES, userAgent);
      const finalUrl = response.headers.get('x-mysearch-final-url') || url;
      if (new URL(finalUrl).origin !== source.origin) throw new Error('Redirect left the configured origin');
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      if (!(response.headers.get('content-type') || '').toLowerCase().includes('text/html')) throw new Error('Not an HTML page');
      const html = await response.text();
      if (new TextEncoder().encode(html).byteLength > MAX_HTML_BYTES) throw new Error('Response exceeds size limit');

      let robotsMeta = '';
      const metaReader = new HTMLRewriter().on('meta[name="robots"]', {
        element(element) { robotsMeta += ` ${element.getAttribute('content') || ''}`; },
      });
      await metaReader.transform(new Response(html)).text();
      if (robotsMeta.toLowerCase().includes('noindex')) {
        await recordError(env.DB, target.hostname, url, 'Blocked by noindex');
        await run(env.DB, "UPDATE crawl_seen SET status = 'done' WHERE source_id = ? AND url = ?", source.id, url);
        const remaining = await one(env.DB, "SELECT COUNT(*) AS n FROM crawl_seen WHERE source_id = ? AND status = 'queued'", source.id);
        if (!remaining.n) await run(env.DB, "UPDATE sources SET status = 'idle', last_crawled_at = ? WHERE id = ?", Date.now(), source.id);
        message.ack();
        continue;
      }

      const page = await extractPage(new Response(html));
      const pageId = await documentId(url);
      await env.DB.batch([
        env.DB.prepare('DELETE FROM search_fts WHERE id = ?').bind(pageId),
        env.DB.prepare(`
          INSERT INTO search_pages (id, url, domain, title, description, content, crawled_at)
          VALUES (?, ?, ?, ?, ?, ?, ?)
          ON CONFLICT(id) DO UPDATE SET url=excluded.url, domain=excluded.domain, title=excluded.title,
            description=excluded.description, content=excluded.content, crawled_at=excluded.crawled_at
        `).bind(pageId, url, target.hostname, page.title || url, page.description, page.content, Date.now()),
        env.DB.prepare('INSERT INTO search_fts (id, url, domain, title, description, content) VALUES (?, ?, ?, ?, ?, ?)')
          .bind(pageId, url, target.hostname, page.title || url, page.description, page.content),
        env.DB.prepare('UPDATE sources SET pages_crawled = pages_crawled + 1 WHERE id = ?').bind(source.id),
        env.DB.prepare('UPDATE crawl_seen SET status = ? WHERE source_id = ? AND url = ?').bind('done', source.id, url),
      ]);

      const nofollow = robotsMeta.toLowerCase().includes('nofollow');
      {
        const links = [...new Set([
          ...(url === source.url ? sitemaps : []),
          ...(!nofollow ? page.links.map(link => normalizeLink(link, url)).filter(Boolean) : []),
        ])].filter(link => link !== url).slice(0, 250);
        const queued = [];
        for (const link of links) {
          const inserted = await one(env.DB, 'INSERT OR IGNORE INTO crawl_seen (source_id, url) VALUES (?, ?) RETURNING url', source.id, link);
          if (inserted) queued.push(link);
        }
        if (queued.length) {
          for (let i = 0; i < queued.length; i += 100) {
            const batchMessages = queued.slice(i, i + 100).map(link => ({ body: { sourceId: source.id, url: link } }));
            await env.CRAWL_QUEUE.sendBatch(batchMessages);
          }
        }
      }

      const remaining = await one(env.DB, "SELECT COUNT(*) AS n FROM crawl_seen WHERE source_id = ? AND status = 'queued'", source.id);
      if (remaining.n === 0 || source.pages_crawled + 1 >= source.max_pages) {
        await run(env.DB, "UPDATE sources SET status = 'idle', last_crawled_at = ?, last_error = NULL WHERE id = ?", Date.now(), source.id);
      }
      message.ack();
    } catch (error) {
      await recordError(env.DB, new URL(source.url).hostname, url, error.message).catch(logError => console.error('crawl error log failed:', logError));
      await run(env.DB, "UPDATE sources SET last_error = ?, status = 'error' WHERE id = ?", String(error.message).slice(0, 500), source.id)
        .catch(updateError => console.error('crawl status update failed:', updateError));
      message.retry({ delaySeconds: Math.min(60 * message.attempts, 3600) });
    }
  }
}

export async function crawlAllVerified(env) {
  const sources = await all(env.DB, `
    SELECT s.* FROM sources s
    JOIN sites v ON v.origin = s.origin AND v.verified_at IS NOT NULL
    WHERE s.status != 'running'
  `);
  for (const source of sources) await enqueueCrawl(env, source).catch(error => console.error('scheduled crawl enqueue failed:', error));
}
