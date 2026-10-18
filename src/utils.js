export const escapeHtml = value => String(value ?? '').replace(/[&<>"']/g, char => ({
  '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
})[char]);

export const randomHex = (bytes = 24) => {
  const data = crypto.getRandomValues(new Uint8Array(bytes));
  return [...data].map(byte => byte.toString(16).padStart(2, '0')).join('');
};

export function htmlPage(title, content, { siteName = 'MySearch', csrf = '', actor = null } = {}) {
  const nav = actor
    ? `<nav><a href="/">Search</a> <a href="/account">My sites</a> <a href="/admin">Admin</a>
       <form class="inline" method="post" action="/logout"><input type="hidden" name="csrf" value="${escapeHtml(csrf)}"><button>Log out</button></form></nav>`
    : `<nav><a href="/">Search</a> <a href="/submit">Submit a site</a> <a href="/account/login">Site owner login</a> <a href="/admin/login">Admin</a></nav>`;
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${escapeHtml(title)} - ${escapeHtml(siteName)}</title><link rel="stylesheet" href="/style.css"><meta name="robots" content="noindex,follow"></head><body><header><a class="brand" href="/">${escapeHtml(siteName)}</a>${nav}</header><main>${content}</main><footer><a href="/sitemap.xml">Sitemap</a> · <a href="/robots.txt">Robots</a></footer></body></html>`;
}

export function field(name, label, type = 'text', value = '', attrs = '') {
  return `<label>${escapeHtml(label)}<input name="${escapeHtml(name)}" type="${escapeHtml(type)}" value="${escapeHtml(value)}" ${attrs}></label>`;
}

export const hiddenCsrf = token => `<input type="hidden" name="csrf" value="${escapeHtml(token)}">`;

export function form(action, csrf, fields, submit, extra = '') {
  return `<form method="post" action="${escapeHtml(action)}">${hiddenCsrf(csrf)}${fields}<button type="submit">${escapeHtml(submit)}</button>${extra}</form>`;
}

export function notice(message, kind = 'info') {
  return message ? `<p class="notice ${escapeHtml(kind)}">${escapeHtml(message)}</p>` : '';
}

export function redirect(path, status = 303) {
  return new Response(null, { status, headers: { Location: path } });
}

export function documentId(url) {
  return createDigest(url);
}

async function createDigest(value) {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value));
  return [...new Uint8Array(digest)].map(byte => byte.toString(16).padStart(2, '0')).join('');
}

export function truncate(value, length) {
  return String(value ?? '').replace(/\s+/g, ' ').trim().slice(0, length);
}
