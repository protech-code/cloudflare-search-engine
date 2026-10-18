export const one = (db, sql, ...values) => db.prepare(sql).bind(...values).first();
export const all = async (db, sql, ...values) => (await db.prepare(sql).bind(...values).all()).results;
export const run = (db, sql, ...values) => db.prepare(sql).bind(...values).run();

export async function recordEvent(db, type, hits, query) {
  if (!hits.length) return;
  const statements = hits.slice(0, 10).map(hit => db.prepare(
    'INSERT INTO events (domain, url, q, type) VALUES (?, ?, ?, ?)',
  ).bind(hit.domain, hit.url, query.toLowerCase().slice(0, 200), type));
  await db.batch(statements);
}

export async function rateLimit(db, key, limit, windowMs, now = Date.now()) {
  const row = await one(db, `
    INSERT INTO rate_limits (key, count, window_start) VALUES (?, 1, ?)
    ON CONFLICT(key) DO UPDATE SET
      count = CASE WHEN rate_limits.window_start + ? <= ? THEN 1 ELSE rate_limits.count + 1 END,
      window_start = CASE WHEN rate_limits.window_start + ? <= ? THEN ? ELSE rate_limits.window_start END
    RETURNING count
  `, key, now, windowMs, now, windowMs, now, now);
  return row.count <= limit;
}
