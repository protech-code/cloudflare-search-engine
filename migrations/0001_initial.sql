PRAGMA foreign_keys = ON;

CREATE TABLE roles (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL UNIQUE,
  permissions TEXT NOT NULL DEFAULT '[]',
  builtin INTEGER NOT NULL DEFAULT 0
);

INSERT INTO roles (name, permissions, builtin) VALUES
  ('superadmin', '["*"]', 1),
  ('admin', '["dashboard.view","sources.manage","index.manage","keywords.manage","submissions.manage","sites.manage","seo.manage","appearance.manage","engine.view"]', 1),
  ('editor', '["dashboard.view","sources.manage","keywords.manage","submissions.manage"]', 1),
  ('viewer', '["dashboard.view"]', 1);

CREATE TABLE admins (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE COLLATE NOCASE,
  password_hash TEXT NOT NULL,
  role_id INTEGER NOT NULL REFERENCES roles(id),
  disabled INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_login_at TEXT
);

CREATE TABLE users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT NOT NULL UNIQUE COLLATE NOCASE,
  password_hash TEXT NOT NULL,
  disabled INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_login_at TEXT
);

CREATE TABLE sessions (
  id TEXT PRIMARY KEY,
  actor_type TEXT,
  actor_id INTEGER,
  csrf_token TEXT NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE INDEX sessions_expires_idx ON sessions(expires_at);

CREATE TABLE sources (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  url TEXT NOT NULL UNIQUE,
  origin TEXT NOT NULL,
  max_pages INTEGER NOT NULL DEFAULT 50,
  status TEXT NOT NULL DEFAULT 'idle',
  pages_crawled INTEGER NOT NULL DEFAULT 0,
  sitemap_url TEXT,
  crawl_requested_at INTEGER,
  last_crawled_at INTEGER,
  last_error TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX sources_origin_idx ON sources(origin);

CREATE TABLE crawl_seen (
  source_id INTEGER NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
  url TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'queued',
  PRIMARY KEY (source_id, url)
);

CREATE TABLE crawl_metadata (
  source_id INTEGER PRIMARY KEY REFERENCES sources(id) ON DELETE CASCADE,
  robots_text TEXT NOT NULL DEFAULT '',
  sitemaps_json TEXT NOT NULL DEFAULT '[]',
  expires_at INTEGER NOT NULL
);

CREATE TABLE search_pages (
  id TEXT PRIMARY KEY,
  url TEXT NOT NULL UNIQUE,
  domain TEXT NOT NULL,
  title TEXT NOT NULL DEFAULT '',
  description TEXT NOT NULL DEFAULT '',
  content TEXT NOT NULL DEFAULT '',
  crawled_at INTEGER NOT NULL
);
CREATE INDEX search_pages_domain_idx ON search_pages(domain);

CREATE VIRTUAL TABLE search_fts USING fts5(
  id UNINDEXED,
  url UNINDEXED,
  domain UNINDEXED,
  title,
  description,
  content,
  tokenize = 'unicode61 remove_diacritics 2'
);

CREATE TABLE queries (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  q TEXT NOT NULL,
  results INTEGER NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX queries_created_idx ON queries(created_at);
CREATE INDEX queries_q_idx ON queries(q);

CREATE TABLE events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  domain TEXT NOT NULL,
  url TEXT NOT NULL,
  q TEXT NOT NULL,
  type TEXT NOT NULL CHECK (type IN ('impression', 'click')),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX events_domain_created_idx ON events(domain, created_at);

CREATE TABLE crawl_errors (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  host TEXT NOT NULL,
  url TEXT NOT NULL,
  reason TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX crawl_errors_host_idx ON crawl_errors(host);

CREATE TABLE keywords (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  q TEXT NOT NULL UNIQUE COLLATE NOCASE,
  kind TEXT NOT NULL CHECK (kind IN ('pinned', 'blocked')),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE submissions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  url TEXT NOT NULL,
  origin TEXT NOT NULL,
  email TEXT NOT NULL,
  ip TEXT,
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'rejected')),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX submissions_status_created_idx ON submissions(status, created_at);

CREATE TABLE sites (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  origin TEXT NOT NULL,
  host TEXT NOT NULL,
  verify_token TEXT NOT NULL,
  verified_at TEXT,
  verify_method TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(user_id, origin)
);
CREATE UNIQUE INDEX sites_verified_origin_idx ON sites(origin) WHERE verified_at IS NOT NULL;

CREATE TABLE settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

CREATE TABLE rate_limits (
  key TEXT PRIMARY KEY,
  count INTEGER NOT NULL,
  window_start INTEGER NOT NULL
);
