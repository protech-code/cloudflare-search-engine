# Cloudflare Search Engine

[![Cloudflare Workers](https://img.shields.io/badge/Cloudflare-Workers-F38020?logo=cloudflare&logoColor=white)](https://workers.cloudflare.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](./LICENSE)

A Cloudflare-native search engine inspired by the original Node Search Engine project. This is a separate application, not a line-for-line port. It runs on Cloudflare Workers, stores application and index data in D1, uses SQLite FTS5 for full-text search, and processes crawl jobs with Cloudflare Queues.

It does not require an Express server, Docker, PostgreSQL, Meilisearch, or a permanently running VM.

## Contents

- [Features](#features)
- [Architecture](#architecture)
- [Requirements](#requirements)
- [Run locally](#run-locally)
- [Deploy to Cloudflare](#deploy-to-cloudflare)
- [Configuration](#configuration)
- [Using the application](#using-the-application)
- [Crawler behavior and responsible use](#crawler-behavior-and-responsible-use)
- [Testing and maintenance](#testing-and-maintenance)
- [Limits and production considerations](#limits-and-production-considerations)
- [Troubleshooting](#troubleshooting)
- [Project structure](#project-structure)
- [Current scope and parity gaps](#current-scope-and-parity-gaps)

## Features

### Public search

- Search indexed pages using D1 SQLite FTS5.
- Show result titles, domains, descriptions, and highlighted text snippets.
- Record searches, result impressions, and result clicks.
- Show popular queries and provide basic search suggestions.
- Accept public website submissions for administrator review.
- Serve basic `robots.txt` and `sitemap.xml` endpoints.

### Administration

- One-time bootstrap flow for creating the first administrator.
- Password-based administrator login with signed sessions and CSRF protection.
- Permission-checked administrative sections for dashboard, crawl sources, index, keywords, submissions, roles, accounts, settings, and engine status.
- Add, crawl, recrawl, and remove sources.
- Review and moderate submitted websites.
- Inspect and manage indexed pages and keywords.
- Create custom roles and manage administrator and site-owner accounts.
- Apply site name and basic search-engine settings.

### Site-owner accounts

- Register and log in as a site owner.
- Add and manage websites associated with an account.
- Verify ownership using the supported meta-tag, file, or DNS TXT methods.
- Request crawls, configure a sitemap URL, and review basic crawl information and search analytics.

### Crawler

- Process crawl work asynchronously through Cloudflare Queues.
- Discover same-host links and sitemap URLs.
- Observe `robots.txt`, `noindex`, and `nofollow` signals.
- Limit response size and redirect count.
- Validate public DNS destinations and re-check each redirect to reduce server-side request forgery (SSRF) risk.
- Keep crawl state in D1 instead of relying on in-memory state between Worker invocations.

Cloudflare Turnstile can optionally protect supported public registration, login, and submission forms.

## Architecture

| Component | Cloudflare service | Purpose |
| --- | --- | --- |
| Web application and API routes | Workers + Hono | Serves the search UI, account pages, admin pages, and endpoints |
| Search index and application data | D1 | Stores users, sessions, crawl state, indexed pages, queries, and settings |
| Full-text search | SQLite FTS5 in D1 | Matches indexed page content and titles |
| Crawl jobs | Cloudflare Queues | Runs asynchronous crawler work outside the request that schedules it |
| Static files | Workers Assets | Serves files from `public/` |
| Scheduled cleanup | Workers Cron Triggers | Runs the configured daily cleanup task |

The bindings, queue consumer settings, asset directory, and cron schedule are configured in [`wrangler.jsonc`](./wrangler.jsonc). The database schema and FTS table are in [`migrations/`](./migrations/).

## Requirements

- Node.js and npm.
- A Cloudflare account for deployment.
- Wrangler, installed as a project dependency. The commands below use `npx wrangler`.
- For a production deployment: a D1 database, two Cloudflare Queues, and a Worker secret for `SESSION_SECRET`.

Cloudflare plan limits and prices can change. Review the current [Workers limits](https://developers.cloudflare.com/workers/platform/limits/), [D1 limits](https://developers.cloudflare.com/d1/platform/limits/), and [Queues limits](https://developers.cloudflare.com/queues/platform/limits/) before deploying or estimating operating costs.

## Run locally

Run these commands from this project directory:

```powershell
npm install
Copy-Item .dev.vars.example .dev.vars
```

Edit `.dev.vars` and replace the example values:

- `SESSION_SECRET`: use a cryptographically random secret with at least 32 characters.
- `BOOTSTRAP_TOKEN`: use a separate, long, one-time setup token.
- `TURNSTILE_SECRET_KEY` and `TURNSTILE_SITE_KEY`: optional; configure both to enable Turnstile.

Do not commit `.dev.vars`. It is excluded by `.gitignore`.

Apply the schema to the local D1 database and start the development server:

```powershell
npm run db:local
npm run dev
```

Open the local URL printed by Wrangler, normally `http://localhost:8787`. Local Wrangler provides local development versions of the configured D1 and Queue bindings; no Cloudflare login or production resources are needed for this workflow.

To create the first local administrator:

1. Open `/admin/setup`.
2. Enter the `BOOTSTRAP_TOKEN` from `.dev.vars`, a username, and a strong password.
3. Sign in at `/admin/login`.

The bootstrap endpoint refuses to create another administrator after the first one exists. The local D1 data is stored in Wrangler's local state directory.

## Deploy to Cloudflare

Run all commands below from this project directory.

### 1. Install and authenticate

```powershell
npm install
npx wrangler login
```

### 2. Create the D1 database

```powershell
npx wrangler d1 create cloudflare-search-engine
```

Wrangler prints a `database_id`. Open `wrangler.jsonc` and replace the placeholder value in the `d1_databases` section:

```jsonc
"database_id": "00000000-0000-0000-0000-000000000001"
```

with the real ID returned by Wrangler. Do not deploy with the placeholder ID.

### 3. Create the queues

The queue names must match the names configured in `wrangler.jsonc`:

```powershell
npx wrangler queues create cloudflare-search-crawl
npx wrangler queues create cloudflare-search-crawl-dlq
```

The first queue handles crawl jobs. The second is the dead-letter queue for messages that fail after the configured retries.

### 4. Configure secrets

Set unique production values. Never reuse the example or local development secrets:

```powershell
npx wrangler secret put SESSION_SECRET
npx wrangler secret put BOOTSTRAP_TOKEN
```

Wrangler prompts for each value. `SESSION_SECRET` must contain at least 32 characters. Use a separate, long, one-time `BOOTSTRAP_TOKEN`.

To enable Turnstile, also set the server-side secret:

```powershell
npx wrangler secret put TURNSTILE_SECRET_KEY
```

Set `TURNSTILE_SITE_KEY` as a Worker variable in the Cloudflare dashboard or in the `vars` section of `wrangler.jsonc`. Both Turnstile keys must be configured for the challenge to work.

### 5. Apply the schema and deploy

```powershell
npm run db:remote
npm run deploy
```

`npm run db:remote` applies pending migrations to the remote D1 database. `npm run deploy` publishes the Worker and configured assets.

### 6. Finish initial setup

1. Open the deployed site at `/admin/setup`.
2. Use the production `BOOTSTRAP_TOKEN` to create the first administrator.
3. Sign in at `/admin/login` and confirm the dashboard is accessible.
4. Remove or replace `BOOTSTRAP_TOKEN` in the Cloudflare dashboard once setup is complete. The setup route is also disabled after an administrator exists.
5. Set a production `BASE_URL` and a descriptive `BOT_UA` in the Cloudflare dashboard or `wrangler.jsonc`.
6. Add a custom domain to the Worker in Cloudflare if desired.

After changing a checked-in `vars` value in `wrangler.jsonc`, deploy again for the new value to take effect.

## Configuration

| Name | Type | Required | Description |
| --- | --- | --- | --- |
| `SESSION_SECRET` | Secret | Yes | Signs session cookies; must be at least 32 characters. |
| `BOOTSTRAP_TOKEN` | Secret | Required for first admin setup | Authorizes creation of the first administrator. Use a unique, one-time value. |
| `TURNSTILE_SECRET_KEY` | Secret | No | Server-side Turnstile verification key. |
| `TURNSTILE_SITE_KEY` | Variable | No | Public Turnstile key rendered in supported forms. Configure it together with `TURNSTILE_SECRET_KEY`. |
| `SITE_NAME` | Variable | No | Default name displayed by the application. |
| `BASE_URL` | Variable | Recommended | Canonical public URL used by sitemap and crawler-related links. Set this to the deployed HTTPS URL. |
| `BOT_UA` | Variable | Recommended | Crawler user-agent string. Use a descriptive value that identifies the crawler and provides a contact or policy URL. |
| `CRAWL_DELAY_MS` | Variable | No | Delay configured between crawler requests. |
| `VERIFIED_MAX_PAGES` | Variable | No | Default maximum page limit used for verified sites. |
| `DB` | D1 binding | Yes | D1 database binding configured in `wrangler.jsonc`. |
| `CRAWL_QUEUE` | Queue producer binding | Yes | Queue used to enqueue crawl work. |
| `ASSETS` | Assets binding | Yes | Static files from `public/`. |

`wrangler.jsonc` contains development-oriented defaults for non-secret variables. Review and update these values for production; do not put credentials or private tokens in `vars`.

## Using the application

| Path | Purpose |
| --- | --- |
| `/` | Search home page |
| `/search?q=...` | Search indexed pages |
| `/suggest?q=...` | Search suggestions |
| `/submit` | Submit a website for administrator review |
| `/robots.txt` | Basic robots policy and sitemap location |
| `/sitemap.xml` | Basic sitemap for the search application |
| `/admin/setup` | Create the first administrator |
| `/admin/login` | Administrator login |
| `/admin` | Administrator dashboard |
| `/admin/sources` | Manage crawl sources and crawl jobs |
| `/admin/index` | Inspect and manage indexed pages |
| `/admin/keywords` | Manage keyword controls |
| `/admin/submissions` | Review submitted websites |
| `/admin/roles` | View and create roles |
| `/admin/users` | Manage administrator and site-owner accounts |
| `/admin/settings` | Configure available site and SEO settings |
| `/admin/engine` | View engine status |
| `/account/register` | Create a site-owner account |
| `/account/login` | Site-owner login |
| `/account` | Manage sites owned by the signed-in account |

Administrative and account pages require an authenticated session. Actions that change data use POST requests and CSRF tokens.

## Crawler behavior and responsible use

Only add websites that you are authorized to crawl. Before indexing a site, review its terms of service, applicable laws, and operator preferences. `robots.txt` is one signal the crawler observes; it is not permission to crawl content.

The crawler is intentionally constrained:

- It only supports HTTP and HTTPS URLs on standard ports.
- It rejects URLs with embedded credentials and destinations that resolve to private or reserved IP ranges.
- It validates redirect destinations as well as the initial URL.
- It limits redirect count, response size, and crawl scope.
- It observes supported `robots.txt` rules and page-level `noindex`/`nofollow` directives.
- It processes work asynchronously through the configured Queue consumer.

These protections reduce risk but do not replace operational monitoring, permission checks, or a responsible crawl policy. Configure an honest user-agent and contact URL before production use.

## Testing and maintenance

Run the unit tests:

```powershell
npm test
```

Check that Wrangler can build the production bundle without publishing it:

```powershell
npx wrangler deploy --dry-run
```

Check local migration status or apply local migrations:

```powershell
npx wrangler d1 migrations list DB --local
npm run db:local
```

Apply pending migrations to the production database before deploying a schema-dependent change:

```powershell
npm run db:remote
npm run deploy
```

Review Cloudflare Worker, D1, Queue, and Cron Trigger logs during operation. Monitor failed Queue messages and the dead-letter queue, crawl errors, D1 storage, and Worker CPU usage. Back up data according to your operational requirements before migrations or destructive index operations.

## Limits and production considerations

- Worker CPU time, D1 storage and query limits, Queue operations, and request quotas depend on the Cloudflare plan and can change. Check Cloudflare's current service documentation before launch.
- Password hashing uses PBKDF2 with 210,000 iterations. Login, account registration, and full-page rendering may exceed a low Worker CPU allowance under some conditions. Increase the configured Worker CPU limit when appropriate or optimize measured hotspots; do not reduce password-hashing strength without a security review.
- D1 is suitable for a modest index but has storage and throughput limits. Evaluate expected document volume and query load before indexing large sites.
- Queue retries can send repeatedly failing messages to the configured dead-letter queue. Add monitoring and a recovery procedure for failed crawl work.
- Local tests and `wrangler deploy --dry-run` do not deploy the project or validate remote account resources, secrets, DNS, custom domains, or production permissions.
- This project does not automatically migrate existing PostgreSQL or Meilisearch data. Plan a separate data export/import if existing records must be retained.

## Troubleshooting

### Wrangler reports an invalid D1 database ID

Create the D1 database and replace the placeholder `database_id` in `wrangler.jsonc` with the ID returned by `wrangler d1 create`.

### Crawl jobs are not processed

Confirm that both queues exist and that their names match the producer and consumer configuration in `wrangler.jsonc`. Review the Worker and Queue logs, source status, crawl errors, and dead-letter queue.

### Login or account creation exceeds CPU limits

Password hashing is intentionally computationally expensive. Review Worker CPU usage and configured limits. Consider an appropriate CPU limit or measured code optimization rather than weakening the password hash.

### Search returns no results

Confirm that at least one source has been added and crawled successfully, the crawl Queue is processing messages, pages have been indexed, and the D1 migration has been applied to the same database bound to the Worker.

### Turnstile verification fails

Confirm that the site key and secret key belong to the same Turnstile widget, that the site key is configured as `TURNSTILE_SITE_KEY`, and that the secret is configured as `TURNSTILE_SECRET_KEY`.

### Local Worker fails to start or sessions fail

Confirm that `.dev.vars` exists, that `SESSION_SECRET` has at least 32 characters, and that local migrations have been applied with `npm run db:local`. Do not use production credentials in local development.

## Project structure

```text
cloudflare-search-engine/
├── migrations/          D1 schema and FTS5 virtual table
├── public/              Static assets served by Workers Assets
├── src/
│   ├── auth.js           Sessions, CSRF, password hashing, permissions
│   ├── crawler.js        Queue consumer, crawling, URL safety checks
│   ├── db.js             D1 helpers, rate limits, analytics events
│   ├── index.js          Hono app, routes, and scheduled/queue handlers
│   ├── search.js         Search query normalization and FTS expressions
│   └── utils.js          HTML helpers, escaping, and shared utilities
├── test/                 Node.js unit tests
├── .dev.vars.example     Local secret configuration template
├── package.json          Scripts and dependencies
└── wrangler.jsonc        Worker bindings, queues, assets, vars, and cron
```

## Current scope and parity gaps

This is a new Cloudflare-focused implementation and is not yet a complete feature-for-feature replacement for the original application. Current known gaps include:

- The original full Vietnamese/English translation catalog.
- A complete theme, logo, and background editor with uploads.
- All verification page-list controls and SEO options from the original application.
- Detailed daily analytics charts.
- Full edit/delete workflows for built-in roles.
- Automatic import of existing PostgreSQL or Meilisearch data.

Review these limitations against your requirements before replacing an existing deployment.
