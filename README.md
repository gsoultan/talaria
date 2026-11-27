# Talaria

A fast, low-footprint mail server with built-in webmail, sized for a
2 vCPU / 2 GB RAM machine with a small disk.

- One Go binary: inbound SMTP, submission, outbound queue with DKIM, IMAP,
  POP3, and a JSON API built on [kakarot](https://github.com/gsoultan/kakarot),
  described by an OpenAPI document at `/api/v1/openapi.json`.
- Multi-tenant: each tenant has its own domains, users, aliases, admins,
  seat limit and storage quota, and no data crosses tenants.
- PostgreSQL for metadata and full-text search; message bodies are
  compressed and deduplicated on disk.
- Webmail: React 19, Mantine 9, TanStack Query and Form, built with Bun and
  Vite 8, installable as a PWA, with heavy work in web workers.
- Runs on a public IP, behind a gateway such as Gateon (PROXY protocol), or
  behind Cloudflare Tunnel. See [doc/deployment.md](doc/deployment.md).

Status: phase 6 (mail security) is done: connection filtering, anti-spam,
anti-malware, quarantine, safe links, safe attachments, data loss
prevention, audit logs and S/MIME, see [doc/roadmap.md](doc/roadmap.md). Talaria receives
mail on port 25 or through the HTTP ingest endpoint, checks SPF, DKIM and
DMARC, scores it for spam with a filter that learns from each user, refuses
dangerous attachments, and files it into
compressed, deduplicated storage with full-text search. Users send from the
webmail or from mail apps on 587/465; mail is DKIM-signed and leaves through
a relay or directly, with retries and bounce reports. Mail apps read mail
over IMAP (143/993, with IDLE push) or POP3 (110/995).

The webmail has a three-pane inbox with live updates, conversations, search
with operators (`from:`, `is:unread`, `has:attachment`, `before:`, `in:`),
compose with attachments and autosaved drafts, keyboard shortcuts, and a
phone layout. It installs as an app, keeps mail you have opened for offline
reading, and holds mail written offline in an outbox until you reconnect.
HTML mail renders in a sandboxed frame with scripts off and remote images
blocked until you allow them. Admins manage domains and DNS records, users
and aliases, the outbound queue, and (platform admins) tenants.

It can get its own Let's Encrypt certificates, sends strict browser security
headers, never takes a password over an unencrypted connection (also behind
a gateway), and limits connections per client address.

## Build

Requirements: Go 1.27.4, Bun 1.4.5 and PostgreSQL 15 or newer. The kakarot code generator is a Go
tool dependency, so `go tool kakarot` needs nothing else installed.

```sh
make gen     # regenerate endpoints, transport, OpenAPI and the TS client
make check   # kakarot layer rules; generated code is current
make build   # builds the webmail, embeds it, writes bin/talaria
make test    # set TALARIA_TEST_DATABASE_URL to run the database tests
./bin/talaria -config talaria.example.toml
```

Tests that need PostgreSQL use `TALARIA_TEST_DATABASE_URL` (for example
`postgres://talaria:talaria@localhost:5432/talaria_test`); each test gets an
empty schema of its own and drops it afterwards. Without the variable those
tests are skipped.

## First run

Create a database and a user for Talaria, then point `database.url` (or
`TALARIA_DATABASE_URL`) at it. Talaria creates its tables on first start.

```sh
sudo -u postgres createuser -P talaria
sudo -u postgres createdb -O talaria talaria
export TALARIA_DATABASE_URL=postgres://talaria:SECRET@localhost:5432/talaria
talaria init -config talaria.toml -tenant acme -domain acme.example -admin you@acme.example
talaria user -config talaria.toml -tenant acme -email ana@acme.example -name "Ana"
talaria alias -config talaria.toml -tenant acme -alias sales@acme.example -to ana@acme.example
talaria -config talaria.toml
```

`init` creates the first tenant, its domain and a platform admin. Run
`talaria help` for every management command; the Admin API does the same
from the webmail.

For webmail development, run the server and `cd web && bun run dev`; Vite
proxies API calls to `localhost:8080`.

## Layout

```
cmd/talaria/      entry point
internal/config   TOML config
internal/server   wiring, listeners, housekeeping
internal/listener SMTP/IMAP listeners with PROXY protocol
internal/clientip real client address behind trusted proxies
internal/store    PostgreSQL: tenants, domains, users, mailboxes, messages, search
internal/blob     zstd-compressed, content-addressed message bodies
internal/mail     parsing, SPF/DKIM/DMARC, delivery
internal/smtpd    inbound SMTP and submission
internal/imapd    IMAP server
internal/pop3     POP3 server
internal/outbound DKIM signing, queue, relay and direct delivery, bounces
internal/ingest   HTTP ingest for Cloudflare Email Workers
internal/hub      live mailbox change notifications
internal/auth     Argon2id passwords, login rate limits
domain/           API request and response types, error codes
usecase/          what the API does: sign-in, mail, admin
service/          API interfaces with //kakarot: routes
endpoint/         generated by kakarot gen (committed)
transport/        generated by kakarot gen (committed)
app/              HTTP wiring: sessions, uploads, downloads, middleware
api/openapi.json  the API, generated from the code
internal/uploads  attachments uploaded ahead of sending
internal/webui    embedded, precompressed webmail
web/              webmail (web/src/gen/api.ts is generated from the OpenAPI)
deploy/           systemd unit
```
