# Talaria

A fast, low-footprint mail server with built-in webmail, sized for a
2 vCPU / 2 GB RAM machine with a small disk.

- One Go binary: inbound SMTP, submission, outbound queue with DKIM, IMAP,
  POP3, and gRPC services exposed through Connect RPC.
- Multi-tenant: each tenant has its own domains, users, aliases, admins,
  seat limit and storage quota, and no data crosses tenants.
- Webmail: React 19, Mantine 9, TanStack Query and Form, built with Bun and
  Vite 8, installable as a PWA, with heavy work in web workers.
- Runs on a public IP, behind a gateway such as Gateon (PROXY protocol), or
  behind Cloudflare Tunnel. See [doc/deployment.md](doc/deployment.md).

Status: phase 3 (mail apps). Talaria receives mail on port 25 or through
the HTTP ingest endpoint, checks SPF, DKIM and DMARC, and files it into
compressed, deduplicated storage with full-text search. Users send from the
API or from mail apps on 587/465; mail is DKIM-signed and leaves through a
relay or directly, with retries and bounce reports. Mail apps read mail over
IMAP (143/993, with IDLE push, MOVE and special folders) or POP3 (110/995).
The full webmail follows.

## Build

Requirements: Go 1.27.4, Bun 1.4.5, and `buf` plus `protoc-gen-go` and
`protoc-gen-connect-go` for code generation.

```sh
make gen     # regenerate Go and TypeScript from proto/
make build   # builds the webmail, embeds it, writes bin/talaria
make test
./bin/talaria -config talaria.example.toml
```

## First run

```sh
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
internal/store    SQLite metadata: tenants, domains, users, mailboxes, messages
internal/blob     zstd-compressed, content-addressed message bodies
internal/mail     parsing, SPF/DKIM/DMARC, delivery
internal/smtpd    inbound SMTP and submission
internal/imapd    IMAP server
internal/pop3     POP3 server
internal/outbound DKIM signing, queue, relay and direct delivery, bounces
internal/ingest   HTTP ingest for Cloudflare Email Workers
internal/hub      live mailbox change notifications
internal/auth     Argon2id passwords, login rate limits
internal/api      Connect RPC services
internal/webui    embedded, precompressed webmail
proto/            protobuf API definitions
gen/go/           generated Go code (committed)
web/              webmail (web/src/gen holds generated TS)
deploy/           systemd unit
```
