# Talaria

A fast, low-footprint mail server with built-in webmail, sized for a
2 vCPU / 2 GB RAM machine with a small disk.

- One Go binary: inbound SMTP, submission, outbound queue with DKIM, IMAP,
  and gRPC services exposed through Connect RPC.
- Multiple domains, managed at runtime.
- Webmail: React 19, Mantine 9, TanStack Query and Form, built with Bun and
  Vite 8, installable as a PWA, with heavy work in web workers.
- Runs on a public IP, behind a gateway such as Gateon (PROXY protocol), or
  behind Cloudflare Tunnel. See [doc/deployment.md](doc/deployment.md).

Status: phase 0 (foundation). The HTTP server, config, Connect API skeleton,
webmail shell and gateway support are in place; mail handling lands in the
next phases.

## Build

Requirements: Go 1.27.4, Bun 1.4.5, and `buf` plus `protoc-gen-go` and
`protoc-gen-connect-go` for code generation.

```sh
make gen     # regenerate Go and TypeScript from proto/
make build   # builds the webmail, embeds it, writes bin/talaria
make test
./bin/talaria -config talaria.example.toml
```

For webmail development, run the server and `cd web && bun run dev`; Vite
proxies API calls to `localhost:8080`.

## Layout

```
cmd/talaria/      entry point
internal/config   TOML config
internal/server   listeners, client-IP handling
internal/listener SMTP/IMAP listeners with PROXY protocol
internal/api      Connect RPC services
internal/webui    embedded, precompressed webmail
proto/            protobuf API definitions
gen/go/           generated Go code (committed)
web/              webmail (web/src/gen holds generated TS)
deploy/           systemd unit
```
