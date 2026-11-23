# Deploying Talaria

Talaria is one binary. It runs directly on a host with a public IP, behind a
TCP/HTTP gateway such as [Gateon](https://github.com/gsoultan/gateon), or
behind Cloudflare Tunnel. The three differ only in how traffic reaches it.

| Traffic | Direct public IP | Behind Gateon (or HAProxy, nginx) | Cloudflare Tunnel only |
|---|---|---|---|
| Webmail and API (HTTP) | yes | yes, HTTP route | yes |
| Inbound mail (SMTP 25) | yes | yes, L4 TCP route + PROXY protocol | via Cloudflare Email Routing and the HTTP ingest endpoint |
| Mail apps (IMAP 143/993, submission 587/465) | yes | yes, L4 TCP routes | no, unless each client runs WARP or `cloudflared access tcp` |
| Outbound mail | relay (default) or direct on 25 | same | relay |

## Outbound mail

Most VPS providers block outbound port 25, so `outbound.mode = "relay"` is the
default: Talaria hands every message to a smarthost on 587 or 465 with
username and password. Switch to `direct` only where port 25 is open and the
IP has a clean reputation and matching reverse DNS.

Queued mail is retried after 1, 5, 15 and 30 minutes, then hourly with
growing gaps, for up to four days; after that, or on a permanent 5xx reply,
the sender gets a bounce report in their Inbox. Each tenant's
`daily_send_limit` caps how many recipients it can send to per 24 hours.
Without a relay host configured, mail waits in the queue and the admin queue
view says why.

## DNS records

Every domain needs MX, SPF, DKIM and DMARC records, plus SRV records so mail
apps can find the server. The admin API (`GetDomainSetup`, and the Domains
screen in the webmail) lists the exact values, creates the DKIM key on first
use, and can look the records up to show which are missing. When mail leaves
through a relay, add the relay's SPF include to the SPF record.

## Behind a web gateway (HTTP)

Point the gateway at `http.listen` (default `:8080`). Talaria speaks HTTP/1.1
and cleartext HTTP/2 (h2c), so gRPC, gRPC-Web and Connect all pass. Tell
Talaria which addresses are the gateway, so it believes their client-IP header
and nobody else's:

```toml
[http]
listen = "127.0.0.1:8080"
trusted_proxies = ["127.0.0.1"]
client_ip_header = "X-Forwarded-For"   # or X-Real-IP
```

For `X-Forwarded-For`, Talaria takes the rightmost address that is not a
trusted proxy, so a client cannot spoof its address by sending the header.

## Behind Gateon (SMTP and IMAP)

Gateon's L4 TCP proxy carries SMTP and IMAP unchanged, including STARTTLS.
Its guide is `doc/email-backend-setup.md` in the Gateon repository. On the
Gateon side:

1. Create one TCP entrypoint per mail port (25, 587, 465, 143, 993) and give
   each only its `tcp` route. A port that also serves HTTP routes delays the
   greeting by 500 ms, because Gateon waits to see whether the client speaks
   first. Also list explicit entrypoints on every HTTP and gRPC route, or they
   get served on the mail ports too.
2. Create a TCP service whose targets are Talaria's ports, with **Send PROXY
   protocol** on. Gateon's L4 proxy sends v1; Talaria accepts v1 and v2.
3. Leave TLS off on the STARTTLS ports (25, 587, 143).
4. For 465 and 993, either pass TLS through to Talaria (no TLS on the
   entrypoint, targets on Talaria's 465/993), or let Gateon terminate TLS and
   point the targets at Talaria's plaintext listeners with `upstream_tls`.

On the Talaria side, trust Gateon's address:

```toml
[smtp]
trusted_proxies = ["10.0.0.2"]   # Gateon's address as Talaria sees it
upstream_tls = false             # true if Gateon terminates TLS on 465

[imap]
trusted_proxies = ["10.0.0.2"]
upstream_tls = false             # true if Gateon terminates TLS on 993
```

Connections from a trusted proxy must start with a PROXY header; the address
in it is what SPF, DNSBL lookups, rate limits and logs use. Connections from
any other address are served directly, and a PROXY header they send is not
believed. Firewall the mail ports so only Gateon can reach them if Talaria
should never take direct traffic.

## Behind Cloudflare Tunnel

Cloudflare Tunnel carries HTTP, so webmail and the API work as-is:

```yaml
# /etc/cloudflared/config.yml
tunnel: <tunnel-id>
credentials-file: /etc/cloudflared/<tunnel-id>.json
ingress:
  - hostname: mail.example.com
    service: http://localhost:8080
  - service: http_status:404
```

```toml
[http]
listen = "127.0.0.1:8080"
trusted_proxies = ["127.0.0.1", "::1"]
client_ip_header = "CF-Connecting-IP"

[tls]
mode = "off"   # Cloudflare terminates HTTPS
```

The webmail uses the Connect protocol over plain HTTP POST/GET, not raw gRPC,
so it does not depend on end-to-end HTTP/2 trailers through the tunnel.

A public tunnel does **not** accept raw TCP from the internet, so port 25 and
IMAP need another path:

- **Inbound mail through Cloudflare Email Routing.** Email Routing
  receives mail for the domain and an Email Worker posts each raw message to
  Talaria's ingest endpoint through the tunnel, authenticated with a bearer
  token (`[ingest]` in the config). Cloudflare then sees all inbound mail,
  messages are limited to Email Routing's size cap, the SMTP-level rejection
  of unknown recipients happens in the Worker, and SPF is evaluated by
  Cloudflare rather than by Talaria, which only sees the Worker. Each domain
  must use Cloudflare DNS.
- **Mail apps.** IMAP and SMTP submission need either a public TCP path
  (Gateon or a direct port on some host with a public IP) or clients on
  Cloudflare WARP / private networks. With the tunnel alone, webmail is the
  way to read and send mail.

### Cloudflare Email Worker for inbound mail

1. Create a token of at least 32 characters and point the config at it:

   ```sh
   openssl rand -base64 48 > /etc/talaria/ingest-token
   chmod 600 /etc/talaria/ingest-token
   ```

   ```toml
   [ingest]
   enabled = true
   token_file = "/etc/talaria/ingest-token"
   ```

2. Create an Email Worker with the same token as the secret `TALARIA_TOKEN`
   and the variable `TALARIA_URL` set to `https://mail.example.com`:

   ```js
   export default {
     async email(message, env) {
       const res = await fetch(`${env.TALARIA_URL}/ingest/v1/message`, {
         method: "POST",
         headers: {
           Authorization: `Bearer ${env.TALARIA_TOKEN}`,
           "X-Envelope-From": message.from,
           "X-Envelope-To": message.to,
         },
         body: message.raw,
       });
       if (res.ok) return;
       const why = await res.text();
       // 550 and 413 are permanent: refuse the message so the sender gets a bounce.
       if (res.status === 550 || res.status === 413) {
         message.setReject(why);
         return;
       }
       // Anything else is temporary; failing lets the sender retry.
       throw new Error(`talaria ${res.status}: ${why}`);
     },
   };
   ```

3. In Email Routing, send the catch-all (or each address) to the Worker.

The endpoint answers `200` when delivered, `550` when no recipient exists or
the message is refused, `413` when it is larger than `smtp.max_message_size`,
and `503` for temporary problems. Messages that fail DMARC are filed in Junk
rather than refused, because the Worker cannot pass on the sender's IP for
an SPF check.

A combined setup works well: Cloudflare Tunnel for webmail, and Gateon (or a
small public-IP host) for ports 25, 587, 465, 143 and 993.
