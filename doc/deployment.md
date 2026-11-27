# Deploying Talaria

Talaria is one binary. It runs directly on a host with a public IP, behind a
TCP/HTTP gateway such as [Gateon](https://github.com/gsoultan/gateon), or
behind Cloudflare Tunnel. The three differ only in how traffic reaches it.

| Traffic | Direct public IP | Behind Gateon (or HAProxy, nginx) | Cloudflare Tunnel only |
|---|---|---|---|
| Webmail and API (HTTP) | yes | yes, HTTP route | yes |
| Inbound mail (SMTP 25) | yes | yes, L4 TCP route + PROXY protocol | via Cloudflare Email Routing and the HTTP ingest endpoint |
| Mail apps (IMAP 143/993, POP3 110/995, submission 587/465) | yes | yes, L4 TCP routes | no, unless each client runs WARP or `cloudflared access tcp` |
| Outbound mail | relay (default) or direct on 25 | same | relay |

## PostgreSQL

Talaria keeps tenants, users, mailboxes, message summaries and the search
index in PostgreSQL 15 or newer; message bodies stay on disk under
`data_dir`, compressed and stored once per tenant. Most of the database is
the search index, which stores each message's words once without their
positions.

On one 2 GB machine running both, install PostgreSQL from the distribution
and copy [deploy/postgresql-talaria.conf](../deploy/postgresql-talaria.conf)
into its `conf.d`: it caps PostgreSQL near 600 MB and listens on localhost
only. Keep `synchronous_commit` on, so mail that was accepted survives a
crash. A managed PostgreSQL (or one on another host) works the same; use
`sslmode=require` in the URL.

```sh
sudo -u postgres createuser -P talaria
sudo -u postgres createdb -O talaria talaria
echo 'TALARIA_DATABASE_URL=postgres://talaria:SECRET@localhost:5432/talaria' | sudo tee /etc/talaria/env
sudo chmod 600 /etc/talaria/env
```

The systemd unit reads `/etc/talaria/env`. Back up with `pg_dump` together
with `data_dir/blobs`; a database without its blobs, or the reverse, is
incomplete.

## Inbound filtering

Port 25 checks every connection before it accepts mail, so refused mail is
never stored:

- **HELO.** A server that claims this server's own name, or an address
  literal that is not its own, is refused.
- **DNS blocklists** (`filter.dnsbl`). Spamhaus answers only through your
  own resolver: install `unbound` and point `/etc/resolv.conf` at
  127.0.0.1, or drop it from the list.
- **Greylisting** (`filter.greylist`, off by default). The first message
  from an unknown sender, network and recipient is deferred for five
  minutes; real servers retry, most spam software does not. It delays the
  first mail from every new sender.
- **Reverse DNS** (`filter.require_rdns`, off by default).
- **Rate limit** (`filter.max_per_ip_hour`).
- **Tenant lists.** Admins block or allow senders by address, domain or IP
  range under Admin > Sender filtering. Allow skips the blocklists,
  greylisting and reverse DNS check.

Mail from loopback and private addresses skips the network checks.

## Spam

Accepted mail gets a spam score (`[spam]`), shown in the `X-Spam-Status`
header. Around 0 is normal mail. At `junk_score` (6) it goes to Junk; at
`quarantine_score` (10) it is held in quarantine; at `reject_score` (15) it is refused during SMTP, so the sender learns it was
not delivered. The score comes from:

- **Sender checks.** DMARC, DKIM or SPF passes lower it; a stranger with
  none of them, or an SPF or DMARC failure, raises it. So do a bad HELO and
  missing reverse DNS.
- **Message tells.** A missing Message-ID or Date, an empty or all-capitals
  subject, a display name that holds another address
  (`"service@paypal.com" <x@elsewhere>`), phishing phrases, links to bare
  IP addresses and to link shorteners.
- **Each person's own filter.** Moving mail into Junk, or out of Junk to
  any folder but Trash, in the webmail or in an IMAP app that uses MOVE,
  teaches that person's Bayesian filter. It starts scoring once they have
  marked 20 messages each way, and can then add up to 5 or take away up
  to 4.
- **Rspamd, optional** (`spam.rspamd_url`). Its score is added. It needs
  about 200 MB of memory with Redis, so leave it off on a 2 GB machine
  that also runs PostgreSQL unless spam gets through.

Senders on a tenant's allow list are never junked, held or refused for
their score.

## Malware

Inbound mail with a dangerous attachment is refused during SMTP
(`[malware]`), so the sender gets a bounce that names the file. Talaria
looks inside each attachment, and inside zip files up to three levels
deep:

- **File types that run code:** `.exe`, `.js`, `.vbs`, `.lnk`, `.iso`,
  `.img`, `.hta`, `.scr`, `.one` and about fifty more, by name and also
  by content, so a program renamed to `.pdf` is still caught.
- **Office macros** (`block_macros`): `.docm`, `.xlsm` and the like, and
  `.docx`, `.xlsx` or old `.doc` and `.xls` files that carry a VBA project.
- **YARA rules.** Built-in rules catch the EICAR test file, HTML
  smuggling, PDFs that run JavaScript when opened, script downloaders
  and Office DDE commands. Add your own `.yar` files in
  `malware.rules_dir`; YARA modules such as `pe` are not supported.
- **Password-protected archives** (`block_encrypted_archives`, off by
  default). The names inside are still checked.
- **ClamAV, optional** (`malware.clamav`). It needs about 1 GB of memory,
  so only add it on a larger machine. When it is down, mail is deferred
  with a temporary error rather than let in unscanned.

With `malware.action = "quarantine"` (the default) such mail is held for
an admin instead of refused. To test it, send a message with the EICAR
test file attached.

## Quarantine

Held mail stays out of every folder, IMAP and POP3 included, until it is
released or deleted.

- **People** see their own held mail under Quarantine in the webmail and
  can release spam to their Inbox or delete it. Mail held for a dangerous
  attachment needs an admin, unless `malware.user_release` is on.
- **A daily digest** (`quarantine.digest`, at `digest_hour`) lists what
  was held for each person since the last one, with a link to the
  webmail. Set `quarantine.web_url` if the webmail is not at
  `https://<hostname>`.
- **Admins** review a tenant's held mail under Admin > Quarantine: the
  findings, attachment names, headers and the text of the message (never
  its HTML), then release it to the recipient or delete it.
- Held mail is deleted after `quarantine.keep_days` (30).

## Safe links

Every link in a message opened in the webmail goes through
`/api/v1/link`, which checks it when it is clicked, so a link that turned
bad after the mail arrived is still caught (`[safe_links]`):

- **Threat feeds.** URLhaus (malware) and OpenPhish (phishing) are
  downloaded every 30 minutes and kept in `data_dir/safelinks`, so a
  restart works without them. Replace them with `[[safe_links.feed]]`
  entries: one URL per line, or one host per line with `hosts = true`.
- **Blocked domains** (`safe_links.block`), with their subdomains.
- **Tells of phishing** get a warning with a way through: a bare IP
  address, look-alike international characters, a user name in front of
  the real host (`https://paypal.com@evil.example`), an unusual port.

Only signed-in users are redirected, so the link check cannot be used as
an open redirect. The stored message is not changed: mail apps over IMAP
and POP3 see the original links.

## Safe attachments

Clicking an attachment in the webmail opens a preview, not the file.
The server reads the file and sends back only what is in it, so nothing
in it runs in the browser or on the computer:

- **Text** of Word, Excel, PowerPoint and OpenDocument files, PDFs, RTF,
  HTML (as plain text), saved messages and text files.
- **The file list** of zip archives.
- **Images** decoded and drawn again as PNG, which leaves behind metadata
  and anything hidden in or appended to the file.

Types that can carry macros or exploits (Office, PDF, archives, HTML,
programs) are marked, and the preview says what the malware scanner
finds in the file. Download is a separate button, and is not offered at
all for a file the scanner flags. PDFs drawn from scanned pages or fonts
with their own encodings have no readable text; the preview says so.

## Data loss prevention

Tenant admins set policies under **Admin → Data loss prevention**. Each
policy looks for one kind of data in outgoing mail: the subject, the body
and the text of attachments (the same reader as the attachment preview).

- **Detectors**: payment card numbers (with the Luhn check digit), IBANs
  (with their check digits), US Social Security numbers, Indonesian NIK
  numbers, a regular expression of your own, or a list of words.
- **Matches needed**: how many different values must be found.
- **Outside recipients only** (the default): skip mail that stays in the
  tenant's own domains.

What a policy does when it matches, strongest first:

| Action | Webmail | Mail apps (587/465) |
| --- | --- | --- |
| Block | Refused with a message naming the policy | Refused, `550 5.7.1` |
| Warn | Asks the sender to confirm, then sends | Sent; the contact is told |
| Require encryption | Sent only over a verified TLS connection | Same |
| Notify | Sent; the contact is told | Same |

Notices go to the policy's contact address (a user in the tenant) or, when
it has none, to the tenant's admins. They name the policy, the sender, the
recipients and the subject, and show masked samples such as
`••••••••••••1111`, never the message.

**Require encryption** with `outbound.mode = "direct"` sends only when the
recipient's server offers STARTTLS with a certificate that verifies, and
otherwise retries and then bounces. With a relay, the hop to the relay is
always encrypted; Talaria also asks the relay to keep it encrypted to the
recipient (REQUIRETLS, RFC 8689) when the relay offers that. Most relays do
not, so what happens after the relay is up to the relay.

The admin page has a box to try your policies on sample text before you
turn them on.

## Audit log

**Admin → Audit log** lists what happened in a tenant, newest first, with
filters and a CSV export (up to 100,000 rows, and the export is itself
recorded):

- **Sign-ins** to the webmail, IMAP, POP3 and SMTP submission, and failed
  ones with the reason. Mail apps sign in every few minutes, so their
  successful sign-ins are recorded once a day per account, IP and
  protocol, and failures at most once a minute. Attempts on an address
  that does not exist go to the tenant that owns its domain.
- **Admin actions**: every change made in the admin pages or API, with the
  request (passwords and secrets hidden) and the result, including
  refused ones. A tenant admin's attempt on another tenant shows in their
  own tenant's log.
- **Admins reading held mail** in the quarantine review.
- **Policy matches**: data loss prevention hits (policy names and counts,
  never the data), and links that were blocked or warned about when
  clicked. Users releasing their own held mail.
- **Command line** changes (`talaria user`, `passwd` and so on).

Platform admins see entries that belong to no tenant, such as command line
changes, under their own tenant.

The table is append-only: PostgreSQL refuses to update, delete or truncate
it. The only exception is the nightly retention purge (`[audit] keep_days`,
365 by default, 0 to keep everything), and even it cannot remove anything
less than a day old. Each entry also carries a hash over the one before it,
so an entry edited or removed by someone who bypasses the database rules
breaks the chain. Check it with:

```
talaria audit-verify -config /etc/talaria/talaria.toml
```

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
and cleartext HTTP/2 (h2c). The API is plain JSON over HTTP, and live
updates are server-sent events, so any HTTP gateway passes them. Tell
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

1. Create one TCP entrypoint per mail port (25, 587, 465, 143, 993, and 110
   and 995 if POP3 is on) and give
   each only its `tcp` route. A port that also serves HTTP routes delays the
   greeting by 500 ms, because Gateon waits to see whether the client speaks
   first. Also list explicit entrypoints on every HTTP and gRPC route, or they
   get served on the mail ports too.
2. Create a TCP service whose targets are Talaria's ports, with **Send PROXY
   protocol** on. Gateon's L4 proxy sends v1; Talaria accepts v1 and v2.
3. Leave TLS off on the STARTTLS ports (25, 587, 143, 110).
4. For 465, 993 and 995, either pass TLS through to Talaria (no TLS on the
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

[pop3]                           # only if POP3 is on
listen = ":110"
listen_tls = ":995"
trusted_proxies = ["10.0.0.2"]
```

Mail apps send passwords, so Talaria only opens a port where they are safe:

- STARTTLS ports (587, 143, 110) open only with certificates (`tls.mode`).
- Implicit-TLS ports (465, 993, 995) open with certificates, or with
  `upstream_tls` behind a gateway that terminates TLS.
- Port 25 always opens, offering STARTTLS when there are certificates.

`upstream_tls` is checked per connection. Only connections from
`trusted_proxies` that start with a PROXY header count as encrypted. Any
other connection to that port gets a normal TLS handshake when Talaria has
certificates, and is closed when it does not, so a client that reaches the
port directly can never log in over plaintext. `upstream_tls` without
`trusted_proxies` is a configuration error.

Each client address may hold at most 32 connections per mail port, on top of
`smtp.max_connections` for the whole port.

Connections from a trusted proxy must start with a PROXY header; the address
in it is what SPF, DNSBL lookups, rate limits and logs use. Connections from
any other address are served directly, and a PROXY header they send is not
believed. Firewall the mail ports so only Gateon can reach them if Talaria
should never take direct traffic.

## Certificates

With a public IP, let Talaria get certificates from Let's Encrypt:

```toml
[http]
listen = ":80"         # also answers HTTP-01 challenges
listen_tls = ":443"

[tls]
mode = "acme"
email = "admin@example.com"
hosts = ["mail.example.com"]   # defaults to hostname
```

Certificates are kept in `data_dir/acme` and renewed before they expire. The
same certificate serves HTTPS, SMTP, submission, IMAP and POP3; a mail app
that sends no server name gets the one for `hostname`. Port 443 (or 80) must
be reachable from the internet for the domain check.

If certbot or acme.sh already manages certificates, use `mode = "files"`
with `cert_file` and `key_file`. Talaria notices renewed files within a
minute without a restart.

## Browser security

The webmail page only runs its own scripts (a strict Content-Security-Policy)
and cannot be framed by other sites. HTML mail renders in a sandboxed frame
with scripts off, and remote images stay blocked until the reader allows
them. Attachments are sent with `Content-Security-Policy: sandbox`, and
types that can run script (HTML, SVG) always download instead of opening.
Over HTTPS, responses carry HSTS. Behind Cloudflare Tunnel, turn on HSTS in
the Cloudflare dashboard instead.

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

The webmail uses plain JSON over HTTP and server-sent events for live
updates, so it does not depend on end-to-end HTTP/2 through the tunnel. The
server sends a heartbeat every 25 seconds, which keeps the event stream open
through Cloudflare's idle timeout.

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
