# Roadmap

Phases 0 to 5 are done: the mail server, IMAP and POP3, outbound mail
through a relay, the webmail and admin, deployment behind Cloudflare Tunnel
and Gateon, and hardening. The API runs on kakarot and metadata is in
PostgreSQL.

## Phase 6: mail security

Built in this order, each step usable on its own. Everything runs inside
the Talaria binary and fits the 2 GB machine; the heavier scanners are
optional and talk to Talaria over a socket.

1. **Connection filtering** (done). DNS blocklists, greylisting, reverse DNS and
   HELO checks, per-IP rate limits, and per-tenant allow and block lists,
   applied before a message is accepted.
2. **Anti-spam** (done). A built-in scorer in Go using SPF, DKIM and DMARC
   results, header and content heuristics, and per-user Bayesian learning
   from moving mail to and from Junk. Rspamd's score can be added.
3. **Anti-malware** (done). Block dangerous attachment types and Office files with
   macros, with built-in YARA rules. ClamAV is optional, because it needs
   about 1 GB of memory on its own.
4. **Quarantine** (done). Per tenant, with a digest that lets people release or
   delete their own held mail, and an admin review screen.
5. **Safe links** (done). Links in incoming mail are rewritten in the
   webmail to a redirect that checks the target against phishing lists and URLhaus when clicked.
6. **Safe attachments** (done). Attachments open in a preview built on the
   server (text, file lists, redrawn images) instead of downloading.
7. **Data loss prevention** (done). Per-tenant policies for outgoing mail that
   match patterns (card numbers, national IDs, custom ones) and block, warn,
   encrypt or notify.
8. **Audit logs.** Append-only in PostgreSQL: sign-ins, admin changes,
   message access by admins, policy hits. Searchable and exportable.
9. **S/MIME.** Sign and encrypt in the webmail with keys that stay in the
   browser (WebCrypto in a worker), and certificates published in the
   address book.

Not planned yet: calendar, contacts and Exchange ActiveSync.
