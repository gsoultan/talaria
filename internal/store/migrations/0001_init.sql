-- Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
-- SPDX-License-Identifier: MIT

-- Every row below a tenant carries tenant_id, so every query can be scoped to
-- one tenant and no data crosses tenants. Times are unix seconds.

CREATE TABLE tenants (
  id            BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  name          TEXT NOT NULL UNIQUE,
  display_name  TEXT NOT NULL,
  seat_limit    BIGINT NOT NULL DEFAULT 0,       -- 0 = unlimited
  quota_bytes   BIGINT NOT NULL DEFAULT 0,       -- 0 = unlimited
  daily_send_limit BIGINT NOT NULL DEFAULT 0,    -- 0 = unlimited
  suspended     BOOLEAN NOT NULL DEFAULT false,
  created_at    BIGINT NOT NULL
);

CREATE TABLE domains (
  id            BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  tenant_id     BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  name          TEXT NOT NULL UNIQUE,            -- lower-case ASCII (punycode)
  catchall_user_id BIGINT,
  created_at    BIGINT NOT NULL
);
CREATE INDEX domains_tenant ON domains(tenant_id);

CREATE TABLE users (
  id            BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  tenant_id     BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  domain_id     BIGINT NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
  local_part    TEXT NOT NULL,                   -- lower-case
  display_name  TEXT NOT NULL DEFAULT '',
  password_hash TEXT NOT NULL,
  role          SMALLINT NOT NULL DEFAULT 0,     -- 0 user, 1 tenant admin, 2 platform admin
  quota_bytes   BIGINT NOT NULL DEFAULT 0,       -- 0 = tenant default / unlimited
  used_bytes    BIGINT NOT NULL DEFAULT 0,
  suspended     BOOLEAN NOT NULL DEFAULT false,
  created_at    BIGINT NOT NULL,
  UNIQUE (domain_id, local_part)
);
CREATE INDEX users_tenant ON users(tenant_id);

ALTER TABLE domains ADD FOREIGN KEY (catchall_user_id) REFERENCES users(id) ON DELETE SET NULL;

CREATE TABLE aliases (
  id            BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  tenant_id     BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  domain_id     BIGINT NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
  local_part    TEXT NOT NULL,
  user_id       BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  UNIQUE (domain_id, local_part)
);
CREATE INDEX aliases_user ON aliases(user_id);
CREATE INDEX aliases_tenant ON aliases(tenant_id);

CREATE TABLE sessions (
  token_hash    BYTEA PRIMARY KEY,               -- SHA-256 of the bearer token
  user_id       BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at    BIGINT NOT NULL,
  expires_at    BIGINT NOT NULL,
  user_agent    TEXT NOT NULL DEFAULT '',
  client_ip     TEXT NOT NULL DEFAULT ''
);
CREATE INDEX sessions_user ON sessions(user_id);
CREATE INDEX sessions_expiry ON sessions(expires_at);

CREATE TABLE mailboxes (
  id            BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  user_id       BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name          TEXT NOT NULL,
  special_use   TEXT NOT NULL DEFAULT '',        -- \Inbox, \Sent, \Drafts, \Junk, \Trash, \Archive
  uid_validity  BIGINT NOT NULL,
  uid_next      BIGINT NOT NULL DEFAULT 1,
  highest_modseq BIGINT NOT NULL DEFAULT 1,
  subscribed    BOOLEAN NOT NULL DEFAULT true,
  UNIQUE (user_id, name)
);

-- One message body is stored once per tenant, however many recipients or
-- copies refer to it.
CREATE TABLE blobs (
  id            BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  tenant_id     BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  hash          BYTEA NOT NULL,                  -- SHA-256 of tenant id + content
  size          BIGINT NOT NULL,                 -- raw bytes
  stored_size   BIGINT NOT NULL,                 -- compressed bytes on disk
  refs          BIGINT NOT NULL DEFAULT 0,
  UNIQUE (tenant_id, hash)
);
CREATE INDEX blobs_unreferenced ON blobs(id) WHERE refs <= 0;

CREATE TABLE messages (
  id            BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  mailbox_id    BIGINT NOT NULL REFERENCES mailboxes(id) ON DELETE CASCADE,
  uid           BIGINT NOT NULL,
  modseq        BIGINT NOT NULL,
  blob_id       BIGINT NOT NULL REFERENCES blobs(id),
  thread_id     BIGINT NOT NULL DEFAULT 0,
  flags         BIGINT NOT NULL DEFAULT 0,       -- bitmask, see store.Flag
  internal_date BIGINT NOT NULL,
  size          BIGINT NOT NULL,
  sent_date     BIGINT NOT NULL DEFAULT 0,
  subject       TEXT NOT NULL DEFAULT '',
  from_name     TEXT NOT NULL DEFAULT '',
  from_addr     TEXT NOT NULL DEFAULT '',
  to_addrs      TEXT NOT NULL DEFAULT '',
  cc_addrs      TEXT NOT NULL DEFAULT '',
  message_id    TEXT NOT NULL DEFAULT '',
  in_reply_to   TEXT NOT NULL DEFAULT '',
  preview       TEXT NOT NULL DEFAULT '',
  has_attachments BOOLEAN NOT NULL DEFAULT false,
  auth_results  BIGINT NOT NULL DEFAULT 0,       -- bitmask: spf/dkim/dmarc pass
  -- Folded words of subject, addresses and body, without positions; the
  -- text itself is not stored. See store.searchText.
  search        TSVECTOR NOT NULL DEFAULT ''::tsvector,
  UNIQUE (mailbox_id, uid)
);
CREATE INDEX messages_list ON messages(mailbox_id, internal_date DESC, id DESC);
CREATE INDEX messages_modseq ON messages(mailbox_id, modseq);
CREATE INDEX messages_msgid ON messages(message_id) WHERE message_id <> '';
CREATE INDEX messages_thread ON messages(thread_id);
CREATE INDEX messages_blob ON messages(blob_id);
CREATE INDEX messages_search ON messages USING gin(search);

-- Keywords beyond the system flags (IMAP keywords, labels).
CREATE TABLE message_keywords (
  message_id    BIGINT NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
  keyword       TEXT NOT NULL,
  PRIMARY KEY (message_id, keyword)
);

-- Removed messages, kept so clients can sync deletions (IMAP QRESYNC, webmail
-- live updates). Old rows are pruned.
CREATE TABLE expunged (
  mailbox_id    BIGINT NOT NULL REFERENCES mailboxes(id) ON DELETE CASCADE,
  uid           BIGINT NOT NULL,
  modseq        BIGINT NOT NULL,
  message_id    BIGINT NOT NULL,
  PRIMARY KEY (mailbox_id, uid)
);
CREATE INDEX expunged_modseq ON expunged(mailbox_id, modseq);

-- DKIM signing keys, one active key per domain.
CREATE TABLE dkim_keys (
  domain_id     BIGINT PRIMARY KEY REFERENCES domains(id) ON DELETE CASCADE,
  selector      TEXT NOT NULL,
  algorithm     TEXT NOT NULL,                   -- rsa or ed25519
  private_key   BYTEA NOT NULL,                  -- PKCS#8 DER
  created_at    BIGINT NOT NULL
);

-- Outbound queue: one row per remote recipient. The body is a blob of the
-- sender's tenant, referenced like a message so it is kept until sent.
CREATE TABLE queue (
  id            BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  tenant_id     BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  user_id       BIGINT REFERENCES users(id) ON DELETE SET NULL,
  blob_id       BIGINT NOT NULL REFERENCES blobs(id),
  mail_from     TEXT NOT NULL,
  rcpt_to       TEXT NOT NULL,
  rcpt_domain   TEXT NOT NULL,
  size          BIGINT NOT NULL,
  status        SMALLINT NOT NULL DEFAULT 0,     -- 0 waiting, 1 sending, 2 sent, 3 bounced
  attempts      INTEGER NOT NULL DEFAULT 0,
  next_attempt  BIGINT NOT NULL,
  last_error    TEXT NOT NULL DEFAULT '',
  created_at    BIGINT NOT NULL,
  updated_at    BIGINT NOT NULL
);
CREATE INDEX queue_due ON queue(status, next_attempt);
CREATE INDEX queue_tenant ON queue(tenant_id, created_at DESC);
CREATE INDEX queue_user_sent ON queue(user_id, created_at);
CREATE INDEX queue_blob ON queue(blob_id);
