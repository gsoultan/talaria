-- Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
-- SPDX-License-Identifier: MIT

-- Every row below a tenant carries tenant_id, so every query can be scoped to
-- one tenant and no data crosses tenants.

CREATE TABLE tenants (
  id            INTEGER PRIMARY KEY,
  name          TEXT NOT NULL UNIQUE,
  display_name  TEXT NOT NULL,
  seat_limit    INTEGER NOT NULL DEFAULT 0,      -- 0 = unlimited
  quota_bytes   INTEGER NOT NULL DEFAULT 0,      -- 0 = unlimited
  daily_send_limit INTEGER NOT NULL DEFAULT 0,   -- 0 = unlimited
  suspended     INTEGER NOT NULL DEFAULT 0,
  created_at    INTEGER NOT NULL
) STRICT;

CREATE TABLE domains (
  id            INTEGER PRIMARY KEY,
  tenant_id     INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  name          TEXT NOT NULL UNIQUE,            -- lower-case ASCII (punycode)
  catchall_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
  created_at    INTEGER NOT NULL
) STRICT;
CREATE INDEX domains_tenant ON domains(tenant_id);

CREATE TABLE users (
  id            INTEGER PRIMARY KEY,
  tenant_id     INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  domain_id     INTEGER NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
  local_part    TEXT NOT NULL,                   -- lower-case
  display_name  TEXT NOT NULL DEFAULT '',
  password_hash TEXT NOT NULL,
  role          INTEGER NOT NULL DEFAULT 0,      -- 0 user, 1 tenant admin, 2 platform admin
  quota_bytes   INTEGER NOT NULL DEFAULT 0,      -- 0 = tenant default / unlimited
  used_bytes    INTEGER NOT NULL DEFAULT 0,
  suspended     INTEGER NOT NULL DEFAULT 0,
  created_at    INTEGER NOT NULL,
  UNIQUE (domain_id, local_part)
) STRICT;
CREATE INDEX users_tenant ON users(tenant_id);

CREATE TABLE aliases (
  id            INTEGER PRIMARY KEY,
  tenant_id     INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  domain_id     INTEGER NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
  local_part    TEXT NOT NULL,
  user_id       INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  UNIQUE (domain_id, local_part)
) STRICT;
CREATE INDEX aliases_user ON aliases(user_id);

CREATE TABLE sessions (
  token_hash    BLOB PRIMARY KEY,                -- SHA-256 of the bearer token
  user_id       INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at    INTEGER NOT NULL,
  expires_at    INTEGER NOT NULL,
  user_agent    TEXT NOT NULL DEFAULT '',
  client_ip     TEXT NOT NULL DEFAULT ''
) WITHOUT ROWID, STRICT;
CREATE INDEX sessions_user ON sessions(user_id);
CREATE INDEX sessions_expiry ON sessions(expires_at);

CREATE TABLE mailboxes (
  id            INTEGER PRIMARY KEY,
  user_id       INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name          TEXT NOT NULL,
  special_use   TEXT NOT NULL DEFAULT '',        -- \Inbox, \Sent, \Drafts, \Junk, \Trash, \Archive
  uid_validity  INTEGER NOT NULL,
  uid_next      INTEGER NOT NULL DEFAULT 1,
  highest_modseq INTEGER NOT NULL DEFAULT 1,
  subscribed    INTEGER NOT NULL DEFAULT 1,
  UNIQUE (user_id, name)
) STRICT;

-- One message body is stored once per tenant, however many recipients or
-- copies refer to it.
CREATE TABLE blobs (
  id            INTEGER PRIMARY KEY,
  tenant_id     INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  hash          BLOB NOT NULL,                   -- SHA-256 of tenant id + content
  size          INTEGER NOT NULL,                -- raw bytes
  stored_size   INTEGER NOT NULL,                -- compressed bytes on disk
  refs          INTEGER NOT NULL DEFAULT 0,
  UNIQUE (tenant_id, hash)
) STRICT;

CREATE TABLE messages (
  id            INTEGER PRIMARY KEY,
  mailbox_id    INTEGER NOT NULL REFERENCES mailboxes(id) ON DELETE CASCADE,
  uid           INTEGER NOT NULL,
  modseq        INTEGER NOT NULL,
  blob_id       INTEGER NOT NULL REFERENCES blobs(id),
  thread_id     INTEGER NOT NULL DEFAULT 0,
  flags         INTEGER NOT NULL DEFAULT 0,      -- bitmask, see store.Flag
  internal_date INTEGER NOT NULL,                -- unix seconds
  size          INTEGER NOT NULL,
  sent_date     INTEGER NOT NULL DEFAULT 0,
  subject       TEXT NOT NULL DEFAULT '',
  from_name     TEXT NOT NULL DEFAULT '',
  from_addr     TEXT NOT NULL DEFAULT '',
  to_addrs      TEXT NOT NULL DEFAULT '',
  cc_addrs      TEXT NOT NULL DEFAULT '',
  message_id    TEXT NOT NULL DEFAULT '',
  in_reply_to   TEXT NOT NULL DEFAULT '',
  preview       TEXT NOT NULL DEFAULT '',
  has_attachments INTEGER NOT NULL DEFAULT 0,
  auth_results  INTEGER NOT NULL DEFAULT 0,      -- bitmask: spf/dkim/dmarc pass
  UNIQUE (mailbox_id, uid)
) STRICT;
CREATE INDEX messages_list ON messages(mailbox_id, internal_date DESC, id DESC);
CREATE INDEX messages_modseq ON messages(mailbox_id, modseq);
CREATE INDEX messages_msgid ON messages(message_id) WHERE message_id <> '';
CREATE INDEX messages_thread ON messages(thread_id);
CREATE INDEX messages_blob ON messages(blob_id);

-- Keywords beyond the system flags (IMAP keywords, labels).
CREATE TABLE message_keywords (
  message_id    INTEGER NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
  keyword       TEXT NOT NULL,
  PRIMARY KEY (message_id, keyword)
) WITHOUT ROWID, STRICT;

-- Contentless full-text index: only the index is stored, not the text, which
-- keeps the database small. rowid = messages.id.
CREATE VIRTUAL TABLE messages_fts USING fts5(
  subject, addrs, body,
  content='', contentless_delete=1, tokenize='unicode61 remove_diacritics 2'
);

-- Removed messages, kept so clients can sync deletions (IMAP QRESYNC, webmail
-- live updates). Old rows are pruned.
CREATE TABLE expunged (
  mailbox_id    INTEGER NOT NULL REFERENCES mailboxes(id) ON DELETE CASCADE,
  uid           INTEGER NOT NULL,
  modseq        INTEGER NOT NULL,
  message_id    INTEGER NOT NULL,
  PRIMARY KEY (mailbox_id, uid)
) WITHOUT ROWID, STRICT;
CREATE INDEX expunged_modseq ON expunged(mailbox_id, modseq);
