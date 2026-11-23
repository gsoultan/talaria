-- Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
-- SPDX-License-Identifier: MIT

-- DKIM signing keys, one active key per domain.
CREATE TABLE dkim_keys (
  domain_id     INTEGER PRIMARY KEY REFERENCES domains(id) ON DELETE CASCADE,
  selector      TEXT NOT NULL,
  algorithm     TEXT NOT NULL,                   -- rsa or ed25519
  private_key   BLOB NOT NULL,                   -- PKCS#8 DER
  created_at    INTEGER NOT NULL
) STRICT;

-- Outbound queue: one row per remote recipient. The body is a blob of the
-- sender's tenant, referenced like a message so it is kept until sent.
CREATE TABLE queue (
  id            INTEGER PRIMARY KEY,
  tenant_id     INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  user_id       INTEGER REFERENCES users(id) ON DELETE SET NULL,
  blob_id       INTEGER NOT NULL REFERENCES blobs(id),
  mail_from     TEXT NOT NULL,
  rcpt_to       TEXT NOT NULL,
  rcpt_domain   TEXT NOT NULL,
  size          INTEGER NOT NULL,
  status        INTEGER NOT NULL DEFAULT 0,      -- 0 waiting, 1 sending, 2 sent, 3 bounced
  attempts      INTEGER NOT NULL DEFAULT 0,
  next_attempt  INTEGER NOT NULL,
  last_error    TEXT NOT NULL DEFAULT '',
  created_at    INTEGER NOT NULL,
  updated_at    INTEGER NOT NULL
) STRICT;
CREATE INDEX queue_due ON queue(status, next_attempt);
CREATE INDEX queue_tenant ON queue(tenant_id, created_at DESC);
CREATE INDEX queue_user_sent ON queue(user_id, created_at);
