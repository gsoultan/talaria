-- Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
-- SPDX-License-Identifier: MIT

-- Mail held back from a user: likely spam, or dangerous attachments. The
-- raw message stays in the blob store, referenced like a message is.
CREATE TABLE quarantine (
  id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  tenant_id   BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  user_id     BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  blob_id     BIGINT NOT NULL REFERENCES blobs(id),
  reason      TEXT NOT NULL CHECK (reason IN ('spam', 'malware')),
  detail      TEXT NOT NULL DEFAULT '',
  spam_score  REAL NOT NULL DEFAULT 0,
  auth_results BIGINT NOT NULL DEFAULT 0,
  env_from    TEXT NOT NULL DEFAULT '',
  from_name   TEXT NOT NULL DEFAULT '',
  from_addr   TEXT NOT NULL DEFAULT '',
  subject     TEXT NOT NULL DEFAULT '',
  size        BIGINT NOT NULL,
  created_at  BIGINT NOT NULL,
  notified    BOOLEAN NOT NULL DEFAULT FALSE
);
CREATE INDEX quarantine_tenant ON quarantine(tenant_id, id DESC);
CREATE INDEX quarantine_user ON quarantine(user_id, id DESC);
CREATE INDEX quarantine_created ON quarantine(created_at);
CREATE INDEX quarantine_digest ON quarantine(user_id) WHERE NOT notified;

-- Every way a row goes (release, delete, expiry, user or tenant removal)
-- gives its blob reference back.
CREATE FUNCTION quarantine_unref() RETURNS trigger AS $$
BEGIN
  UPDATE blobs SET refs = refs - 1 WHERE id = OLD.blob_id;
  RETURN OLD;
END $$ LANGUAGE plpgsql;
CREATE TRIGGER quarantine_unref AFTER DELETE ON quarantine FOR EACH ROW EXECUTE FUNCTION quarantine_unref();
