-- Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
-- SPDX-License-Identifier: MIT

-- Audit log: append-only. Rows cannot be changed, and can be deleted only
-- by the retention purge, which marks its transaction and removes rows
-- older than a day. Each row's hash covers the previous row's hash, so a
-- row removed or edited behind the database's back breaks the chain.
-- tenant_id has no foreign key on purpose: the record outlives the tenant.
CREATE TABLE audit_log (
  id         BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  at         BIGINT NOT NULL,
  tenant_id  BIGINT NOT NULL DEFAULT 0,
  actor_id   BIGINT NOT NULL DEFAULT 0,
  actor      TEXT NOT NULL DEFAULT '',
  ip         TEXT NOT NULL DEFAULT '',
  action     TEXT NOT NULL,
  target     TEXT NOT NULL DEFAULT '',
  outcome    TEXT NOT NULL DEFAULT 'ok',
  detail     TEXT NOT NULL DEFAULT '',
  hash       BYTEA NOT NULL
);
CREATE INDEX audit_tenant ON audit_log(tenant_id, id DESC);
CREATE INDEX audit_at ON audit_log(at);

CREATE FUNCTION audit_log_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'DELETE' AND current_setting('talaria.audit_purge', true) = 'on'
     AND OLD.at < extract(epoch FROM now())::bigint - 86400 THEN
    RETURN OLD;
  END IF;
  RAISE EXCEPTION 'audit_log is append-only' USING ERRCODE = 'insufficient_privilege';
END $$;

CREATE TRIGGER audit_log_no_change BEFORE UPDATE OR DELETE ON audit_log
  FOR EACH ROW EXECUTE FUNCTION audit_log_guard();
CREATE TRIGGER audit_log_no_truncate BEFORE TRUNCATE ON audit_log
  FOR EACH STATEMENT EXECUTE FUNCTION audit_log_guard();
