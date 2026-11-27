-- Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
-- SPDX-License-Identifier: MIT

-- Data loss prevention: per-tenant rules for outgoing mail.
CREATE TABLE dlp_policies (
  id            BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  tenant_id     BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  name          TEXT NOT NULL,
  detector      TEXT NOT NULL,
  pattern       TEXT NOT NULL DEFAULT '',
  min_count     INTEGER NOT NULL DEFAULT 1,
  action        TEXT NOT NULL CHECK (action IN ('block', 'warn', 'encrypt', 'notify')),
  external_only BOOLEAN NOT NULL DEFAULT TRUE,
  notify        TEXT NOT NULL DEFAULT '',
  enabled       BOOLEAN NOT NULL DEFAULT TRUE,
  created_at    BIGINT NOT NULL
);
CREATE INDEX dlp_policies_tenant ON dlp_policies(tenant_id);

-- Mail a policy says must only travel encrypted.
ALTER TABLE queue ADD COLUMN require_tls BOOLEAN NOT NULL DEFAULT FALSE;
