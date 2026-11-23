-- Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
-- SPDX-License-Identifier: MIT

-- Per-tenant allow and block lists for inbound mail. A rule matches the
-- connecting IP (an address or CIDR range), the sender's domain (and its
-- subdomains), or one sender address. Allow skips the connection checks
-- (blocklists, greylisting, reverse DNS); block refuses the mail.
CREATE TABLE sender_rules (
  id            BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  tenant_id     BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  kind          TEXT NOT NULL CHECK (kind IN ('ip', 'domain', 'address')),
  value         TEXT NOT NULL,                   -- lower case; CIDR for ip
  action        TEXT NOT NULL CHECK (action IN ('allow', 'block')),
  note          TEXT NOT NULL DEFAULT '',
  created_at    BIGINT NOT NULL,
  UNIQUE (tenant_id, kind, value)
);

-- Greylisting: the first message from an unknown (network, sender,
-- recipient) triplet is deferred; a real server retries and is let in.
CREATE TABLE greylist (
  key           BYTEA PRIMARY KEY,               -- SHA-256 of the triplet
  first_seen    BIGINT NOT NULL,
  last_seen     BIGINT NOT NULL,
  passed        BOOLEAN NOT NULL DEFAULT false
);
CREATE INDEX greylist_last_seen ON greylist(last_seen);
