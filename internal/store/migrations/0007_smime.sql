-- Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
-- SPDX-License-Identifier: MIT

-- S/MIME certificates each user knows: their own (public part only; the
-- private key stays in their browser), ones they imported, and ones taken
-- from signed mail they received.
CREATE TABLE smime_certs (
  id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  user_id     BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  email       TEXT NOT NULL,
  der         BYTEA NOT NULL,
  fingerprint BYTEA NOT NULL,
  subject     TEXT NOT NULL,
  issuer      TEXT NOT NULL,
  not_before  BIGINT NOT NULL,
  not_after   BIGINT NOT NULL,
  source      TEXT NOT NULL CHECK (source IN ('own', 'imported', 'harvested')),
  created_at  BIGINT NOT NULL,
  UNIQUE (user_id, email, fingerprint)
);
CREATE INDEX smime_certs_email ON smime_certs(email, source);
