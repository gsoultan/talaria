-- Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
-- SPDX-License-Identifier: MIT

-- Spam score given at delivery, and how the message trained the filter:
-- 0 not used, 1 as spam, 2 as ham.
ALTER TABLE messages ADD COLUMN spam_score REAL NOT NULL DEFAULT 0;
ALTER TABLE messages ADD COLUMN trained SMALLINT NOT NULL DEFAULT 0;

-- Per-user Bayesian word counts. token is a 64-bit hash of the word, so no
-- text is stored.
CREATE TABLE bayes_tokens (
  user_id       BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token         BIGINT NOT NULL,
  spam          INTEGER NOT NULL DEFAULT 0,
  ham           INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (user_id, token)
);

-- How many messages each user's counts came from.
CREATE TABLE bayes_users (
  user_id       BIGINT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  spam          INTEGER NOT NULL DEFAULT 0,
  ham           INTEGER NOT NULL DEFAULT 0
);

-- Messages moved into or out of Junk, waiting to train the filter.
CREATE TABLE spam_train (
  id            BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  user_id       BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  message_id    BIGINT NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
  spam          BOOLEAN NOT NULL,
  created_at    BIGINT NOT NULL
);
CREATE INDEX spam_train_message ON spam_train(message_id);
