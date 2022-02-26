-- +migrate Up
ALTER TABLE tokens ADD COLUMN account_id VARCHAR(36) NOT NULL DEFAULT '';

-- +migrate Down
ALTER TABLE tokens DROP COLUMN IF EXISTS account_id;
