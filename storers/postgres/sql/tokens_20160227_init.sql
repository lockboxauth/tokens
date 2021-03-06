-- +migrate Up
CREATE TABLE tokens (
	id VARCHAR(64) PRIMARY KEY,
	created_at TIMESTAMPTZ NOT NULL,
	created_from TEXT NOT NULL,
	profile_id VARCHAR(36) NOT NULL,
	client_id VARCHAR(36) NOT NULL,
	revoked BOOLEAN NOT NULL,
	used BOOLEAN NOT NULL,
	scopes VARCHAR[] NOT NULL
);

-- +migrate Down
DROP TABLE tokens;
