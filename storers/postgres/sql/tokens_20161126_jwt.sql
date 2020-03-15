-- +migrate Down
ALTER TABLE tokens ADD COLUMN hash VARCHAR(64) NOT NULL DEFAULT '',
		   ADD COLUMN hash_salt VARCHAR(64) NOT NULL DEFAULT '',
		   ADD COLUMN hash_iterations INT NOT NULL DEFAULT 0,
		   ADD CONSTRAINT unique_value UNIQUE(hash, hash_salt, hash_iterations);

-- +migrate Up
ALTER TABLE tokens DROP COLUMN IF EXISTS hash,
		   DROP COLUMN IF EXISTS hash_salt,
		   DROP COLUMN IF EXISTS hash_iterations,
		   DROP CONSTRAINT IF EXISTS unique_value;
