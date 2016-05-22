ALTER TABLE tokens ADD COLUMN hash VARCHAR(64) NOT NULL DEFAULT '',
		   ADD COLUMN hash_salt VARCHAR(64) NOT NULL DEFAULT '',
		   ADD COLUMN hash_iterations INT NOT NULL DEFAULT 0,
		   ADD CONSTRAINT unique_value UNIQUE(hash, hash_salt, hash_iterations);
