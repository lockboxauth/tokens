ALTER TABLE tokens ADD COLUMN hash VARCHAR(64) NOT NULL,
		   ADD COLUMN hash_salt VARCHAR(64) NOT NULL,
		   ADD COLUMN hash_iterations INT NOT NULL,
		   ADD CONSTRAINT unique_value UNIQUE(hash, hash_salt, hash_iterations);
