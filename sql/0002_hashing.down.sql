ALTER TABLE tokens DROP COLUMN IF EXISTS hash,
		   DROP COLUMN IF EXISTS hash_salt,
		   DROP COLUMN IF EXISTS hash_iterations,
		   DROP CONSTRAINT IF EXISTS unique_value;
