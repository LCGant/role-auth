ALTER TABLE sessions
ADD COLUMN IF NOT EXISTS aal INTEGER NOT NULL DEFAULT 1;

UPDATE sessions
SET aal = 1
WHERE aal < 1;

ALTER TABLE sessions
DROP CONSTRAINT IF EXISTS sessions_aal_check;

ALTER TABLE sessions
ADD CONSTRAINT sessions_aal_check CHECK (aal >= 1);

