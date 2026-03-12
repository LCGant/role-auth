ALTER TABLE sessions
ADD COLUMN IF NOT EXISTS auth_time TIMESTAMPTZ;

UPDATE sessions
SET auth_time = created_at
WHERE auth_time IS NULL;

ALTER TABLE sessions
ALTER COLUMN auth_time SET NOT NULL;

ALTER TABLE mfa_totp
ADD COLUMN IF NOT EXISTS pending_encrypted_secret BYTEA,
ADD COLUMN IF NOT EXISTS pending_nonce BYTEA,
ADD COLUMN IF NOT EXISTS pending_created_at TIMESTAMPTZ;
