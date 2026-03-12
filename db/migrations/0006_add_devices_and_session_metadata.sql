CREATE TABLE IF NOT EXISTS devices (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    client_family TEXT NOT NULL DEFAULT 'generic',
    trust_level TEXT NOT NULL DEFAULT 'known',
    risk_score INTEGER NOT NULL DEFAULT 0,
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_ip TEXT,
    last_user_agent TEXT,
    revoked_at TIMESTAMPTZ,
    CONSTRAINT devices_trust_level_check CHECK (trust_level IN ('known', 'trusted', 'verified')),
    CONSTRAINT devices_risk_score_check CHECK (risk_score >= 0)
);

CREATE INDEX IF NOT EXISTS idx_devices_user_id ON devices(user_id);
CREATE INDEX IF NOT EXISTS idx_devices_last_seen_at ON devices(last_seen_at);

ALTER TABLE sessions
ADD COLUMN IF NOT EXISTS device_id BIGINT REFERENCES devices(id) ON DELETE SET NULL;

ALTER TABLE sessions
ADD COLUMN IF NOT EXISTS idle_expires_at TIMESTAMPTZ;

UPDATE sessions
SET idle_expires_at = expires_at
WHERE idle_expires_at IS NULL;

ALTER TABLE sessions
ALTER COLUMN idle_expires_at SET NOT NULL;

ALTER TABLE sessions
ADD COLUMN IF NOT EXISTS risk_score INTEGER NOT NULL DEFAULT 0;

ALTER TABLE sessions
ADD COLUMN IF NOT EXISTS auth_method TEXT NOT NULL DEFAULT 'session';

CREATE INDEX IF NOT EXISTS idx_sessions_device_id ON sessions(device_id);
