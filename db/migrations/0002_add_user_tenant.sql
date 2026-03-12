ALTER TABLE users
    ADD COLUMN IF NOT EXISTS tenant_id TEXT;

UPDATE users
SET tenant_id = 'default'
WHERE tenant_id IS NULL OR tenant_id = '';

ALTER TABLE users
    ALTER COLUMN tenant_id SET DEFAULT 'default';

ALTER TABLE users
    ALTER COLUMN tenant_id SET NOT NULL;

CREATE INDEX IF NOT EXISTS idx_users_tenant_id ON users(tenant_id);
