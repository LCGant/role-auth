ALTER TABLE users
ADD COLUMN IF NOT EXISTS password_auth_enabled BOOLEAN;

UPDATE users u
SET password_auth_enabled = CASE
    WHEN EXISTS (
        SELECT 1
        FROM audit_log a
        WHERE a.user_id = u.id
          AND a.event_type = 'register'
    ) THEN TRUE
    WHEN EXISTS (
        SELECT 1
        FROM password_resets pr
        WHERE pr.user_id = u.id
          AND pr.used_at IS NOT NULL
    ) THEN TRUE
    WHEN NOT EXISTS (
        SELECT 1
        FROM identities i
        WHERE i.user_id = u.id
    ) THEN TRUE
    ELSE FALSE
END
WHERE password_auth_enabled IS NULL;

ALTER TABLE users
ALTER COLUMN password_auth_enabled SET NOT NULL;
