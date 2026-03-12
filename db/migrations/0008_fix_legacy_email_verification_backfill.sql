UPDATE users u
SET email_verified = FALSE,
    status = CASE WHEN status = 'active' THEN 'pending_verification' ELSE status END,
    updated_at = NOW()
WHERE u.email_verified = TRUE
  AND u.password_auth_enabled = TRUE
  AND NOT EXISTS (
      SELECT 1
      FROM email_verifications ev
      WHERE ev.user_id = u.id
        AND ev.used_at IS NOT NULL
  )
  AND NOT EXISTS (
      SELECT 1
      FROM identities i
      WHERE i.user_id = u.id
        AND i.email_verified = TRUE
  );
