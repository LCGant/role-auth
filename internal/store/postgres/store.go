package postgres

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/LCGant/role-auth/internal/security"
	"github.com/LCGant/role-auth/internal/store"
)

type Store struct {
	db *sql.DB
}

func New(db *sql.DB) *Store {
	return &Store{db: db}
}

func (s *Store) CreateUser(ctx context.Context, u *store.User) error {
	query := `
	INSERT INTO users (tenant_id, email, email_verified, username, password_hash, password_auth_enabled, status, mfa_enabled, created_at, updated_at)
	VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW(), NOW())
	RETURNING id, tenant_id, email_verified, password_auth_enabled, created_at, updated_at`
	return s.db.QueryRowContext(ctx, query, u.TenantID, u.Email, u.EmailVerified, u.Username, u.PasswordHash, u.PasswordAuthEnabled, u.Status, u.MFAEnabled).
		Scan(&u.ID, &u.TenantID, &u.EmailVerified, &u.PasswordAuthEnabled, &u.CreatedAt, &u.UpdatedAt)
}

func (s *Store) CreateUserWithIdentity(ctx context.Context, u *store.User, ident *store.Identity) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	userQuery := `
	INSERT INTO users (tenant_id, email, email_verified, username, password_hash, password_auth_enabled, status, mfa_enabled, created_at, updated_at)
	VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW(), NOW())
	RETURNING id, tenant_id, email_verified, password_auth_enabled, created_at, updated_at`
	if err := tx.QueryRowContext(ctx, userQuery, u.TenantID, u.Email, u.EmailVerified, u.Username, u.PasswordHash, u.PasswordAuthEnabled, u.Status, u.MFAEnabled).
		Scan(&u.ID, &u.TenantID, &u.EmailVerified, &u.PasswordAuthEnabled, &u.CreatedAt, &u.UpdatedAt); err != nil {
		return err
	}

	ident.UserID = u.ID
	identQuery := `
	INSERT INTO identities (user_id, provider, subject, email, email_verified, created_at, last_login_at)
	VALUES ($1, $2, $3, $4, $5, NOW(), NOW())
	RETURNING id, created_at, last_login_at`
	if err := tx.QueryRowContext(ctx, identQuery, ident.UserID, ident.Provider, ident.Subject, ident.Email, ident.EmailVerified).
		Scan(&ident.ID, &ident.CreatedAt, &ident.LastLoginAt); err != nil {
		return err
	}

	return tx.Commit()
}

func (s *Store) DeleteUserByID(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM users WHERE id = $1`, id)
	return err
}

func (s *Store) FindUserByEmailOrUsername(ctx context.Context, identifier string) (*store.User, error) {
	query := `
	SELECT id, tenant_id, email, email_verified, username, password_hash, password_auth_enabled, status, mfa_enabled, created_at, updated_at
	FROM users
	WHERE lower(email) = lower($1) OR lower(username) = lower($1)
	LIMIT 1`
	u := &store.User{}
	err := s.db.QueryRowContext(ctx, query, identifier).
		Scan(&u.ID, &u.TenantID, &u.Email, &u.EmailVerified, &u.Username, &u.PasswordHash, &u.PasswordAuthEnabled, &u.Status, &u.MFAEnabled, &u.CreatedAt, &u.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return u, nil
}

func (s *Store) GetUserByID(ctx context.Context, id int64) (*store.User, error) {
	query := `
	SELECT id, tenant_id, email, email_verified, username, password_hash, password_auth_enabled, status, mfa_enabled, created_at, updated_at
	FROM users WHERE id = $1`
	u := &store.User{}
	err := s.db.QueryRowContext(ctx, query, id).
		Scan(&u.ID, &u.TenantID, &u.Email, &u.EmailVerified, &u.Username, &u.PasswordHash, &u.PasswordAuthEnabled, &u.Status, &u.MFAEnabled, &u.CreatedAt, &u.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return u, nil
}

func (s *Store) UpdateUserPassword(ctx context.Context, userID int64, passwordHash string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE users SET password_hash = $1, password_auth_enabled = true, updated_at = NOW() WHERE id = $2`, passwordHash, userID)
	return err
}

func (s *Store) CreateDevice(ctx context.Context, device *store.Device) error {
	query := `
	INSERT INTO devices (user_id, token_hash, client_family, trust_level, risk_score, first_seen_at, last_seen_at, last_ip, last_user_agent, revoked_at)
	VALUES ($1, $2, $3, $4, $5, NOW(), NOW(), $6, $7, NULL)
	RETURNING id, first_seen_at, last_seen_at`
	return s.db.QueryRowContext(ctx, query,
		device.UserID,
		device.TokenHash,
		device.ClientFamily,
		device.TrustLevel,
		device.RiskScore,
		device.LastIP,
		device.LastUserAgent,
	).Scan(&device.ID, &device.FirstSeenAt, &device.LastSeenAt)
}

func (s *Store) GetDeviceByTokenHash(ctx context.Context, userID int64, tokenHash string) (*store.Device, error) {
	query := `
	SELECT id, user_id, token_hash, client_family, trust_level, risk_score, first_seen_at, last_seen_at, last_ip, last_user_agent, revoked_at
	FROM devices
	WHERE user_id = $1 AND token_hash = $2 AND revoked_at IS NULL`
	device := &store.Device{}
	err := s.db.QueryRowContext(ctx, query, userID, tokenHash).Scan(
		&device.ID,
		&device.UserID,
		&device.TokenHash,
		&device.ClientFamily,
		&device.TrustLevel,
		&device.RiskScore,
		&device.FirstSeenAt,
		&device.LastSeenAt,
		&device.LastIP,
		&device.LastUserAgent,
		&device.RevokedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return device, nil
}

func (s *Store) UpdateDeviceSeen(ctx context.Context, deviceID int64, clientFamily, ip, userAgent, trustLevel string, riskScore int) error {
	_, err := s.db.ExecContext(ctx, `
	UPDATE devices
	SET last_seen_at = NOW(),
	    client_family = $2,
	    last_ip = $3,
	    last_user_agent = $4,
	    trust_level = $5,
	    risk_score = $6
	WHERE id = $1 AND revoked_at IS NULL`, deviceID, clientFamily, ip, userAgent, trustLevel, riskScore)
	return err
}

func (s *Store) CreateSession(ctx context.Context, sess *store.Session) error {
	if sess.AAL <= 0 {
		sess.AAL = 1
	}
	if sess.AuthTime.IsZero() {
		sess.AuthTime = time.Now().UTC()
	}
	if sess.IdleExpiresAt.IsZero() {
		sess.IdleExpiresAt = sess.ExpiresAt
	}
	if sess.AuthMethod == "" {
		sess.AuthMethod = "session"
	}
	query := `
	INSERT INTO sessions (user_id, device_id, token_hash, expires_at, idle_expires_at, auth_time, created_at, last_seen_at, ip, user_agent, aal, risk_score, auth_method)
	VALUES ($1, $2, $3, $4, $5, $6, NOW(), NOW(), $7, $8, $9, $10, $11)
	RETURNING id, auth_time, created_at, last_seen_at`
	return s.db.QueryRowContext(ctx, query,
		sess.UserID,
		nullInt64(sess.DeviceID),
		sess.TokenHash,
		sess.ExpiresAt,
		sess.IdleExpiresAt,
		sess.AuthTime,
		sess.IP,
		sess.UserAgent,
		sess.AAL,
		sess.RiskScore,
		sess.AuthMethod,
	).Scan(&sess.ID, &sess.AuthTime, &sess.CreatedAt, &sess.LastSeenAt)
}

func (s *Store) GetSessionByTokenHash(ctx context.Context, tokenHash string) (*store.Session, error) {
	query := `
	SELECT s.id, s.user_id, COALESCE(s.device_id, 0), s.aal, s.token_hash, s.expires_at, s.idle_expires_at, s.auth_time, s.created_at, s.last_seen_at, s.ip, s.user_agent, s.auth_method, s.risk_score,
	       COALESCE(d.trust_level, 'legacy'), COALESCE(d.client_family, 'legacy')
	FROM sessions s
	LEFT JOIN devices d ON d.id = s.device_id AND d.revoked_at IS NULL
	WHERE s.token_hash = $1
	  AND (s.device_id IS NULL OR d.id IS NOT NULL)`
	sess := &store.Session{}
	err := s.db.QueryRowContext(ctx, query, tokenHash).
		Scan(
			&sess.ID,
			&sess.UserID,
			&sess.DeviceID,
			&sess.AAL,
			&sess.TokenHash,
			&sess.ExpiresAt,
			&sess.IdleExpiresAt,
			&sess.AuthTime,
			&sess.CreatedAt,
			&sess.LastSeenAt,
			&sess.IP,
			&sess.UserAgent,
			&sess.AuthMethod,
			&sess.RiskScore,
			&sess.DeviceTrustLevel,
			&sess.DeviceClientFamily,
		)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return sess, nil
}

func (s *Store) DeleteSessionByHash(ctx context.Context, tokenHash string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE token_hash = $1`, tokenHash)
	return err
}

func (s *Store) DeleteSessionsByUserID(ctx context.Context, userID int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE user_id = $1`, userID)
	return err
}

func (s *Store) DeleteOtherSessionsByUserID(ctx context.Context, userID int64, keepTokenHash string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE user_id = $1 AND token_hash <> $2`, userID, keepTokenHash)
	return err
}

func (s *Store) TouchSession(ctx context.Context, tokenHash string, idleExpiresAt time.Time) error {
	_, err := s.db.ExecContext(ctx, `UPDATE sessions SET last_seen_at = NOW(), idle_expires_at = $2 WHERE token_hash = $1`, tokenHash, idleExpiresAt)
	return err
}

func (s *Store) RotateSession(ctx context.Context, oldTokenHash, newTokenHash string, authTime, idleExpiresAt time.Time, aal int) error {
	res, err := s.db.ExecContext(ctx, `
	UPDATE sessions
	SET token_hash = $1,
	    auth_time = $2,
	    aal = $3,
	    idle_expires_at = $4,
	    last_seen_at = NOW()
	WHERE token_hash = $5`, newTokenHash, authTime, aal, idleExpiresAt, oldTokenHash)
	if err != nil {
		return err
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return sql.ErrNoRows
	}
	if aal >= 2 {
		if _, err := s.db.ExecContext(ctx, `
		UPDATE devices
		SET trust_level = CASE WHEN trust_level = 'verified' THEN trust_level ELSE 'trusted' END
		WHERE id = (SELECT device_id FROM sessions WHERE token_hash = $1)`, newTokenHash); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) RotateSessionAndDeleteOthers(ctx context.Context, userID int64, oldTokenHash, newTokenHash string, authTime, idleExpiresAt time.Time, aal int) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	res, err := tx.ExecContext(ctx, `
	UPDATE sessions
	SET token_hash = $1,
	    auth_time = $2,
	    aal = $3,
	    idle_expires_at = $4,
	    last_seen_at = NOW()
	WHERE token_hash = $5 AND user_id = $6`, newTokenHash, authTime, aal, idleExpiresAt, oldTokenHash, userID)
	if err != nil {
		return err
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return sql.ErrNoRows
	}
	if aal >= 2 {
		if _, err := tx.ExecContext(ctx, `
		UPDATE devices
		SET trust_level = CASE WHEN trust_level = 'verified' THEN trust_level ELSE 'trusted' END
		WHERE id = (SELECT device_id FROM sessions WHERE token_hash = $1)`, newTokenHash); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE user_id = $1 AND token_hash <> $2`, userID, newTokenHash); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) UpsertTOTPSecret(ctx context.Context, userID int64, encryptedSecret, nonce []byte) error {
	query := `
	INSERT INTO mfa_totp (user_id, encrypted_secret, nonce, enabled_at, pending_encrypted_secret, pending_nonce, pending_created_at)
	VALUES ($1, $2, $3, NULL, NULL, NULL, NULL)
	ON CONFLICT (user_id) DO UPDATE
	SET encrypted_secret = EXCLUDED.encrypted_secret,
	    nonce = EXCLUDED.nonce,
	    enabled_at = NULL,
	    pending_encrypted_secret = NULL,
	    pending_nonce = NULL,
	    pending_created_at = NULL,
	    last_used_at = NULL`
	_, err := s.db.ExecContext(ctx, query, userID, encryptedSecret, nonce)
	return err
}

func (s *Store) SetPendingTOTPSecret(ctx context.Context, userID int64, encryptedSecret, nonce []byte) error {
	res, err := s.db.ExecContext(ctx, `
	UPDATE mfa_totp
	SET pending_encrypted_secret = $2,
	    pending_nonce = $3,
	    pending_created_at = NOW()
	WHERE user_id = $1`, userID, encryptedSecret, nonce)
	if err != nil {
		return err
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if affected > 0 {
		return nil
	}
	return s.UpsertTOTPSecret(ctx, userID, encryptedSecret, nonce)
}

func (s *Store) PromotePendingTOTP(ctx context.Context, userID int64) error {
	_, err := s.db.ExecContext(ctx, `
	UPDATE mfa_totp
	SET encrypted_secret = COALESCE(pending_encrypted_secret, encrypted_secret),
	    nonce = COALESCE(pending_nonce, nonce),
	    pending_encrypted_secret = NULL,
	    pending_nonce = NULL,
	    pending_created_at = NULL,
	    last_used_at = NULL
	WHERE user_id = $1`, userID)
	return err
}

func (s *Store) EnableTOTP(ctx context.Context, userID int64) error {
	_, err := s.db.ExecContext(ctx, `UPDATE mfa_totp SET enabled_at = NOW() WHERE user_id = $1`, userID)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `UPDATE users SET mfa_enabled = true WHERE id = $1`, userID)
	return err
}

func (s *Store) FinalizeTOTPEnrollment(ctx context.Context, userID int64, backupHashes []string, oldTokenHash, newTokenHash string, authTime, idleExpiresAt time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	res, err := tx.ExecContext(ctx, `
	UPDATE mfa_totp
	SET encrypted_secret = COALESCE(pending_encrypted_secret, encrypted_secret),
	    nonce = COALESCE(pending_nonce, nonce),
	    pending_encrypted_secret = NULL,
	    pending_nonce = NULL,
	    pending_created_at = NULL,
	    last_used_at = NULL,
	    enabled_at = NOW()
	WHERE user_id = $1`, userID)
	if err != nil {
		return err
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return sql.ErrNoRows
	}
	if _, err := tx.ExecContext(ctx, `UPDATE users SET mfa_enabled = true WHERE id = $1`, userID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM backup_codes WHERE user_id = $1`, userID); err != nil {
		return err
	}
	stmt, err := tx.PrepareContext(ctx, `INSERT INTO backup_codes (user_id, code_hash) VALUES ($1, $2)`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, hash := range backupHashes {
		if _, err := stmt.ExecContext(ctx, userID, hash); err != nil {
			return err
		}
	}
	res, err = tx.ExecContext(ctx, `
	UPDATE sessions
	SET token_hash = $1,
	    auth_time = $2,
	    aal = 2,
	    idle_expires_at = $3,
	    last_seen_at = NOW()
	WHERE token_hash = $4 AND user_id = $5`, newTokenHash, authTime, idleExpiresAt, oldTokenHash, userID)
	if err != nil {
		return err
	}
	rows, err = res.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return sql.ErrNoRows
	}
	if _, err := tx.ExecContext(ctx, `
	UPDATE devices
	SET trust_level = CASE WHEN trust_level = 'verified' THEN trust_level ELSE 'trusted' END
	WHERE id = (SELECT device_id FROM sessions WHERE token_hash = $1)`, newTokenHash); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE user_id = $1 AND token_hash <> $2`, userID, newTokenHash); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) DisableTOTPAndRotateSession(ctx context.Context, userID int64, oldTokenHash, newTokenHash string, authTime, idleExpiresAt time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx, `UPDATE users SET mfa_enabled = false WHERE id = $1`, userID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM mfa_totp WHERE user_id = $1`, userID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM backup_codes WHERE user_id = $1`, userID); err != nil {
		return err
	}
	res, err := tx.ExecContext(ctx, `
	UPDATE sessions
	SET token_hash = $1,
	    auth_time = $2,
	    aal = 1,
	    idle_expires_at = $3,
	    last_seen_at = NOW()
	WHERE token_hash = $4 AND user_id = $5`, newTokenHash, authTime, idleExpiresAt, oldTokenHash, userID)
	if err != nil {
		return err
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return sql.ErrNoRows
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE user_id = $1 AND token_hash <> $2`, userID, newTokenHash); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) GetTOTP(ctx context.Context, userID int64) (*store.MFATOTP, error) {
	query := `
	SELECT user_id, encrypted_secret, nonce, pending_encrypted_secret, pending_nonce, pending_created_at, enabled_at, last_used_at
	FROM mfa_totp WHERE user_id = $1`
	record := &store.MFATOTP{}
	err := s.db.QueryRowContext(ctx, query, userID).
		Scan(&record.UserID, &record.EncryptedSecret, &record.Nonce, &record.PendingEncryptedSecret, &record.PendingNonce, &record.PendingCreatedAt, &record.EnabledAt, &record.LastUsedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return record, nil
}

func (s *Store) UpdateTOTPUsed(ctx context.Context, userID int64, t time.Time) error {
	_, err := s.db.ExecContext(ctx, `UPDATE mfa_totp SET last_used_at = $1 WHERE user_id = $2`, t, userID)
	return err
}

func (s *Store) ReplaceBackupCodes(ctx context.Context, userID int64, hashes []string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM backup_codes WHERE user_id = $1`, userID); err != nil {
		return err
	}
	stmt, err := tx.PrepareContext(ctx, `INSERT INTO backup_codes (user_id, code_hash) VALUES ($1, $2)`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, h := range hashes {
		if _, err := stmt.ExecContext(ctx, userID, h); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) UseBackupCode(ctx context.Context, userID int64, code string) (bool, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, code_hash FROM backup_codes WHERE user_id = $1 AND used_at IS NULL`, userID)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	var matchID *int64
	for rows.Next() {
		var id int64
		var codeHash string
		if err := rows.Scan(&id, &codeHash); err != nil {
			return false, err
		}
		ok, err := security.VerifyPassword(code, codeHash)
		if err != nil {
			return false, err
		}
		if ok {
			matchID = &id
			break
		}
	}
	if matchID == nil {
		return false, nil
	}
	res, err := s.db.ExecContext(ctx, `UPDATE backup_codes SET used_at = NOW() WHERE id = $1 AND used_at IS NULL`, *matchID)
	if err != nil {
		return false, err
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	if affected == 0 {
		return false, nil
	}
	return true, nil
}

func (s *Store) CreatePasswordReset(ctx context.Context, pr *store.PasswordReset) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx, `
	DELETE FROM password_resets
	WHERE user_id = $1 AND used_at IS NULL`, pr.UserID); err != nil {
		return err
	}

	query := `
	INSERT INTO password_resets (user_id, email, token_hash, expires_at, used_at, created_at, request_ip)
	VALUES ($1, $2, $3, $4, NULL, NOW(), $5)
	RETURNING id, created_at`
	if err := tx.QueryRowContext(ctx, query, pr.UserID, pr.Email, pr.TokenHash, pr.ExpiresAt, pr.RequestIP).
		Scan(&pr.ID, &pr.CreatedAt); err != nil {
		return err
	}

	return tx.Commit()
}

func (s *Store) CreateEmailVerification(ctx context.Context, ev *store.EmailVerification) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx, `
	DELETE FROM email_verifications
	WHERE user_id = $1 AND used_at IS NULL`, ev.UserID); err != nil {
		return err
	}

	query := `
	INSERT INTO email_verifications (user_id, email, token_hash, expires_at, used_at, created_at, request_ip)
	VALUES ($1, $2, $3, $4, NULL, NOW(), $5)
	RETURNING id, created_at`
	if err := tx.QueryRowContext(ctx, query, ev.UserID, ev.Email, ev.TokenHash, ev.ExpiresAt, ev.RequestIP).
		Scan(&ev.ID, &ev.CreatedAt); err != nil {
		return err
	}

	return tx.Commit()
}

func (s *Store) ConsumePasswordReset(ctx context.Context, tokenHash string) (*store.PasswordReset, error) {
	query := `
	UPDATE password_resets
	SET used_at = NOW()
	WHERE token_hash = $1 AND used_at IS NULL AND expires_at > NOW()
	RETURNING id, user_id, email, token_hash, expires_at, used_at, created_at, request_ip`
	pr := &store.PasswordReset{}
	err := s.db.QueryRowContext(ctx, query, tokenHash).
		Scan(&pr.ID, &pr.UserID, &pr.Email, &pr.TokenHash, &pr.ExpiresAt, &pr.UsedAt, &pr.CreatedAt, &pr.RequestIP)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return pr, nil
}

func (s *Store) ApplyPasswordReset(ctx context.Context, tokenHash, passwordHash string) (int64, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	var userID int64
	if err := tx.QueryRowContext(ctx, `
		UPDATE password_resets
		SET used_at = NOW()
		WHERE token_hash = $1 AND used_at IS NULL AND expires_at > NOW()
		RETURNING user_id`, tokenHash).Scan(&userID); errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	} else if err != nil {
		return 0, err
	}

	if _, err := tx.ExecContext(ctx, `
		UPDATE users
		SET password_hash = $2,
		    password_auth_enabled = TRUE,
		    updated_at = NOW()
		WHERE id = $1`, userID, passwordHash); err != nil {
		return 0, err
	}

	if _, err := tx.ExecContext(ctx, `
		DELETE FROM password_resets
		WHERE user_id = $1 AND used_at IS NULL`, userID); err != nil {
		return 0, err
	}

	if _, err := tx.ExecContext(ctx, `
		DELETE FROM sessions
		WHERE user_id = $1`, userID); err != nil {
		return 0, err
	}

	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return userID, nil
}

func (s *Store) DeletePendingPasswordResetsByUserID(ctx context.Context, userID int64) error {
	_, err := s.db.ExecContext(ctx, `
	DELETE FROM password_resets
	WHERE user_id = $1 AND used_at IS NULL`, userID)
	return err
}

func (s *Store) ConsumeEmailVerification(ctx context.Context, tokenHash string) (*store.EmailVerification, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	query := `
	UPDATE email_verifications
	SET used_at = NOW()
	WHERE token_hash = $1 AND used_at IS NULL AND expires_at > NOW()
	RETURNING id, user_id, email, token_hash, expires_at, used_at, created_at, request_ip`
	ev := &store.EmailVerification{}
	err = tx.QueryRowContext(ctx, query, tokenHash).
		Scan(&ev.ID, &ev.UserID, &ev.Email, &ev.TokenHash, &ev.ExpiresAt, &ev.UsedAt, &ev.CreatedAt, &ev.RequestIP)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, `
	UPDATE users
	SET email_verified = TRUE,
	    status = CASE WHEN status = 'pending_verification' THEN 'active' ELSE status END,
	    updated_at = NOW()
	WHERE id = $1`, ev.UserID); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return ev, nil
}

func (s *Store) CreateIdentity(ctx context.Context, ident *store.Identity) error {
	query := `
	INSERT INTO identities (user_id, provider, subject, email, email_verified, created_at, last_login_at)
	VALUES ($1, $2, $3, $4, $5, NOW(), NOW())
	RETURNING id, created_at, last_login_at`
	return s.db.QueryRowContext(ctx, query, ident.UserID, ident.Provider, ident.Subject, ident.Email, ident.EmailVerified).
		Scan(&ident.ID, &ident.CreatedAt, &ident.LastLoginAt)
}

func (s *Store) GetIdentity(ctx context.Context, provider, subject string) (*store.Identity, error) {
	query := `
	SELECT id, user_id, provider, subject, email, email_verified, created_at, last_login_at
	FROM identities
	WHERE provider = $1 AND subject = $2`
	ident := &store.Identity{}
	err := s.db.QueryRowContext(ctx, query, provider, subject).
		Scan(&ident.ID, &ident.UserID, &ident.Provider, &ident.Subject, &ident.Email, &ident.EmailVerified, &ident.CreatedAt, &ident.LastLoginAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return ident, nil
}

func (s *Store) UpdateIdentityLogin(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `UPDATE identities SET last_login_at = NOW() WHERE id = $1`, id)
	return err
}

func (s *Store) DeleteIdentity(ctx context.Context, userID int64, provider string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM identities WHERE user_id = $1 AND provider = $2`, userID, provider)
	return err
}

func (s *Store) CountIdentitiesByUserID(ctx context.Context, userID int64) (int, error) {
	var count int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM identities WHERE user_id = $1`, userID).Scan(&count)
	return count, err
}

func (s *Store) InsertAuditLog(ctx context.Context, entry *store.AuditLog) error {
	_, err := s.db.ExecContext(ctx, `
	INSERT INTO audit_log (event_type, user_id, provider, ip, user_agent, success, created_at)
	VALUES ($1, $2, $3, $4, $5, $6, NOW())`,
		entry.EventType, entry.UserID, entry.Provider, entry.IP, entry.UserAgent, entry.Success)
	return err
}

func (s *Store) SaveOAuthState(ctx context.Context, state store.OAuthState) error {
	_, err := s.db.ExecContext(ctx, `
	INSERT INTO oauth_states (state, provider, action, user_id, code_verifier, nonce, expires_at, created_at)
	VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())`,
		state.State, state.Provider, state.Action, state.UserID, state.CodeVerifier, state.Nonce, state.ExpiresAt)
	return err
}

func (s *Store) ConsumeOAuthState(ctx context.Context, state string) (*store.OAuthState, error) {
	query := `
	DELETE FROM oauth_states
	WHERE state = $1 AND expires_at > NOW()
	RETURNING state, provider, action, user_id, code_verifier, nonce, expires_at, created_at`
	var rec store.OAuthState
	err := s.db.QueryRowContext(ctx, query, state).Scan(
		&rec.State, &rec.Provider, &rec.Action, &rec.UserID, &rec.CodeVerifier, &rec.Nonce, &rec.ExpiresAt, &rec.CreatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &rec, nil
}

func (s *Store) ListSessionsByUserID(ctx context.Context, userID int64) ([]*store.Session, error) {
	rows, err := s.db.QueryContext(ctx, `
	SELECT s.id, s.user_id, COALESCE(s.device_id, 0), s.aal, s.token_hash, s.expires_at, s.idle_expires_at, s.auth_time, s.created_at, s.last_seen_at,
	       s.ip, s.user_agent, s.auth_method, s.risk_score,
	       COALESCE(d.trust_level, 'legacy'), COALESCE(d.client_family, 'legacy')
	FROM sessions s
	LEFT JOIN devices d ON d.id = s.device_id AND d.revoked_at IS NULL
	WHERE s.user_id = $1
	ORDER BY s.last_seen_at DESC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var sessions []*store.Session
	for rows.Next() {
		sess := &store.Session{}
		if err := rows.Scan(
			&sess.ID,
			&sess.UserID,
			&sess.DeviceID,
			&sess.AAL,
			&sess.TokenHash,
			&sess.ExpiresAt,
			&sess.IdleExpiresAt,
			&sess.AuthTime,
			&sess.CreatedAt,
			&sess.LastSeenAt,
			&sess.IP,
			&sess.UserAgent,
			&sess.AuthMethod,
			&sess.RiskScore,
			&sess.DeviceTrustLevel,
			&sess.DeviceClientFamily,
		); err != nil {
			return nil, err
		}
		sessions = append(sessions, sess)
	}
	return sessions, rows.Err()
}

func (s *Store) DeleteSessionByID(ctx context.Context, userID, sessionID int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE id = $1 AND user_id = $2`, sessionID, userID)
	return err
}

func (s *Store) ListDevicesByUserID(ctx context.Context, userID int64) ([]*store.Device, error) {
	rows, err := s.db.QueryContext(ctx, `
	SELECT id, user_id, token_hash, client_family, trust_level, risk_score, first_seen_at, last_seen_at, last_ip, last_user_agent, revoked_at
	FROM devices
	WHERE user_id = $1 AND revoked_at IS NULL
	ORDER BY last_seen_at DESC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var devices []*store.Device
	for rows.Next() {
		device := &store.Device{}
		if err := rows.Scan(
			&device.ID,
			&device.UserID,
			&device.TokenHash,
			&device.ClientFamily,
			&device.TrustLevel,
			&device.RiskScore,
			&device.FirstSeenAt,
			&device.LastSeenAt,
			&device.LastIP,
			&device.LastUserAgent,
			&device.RevokedAt,
		); err != nil {
			return nil, err
		}
		devices = append(devices, device)
	}
	return devices, rows.Err()
}

func (s *Store) RevokeDeviceByID(ctx context.Context, userID, deviceID int64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	res, err := tx.ExecContext(ctx, `UPDATE devices SET revoked_at = NOW() WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL`, deviceID, userID)
	if err != nil {
		return err
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return sql.ErrNoRows
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE user_id = $1 AND device_id = $2`, userID, deviceID); err != nil {
		return err
	}
	return tx.Commit()
}

func nullInt64(v int64) interface{} {
	if v <= 0 {
		return nil
	}
	return v
}

func (s *Store) GetOAuthState(ctx context.Context, state string) (*store.OAuthState, error) {
	query := `
	SELECT state, provider, action, user_id, code_verifier, nonce, expires_at, created_at
	FROM oauth_states
	WHERE state = $1 AND expires_at > NOW()`
	var rec store.OAuthState
	err := s.db.QueryRowContext(ctx, query, state).Scan(
		&rec.State, &rec.Provider, &rec.Action, &rec.UserID, &rec.CodeVerifier, &rec.Nonce, &rec.ExpiresAt, &rec.CreatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &rec, nil
}
