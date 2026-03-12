package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/LCGant/role-auth/internal/audit"
	"github.com/LCGant/role-auth/internal/config"
	"github.com/LCGant/role-auth/internal/security"
	"github.com/LCGant/role-auth/internal/store"
)

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrMFARequired        = errors.New("mfa required")
	ErrInvalidMFA         = errors.New("invalid mfa code")
	ErrInvalidToken       = errors.New("invalid token")
	ErrLocked             = errors.New("account temporarily locked")
	ErrOAuthProvisioning  = errors.New("oauth provisioning requires a verified email")
)

type Store interface {
	CreateUser(ctx context.Context, u *store.User) error
	CreateUserWithIdentity(ctx context.Context, u *store.User, ident *store.Identity) error
	DeleteUserByID(ctx context.Context, id int64) error
	FindUserByEmailOrUsername(ctx context.Context, identifier string) (*store.User, error)
	GetUserByID(ctx context.Context, id int64) (*store.User, error)
	UpdateUserPassword(ctx context.Context, userID int64, passwordHash string) error

	CreateDevice(ctx context.Context, device *store.Device) error
	GetDeviceByTokenHash(ctx context.Context, userID int64, tokenHash string) (*store.Device, error)
	UpdateDeviceSeen(ctx context.Context, deviceID int64, clientFamily, ip, userAgent, trustLevel string, riskScore int) error

	CreateSession(ctx context.Context, sess *store.Session) error
	GetSessionByTokenHash(ctx context.Context, tokenHash string) (*store.Session, error)
	DeleteSessionByHash(ctx context.Context, tokenHash string) error
	DeleteSessionByID(ctx context.Context, userID, sessionID int64) error
	DeleteSessionsByUserID(ctx context.Context, userID int64) error
	DeleteOtherSessionsByUserID(ctx context.Context, userID int64, keepTokenHash string) error
	TouchSession(ctx context.Context, tokenHash string, idleExpiresAt time.Time) error
	RotateSession(ctx context.Context, oldTokenHash, newTokenHash string, authTime, idleExpiresAt time.Time, aal int) error
	RotateSessionAndDeleteOthers(ctx context.Context, userID int64, oldTokenHash, newTokenHash string, authTime, idleExpiresAt time.Time, aal int) error
	ListSessionsByUserID(ctx context.Context, userID int64) ([]*store.Session, error)
	ListDevicesByUserID(ctx context.Context, userID int64) ([]*store.Device, error)
	RevokeDeviceByID(ctx context.Context, userID, deviceID int64) error

	UpsertTOTPSecret(ctx context.Context, userID int64, encryptedSecret, nonce []byte) error
	SetPendingTOTPSecret(ctx context.Context, userID int64, encryptedSecret, nonce []byte) error
	PromotePendingTOTP(ctx context.Context, userID int64) error
	EnableTOTP(ctx context.Context, userID int64) error
	FinalizeTOTPEnrollment(ctx context.Context, userID int64, backupHashes []string, oldTokenHash, newTokenHash string, authTime, idleExpiresAt time.Time) error
	DisableTOTPAndRotateSession(ctx context.Context, userID int64, oldTokenHash, newTokenHash string, authTime, idleExpiresAt time.Time) error
	GetTOTP(ctx context.Context, userID int64) (*store.MFATOTP, error)
	UpdateTOTPUsed(ctx context.Context, userID int64, t time.Time) error
	ReplaceBackupCodes(ctx context.Context, userID int64, hashes []string) error
	UseBackupCode(ctx context.Context, userID int64, code string) (bool, error)

	CreatePasswordReset(ctx context.Context, pr *store.PasswordReset) error
	ConsumePasswordReset(ctx context.Context, tokenHash string) (*store.PasswordReset, error)
	ApplyPasswordReset(ctx context.Context, tokenHash, passwordHash string) (int64, error)
	DeletePendingPasswordResetsByUserID(ctx context.Context, userID int64) error
	CreateEmailVerification(ctx context.Context, ev *store.EmailVerification) error
	ConsumeEmailVerification(ctx context.Context, tokenHash string) (*store.EmailVerification, error)

	CreateIdentity(ctx context.Context, ident *store.Identity) error
	GetIdentity(ctx context.Context, provider, subject string) (*store.Identity, error)
	UpdateIdentityLogin(ctx context.Context, id int64) error
	DeleteIdentity(ctx context.Context, userID int64, provider string) error
	CountIdentitiesByUserID(ctx context.Context, userID int64) (int, error)

	InsertAuditLog(ctx context.Context, entry *store.AuditLog) error

	SaveOAuthState(ctx context.Context, state store.OAuthState) error
	ConsumeOAuthState(ctx context.Context, state string) (*store.OAuthState, error)
	GetOAuthState(ctx context.Context, state string) (*store.OAuthState, error)
}

type Service struct {
	store       Store
	cfg         config.Config
	argonParams security.Argon2Params
	lockout     security.Lockout
	dummyHash   string
	auditClient *audit.Client
}

type LoginResult struct {
	User         *store.User
	SessionToken string
	DeviceToken  string
	RequiresMFA  bool
	CSRFToken    string
}

type SessionReissueResult struct {
	SessionToken string
	CSRFToken    string
	AuthTime     time.Time
	AAL          int
}

type OAuthLoginResult struct {
	User         *store.User
	SessionToken string
	DeviceToken  string
	CSRFToken    string
	RequiresMFA  bool
	PendingState string
	Provider     string
}

type DeviceBinding struct {
	Token        string
	ClientFamily string
}

type SessionValidation struct {
	DeviceToken     string
	ClientFamily    string
	IP              string
	UserAgent       string
	RefreshMetadata bool
}

func New(store Store, cfg config.Config) *Service {
	lockout := selectLockout(cfg)
	dummyHash := ""
	hash, err := security.HashPassword("dummy", security.Argon2Params{
		Memory:      cfg.Security.Argon2.Memory,
		Iterations:  cfg.Security.Argon2.Iterations,
		Parallelism: cfg.Security.Argon2.Parallelism,
		SaltLength:  cfg.Security.Argon2.SaltLength,
		KeyLength:   cfg.Security.Argon2.KeyLength,
	})
	if err == nil {
		dummyHash = hash
	}
	return &Service{
		store:   store,
		cfg:     cfg,
		lockout: lockout,
		argonParams: security.Argon2Params{
			Memory:      cfg.Security.Argon2.Memory,
			Iterations:  cfg.Security.Argon2.Iterations,
			Parallelism: cfg.Security.Argon2.Parallelism,
			SaltLength:  cfg.Security.Argon2.SaltLength,
			KeyLength:   cfg.Security.Argon2.KeyLength,
		},
		dummyHash:   dummyHash,
		auditClient: audit.NewClient(cfg),
	}
}

func selectLockout(cfg config.Config) security.Lockout {
	lcfg := cfg.Security.Lockout
	if lcfg.RedisURL != "" {
		return security.NewRedisLockout(lcfg.RedisURL, lcfg.MaxAttempts, lcfg.Window, lcfg.BlockFor)
	}
	return security.NewInMemoryLockout(lcfg.MaxAttempts, lcfg.Window, lcfg.BlockFor)
}

func (s *Service) Register(ctx context.Context, email, username, password, ip, ua string) (*store.User, error) {
	if err := security.ValidatePasswordStrength(password); err != nil {
		return nil, err
	}
	hash, err := security.HashPassword(password, s.argonParams)
	if err != nil {
		return nil, err
	}
	user := &store.User{
		TenantID:            s.defaultTenantID(),
		Email:               email,
		EmailVerified:       false,
		Username:            username,
		PasswordHash:        hash,
		PasswordAuthEnabled: true,
		Status:              "pending_verification",
	}
	err = s.store.CreateUser(ctx, user)
	s.audit(ctx, "register", &user.ID, "", ip, ua, err == nil)
	if err != nil {
		return nil, err
	}
	return user, nil
}

func (s *Service) StartEmailVerification(ctx context.Context, email, ip, ua string) (string, error) {
	user, err := s.store.FindUserByEmailOrUsername(ctx, email)
	if err != nil || user == nil {
		return "", err
	}
	if user.EmailVerified {
		return "", nil
	}
	token, hash, err := security.GenerateToken(32)
	if err != nil {
		return "", err
	}
	ev := &store.EmailVerification{
		UserID:    user.ID,
		Email:     user.Email,
		TokenHash: hash,
		ExpiresAt: time.Now().UTC().Add(24 * time.Hour),
		RequestIP: ip,
	}
	if err := s.store.CreateEmailVerification(ctx, ev); err != nil {
		return "", err
	}
	s.audit(ctx, "email-verification-request", &user.ID, "", ip, ua, true)
	return token, nil
}

func (s *Service) CompleteEmailVerification(ctx context.Context, token, ip, ua string) error {
	hash := security.HashToken(token)
	ev, err := s.store.ConsumeEmailVerification(ctx, hash)
	if err != nil || ev == nil {
		return ErrInvalidToken
	}
	s.audit(ctx, "email-verification-complete", &ev.UserID, "", ip, ua, true)
	return nil
}

func (s *Service) Login(ctx context.Context, identifier, password, totpCode, backupCode, ip, ua string, deviceBinding DeviceBinding) (*LoginResult, error) {
	user, err := s.store.FindUserByEmailOrUsername(ctx, identifier)
	userKey := unknownUserLockoutKey(identifier)
	if user != nil {
		userKey = fmt.Sprintf("user:%d", user.ID)
	}

	if locked, ttl := s.isLocked(ctx, userKey, ip); locked {
		s.audit(ctx, "login-lockout", nilUserID(user), "", ip, ua, false)
		return nil, fmt.Errorf("%w: retry in %s", ErrLocked, ttl.String())
	}

	if err != nil || user == nil {
		// Dummy verification to equalize timing when user is missing
		if s.dummyHash != "" {
			_, _ = security.VerifyPassword(password, s.dummyHash)
		}
		s.registerFailure(ctx, userKey, ip)
		s.audit(ctx, "login", nilUserID(user), "", ip, ua, false)
		return nil, ErrInvalidCredentials
	}
	if !user.PasswordAuthEnabled || strings.TrimSpace(user.PasswordHash) == "" {
		s.registerFailure(ctx, userKey, ip)
		s.audit(ctx, "login", &user.ID, "", ip, ua, false)
		return nil, ErrInvalidCredentials
	}
	ok, err := security.VerifyPassword(password, user.PasswordHash)
	if err != nil || !ok {
		s.registerFailure(ctx, userKey, ip)
		s.audit(ctx, "login", &user.ID, "", ip, ua, false)
		return nil, ErrInvalidCredentials
	}

	if user.Status != "active" {
		s.audit(ctx, "login", &user.ID, "", ip, ua, false)
		return nil, errors.New("user inactive")
	}

	sessionAAL := 1
	authMethod := "password"
	if user.MFAEnabled {
		if totpCode == "" && backupCode == "" {
			return &LoginResult{User: user, RequiresMFA: true}, ErrMFARequired
		}
		if totpCode != "" {
			record, err := s.store.GetTOTP(ctx, user.ID)
			if err != nil || record == nil {
				s.registerFailure(ctx, userKey, ip)
				return &LoginResult{User: user, RequiresMFA: true}, ErrInvalidMFA
			}
			secret, err := security.Decrypt(s.cfg.Security.EncryptionKey, record.Nonce, record.EncryptedSecret)
			if err != nil {
				return nil, fmt.Errorf("decrypt totp: %w", err)
			}
			if !security.VerifyTOTP(string(secret), totpCode, time.Now(), 1) {
				s.registerFailure(ctx, userKey, ip)
				s.audit(ctx, "login-mfa", &user.ID, "", ip, ua, false)
				return &LoginResult{User: user, RequiresMFA: true}, ErrInvalidMFA
			}
			_ = s.store.UpdateTOTPUsed(ctx, user.ID, time.Now())
			sessionAAL = 2
			authMethod = "password+totp"
		} else if backupCode != "" {
			used, err := s.store.UseBackupCode(ctx, user.ID, backupCode)
			if err != nil || !used {
				s.registerFailure(ctx, userKey, ip)
				s.audit(ctx, "login-backup", &user.ID, "", ip, ua, false)
				return &LoginResult{User: user, RequiresMFA: true}, ErrInvalidMFA
			}
			sessionAAL = 2
			authMethod = "password+backup"
		}
	}

	sessionToken, deviceToken, err := s.startSession(ctx, user.ID, ip, ua, sessionAAL, authMethod, deviceBinding)
	if err != nil {
		return nil, err
	}
	csrfToken, _, err := security.GenerateToken(32)
	if err != nil {
		return nil, err
	}
	s.clearFailures(ctx, userKey, ip)
	s.audit(ctx, "login", &user.ID, "", ip, ua, true)
	return &LoginResult{User: user, SessionToken: sessionToken, DeviceToken: deviceToken, CSRFToken: csrfToken}, nil
}

func (s *Service) startSession(ctx context.Context, userID int64, ip, ua string, aal int, authMethod string, deviceBinding DeviceBinding) (string, string, error) {
	token, hash, err := security.GenerateToken(32)
	if err != nil {
		return "", "", err
	}
	if aal <= 0 {
		aal = 1
	}
	device, deviceToken, err := s.bindDevice(ctx, userID, ip, ua, aal, deviceBinding)
	if err != nil {
		return "", "", err
	}
	now := time.Now().UTC()
	session := &store.Session{
		UserID:        userID,
		DeviceID:      device.ID,
		AAL:           aal,
		TokenHash:     hash,
		ExpiresAt:     now.Add(s.cfg.Security.SessionTTL),
		IdleExpiresAt: now.Add(s.cfg.Security.SessionIdleTTL),
		AuthTime:      now,
		IP:            ip,
		UserAgent:     ua,
		AuthMethod:    authMethod,
		RiskScore:     device.RiskScore,
	}
	if err := s.store.CreateSession(ctx, session); err != nil {
		return "", "", err
	}
	return token, deviceToken, nil
}

func (s *Service) ValidateSession(ctx context.Context, token string, validation SessionValidation) (*store.User, *store.Session, error) {
	hash := security.HashToken(token)
	session, err := s.store.GetSessionByTokenHash(ctx, hash)
	if err != nil || session == nil {
		return nil, nil, ErrInvalidToken
	}
	now := time.Now()
	idleExpiresAt := session.IdleExpiresAt
	if idleExpiresAt.IsZero() {
		idleExpiresAt = session.ExpiresAt
		session.IdleExpiresAt = idleExpiresAt
	}
	if session.ExpiresAt.Before(now) || idleExpiresAt.Before(now) {
		_ = s.store.DeleteSessionByHash(ctx, hash)
		return nil, nil, ErrInvalidToken
	}
	if err := s.enforceSessionDevice(ctx, session, validation); err != nil {
		return nil, nil, err
	}
	user, err := s.store.GetUserByID(ctx, session.UserID)
	if err != nil || user == nil {
		return nil, nil, ErrInvalidToken
	}
	if user.Status != "active" {
		_ = s.store.DeleteSessionByHash(ctx, hash)
		return nil, nil, ErrInvalidToken
	}
	if s.shouldTouchSession(session, now) {
		_ = s.store.TouchSession(ctx, hash, now.UTC().Add(s.cfg.Security.SessionIdleTTL))
	}
	return user, session, nil
}

func (s *Service) Logout(ctx context.Context, token string) error {
	hash := security.HashToken(token)
	return s.store.DeleteSessionByHash(ctx, hash)
}

func (s *Service) DeleteUser(ctx context.Context, userID int64) error {
	if userID <= 0 {
		return nil
	}
	return s.store.DeleteUserByID(ctx, userID)
}

func (s *Service) SetupTOTP(ctx context.Context, userID int64, accountName, issuer string) (secret string, provisioningURI string, err error) {
	secret, err = security.GenerateTOTPSecret(20)
	if err != nil {
		return "", "", err
	}
	nonce, cipher, err := security.Encrypt(s.cfg.Security.EncryptionKey, []byte(secret))
	if err != nil {
		return "", "", err
	}
	record, err := s.store.GetTOTP(ctx, userID)
	if err != nil {
		return "", "", err
	}
	if record != nil && record.EnabledAt != nil {
		if err := s.store.SetPendingTOTPSecret(ctx, userID, cipher, nonce); err != nil {
			return "", "", err
		}
	} else if err := s.store.UpsertTOTPSecret(ctx, userID, cipher, nonce); err != nil {
		return "", "", err
	}
	provisioningURI = security.ProvisioningURI(secret, accountName, issuer)
	return secret, provisioningURI, nil
}

func (s *Service) ConfirmTOTPAndReissue(ctx context.Context, userID int64, code, tokenHash string) ([]string, *SessionReissueResult, error) {
	if strings.TrimSpace(tokenHash) == "" {
		return nil, nil, ErrInvalidToken
	}
	record, err := s.store.GetTOTP(ctx, userID)
	if err != nil || record == nil {
		return nil, nil, ErrInvalidMFA
	}
	secretCipher := record.EncryptedSecret
	nonce := record.Nonce
	if len(record.PendingEncryptedSecret) > 0 && len(record.PendingNonce) > 0 {
		secretCipher = record.PendingEncryptedSecret
		nonce = record.PendingNonce
	}
	secret, err := security.Decrypt(s.cfg.Security.EncryptionKey, nonce, secretCipher)
	if err != nil {
		return nil, nil, err
	}
	if !security.VerifyTOTP(string(secret), code, time.Now(), 1) {
		return nil, nil, ErrInvalidMFA
	}
	codes, hashes, err := s.generateBackupCodeSet()
	if err != nil {
		return nil, nil, err
	}
	sessionToken, newTokenHash, err := security.GenerateToken(32)
	if err != nil {
		return nil, nil, err
	}
	csrfToken, _, err := security.GenerateToken(32)
	if err != nil {
		return nil, nil, err
	}
	authTime := time.Now().UTC()
	idleExpiresAt := authTime.Add(s.cfg.Security.SessionIdleTTL)
	if err := s.store.FinalizeTOTPEnrollment(ctx, userID, hashes, tokenHash, newTokenHash, authTime, idleExpiresAt); err != nil {
		return nil, nil, err
	}
	return codes, &SessionReissueResult{
		SessionToken: sessionToken,
		CSRFToken:    csrfToken,
		AuthTime:     authTime,
		AAL:          2,
	}, nil
}

func (s *Service) DisableTOTPAndReissue(ctx context.Context, userID int64, tokenHash string) (*SessionReissueResult, error) {
	if strings.TrimSpace(tokenHash) == "" {
		return nil, ErrInvalidToken
	}
	sessionToken, newTokenHash, err := security.GenerateToken(32)
	if err != nil {
		return nil, err
	}
	csrfToken, _, err := security.GenerateToken(32)
	if err != nil {
		return nil, err
	}
	authTime := time.Now().UTC()
	idleExpiresAt := authTime.Add(s.cfg.Security.SessionIdleTTL)
	if err := s.store.DisableTOTPAndRotateSession(ctx, userID, tokenHash, newTokenHash, authTime, idleExpiresAt); err != nil {
		return nil, err
	}
	return &SessionReissueResult{
		SessionToken: sessionToken,
		CSRFToken:    csrfToken,
		AuthTime:     authTime,
		AAL:          1,
	}, nil
}

func (s *Service) RegenerateBackupCodes(ctx context.Context, userID int64) ([]string, error) {
	return s.generateAndStoreBackupCodes(ctx, userID)
}

func (s *Service) generateAndStoreBackupCodes(ctx context.Context, userID int64) ([]string, error) {
	codes, hashes, err := s.generateBackupCodeSet()
	if err != nil {
		return nil, err
	}
	if err := s.store.ReplaceBackupCodes(ctx, userID, hashes); err != nil {
		return nil, err
	}
	return codes, nil
}

func (s *Service) generateBackupCodeSet() ([]string, []string, error) {
	codes := make([]string, 10)
	hashes := make([]string, 10)
	for i := 0; i < 10; i++ {
		code, err := security.GenerateBackupCode()
		if err != nil {
			return nil, nil, err
		}
		codes[i] = code
		hash, err := security.HashPassword(code, s.argonParams)
		if err != nil {
			return nil, nil, err
		}
		hashes[i] = hash
	}
	return codes, hashes, nil
}

func (s *Service) StartPasswordReset(ctx context.Context, email string, ip string) (string, error) {
	user, err := s.store.FindUserByEmailOrUsername(ctx, email)
	if err != nil || user == nil {
		return "", nil
	}
	if user.Status != "active" || !user.EmailVerified {
		return "", nil
	}
	token, hash, err := security.GenerateToken(32)
	if err != nil {
		return "", err
	}
	reset := &store.PasswordReset{
		UserID:    user.ID,
		Email:     user.Email,
		TokenHash: hash,
		ExpiresAt: time.Now().Add(s.cfg.Security.ResetTTL),
		RequestIP: ip,
	}
	if err := s.store.CreatePasswordReset(ctx, reset); err != nil {
		return "", err
	}
	s.audit(ctx, "password-reset", &user.ID, "", ip, "", true)
	return token, nil
}

func (s *Service) StartPasswordResetWithDelivery(ctx context.Context, email, ip, ua string, deliver func(string) error) error {
	user, err := s.store.FindUserByEmailOrUsername(ctx, email)
	if err != nil || user == nil {
		return err
	}
	if user.Status != "active" || !user.EmailVerified {
		return nil
	}
	token, hash, err := security.GenerateToken(32)
	if err != nil {
		return err
	}
	reset := &store.PasswordReset{
		UserID:    user.ID,
		Email:     user.Email,
		TokenHash: hash,
		ExpiresAt: time.Now().Add(s.cfg.Security.ResetTTL),
		RequestIP: ip,
	}
	if err := s.store.CreatePasswordReset(ctx, reset); err != nil {
		return err
	}
	if deliver != nil {
		if err := deliver(token); err != nil {
			_ = s.store.DeletePendingPasswordResetsByUserID(ctx, user.ID)
			return err
		}
	}
	s.audit(ctx, "password-reset", &user.ID, "", ip, ua, true)
	return nil
}

func (s *Service) CompletePasswordReset(ctx context.Context, token, newPassword string) error {
	hash := security.HashToken(token)
	if err := security.ValidatePasswordStrength(newPassword); err != nil {
		return err
	}
	pwdHash, err := security.HashPassword(newPassword, s.argonParams)
	if err != nil {
		return err
	}
	userID, err := s.store.ApplyPasswordReset(ctx, hash, pwdHash)
	if err != nil {
		return err
	}
	if userID == 0 {
		return ErrInvalidToken
	}
	return nil
}

func (s *Service) LoginWithOAuth(ctx context.Context, provider, subject, email string, emailVerified bool, ip, ua string, deviceBinding DeviceBinding) (*OAuthLoginResult, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	ident, err := s.store.GetIdentity(ctx, provider, subject)
	if err != nil {
		return nil, err
	}
	var user *store.User
	if ident != nil {
		user, err = s.store.GetUserByID(ctx, ident.UserID)
		if err != nil || user == nil {
			return nil, ErrInvalidToken
		}
		if user.Status != "active" {
			s.audit(ctx, "oauth-login", &user.ID, provider, ip, ua, false)
			return nil, errors.New("user inactive")
		}
		_ = s.store.UpdateIdentityLogin(ctx, ident.ID)
	} else {
		if email == "" || !emailVerified {
			s.audit(ctx, "oauth-login", nil, provider, ip, ua, false)
			return nil, ErrOAuthProvisioning
		}
		username := fallbackUsername(email, provider)
		user = &store.User{
			TenantID:            s.defaultTenantID(),
			Email:               email,
			EmailVerified:       true,
			Username:            username,
			PasswordHash:        "",
			PasswordAuthEnabled: false,
			Status:              "active",
		}
		ident = &store.Identity{
			Provider:      provider,
			Subject:       subject,
			Email:         email,
			EmailVerified: emailVerified,
		}
		if err := s.store.CreateUserWithIdentity(ctx, user, ident); err != nil {
			return nil, err
		}
	}
	if user.MFAEnabled {
		pendingState, _, err := security.GenerateToken(24)
		if err != nil {
			return nil, err
		}
		if err := s.store.SaveOAuthState(ctx, store.OAuthState{
			State:     pendingState,
			Provider:  provider,
			Action:    "login_mfa",
			UserID:    &user.ID,
			ExpiresAt: time.Now().Add(10 * time.Minute),
		}); err != nil {
			return nil, err
		}
		return &OAuthLoginResult{
			User:         user,
			RequiresMFA:  true,
			PendingState: pendingState,
			Provider:     provider,
		}, nil
	}
	token, deviceToken, err := s.startSession(ctx, user.ID, ip, ua, 1, "oauth:"+provider, deviceBinding)
	if err != nil {
		return nil, err
	}
	csrfToken, _, err := security.GenerateToken(32)
	if err != nil {
		return nil, err
	}
	s.audit(ctx, "oauth-login", &user.ID, provider, ip, ua, true)
	return &OAuthLoginResult{
		User:         user,
		SessionToken: token,
		DeviceToken:  deviceToken,
		CSRFToken:    csrfToken,
		Provider:     provider,
	}, nil
}

func (s *Service) LinkIdentity(ctx context.Context, userID int64, provider, subject, email string, emailVerified bool) error {
	existing, err := s.store.GetIdentity(ctx, provider, subject)
	if err != nil {
		return err
	}
	if existing != nil && existing.UserID != userID {
		return errors.New("identity already linked to another account")
	}
	ident := &store.Identity{
		UserID:        userID,
		Provider:      provider,
		Subject:       subject,
		Email:         email,
		EmailVerified: emailVerified,
	}
	return s.store.CreateIdentity(ctx, ident)
}

func (s *Service) UnlinkIdentity(ctx context.Context, userID int64, provider string) error {
	user, err := s.store.GetUserByID(ctx, userID)
	if err != nil || user == nil {
		return ErrInvalidToken
	}
	count, err := s.store.CountIdentitiesByUserID(ctx, userID)
	if err != nil {
		return err
	}
	if count <= 1 && !user.PasswordAuthEnabled {
		return errors.New("cannot unlink last identity")
	}
	return s.store.DeleteIdentity(ctx, userID, provider)
}

func (s *Service) SaveOAuthState(ctx context.Context, state store.OAuthState) error {
	return s.store.SaveOAuthState(ctx, state)
}

func (s *Service) ConsumeOAuthState(ctx context.Context, state string) (*store.OAuthState, error) {
	return s.store.ConsumeOAuthState(ctx, state)
}

func nilUserID(u *store.User) *int64 {
	if u == nil {
		return nil
	}
	return &u.ID
}

// LogEvent allows handlers to record security/audit events without exposing the audit implementation.
func (s *Service) LogEvent(ctx context.Context, event string, userID *int64, provider string, ip string, ua string, success bool) {
	s.audit(ctx, event, userID, provider, ip, ua, success)
}

func (s *Service) audit(ctx context.Context, event string, userID *int64, provider string, ip string, ua string, success bool) {
	now := time.Now().UTC()
	entry := &store.AuditLog{
		EventType: event,
		UserID:    userID,
		Provider:  provider,
		IP:        ip,
		UserAgent: ua,
		Success:   success,
		CreatedAt: now,
	}
	_ = s.store.InsertAuditLog(ctx, entry)
	if s.auditClient != nil {
		if err := s.auditClient.Record(ctx, audit.Event{
			Source:    "auth",
			EventType: event,
			UserID:    userID,
			Provider:  provider,
			IP:        ip,
			UserAgent: ua,
			Success:   success,
			CreatedAt: now,
		}); err != nil {
			slog.WarnContext(ctx, "auth audit forward dropped", "event", event, "error", err)
		}
	}
}

func (s *Service) VerifyMFAChallenge(ctx context.Context, userID int64, totpCode, backupCode string) error {
	if totpCode == "" && backupCode == "" {
		return ErrMFARequired
	}
	record, err := s.store.GetTOTP(ctx, userID)
	if err != nil || record == nil {
		return ErrInvalidMFA
	}
	if totpCode != "" {
		secret, err := security.Decrypt(s.cfg.Security.EncryptionKey, record.Nonce, record.EncryptedSecret)
		if err != nil {
			return err
		}
		if !security.VerifyTOTP(string(secret), totpCode, time.Now(), 1) {
			return ErrInvalidMFA
		}
		_ = s.store.UpdateTOTPUsed(ctx, userID, time.Now())
		return nil
	}
	if backupCode != "" {
		used, err := s.store.UseBackupCode(ctx, userID, backupCode)
		if err != nil || !used {
			return ErrInvalidMFA
		}
		return nil
	}
	return ErrInvalidMFA
}

func (s *Service) VerifyPasswordChallenge(ctx context.Context, userID int64, password string) error {
	if strings.TrimSpace(password) == "" {
		return ErrInvalidCredentials
	}
	user, err := s.store.GetUserByID(ctx, userID)
	if err != nil || user == nil || user.Status != "active" || !user.PasswordAuthEnabled || user.PasswordHash == "" {
		return ErrInvalidCredentials
	}
	ok, err := security.VerifyPassword(password, user.PasswordHash)
	if err != nil || !ok {
		return ErrInvalidCredentials
	}
	return nil
}

func (s *Service) ReissueSession(ctx context.Context, userID int64, tokenHash string, aal int, revokeOtherSessions bool) (*SessionReissueResult, error) {
	if strings.TrimSpace(tokenHash) == "" {
		return nil, ErrInvalidToken
	}
	if aal <= 0 {
		aal = 1
	}
	sessionToken, newTokenHash, err := security.GenerateToken(32)
	if err != nil {
		return nil, err
	}
	csrfToken, _, err := security.GenerateToken(32)
	if err != nil {
		return nil, err
	}
	authTime := time.Now().UTC()
	idleExpiresAt := authTime.Add(s.cfg.Security.SessionIdleTTL)
	if revokeOtherSessions {
		if err := s.store.RotateSessionAndDeleteOthers(ctx, userID, tokenHash, newTokenHash, authTime, idleExpiresAt, aal); err != nil {
			return nil, err
		}
	} else if err := s.store.RotateSession(ctx, tokenHash, newTokenHash, authTime, idleExpiresAt, aal); err != nil {
		return nil, err
	}
	return &SessionReissueResult{
		SessionToken: sessionToken,
		CSRFToken:    csrfToken,
		AuthTime:     authTime,
		AAL:          aal,
	}, nil
}

func (s *Service) CompleteOAuthLogin(ctx context.Context, pendingState, totpCode, backupCode, ip, ua string, deviceBinding DeviceBinding) (*LoginResult, string, error) {
	if strings.TrimSpace(pendingState) == "" {
		return nil, "", ErrInvalidToken
	}
	state, err := s.store.GetOAuthState(ctx, pendingState)
	if err != nil || state == nil || state.Action != "login_mfa" || state.UserID == nil {
		return nil, "", ErrInvalidToken
	}
	user, err := s.store.GetUserByID(ctx, *state.UserID)
	if err != nil || user == nil || user.Status != "active" || !user.MFAEnabled {
		return nil, state.Provider, ErrInvalidToken
	}
	if err := s.VerifyMFAChallenge(ctx, user.ID, totpCode, backupCode); err != nil {
		s.audit(ctx, "oauth-login", &user.ID, state.Provider, ip, ua, false)
		return nil, state.Provider, err
	}
	consumed, err := s.store.ConsumeOAuthState(ctx, pendingState)
	if err != nil {
		return nil, state.Provider, err
	}
	if consumed == nil || consumed.Action != "login_mfa" || consumed.UserID == nil || *consumed.UserID != user.ID {
		return nil, state.Provider, ErrInvalidToken
	}
	sessionToken, deviceToken, err := s.startSession(ctx, user.ID, ip, ua, 2, "oauth:"+state.Provider+"+mfa", deviceBinding)
	if err != nil {
		return nil, state.Provider, err
	}
	csrfToken, _, err := security.GenerateToken(32)
	if err != nil {
		return nil, state.Provider, err
	}
	s.audit(ctx, "oauth-login", &user.ID, state.Provider, ip, ua, true)
	return &LoginResult{
		User:         user,
		SessionToken: sessionToken,
		DeviceToken:  deviceToken,
		CSRFToken:    csrfToken,
	}, state.Provider, nil
}

func fallbackUsername(email, provider string) string {
	if email == "" {
		return fmt.Sprintf("%s_%d", provider, time.Now().UnixNano())
	}
	beforeAt := email
	if idx := strings.Index(email, "@"); idx > 0 {
		beforeAt = email[:idx]
	}
	return beforeAt
}

func unknownUserLockoutKey(identifier string) string {
	normalized := strings.ToLower(strings.TrimSpace(identifier))
	if normalized == "" {
		normalized = "empty"
	}
	sum := sha256.Sum256([]byte(normalized))
	return "id:" + hex.EncodeToString(sum[:])
}

func (s *Service) isLocked(ctx context.Context, userKey, ip string) (bool, time.Duration) {
	lockedIP, ttlIP := s.lockout.IsLocked(ctx, userKey, ip)
	lockedUser, ttlUser := s.lockout.IsLocked(ctx, userKey, "")
	if !lockedIP && !lockedUser {
		return false, 0
	}
	if ttlUser > ttlIP {
		return true, ttlUser
	}
	return true, ttlIP
}

func (s *Service) registerFailure(ctx context.Context, userKey, ip string) {
	s.lockout.RegisterFailure(ctx, userKey, ip)
	if ip != "" {
		s.lockout.RegisterFailure(ctx, userKey, "")
	}
}

func (s *Service) clearFailures(ctx context.Context, userKey, ip string) {
	s.lockout.Clear(ctx, userKey, ip)
	if ip != "" {
		s.lockout.Clear(ctx, userKey, "")
	}
}

func (s *Service) defaultTenantID() string {
	tenant := strings.TrimSpace(s.cfg.Security.DefaultTenant)
	if tenant == "" {
		return "default"
	}
	return tenant
}

func (s *Service) bindDevice(ctx context.Context, userID int64, ip, ua string, aal int, binding DeviceBinding) (*store.Device, string, error) {
	rawToken := strings.TrimSpace(binding.Token)
	clientFamily := normalizeClientFamily(binding.ClientFamily)

	var existing *store.Device
	var err error
	if rawToken != "" {
		existing, err = s.store.GetDeviceByTokenHash(ctx, userID, security.HashToken(rawToken))
		if err != nil {
			return nil, "", err
		}
	}

	riskScore := scoreDeviceRisk(existing, ip, ua)
	trustLevel := nextTrustLevel(existing, aal)
	if existing != nil {
		family := existing.ClientFamily
		if clientFamily != "generic" {
			family = clientFamily
		}
		if err := s.store.UpdateDeviceSeen(ctx, existing.ID, family, ip, ua, trustLevel, riskScore); err != nil {
			return nil, "", err
		}
		existing.ClientFamily = family
		existing.TrustLevel = trustLevel
		existing.RiskScore = riskScore
		existing.LastIP = ip
		existing.LastUserAgent = ua
		existing.LastSeenAt = time.Now().UTC()
		return existing, rawToken, nil
	}

	rawToken, tokenHash, err := security.GenerateToken(32)
	if err != nil {
		return nil, "", err
	}
	device := &store.Device{
		UserID:        userID,
		TokenHash:     tokenHash,
		ClientFamily:  clientFamily,
		TrustLevel:    trustLevel,
		RiskScore:     riskScore,
		LastIP:        ip,
		LastUserAgent: ua,
	}
	if err := s.store.CreateDevice(ctx, device); err != nil {
		return nil, "", err
	}
	return device, rawToken, nil
}

func (s *Service) enforceSessionDevice(ctx context.Context, session *store.Session, validation SessionValidation) error {
	if session == nil {
		return ErrInvalidToken
	}
	if session.DeviceID == 0 {
		if strings.TrimSpace(session.TokenHash) != "" {
			_ = s.store.DeleteSessionByHash(ctx, session.TokenHash)
		}
		return ErrInvalidToken
	}
	deviceToken := strings.TrimSpace(validation.DeviceToken)
	if deviceToken == "" {
		return ErrInvalidToken
	}
	device, err := s.store.GetDeviceByTokenHash(ctx, session.UserID, security.HashToken(deviceToken))
	if err != nil {
		return err
	}
	if device == nil || device.ID != session.DeviceID || device.RevokedAt != nil {
		return ErrInvalidToken
	}
	clientFamily := device.ClientFamily
	if normalized := normalizeClientFamily(validation.ClientFamily); normalized != "generic" {
		clientFamily = normalized
	}
	riskScore := device.RiskScore
	if riskScore == 0 && session.RiskScore > 0 {
		riskScore = session.RiskScore
	}
	trustLevel := device.TrustLevel
	if strings.TrimSpace(trustLevel) == "" {
		trustLevel = nextTrustLevel(device, session.AAL)
	}
	if validation.RefreshMetadata {
		riskScore = scoreDeviceRisk(device, validation.IP, validation.UserAgent)
		trustLevel = nextTrustLevel(device, session.AAL)
		metadataChanged := device.LastIP != validation.IP ||
			device.LastUserAgent != validation.UserAgent ||
			device.RiskScore != riskScore ||
			device.TrustLevel != trustLevel ||
			device.ClientFamily != clientFamily
		if metadataChanged {
			if err := s.store.UpdateDeviceSeen(ctx, device.ID, clientFamily, validation.IP, validation.UserAgent, trustLevel, riskScore); err != nil {
				return err
			}
		}
		session.IP = validation.IP
		session.UserAgent = validation.UserAgent
	}
	session.RiskScore = riskScore
	session.DeviceTrustLevel = trustLevel
	session.DeviceClientFamily = clientFamily
	return nil
}

func (s *Service) shouldTouchSession(session *store.Session, now time.Time) bool {
	if session == nil {
		return false
	}
	if s.cfg.Security.SessionTouchEvery <= 0 {
		return true
	}
	return now.Sub(session.LastSeenAt) >= s.cfg.Security.SessionTouchEvery
}

func scoreDeviceRisk(device *store.Device, ip, ua string) int {
	if device == nil {
		return 60
	}
	score := 0
	if device.LastIP != "" && ip != "" && device.LastIP != ip {
		score += 60
	}
	if device.LastUserAgent != "" && ua != "" && device.LastUserAgent != ua {
		score += 30
	}
	if score > 100 {
		return 100
	}
	return score
}

func nextTrustLevel(device *store.Device, aal int) string {
	if device == nil {
		if aal >= 2 {
			return "trusted"
		}
		return "known"
	}
	if device.TrustLevel == "verified" {
		return "verified"
	}
	if aal >= 2 {
		return "trusted"
	}
	if strings.TrimSpace(device.TrustLevel) == "" {
		return "known"
	}
	return device.TrustLevel
}

func normalizeClientFamily(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "web", "browser":
		return "browser"
	case "mobile_web", "mobile-browser":
		return "mobile_web"
	case "mobile_app", "mobile-app", "app":
		return "mobile_app"
	case "cli":
		return "cli"
	default:
		return "generic"
	}
}

func (s *Service) ListSessions(ctx context.Context, userID int64) ([]*store.Session, error) {
	return s.store.ListSessionsByUserID(ctx, userID)
}

func (s *Service) ListDevices(ctx context.Context, userID int64) ([]*store.Device, error) {
	return s.store.ListDevicesByUserID(ctx, userID)
}

func (s *Service) RevokeSession(ctx context.Context, userID, sessionID int64) error {
	return s.store.DeleteSessionByID(ctx, userID, sessionID)
}

func (s *Service) RevokeOtherSessions(ctx context.Context, userID int64, keepTokenHash string) error {
	if strings.TrimSpace(keepTokenHash) == "" {
		return ErrInvalidToken
	}
	return s.store.DeleteOtherSessionsByUserID(ctx, userID, keepTokenHash)
}

func (s *Service) RevokeDevice(ctx context.Context, userID, deviceID int64) error {
	return s.store.RevokeDeviceByID(ctx, userID, deviceID)
}
