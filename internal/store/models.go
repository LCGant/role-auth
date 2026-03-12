package store

import "time"

type User struct {
	ID                  int64
	TenantID            string
	Email               string
	EmailVerified       bool
	Username            string
	PasswordHash        string
	PasswordAuthEnabled bool
	Status              string
	MFAEnabled          bool
	CreatedAt           time.Time
	UpdatedAt           time.Time
}

type Identity struct {
	ID            int64
	UserID        int64
	Provider      string
	Subject       string
	Email         string
	EmailVerified bool
	CreatedAt     time.Time
	LastLoginAt   time.Time
}

type Session struct {
	ID                 int64
	UserID             int64
	DeviceID           int64
	AAL                int
	TokenHash          string
	ExpiresAt          time.Time
	IdleExpiresAt      time.Time
	AuthTime           time.Time
	CreatedAt          time.Time
	LastSeenAt         time.Time
	IP                 string
	UserAgent          string
	AuthMethod         string
	RiskScore          int
	DeviceTrustLevel   string
	DeviceClientFamily string
}

type Device struct {
	ID            int64
	UserID        int64
	TokenHash     string
	ClientFamily  string
	TrustLevel    string
	RiskScore     int
	FirstSeenAt   time.Time
	LastSeenAt    time.Time
	LastIP        string
	LastUserAgent string
	RevokedAt     *time.Time
}

type MFATOTP struct {
	UserID                 int64
	EncryptedSecret        []byte
	Nonce                  []byte
	PendingEncryptedSecret []byte
	PendingNonce           []byte
	PendingCreatedAt       *time.Time
	EnabledAt              *time.Time
	LastUsedAt             *time.Time
}

type BackupCode struct {
	ID       int64
	UserID   int64
	CodeHash string
	UsedAt   *time.Time
}

type PasswordReset struct {
	ID        int64
	UserID    int64
	Email     string
	TokenHash string
	ExpiresAt time.Time
	UsedAt    *time.Time
	CreatedAt time.Time
	RequestIP string
}

type EmailVerification struct {
	ID        int64
	UserID    int64
	Email     string
	TokenHash string
	ExpiresAt time.Time
	UsedAt    *time.Time
	CreatedAt time.Time
	RequestIP string
}

type AuditLog struct {
	ID        int64
	EventType string
	UserID    *int64
	Provider  string
	IP        string
	UserAgent string
	Success   bool
	CreatedAt time.Time
}

type OAuthState struct {
	State        string
	Provider     string
	Action       string
	UserID       *int64
	CodeVerifier string
	Nonce        string
	ExpiresAt    time.Time
	CreatedAt    time.Time
}
