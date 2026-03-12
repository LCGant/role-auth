package security

import (
	"encoding/base64"
	"testing"
	"time"
)

func TestTokenGenerateAndHash(t *testing.T) {
	token, hash, err := GenerateToken(32)
	if err != nil {
		t.Fatalf("generate token: %v", err)
	}
	if len(token) == 0 || len(hash) == 0 {
		t.Fatalf("token/hash empty")
	}
	if HashToken(token) != hash {
		t.Fatalf("hash mismatch")
	}
	if !ConstantTimeEqualHash(hash, HashToken(token)) {
		t.Fatalf("constant time comparison failed")
	}
}

func TestHashPassword(t *testing.T) {
	params := Argon2Params{Memory: 64 * 1024, Iterations: 1, Parallelism: 4, SaltLength: 16, KeyLength: 32}
	hash, err := HashPassword("StrongP@ss", params)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	ok, err := VerifyPassword("StrongP@ss", hash)
	if err != nil || !ok {
		t.Fatalf("verify password failed: %v", err)
	}
	ok, _ = VerifyPassword("wrong", hash)
	if ok {
		t.Fatalf("expected failure for wrong password")
	}
}

func TestCryptoEncryptDecrypt(t *testing.T) {
	key := make([]byte, 32)
	copy(key, []byte("0123456789abcdef0123456789abcdef"))
	nonce, cipher, err := Encrypt(key, []byte("secret"))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	plain, err := Decrypt(key, nonce, cipher)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if string(plain) != "secret" {
		t.Fatalf("unexpected plaintext: %s", plain)
	}
}

func TestTOTP(t *testing.T) {
	secret, err := GenerateTOTPSecret(20)
	if err != nil {
		t.Fatalf("secret: %v", err)
	}
	code, err := TOTPCode(secret, time.Now(), DefaultTOTPDigits, DefaultTOTPPeriod)
	if err != nil {
		t.Fatalf("code: %v", err)
	}
	if !VerifyTOTP(secret, code, time.Now(), 1) {
		t.Fatalf("verify failed")
	}
}

func TestBackupCodeFormat(t *testing.T) {
	code, err := GenerateBackupCode()
	if err != nil {
		t.Fatalf("backup code: %v", err)
	}
	if len(code) == 0 {
		t.Fatalf("empty code")
	}
	if _, err := base64.StdEncoding.DecodeString(code); err == nil {
		// should be base32-like, not valid std base64
		t.Fatalf("expected base64 decode to fail")
	}
}

func TestValidatePasswordStrength(t *testing.T) {
	valid := "StrongPass1!"
	if err := ValidatePasswordStrength(valid); err != nil {
		t.Fatalf("expected valid password, got error: %v", err)
	}

	cases := []string{
		"short1!",
		"alllowercase1",
		"ALLUPPERCASE1",
		"NoDigitsOnly",
		"nosymbols123",
		"Password123",
		"Space Pass1!",
	}
	for _, tc := range cases {
		if err := ValidatePasswordStrength(tc); err == nil {
			t.Fatalf("expected %q to be rejected", tc)
		}
	}
}
