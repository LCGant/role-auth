package security

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	DefaultTOTPDigits = 6
	DefaultTOTPPeriod = 30
)

func GenerateTOTPSecret(length int) (string, error) {
	if length < 20 {
		length = 20
	}
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate totp secret: %w", err)
	}
	secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)
	return secret, nil
}

func TOTPCode(secret string, t time.Time, digits int, period int) (string, error) {
	if digits == 0 {
		digits = DefaultTOTPDigits
	}
	if period == 0 {
		period = DefaultTOTPPeriod
	}
	secret = strings.ToUpper(secret)
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil {
		return "", fmt.Errorf("decode secret: %w", err)
	}

	counter := uint64(t.Unix() / int64(period))
	buf := make([]byte, 8)
	for i := uint(0); i < 8; i++ {
		buf[7-i] = byte(counter >> (i * 8))
	}

	mac := hmac.New(sha1.New, key)
	if _, err := mac.Write(buf); err != nil {
		return "", fmt.Errorf("hmac: %w", err)
	}
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0F
	code := (uint32(sum[offset])&0x7F)<<24 |
		(uint32(sum[offset+1])&0xFF)<<16 |
		(uint32(sum[offset+2])&0xFF)<<8 |
		(uint32(sum[offset+3]) & 0xFF)
	code = code % pow10(digits)
	return fmt.Sprintf("%0*d", digits, code), nil
}

func VerifyTOTP(secret, code string, t time.Time, window int) bool {
	if window <= 0 {
		window = 1
	}
	for i := -window; i <= window; i++ {
		ts := t.Add(time.Duration(i*DefaultTOTPPeriod) * time.Second)
		expected, err := TOTPCode(secret, ts, DefaultTOTPDigits, DefaultTOTPPeriod)
		if err != nil {
			continue
		}
		if subtleConstantTimeStringCompare(code, expected) {
			return true
		}
	}
	return false
}

func ProvisioningURI(secret, accountName, issuer string) string {
	v := url.Values{}
	v.Set("secret", secret)
	v.Set("issuer", issuer)
	v.Set("period", strconv.Itoa(DefaultTOTPPeriod))
	v.Set("digits", strconv.Itoa(DefaultTOTPDigits))
	label := url.PathEscape(fmt.Sprintf("%s:%s", issuer, accountName))
	return fmt.Sprintf("otpauth://totp/%s?%s", label, v.Encode())
}

func GenerateBackupCode() (string, error) {
	raw := make([]byte, 8)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("backup code: %w", err)
	}
	return strings.ToUpper(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw)), nil
}

func pow10(n int) uint32 {
	res := uint32(1)
	for i := 0; i < n; i++ {
		res *= 10
	}
	return res
}

func subtleConstantTimeStringCompare(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var result byte
	for i := 0; i < len(a); i++ {
		result |= a[i] ^ b[i]
	}
	return result == 0
}
