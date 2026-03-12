package security

import (
	"errors"
	"fmt"
	"strings"
	"unicode"
)

const (
	minPasswordLength = 8
	maxPasswordLength = 128
)

var (
	ErrWeakPassword = errors.New("weak password")

	commonWeakPasswords = map[string]struct{}{
		"12345678":     {},
		"123456789":    {},
		"1234567890":   {},
		"password":     {},
		"password1":    {},
		"password123":  {},
		"qwerty123":    {},
		"admin123":     {},
		"letmein123":   {},
		"welcome123":   {},
		"iloveyou123":  {},
		"changeme123":  {},
		"senha123":     {},
		"senha12345":   {},
		"senhaforte1!": {},
	}
)

// ValidatePasswordStrength enforces a baseline password policy.
func ValidatePasswordStrength(password string) error {
	if len(password) < minPasswordLength {
		return fmt.Errorf("%w: password must have at least %d characters", ErrWeakPassword, minPasswordLength)
	}
	if len(password) > maxPasswordLength {
		return fmt.Errorf("%w: password is too long", ErrWeakPassword)
	}

	var hasLower, hasUpper, hasDigit, hasSymbol bool
	for _, r := range password {
		if unicode.IsSpace(r) {
			return fmt.Errorf("%w: password cannot contain spaces", ErrWeakPassword)
		}
		switch {
		case unicode.IsLower(r):
			hasLower = true
		case unicode.IsUpper(r):
			hasUpper = true
		case unicode.IsDigit(r):
			hasDigit = true
		default:
			hasSymbol = true
		}
	}

	classes := 0
	if hasLower {
		classes++
	}
	if hasUpper {
		classes++
	}
	if hasDigit {
		classes++
	}
	if hasSymbol {
		classes++
	}
	if classes < 3 {
		return fmt.Errorf("%w: password must include at least 3 character classes", ErrWeakPassword)
	}

	normalized := strings.ToLower(strings.TrimSpace(password))
	if _, banned := commonWeakPasswords[normalized]; banned {
		return fmt.Errorf("%w: password is too common", ErrWeakPassword)
	}

	return nil
}
