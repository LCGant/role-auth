package security

import "crypto/subtle"

// ConstantTimeEqualHash compares two hash strings in constant time to avoid timing leaks.
func ConstantTimeEqualHash(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
