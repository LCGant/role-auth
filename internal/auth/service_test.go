package auth

import "testing"

func TestUnknownUserLockoutKeyDeterministic(t *testing.T) {
	k1 := unknownUserLockoutKey("  USER@example.com ")
	k2 := unknownUserLockoutKey("user@example.com")
	if k1 != k2 {
		t.Fatalf("expected normalized keys to match, got %q and %q", k1, k2)
	}
	if len(k1) != len("id:")+64 {
		t.Fatalf("expected fixed key length, got %d", len(k1))
	}
}

func TestUnknownUserLockoutKeyDifferentInputs(t *testing.T) {
	k1 := unknownUserLockoutKey("user-a@example.com")
	k2 := unknownUserLockoutKey("user-b@example.com")
	if k1 == k2 {
		t.Fatalf("expected different identifiers to produce different keys")
	}
}
