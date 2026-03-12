package config

import "testing"

func TestValidateInternalServiceURLRejectsRemoteHTTPByDefault(t *testing.T) {
	if err := validateInternalServiceURL("http://notification:8080", false); err == nil {
		t.Fatalf("expected remote http to be rejected without explicit opt-in")
	}
	if err := validateInternalServiceURL("http://127.0.0.1:8080", false); err != nil {
		t.Fatalf("expected loopback http to remain allowed, got %v", err)
	}
	if err := validateInternalServiceURL("https://notification.internal", false); err != nil {
		t.Fatalf("expected https to be allowed, got %v", err)
	}
}
