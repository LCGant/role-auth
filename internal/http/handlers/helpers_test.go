package handlers

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestReadJSONAcceptsSingleObject(t *testing.T) {
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{"email":"a@b.com"}`))
	req.Header.Set("Content-Type", "application/json")
	var payload struct {
		Email string `json:"email"`
	}
	if err := readJSON(req, &payload); err != nil {
		t.Fatalf("readJSON failed: %v", err)
	}
	if payload.Email != "a@b.com" {
		t.Fatalf("unexpected payload: %+v", payload)
	}
}

func TestReadJSONRejectsTrailingData(t *testing.T) {
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{"email":"a@b.com"}{"x":1}`))
	req.Header.Set("Content-Type", "application/json")
	var payload struct {
		Email string `json:"email"`
	}
	if err := readJSON(req, &payload); err == nil {
		t.Fatalf("expected error for trailing data")
	}
}

func TestReadJSONRejectsUnknownFields(t *testing.T) {
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{"email":"a@b.com","unexpected":true}`))
	req.Header.Set("Content-Type", "application/json")
	var payload struct {
		Email string `json:"email"`
	}
	if err := readJSON(req, &payload); err == nil {
		t.Fatalf("expected error for unknown fields")
	}
}

func TestReadJSONRejectsMissingJSONContentType(t *testing.T) {
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{"email":"a@b.com"}`))
	var payload struct {
		Email string `json:"email"`
	}
	if err := readJSON(req, &payload); err == nil {
		t.Fatalf("expected error for missing content type")
	}
}

func TestReadJSONRejectsOversizedBody(t *testing.T) {
	oversized := strings.Repeat("a", maxJSONBodyBytes+1)
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{"email":"`+oversized+`"}`))
	req.Header.Set("Content-Type", "application/json")
	var payload struct {
		Email string `json:"email"`
	}
	if err := readJSON(req, &payload); err == nil {
		t.Fatalf("expected error for oversized body")
	}
}

func TestInputValidators(t *testing.T) {
	if !validEmail("user@example.com") {
		t.Fatalf("expected valid email")
	}
	if validEmail("bad email") {
		t.Fatalf("expected invalid email")
	}
	if !validUsername("user_name-01") {
		t.Fatalf("expected valid username")
	}
	if validUsername("x") {
		t.Fatalf("expected username to fail min length")
	}
	if !validIdentifier("user@example.com") {
		t.Fatalf("expected valid identifier")
	}
	if validIdentifier("") {
		t.Fatalf("expected empty identifier to fail")
	}
}
