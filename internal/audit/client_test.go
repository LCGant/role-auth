package audit

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestSendWithRetryEventuallySucceeds(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) < 3 {
			http.Error(w, "try again", http.StatusBadGateway)
			return
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	client := &Client{
		baseURL:       srv.URL,
		internalToken: "secret",
		timeout:       500 * time.Millisecond,
		httpClient:    srv.Client(),
		logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	client.sendWithRetry(Event{Source: "auth", EventType: "login", Success: true, CreatedAt: time.Now().UTC()})

	if got := calls.Load(); got != 3 {
		t.Fatalf("expected 3 attempts, got %d", got)
	}
}

func TestFlushSpoolDeliversPersistedEvents(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	spoolDir := t.TempDir()
	client := &Client{
		baseURL:       srv.URL,
		internalToken: "secret",
		spoolDir:      spoolDir,
		timeout:       500 * time.Millisecond,
		httpClient:    srv.Client(),
		logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	event := Event{Source: "auth", EventType: "login", Success: true, CreatedAt: time.Now().UTC()}
	if err := client.spool(event); err != nil {
		t.Fatalf("spool event: %v", err)
	}

	client.flushSpool()

	if got := calls.Load(); got != 1 {
		t.Fatalf("expected 1 delivery attempt, got %d", got)
	}
	entries, err := os.ReadDir(spoolDir)
	if err != nil {
		t.Fatalf("read spool: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("expected spool to be drained, got %d entries", len(entries))
	}
}

func TestDeliverOrSpoolPersistsOnFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "down", http.StatusBadGateway)
	}))
	defer srv.Close()

	spoolDir := t.TempDir()
	client := &Client{
		baseURL:       srv.URL,
		internalToken: "secret",
		spoolDir:      spoolDir,
		timeout:       200 * time.Millisecond,
		httpClient:    srv.Client(),
		logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	event := Event{Source: "auth", EventType: "login", Success: true, CreatedAt: time.Now().UTC()}

	client.deliverOrSpool(event)

	entries, err := os.ReadDir(spoolDir)
	if err != nil {
		t.Fatalf("read spool: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 spooled event, got %d", len(entries))
	}
	payload, err := os.ReadFile(filepath.Join(spoolDir, entries[0].Name()))
	if err != nil {
		t.Fatalf("read spooled file: %v", err)
	}
	var got Event
	if err := json.Unmarshal(payload, &got); err != nil {
		t.Fatalf("decode spooled event: %v", err)
	}
	if got.EventType != event.EventType {
		t.Fatalf("expected event type %q, got %q", event.EventType, got.EventType)
	}
}
