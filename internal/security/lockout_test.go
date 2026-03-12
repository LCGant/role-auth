package security

import (
	"context"
	"testing"
	"time"
)

func TestLockoutRedisOptionsParsesURL(t *testing.T) {
	opts := redisOptions("redis://:secret@redis.internal:6379/3")
	if opts.Addr != "redis.internal:6379" {
		t.Fatalf("expected parsed addr redis.internal:6379, got %q", opts.Addr)
	}
	if opts.Password != "secret" {
		t.Fatalf("expected parsed password, got %q", opts.Password)
	}
	if opts.DB != 3 {
		t.Fatalf("expected parsed db=3, got %d", opts.DB)
	}
}

func TestLockoutRedisOptionsFallsBackToAddr(t *testing.T) {
	opts := redisOptions("redis:6379")
	if opts.Addr != "redis:6379" {
		t.Fatalf("expected addr fallback, got %q", opts.Addr)
	}
}

func TestInMemoryLockoutCapsTrackedEntries(t *testing.T) {
	l := NewInMemoryLockout(5, time.Minute, time.Minute)
	l.maxEntries = 2
	ctx := context.Background()

	l.RegisterFailure(ctx, "user-a", "10.0.0.1")
	l.RegisterFailure(ctx, "user-b", "10.0.0.2")
	l.RegisterFailure(ctx, "user-c", "10.0.0.3")

	if got := len(l.attempts); got > 2 {
		t.Fatalf("expected attempts map capped at 2 entries, got %d", got)
	}
}
