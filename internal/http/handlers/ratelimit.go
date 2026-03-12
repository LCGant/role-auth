package handlers

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

const defaultRateLimiterMaxEntries = 10000

type Limiter interface {
	Allow(key string) bool
}

type RateLimiter struct {
	mu         sync.Mutex
	limits     map[string]*rateCounter
	max        int
	window     time.Duration
	maxEntries int
}

type rateCounter struct {
	count   int
	resetAt time.Time
}

func NewRateLimiter(max int, window time.Duration) *RateLimiter {
	return &RateLimiter{
		limits:     make(map[string]*rateCounter),
		max:        max,
		window:     window,
		maxEntries: defaultRateLimiterMaxEntries,
	}
}

func (r *RateLimiter) Allow(key string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	rc, ok := r.limits[key]
	now := time.Now()
	if !ok || now.After(rc.resetAt) {
		if !ok {
			r.evictIfNeeded(now)
		}
		r.limits[key] = &rateCounter{count: 1, resetAt: now.Add(r.window)}
		return true
	}
	if rc.count >= r.max {
		return false
	}
	rc.count++
	return true
}

func (r *RateLimiter) evictIfNeeded(now time.Time) {
	if r.maxEntries <= 0 || len(r.limits) < r.maxEntries {
		return
	}
	for k, rec := range r.limits {
		if now.After(rec.resetAt) {
			delete(r.limits, k)
		}
	}
	for len(r.limits) >= r.maxEntries {
		oldestKey := ""
		var oldest time.Time
		for k, rec := range r.limits {
			if oldestKey == "" || rec.resetAt.Before(oldest) {
				oldestKey = k
				oldest = rec.resetAt
			}
		}
		if oldestKey == "" {
			return
		}
		delete(r.limits, oldestKey)
	}
}

// RedisLimiter provides distributed rate limiting with simple counter and TTL per key.
type RedisLimiter struct {
	client *redis.Client
	max    int
	window time.Duration
	local  *RateLimiter
}

func NewRedisLimiter(addr string, max int, window time.Duration) *RedisLimiter {
	opts := redisOptions(addr)
	return &RedisLimiter{
		client: redis.NewClient(opts),
		max:    max,
		window: window,
		local:  NewRateLimiter(max, window),
	}
}

func (r *RedisLimiter) Allow(key string) bool {
	ctx := context.Background()
	script := redis.NewScript(`
local current = redis.call('INCR', KEYS[1])
if tonumber(current) == 1 then
  redis.call('PEXPIRE', KEYS[1], ARGV[1])
end
return current
`)
	res, err := script.Run(ctx, r.client, []string{key}, int(r.window.Milliseconds())).Int()
	if err != nil {
		// Security-first fallback when Redis is unavailable.
		if r.local != nil {
			return r.local.Allow(key)
		}
		return false
	}
	return res <= r.max
}

func redisOptions(addr string) *redis.Options {
	raw := strings.TrimSpace(addr)
	if strings.Contains(raw, "://") {
		if opts, err := redis.ParseURL(raw); err == nil {
			return opts
		}
	}
	return &redis.Options{Addr: raw}
}
