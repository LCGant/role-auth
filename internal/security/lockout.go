package security

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

const defaultInMemoryLockoutMaxEntries = 10000

type Lockout interface {
	IsLocked(ctx context.Context, userKey, ip string) (bool, time.Duration)
	RegisterFailure(ctx context.Context, userKey, ip string)
	Clear(ctx context.Context, userKey, ip string)
}

// InMemoryLockout keeps counters in-process; suitable for dev or single instance.
type InMemoryLockout struct {
	mu         sync.Mutex
	attempts   map[string]*lockRecord
	max        int
	window     time.Duration
	blockTime  time.Duration
	maxEntries int
}

type lockRecord struct {
	count int
	until time.Time
	reset time.Time
}

func NewInMemoryLockout(max int, window, block time.Duration) *InMemoryLockout {
	return &InMemoryLockout{
		attempts:   make(map[string]*lockRecord),
		max:        max,
		window:     window,
		blockTime:  block,
		maxEntries: defaultInMemoryLockoutMaxEntries,
	}
}

func (l *InMemoryLockout) IsLocked(ctx context.Context, userKey, ip string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	key := l.key(userKey, ip)
	rec, ok := l.attempts[key]
	if !ok {
		return false, 0
	}
	now := time.Now()
	if rec.until.After(now) {
		return true, time.Until(rec.until)
	}
	if rec.reset.Before(now) {
		delete(l.attempts, key)
	}
	return false, 0
}

func (l *InMemoryLockout) RegisterFailure(ctx context.Context, userKey, ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	key := l.key(userKey, ip)
	now := time.Now()
	rec, ok := l.attempts[key]
	if !ok || rec.reset.Before(now) {
		if !ok {
			l.evictIfNeeded(now)
		}
		rec = &lockRecord{count: 0, reset: now.Add(l.window)}
		l.attempts[key] = rec
	}
	rec.count++
	if rec.count >= l.max {
		rec.until = now.Add(l.blockTime)
	}
}

func (l *InMemoryLockout) Clear(ctx context.Context, userKey, ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.attempts, l.key(userKey, ip))
}

func (l *InMemoryLockout) key(userKey, ip string) string {
	return userKey + "|" + ip
}

func (l *InMemoryLockout) evictIfNeeded(now time.Time) {
	if l.maxEntries <= 0 || len(l.attempts) < l.maxEntries {
		return
	}
	l.cleanupExpired(now)
	for len(l.attempts) >= l.maxEntries {
		oldestKey := ""
		var oldest time.Time
		for k, rec := range l.attempts {
			if oldestKey == "" || rec.reset.Before(oldest) {
				oldestKey = k
				oldest = rec.reset
			}
		}
		if oldestKey == "" {
			return
		}
		delete(l.attempts, oldestKey)
	}
}

func (l *InMemoryLockout) cleanupExpired(now time.Time) {
	for k, rec := range l.attempts {
		if rec.until.After(now) {
			continue
		}
		if rec.reset.Before(now) {
			delete(l.attempts, k)
		}
	}
}

// RedisLockout provides distributed lockout using Redis counters and TTLs.
type RedisLockout struct {
	client    *redis.Client
	max       int
	window    time.Duration
	blockTime time.Duration
	local     *InMemoryLockout
}

func NewRedisLockout(addr string, max int, window, block time.Duration) *RedisLockout {
	return &RedisLockout{
		client:    redis.NewClient(redisOptions(addr)),
		max:       max,
		window:    window,
		blockTime: block,
		local:     NewInMemoryLockout(max, window, block),
	}
}

func (r *RedisLockout) IsLocked(ctx context.Context, userKey, ip string) (bool, time.Duration) {
	key := r.key(userKey, ip, "lock")
	ttl, err := r.client.TTL(ctx, key).Result()
	if err != nil {
		if r.local != nil {
			return r.local.IsLocked(ctx, userKey, ip)
		}
		return false, 0
	}
	if ttl > 0 {
		return true, ttl
	}
	return false, 0
}

func (r *RedisLockout) RegisterFailure(ctx context.Context, userKey, ip string) {
	countKey := r.key(userKey, ip, "count")
	lockKey := r.key(userKey, ip, "lock")
	script := redis.NewScript(`
local cnt = redis.call('INCR', KEYS[1])
if tonumber(cnt) == 1 then
  redis.call('PEXPIRE', KEYS[1], ARGV[1])
end
if tonumber(cnt) >= tonumber(ARGV[2]) then
  redis.call('SET', KEYS[2], 1, 'PX', ARGV[3])
end
return cnt
`)
	if err := script.Run(ctx, r.client, []string{countKey, lockKey}, int(r.window.Milliseconds()), r.max, int(r.blockTime.Milliseconds())).Err(); err != nil {
		if r.local != nil {
			r.local.RegisterFailure(ctx, userKey, ip)
		}
	}
}

func (r *RedisLockout) Clear(ctx context.Context, userKey, ip string) {
	if r.local != nil {
		r.local.Clear(ctx, userKey, ip)
	}
	_ = r.client.Del(ctx, r.key(userKey, ip, "count"), r.key(userKey, ip, "lock")).Err()
}

func (r *RedisLockout) key(userKey, ip, suffix string) string {
	return "lockout:" + userKey + ":" + ip + ":" + suffix
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
