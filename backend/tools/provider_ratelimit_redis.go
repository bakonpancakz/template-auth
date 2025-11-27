package tools

import (
	"context"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

type ratelimitProviderRedis struct {
	Client *redis.Client
}

func (p *ratelimitProviderRedis) Start(stop context.Context, await *sync.WaitGroup) error {

	// Parse URL and TLS Configuration
	opt, err := redis.ParseURL(RATELIMIT_REDIS_URI)
	if err != nil {
		return err
	}
	if RATELIMIT_REDIS_TLS_ENABLED {
		tls, err := NewTLSConfig(
			RATELIMIT_REDIS_TLS_CERT,
			RATELIMIT_REDIS_TLS_KEY,
			RATELIMIT_REDIS_TLS_CA,
		)
		if err != nil {
			return err
		}
		opt.TLSConfig = tls
	}

	// Create and Test Client
	ctx, cancel := NewContext()
	defer cancel()
	rdb := redis.NewClient(opt)
	if err := rdb.Ping(ctx).Err(); err != nil {
		return err
	}

	// Shutdown Logic
	await.Add(1)
	go func() {
		defer await.Done()
		<-stop.Done()
		rdb.Close()
		LoggerRatelimit.Info("Closed", nil)
	}()

	p.Client = rdb
	return nil
}

func (p *ratelimitProviderRedis) Increment(ctx context.Context, key string, period time.Duration) (int64, error) {

	// Attempt to Set New Key
	ok, err := p.Client.SetNX(ctx, key, 1, period).Result()
	if err != nil {
		return 0, err
	}
	if ok {
		// Using New Key
		return 1, nil
	}

	// Increment Existing Key
	return p.Client.Incr(ctx, key).Result()
}

func (p *ratelimitProviderRedis) Decrement(ctx context.Context, key string) (int64, error) {
	return p.Client.Decr(ctx, key).Result()
}

func (p *ratelimitProviderRedis) TTL(ctx context.Context, key string) (time.Duration, error) {
	return p.Client.PTTL(ctx, key).Result()
}
