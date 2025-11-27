package tools

import (
	"context"
	"sync"
	"testing"
	"time"
)

type RatelimitProvider interface {
	// Interface should mimic the following redis behavior:
	// 	- TTL Non-existing key will equal zero duration
	// 	- Decrement Non-existing key will equal -1
	// 	- Increment Non-existing key will equal 1
	// 	- Increment Existing Key will +1

	Start(stop context.Context, await *sync.WaitGroup) error
	Increment(ctx context.Context, key string, period time.Duration) (int64, error)
	Decrement(ctx context.Context, key string) (int64, error)
	TTL(ctx context.Context, key string) (time.Duration, error)
}

var Ratelimit RatelimitProvider

func SetupRatelimitProvider(stop context.Context, await *sync.WaitGroup) {
	t := time.Now()

	switch RATELIMIT_PROVIDER {
	case "redis":
		Ratelimit = &ratelimitProviderRedis{}
	case "local":
		Ratelimit = &ratelimitProviderLocal{}
	case "none":
		Ratelimit = &rateLimitProviderNone{}
	case "test":
		if !testing.Testing() {
			LoggerStorage.Fatal("Attempt to use testing provider outside of testing", nil)
		}
		Ratelimit = &rateLimitProviderNone{}
	default:
		LoggerRatelimit.Fatal("Unknown Provider", RATELIMIT_PROVIDER)
	}

	if err := Ratelimit.Start(stop, await); err != nil {
		LoggerRatelimit.Fatal("Startup Failed", err.Error())
	}
	LoggerRatelimit.Info("Ready", map[string]any{
		"time": time.Since(t).String(),
	})
}
