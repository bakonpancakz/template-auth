package tools

import (
	"context"
	"sync"
	"time"
)

type rateLimitProviderNone struct {
}

func (p *rateLimitProviderNone) Start(stop context.Context, await *sync.WaitGroup) error {
	return nil
}

func (p *rateLimitProviderNone) Increment(ctx context.Context, key string, period time.Duration) (int64, error) {
	return 0, nil
}

func (p *rateLimitProviderNone) Decrement(ctx context.Context, key string) (int64, error) {
	return 0, nil
}

func (p *rateLimitProviderNone) TTL(ctx context.Context, key string) (time.Duration, error) {
	return 0, nil
}
