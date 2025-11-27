package tools

import (
	"context"
	"sync"
	"time"
)

var opThreshold = 1000

type ratelimitProviderLocal struct {
	mtx    sync.Mutex
	usage  map[string]int64
	expire map[string]int64
	ops    int
}

func (p *ratelimitProviderLocal) Start(stop context.Context, await *sync.WaitGroup) error {
	p.usage = make(map[string]int64, 512)
	p.expire = make(map[string]int64, 512)
	return nil
}

func (p *ratelimitProviderLocal) Increment(ctx context.Context, key string, period time.Duration) (int64, error) {
	p.mtx.Lock()
	defer p.mtx.Unlock()

	if p.ops > opThreshold {
		p.cleanup()
	}
	p.ops++

	now := time.Now().Unix()
	expires, ok := p.expire[key]
	if !ok || now > expires {
		p.usage[key] = 0
		p.expire[key] = now + int64(period.Seconds())
	}
	p.usage[key]++

	return p.usage[key], nil
}

func (p *ratelimitProviderLocal) Decrement(ctx context.Context, key string) (int64, error) {
	p.mtx.Lock()
	defer p.mtx.Unlock()

	if p.ops > opThreshold {
		p.cleanup()
	}
	p.ops++

	now := time.Now().Unix()
	expires, ok := p.expire[key]
	if !ok || now > expires {
		p.usage[key] = 0
		p.expire[key] = now + 60
	}
	p.usage[key]--

	return p.usage[key], nil
}

func (p *ratelimitProviderLocal) TTL(ctx context.Context, key string) (time.Duration, error) {
	p.mtx.Lock()
	defer p.mtx.Unlock()

	now := time.Now().Unix()
	expires, ok := p.expire[key]
	if !ok || expires > now {
		return 0, nil
	}
	ttl := time.Duration(expires-now) * time.Second

	return ttl, nil
}

func (p *ratelimitProviderLocal) cleanup() {
	now := time.Now().Unix()
	for k, expires := range p.expire {
		if now > expires {
			delete(p.expire, k)
			delete(p.usage, k)
		}
	}
	p.ops = 0
}
