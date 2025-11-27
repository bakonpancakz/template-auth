package tools

import (
	"context"
	"io"
	"sync"
)

type storageProviderNone struct{}

func (e *storageProviderNone) Start(stop context.Context, await *sync.WaitGroup) error {
	return nil
}

func (o *storageProviderNone) Put(ctx context.Context, key, contentType string, data []byte) error {
	return nil
}

func (o *storageProviderNone) Get(ctx context.Context, key string) (io.ReadCloser, error) {
	return nil, ErrStorageFileNotFound
}

func (o *storageProviderNone) Delete(ctx context.Context, keys ...string) error {
	return nil
}
