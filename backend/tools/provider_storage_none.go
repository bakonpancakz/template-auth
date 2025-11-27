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

func (o *storageProviderNone) Put(key, contentType string, data []byte) error {
	return nil
}

func (o *storageProviderNone) Get(key string) (io.Reader, error) {
	return nil, ErrStorageFileNotFound
}

func (o *storageProviderNone) Delete(keys ...string) error {
	return nil
}
