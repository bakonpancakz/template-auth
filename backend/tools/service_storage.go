package tools

import (
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"time"
)

type StorageProvider interface {
	Start(stop context.Context, await *sync.WaitGroup) error
	Put(key, contentType string, data []byte) error
	Get(key string) (io.Reader, error)
	Delete(keys ...string) error
}

var Storage StorageProvider

var (
	ErrStorageFileNotFound    = errors.New("file not found")
	ErrStorageInvalidFilename = errors.New("filename contains invalid characters")
)

func SetupStorageProvider(stop context.Context, await *sync.WaitGroup) {
	t := time.Now()

	switch STORAGE_PROVIDER {
	case "s3":
		Storage = &storageProviderS3{}
	case "disk":
		Storage = &storageProviderDisk{}
	case "none":
		Storage = &storageProviderNone{}
	case "test":
		if !testing.Testing() {
			LoggerStorage.Fatal("Attempt to use testing provider outside of testing", nil)
		}
		STORAGE_DISK_DIRECTORY = "images"
		Storage = &storageProviderDisk{}
	default:
		LoggerStorage.Fatal("Unknown Provider", STORAGE_PROVIDER)
	}

	if err := Storage.Start(stop, await); err != nil {
		LoggerStorage.Fatal("Startup Failed", err.Error())
	}
	LoggerStorage.Info("Ready", map[string]any{
		"time": time.Since(t).String(),
	})
}
