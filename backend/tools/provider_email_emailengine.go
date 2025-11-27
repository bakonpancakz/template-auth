package tools

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
)

// EmailEngine is my own email library btw :3
// https://github.com/bakonpancakz/emailengine

type emailProviderEmailEngine struct {
	EndpointUrl string
	EndpointKey string
	FromAddress string
	FromName    string
}

func (e *emailProviderEmailEngine) Start(stop context.Context, await *sync.WaitGroup) error {
	e.EndpointUrl = EMAIL_ENGINE_URL
	e.EndpointKey = EMAIL_ENGINE_KEY
	e.FromAddress = EMAIL_SENDER_ADDRESS
	e.FromName = EMAIL_SENDER_NAME

	// Make Request to Server
	res, err := http.DefaultClient.Post("/verify", "application/json", http.NoBody)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	// Backend checks Auth before Body is Parsed
	// We can use this behavior to test our access key
	switch res.StatusCode {

	case http.StatusBadRequest:
		return nil

	case http.StatusForbidden:
		return fmt.Errorf("incorrect key")

	default:
		return fmt.Errorf("server responded with status %d", res.StatusCode)
	}
}

func (o *emailProviderEmailEngine) Send(ctx context.Context, toAddress, subject, html string) error {

	// Generate Envelope
	var payload []byte
	if d, err := json.Marshal(map[string]any{
		"to_name":      toAddress,
		"to_address":   toAddress,
		"from_address": o.FromAddress,
		"from_name":    o.FromName,
		"subject":      subject,
		"content":      html,
		"html":         true,
	}); err != nil {
		return err
	} else {
		payload = d
	}

	// Setup Compression
	var compressed bytes.Buffer
	gz := gzip.NewWriter(&compressed)
	if _, err := gz.Write(payload); err != nil {
		return err
	}
	gz.Close()

	// Send Request
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, o.EndpointUrl, &compressed)
	if err != nil {
		return err
	}
	req.Header.Add("Content-Encoding", "gzip")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Add("Authorization", o.EndpointKey)

	// Depending on the Server Version it might return
	// a '204 No Content' or a '200 OK' response code
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode > 299 {
		body, _ := io.ReadAll(res.Body)
		return fmt.Errorf("server responded with status %d: %s", res.StatusCode, string(body))
	}

	return nil
}
