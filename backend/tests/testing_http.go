package tests

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"
)

func NewTestRequest(t *testing.T, method, format string, arg ...any) *testRequest {
	pth := fmt.Sprintf(format, arg...)
	url := fmt.Sprintf("%s%s", HTTP_SERVER.URL, pth)
	return &testRequest{
		test:           t,
		requestBody:    http.NoBody,
		requestHeaders: make(map[string]string, 4),
		requestURL:     url,
		requestMethod:  method,
	}
}

type testRequest struct {
	test           *testing.T
	requestBody    io.Reader
	requestHeaders map[string]string
	requestURL     string
	requestMethod  string
	response       *http.Response
	responseRead   bool
	responseBody   []byte
	responseJSON   map[string]any
}

// Include a HTTP Header with your Request
func (t *testRequest) WithHeader(key, value string) *testRequest {
	t.requestHeaders[key] = value
	return t
}

// Add Cookie to Request
func (t *testRequest) WithCookie(name, value string) *testRequest {
	cookies := ""
	if c, ok := t.requestHeaders["Cookie"]; ok {
		cookies = c
	}
	t.requestHeaders["Cookie"] = fmt.Sprintf("%s%s=%s; ", cookies, name, value)
	return t
}

// Include a JSON Object with your Request
func (t *testRequest) WithJSON(body map[string]any) *testRequest {
	t.requestHeaders["Content-Type"] = "application/json"
	b, err := json.Marshal(body)
	if err != nil {
		t.test.Fatalf("json marshal error: %s", err)
	}
	t.requestBody = bytes.NewReader(b)
	return t
}

// Include Basic Authentication with your Request
func (t *testRequest) WithBasicAuth(username, password string) *testRequest {
	credentials := fmt.Sprintf("%s:%s", username, password)
	encoded := base64.URLEncoding.EncodeToString([]byte(credentials))
	t.requestHeaders["Authorization"] = fmt.Sprintf("Basic %s", encoded)
	return t
}

// Include Query Parameters with your Request
func (t *testRequest) WithQuery(body map[string]any) *testRequest {
	// Generate Query String
	items := make([]string, 0, len(body))
	for k, v := range body {
		items = append(items, fmt.Sprintf("%s=%s", url.QueryEscape(k), url.QueryEscape(fmt.Sprint(v))))
	}
	query := strings.Join(items, "&")

	// Append to Request
	if t.requestMethod == http.MethodGet {
		t.requestURL = fmt.Sprint(t.requestURL, "?", query)
	} else {
		t.requestHeaders["Content-Type"] = "application/x-www-form-urlencoded"
		t.requestBody = strings.NewReader(query)
	}
	return t
}

// Send the HTTP Request
func (t *testRequest) Send() *testRequest {
	req, err := http.NewRequest(t.requestMethod, t.requestURL, t.requestBody)
	if err != nil {
		t.test.Fatalf("request error: %s", err)
	}
	for k, v := range t.requestHeaders {
		req.Header.Set(k, v)
	}
	res, err := HTTP_CLIENT.Do(req)
	if err != nil {
		t.test.Fatalf("response error: %s", err)
	}
	t.response = res
	return t
}

// Expect a specific HTTP Status Code
func (t *testRequest) ExpectStatus(status int) *testRequest {
	r := t.response.StatusCode
	if r != status {
		t.ExpectBody()
		t.test.Fatalf("expected status code %d got %d\nBody: %s", status, r, t.responseBody)
	}
	return t
}

// Decode and cache the response body (handles gzip)
func (t *testRequest) ExpectBody() *testRequest {
	if t.responseRead {
		return t
	}
	t.responseRead = true

	var data []byte
	var err error

	if strings.EqualFold(t.response.Header.Get("Content-Encoding"), "gzip") {
		gz, gerr := gzip.NewReader(t.response.Body)
		if gerr != nil {
			t.test.Fatalf("invalid gzip response body: %v", gerr)
		}
		defer gz.Close()
		data, err = io.ReadAll(gz)
	} else {
		data, err = io.ReadAll(t.response.Body)
	}
	t.response.Body.Close()

	if err != nil {
		t.test.Fatalf("failed to read response body: %v", err)
	}
	t.responseBody = data
	return t
}

// Expect and Parse the Response Body to be a JSON Object
func (t *testRequest) ExpectJSON() *testRequest {
	header := strings.ToLower(t.response.Header.Get("Content-Type"))
	if !strings.Contains(header, "application/json") {
		t.test.Fatalf("expected content type of 'application/json'")
	}
	t.ExpectBody()
	t.responseJSON = make(map[string]any)
	if err := json.Unmarshal(t.responseBody, &t.responseJSON); err != nil {
		t.test.Fatalf("json unmarshal error: %s", err)
	}
	return t
}

// Expect a Cookie to be present
func (t *testRequest) ExpectCookie(name string) *testRequest {
	found := false
	for _, header := range t.response.Header.Values("Set-Cookie") {
		cookie, err := http.ParseSetCookie(header)
		if err != nil {
			continue
		}
		if strings.EqualFold(name, cookie.Name) {
			found = true
			break
		}
	}
	if !found {
		t.test.Fatalf("expected cookie '%s' to be present\nHeaders: %s", name, t.response.Header)
	}
	return t
}

// Expect a JSON field to be present
func (t *testRequest) ExpectField(key string) *testRequest {
	t.ExpectJSON()
	v, ok := t.responseJSON[key]
	if !ok {
		t.test.Fatalf("expected field '%s' to be present", key)
	}
	if reflect.ValueOf(v).IsZero() {
		t.test.Fatalf("expected field '%s' to be non-zero", key)
	}
	return t
}

// Expect a JSON field to contain the following string value
func (t *testRequest) ExpectString(key, expected string) *testRequest {
	t.ExpectJSON()
	v, ok := t.responseJSON[key]
	if !ok {
		t.test.Fatalf("expected string field '%s' not found", key)
	}
	s, ok := v.(string)
	if !ok {
		t.test.Fatalf("field '%s' expected string, got %T\nBody: %s", key, v, t.responseBody)
	}
	if s != expected {
		t.test.Fatalf("field '%s' expected '%s', got '%s'\nBody: %s", key, expected, s, t.responseBody)
	}
	return t
}

// Expect a JSON field to contain the following integer value
func (t *testRequest) ExpectInteger(key string, expected int64) *testRequest {
	t.ExpectJSON()
	v, ok := t.responseJSON[key]
	if !ok {
		t.test.Fatalf("expected integer field '%s' not found", key)
	}
	switch n := v.(type) {
	case float64:
		if int64(n) != expected {
			t.test.Fatalf("field '%s' expected %d, got %d\nBody: %s", key, expected, int64(n), t.responseBody)
		}
	default:
		t.test.Fatalf("field '%s' expected number, got %T\nBody: %s", key, v, t.responseBody)
	}
	return t
}
