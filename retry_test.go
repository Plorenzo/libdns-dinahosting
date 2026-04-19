// Package dinahosting tests for the retry logic in doRequest. These tests do
// NOT require live credentials: they spin up an httptest server that lets
// each test case shape the sequence of responses returned to the provider.
package dinahosting

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"
)

// newTestProvider returns a Provider wired up with a short initial backoff
// via a custom HTTPClient so tests do not wait seconds between retries.
func newTestProvider() *Provider {
	return &Provider{
		Username: "u",
		Password: "p",
		HTTPClient: &http.Client{
			Timeout: 5 * time.Second,
		},
	}
}

// serverURL returns the URL for an httptest server as a *url.URL so it can
// be fed directly to doRequest.
func serverURL(t *testing.T, s *httptest.Server) *url.URL {
	t.Helper()
	u, err := url.Parse(s.URL)
	if err != nil {
		t.Fatalf("url.Parse(%q): %v", s.URL, err)
	}
	return u
}

// TestDoRequest_RetriesOn5xx verifies that doRequest retries when the API
// responds with a 5xx status and eventually succeeds.
func TestDoRequest_RetriesOn5xx(t *testing.T) {
	var attempts int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&attempts, 1)
		if n < 3 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintln(w, `{"responseCode":1000,"message":"Success.","data":[]}`)
	}))
	defer srv.Close()

	p := newTestProvider()
	got, err := p.doRequest(context.Background(), serverURL(t, srv))
	if err != nil {
		t.Fatalf("doRequest() unexpected error: %v", err)
	}
	if !got.ok() {
		t.Errorf("doRequest() response not OK: %+v", got)
	}
	if n := atomic.LoadInt32(&attempts); n != 3 {
		t.Errorf("expected 3 attempts, got %d", n)
	}
}

// TestDoRequest_RetriesOnTransportError verifies that doRequest retries when
// the transport layer fails (e.g. connection refused) and gives up after
// exhausting all retries.
func TestDoRequest_RetriesOnTransportError(t *testing.T) {
	// Start a server and close it immediately so any connection attempt
	// fails with "connection refused".
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	u := serverURL(t, srv)
	srv.Close()

	p := newTestProvider()
	start := time.Now()
	_, err := p.doRequest(context.Background(), u)
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("doRequest() expected error when server is unreachable")
	}
	// With maxRetries=3 and initial backoff 1s we expect at least 1+2+4=7s
	// of backoff before giving up.
	if elapsed < 6*time.Second {
		t.Errorf("doRequest() returned in %v; expected retries to make it take longer", elapsed)
	}
}

// TestDoRequest_NoRetryOnBusinessError ensures we do NOT retry when the API
// responded with HTTP 200 but a non-success `responseCode` in the body:
// those errors are deterministic and retrying would only amplify load.
func TestDoRequest_NoRetryOnBusinessError(t *testing.T) {
	var attempts int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&attempts, 1)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintln(w, `{"responseCode":2302,"errors":[{"code":2302,"message":"already exists"}]}`)
	}))
	defer srv.Close()

	p := newTestProvider()
	got, err := p.doRequest(context.Background(), serverURL(t, srv))
	if err != nil {
		t.Fatalf("doRequest() unexpected error: %v", err)
	}
	if got.ok() {
		t.Errorf("doRequest() expected non-OK response; got: %+v", got)
	}
	if n := atomic.LoadInt32(&attempts); n != 1 {
		t.Errorf("expected exactly 1 attempt for business-logic error, got %d", n)
	}
}

// TestDoRequest_ContextCancelled verifies that doRequest returns promptly
// when the caller's context is cancelled during the backoff between
// attempts instead of waiting out the full backoff schedule.
func TestDoRequest_ContextCancelled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	p := newTestProvider()
	start := time.Now()
	_, err := p.doRequest(ctx, serverURL(t, srv))
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("doRequest() expected error when context is cancelled")
	}
	if elapsed > 2*time.Second {
		t.Errorf("doRequest() took %v after context cancellation; expected it to return quickly", elapsed)
	}
}
