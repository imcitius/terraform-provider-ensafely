package client

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// recorder collects the waits the client asked for instead of sleeping.
type recorder struct{ waits []time.Duration }

func (r *recorder) sleep(ctx context.Context, d time.Duration) error {
	r.waits = append(r.waits, d)
	return ctx.Err()
}

func newTestClient(t *testing.T, endpoint string, rec *recorder) *Client {
	t.Helper()
	c, err := New(Config{
		Endpoint:   endpoint,
		APIKey:     "ck_test",
		MaxRetries: 3,
		MinBackoff: time.Second,
		MaxBackoff: 4 * time.Second,
		MaxWait:    90 * time.Second,
		sleep:      rec.sleep,
		jitter:     func(d time.Duration) time.Duration { return d },
	})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// sequence answers each request with the next handler; the last repeats.
func sequence(t *testing.T, calls *int32, handlers ...http.HandlerFunc) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := int(atomic.AddInt32(calls, 1)) - 1
		if n >= len(handlers) {
			n = len(handlers) - 1
		}
		handlers[n](w, r)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func status(code int, body string, headers ...string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		for i := 0; i+1 < len(headers); i += 2 {
			w.Header().Set(headers[i], headers[i+1])
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_, _ = io.WriteString(w, body)
	}
}

func TestDoSendsBearerAndJSON(t *testing.T) {
	var got struct {
		auth, ctype, accept, ua, method, path string
		body                                  map[string]any
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.auth = r.Header.Get("Authorization")
		got.ctype = r.Header.Get("Content-Type")
		got.accept = r.Header.Get("Accept")
		got.ua = r.Header.Get("User-Agent")
		got.method = r.Method
		got.path = r.URL.EscapedPath()
		_ = json.NewDecoder(r.Body).Decode(&got.body)
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, `{"name":"web","enabled":true}`)
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL+"/", &recorder{})
	var out struct {
		Name    string `json:"name"`
		Enabled bool   `json:"enabled"`
	}
	path := "/api/alert-channels/" + PathEscape("ops/eu team")
	if err := c.Post(context.Background(), path, map[string]any{"name": "web"}, &out); err != nil {
		t.Fatal(err)
	}
	if got.auth != "Bearer ck_test" {
		t.Errorf("Authorization = %q", got.auth)
	}
	if got.ctype != "application/json" || got.accept != "application/json" {
		t.Errorf("Content-Type %q, Accept %q", got.ctype, got.accept)
	}
	if got.ua != "terraform-provider-ensafely" {
		t.Errorf("User-Agent = %q", got.ua)
	}
	if got.method != http.MethodPost || got.path != "/api/alert-channels/ops%2Feu%20team" {
		t.Errorf("request = %s %s", got.method, got.path)
	}
	if got.body["name"] != "web" {
		t.Errorf("body = %v", got.body)
	}
	if out.Name != "web" || !out.Enabled {
		t.Errorf("decoded = %+v", out)
	}
}

func TestEndpointWithBasePath(t *testing.T) {
	var path string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.Path
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	c := newTestClient(t, srv.URL+"/prefix/", &recorder{})
	if err := c.Delete(context.Background(), "/api/x", nil); err != nil {
		t.Fatal(err)
	}
	if path != "/prefix/api/x" {
		t.Errorf("path = %q", path)
	}
}

func TestRetry429HonoursRetryAfterSeconds(t *testing.T) {
	var calls int32
	srv := sequence(t, &calls,
		status(429, `{"error":"rate limit exceeded","retry_after":7}`, "Retry-After", "7"),
		status(201, `{"ok":true}`),
	)
	rec := &recorder{}
	c := newTestClient(t, srv.URL, rec)
	// POST is not idempotent, but a 429 is rejected before any handler runs.
	if err := c.Post(context.Background(), "/api/check-definitions", map[string]string{}, nil); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("calls = %d, want 2", calls)
	}
	if len(rec.waits) != 1 || rec.waits[0] != 7*time.Second {
		t.Errorf("waits = %v, want [7s]", rec.waits)
	}
}

func TestRetry429HonoursRetryAfterHTTPDate(t *testing.T) {
	var calls int32
	date := time.Now().Add(20 * time.Second).UTC().Format(http.TimeFormat)
	srv := sequence(t, &calls,
		status(429, `{"error":"rate limit exceeded"}`, "Retry-After", date),
		status(200, `{}`),
	)
	rec := &recorder{}
	c := newTestClient(t, srv.URL, rec)
	if err := c.Get(context.Background(), "/api/x", nil); err != nil {
		t.Fatal(err)
	}
	if len(rec.waits) != 1 || rec.waits[0] < 15*time.Second || rec.waits[0] > 20*time.Second {
		t.Errorf("waits = %v, want ~20s", rec.waits)
	}
}

func TestRetry429ExponentialBackoffWithoutHeader(t *testing.T) {
	var calls int32
	srv := sequence(t, &calls, status(429, `{"error":"rate limit exceeded"}`))
	rec := &recorder{}
	c := newTestClient(t, srv.URL, rec)
	err := c.Get(context.Background(), "/api/x", nil)
	if !IsRateLimited(err) {
		t.Fatalf("err = %v, want rate limited", err)
	}
	if calls != 4 {
		t.Errorf("calls = %d, want 1 + 3 retries", calls)
	}
	want := []time.Duration{time.Second, 2 * time.Second, 4 * time.Second}
	if len(rec.waits) != len(want) {
		t.Fatalf("waits = %v, want %v", rec.waits, want)
	}
	for i := range want {
		if rec.waits[i] != want[i] {
			t.Errorf("waits = %v, want %v", rec.waits, want)
		}
	}
	if !strings.Contains(err.Error(), "rate limited") {
		t.Errorf("message = %q", err)
	}
}

func TestRetry429GivesUpWhenRetryAfterExceedsMaxWait(t *testing.T) {
	var calls int32
	srv := sequence(t, &calls, status(429, `{"error":"rate limit exceeded"}`, "Retry-After", "3600"))
	rec := &recorder{}
	c := newTestClient(t, srv.URL, rec)
	err := c.Get(context.Background(), "/api/x", nil)
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.RetryAfter != time.Hour {
		t.Fatalf("err = %v", err)
	}
	if calls != 1 || len(rec.waits) != 0 {
		t.Errorf("calls %d waits %v, want one call and no wait", calls, rec.waits)
	}
	if !strings.Contains(err.Error(), "retry after 1h0m0s") {
		t.Errorf("message = %q", err)
	}
}

func TestRetryStopsWhenContextEnds(t *testing.T) {
	var calls int32
	srv := sequence(t, &calls, status(429, `{}`, "Retry-After", "5"))
	ctx, cancel := context.WithCancel(context.Background())
	c, err := New(Config{Endpoint: srv.URL, APIKey: "ck_x", sleep: func(context.Context, time.Duration) error {
		cancel()
		return context.Canceled
	}})
	if err != nil {
		t.Fatal(err)
	}
	err = c.Get(ctx, "/api/x", nil)
	if !errors.Is(err, context.Canceled) && !strings.Contains(err.Error(), "context canceled") {
		t.Fatalf("err = %v", err)
	}
	if !IsRateLimited(err) {
		t.Errorf("the 429 should stay inspectable: %v", err)
	}
	if calls != 1 {
		t.Errorf("calls = %d", calls)
	}
}

func TestRetryTransient5xxForIdempotentMethods(t *testing.T) {
	for _, code := range []int{502, 503, 504} {
		var calls int32
		srv := sequence(t, &calls, status(code, `<html>bad gateway</html>`), status(200, `{"ok":true}`))
		rec := &recorder{}
		c := newTestClient(t, srv.URL, rec)
		if err := c.Put(context.Background(), "/api/x", map[string]int{"a": 1}, nil); err != nil {
			t.Fatalf("%d: %v", code, err)
		}
		if calls != 2 || len(rec.waits) != 1 || rec.waits[0] != time.Second {
			t.Errorf("%d: calls %d waits %v", code, calls, rec.waits)
		}
	}
}

func TestRetry5xxIsCapped(t *testing.T) {
	var calls int32
	srv := sequence(t, &calls, status(503, `{"error":"unavailable"}`))
	c := newTestClient(t, srv.URL, &recorder{})
	err := c.Get(context.Background(), "/api/x", nil)
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != 503 || apiErr.Message != "unavailable" {
		t.Fatalf("err = %v", err)
	}
	if calls != 4 {
		t.Errorf("calls = %d, want 4", calls)
	}
}

func TestNoRetryOf5xxForPostUnlessIdempotent(t *testing.T) {
	var calls int32
	srv := sequence(t, &calls, status(503, `{"error":"unavailable"}`), status(503, `{"error":"unavailable"}`), status(201, `{}`))
	c := newTestClient(t, srv.URL, &recorder{})
	if err := c.Post(context.Background(), "/api/x", map[string]int{}, nil); err == nil {
		t.Fatal("POST 503 must not be retried")
	}
	if calls != 1 {
		t.Fatalf("calls = %d", calls)
	}
	if err := c.Post(context.Background(), "/api/x", map[string]int{}, nil, Idempotent()); err != nil {
		t.Fatalf("idempotent POST should retry: %v", err)
	}
	if calls != 3 {
		t.Errorf("calls = %d", calls)
	}
}

func TestNoRetryOf500(t *testing.T) {
	var calls int32
	srv := sequence(t, &calls, status(500, `{"error":"internal server error"}`, "X-Request-ID", "req-1"))
	c := newTestClient(t, srv.URL, &recorder{})
	err := c.Get(context.Background(), "/api/x", nil)
	if err == nil || calls != 1 {
		t.Fatalf("err %v calls %d", err, calls)
	}
	if !strings.Contains(err.Error(), "HTTP 500: internal server error [request id req-1]") {
		t.Errorf("message = %q", err)
	}
}

func TestDialErrorRetriedEvenForPost(t *testing.T) {
	// Reserve a port, then close it so connections are refused.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	rec := &recorder{}
	c := newTestClient(t, "http://"+addr, rec)
	err = c.Post(context.Background(), "/api/x", map[string]int{}, nil)
	if err == nil {
		t.Fatal("expected connection error")
	}
	if len(rec.waits) != 3 {
		t.Errorf("waits = %v, want 3 retries of a refused dial", rec.waits)
	}
}

func TestTransportErrorAfterSendNotRetriedForPost(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		hj, ok := w.(http.Hijacker)
		if !ok {
			t.Fatal("no hijacker")
		}
		conn, _, _ := hj.Hijack()
		_ = conn.Close()
	}))
	defer srv.Close()
	rec := &recorder{}
	c := newTestClient(t, srv.URL, rec)
	if err := c.Post(context.Background(), "/api/x", map[string]int{}, nil); err == nil {
		t.Fatal("expected error")
	}
	if n := atomic.LoadInt32(&calls); n != 1 || len(rec.waits) != 0 {
		t.Errorf("POST: calls %d waits %v, want no retry", n, rec.waits)
	}
	if err := c.Get(context.Background(), "/api/x", nil); err == nil {
		t.Fatal("expected error")
	}
	if n := atomic.LoadInt32(&calls); n != 5 {
		t.Errorf("GET: calls = %d, want 1 + 3 retries", n-1)
	}
}

func TestNotFound(t *testing.T) {
	var calls int32
	srv := sequence(t, &calls, status(404, `{"error":"check not found"}`))
	c := newTestClient(t, srv.URL, &recorder{})
	err := c.Get(context.Background(), "/api/check-definitions/abc", &struct{}{})
	if !IsNotFound(err) {
		t.Fatalf("err = %v, want not found", err)
	}
	if IsQuotaExceeded(err) || IsConflict(err) || calls != 1 {
		t.Errorf("unexpected classification or retries: %v (calls %d)", err, calls)
	}
	if IsNotFound(errors.New("404")) || IsNotFound(nil) {
		t.Error("only API 404s are not-found")
	}
}

func TestQuotaErrorWithResource(t *testing.T) {
	var calls int32
	srv := sequence(t, &calls, status(403, `{"error":"QUOTA_EXCEEDED","resource":"checks","current":10,"limit":10,"hint":"Purchase an additional package to increase your limit"}`))
	c := newTestClient(t, srv.URL, &recorder{})
	err := c.Post(context.Background(), "/api/check-definitions", map[string]any{}, nil)
	if !IsQuotaExceeded(err) {
		t.Fatalf("err = %v", err)
	}
	var apiErr *APIError
	errors.As(err, &apiErr)
	want := QuotaDetail{Resource: "checks", Current: 10, Limit: 10, Hint: "Purchase an additional package to increase your limit"}
	if *apiErr.Quota != want {
		t.Errorf("quota = %+v", *apiErr.Quota)
	}
	if apiErr.Summary() != "Ensafely plan limit reached" {
		t.Errorf("summary = %q", apiErr.Summary())
	}
	msg := err.Error()
	if !strings.Contains(msg, "plan quota exceeded for checks (10 in use, plan limit 10). Purchase an additional package") {
		t.Errorf("message = %q", msg)
	}
	if calls != 1 {
		t.Errorf("quota errors must not be retried; calls = %d", calls)
	}
}

func TestQuotaErrorWithDetail(t *testing.T) {
	var calls int32
	srv := sequence(t, &calls, status(403, `{"error":"QUOTA_EXCEEDED","detail":{"current":4,"limit":2}}`))
	c := newTestClient(t, srv.URL, &recorder{})
	err := c.Put(context.Background(), "/api/platform-regions", map[string]any{}, nil)
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Quota == nil {
		t.Fatalf("err = %v", err)
	}
	if apiErr.Quota.Current != 4 || apiErr.Quota.Limit != 2 || apiErr.Quota.Resource != "" {
		t.Errorf("quota = %+v", *apiErr.Quota)
	}
	if !strings.Contains(err.Error(), "plan quota exceeded (4 in use, plan limit 2)") {
		t.Errorf("message = %q", err)
	}
}

func TestPlanIneligibilityAndScopeErrors(t *testing.T) {
	var calls int32
	srv := sequence(t, &calls, status(403, `{"error":"Platform regions not available on your plan"}`))
	c := newTestClient(t, srv.URL, &recorder{})
	err := c.Put(context.Background(), "/api/platform-regions", map[string]any{}, nil)
	if IsQuotaExceeded(err) {
		t.Fatal("plain 403 is not a quota error")
	}
	if !strings.Contains(err.Error(), "forbidden: Platform regions not available on your plan") ||
		!strings.Contains(err.Error(), "api_write") {
		t.Errorf("message = %q", err)
	}
}

func TestEmailNotVerifiedAndUnauthorized(t *testing.T) {
	var calls int32
	srv := sequence(t, &calls,
		status(403, `{"error":"Please verify your email address before creating or modifying resources.","code":"EMAIL_NOT_VERIFIED"}`),
		status(401, `{"error":"invalid API key"}`),
	)
	c := newTestClient(t, srv.URL, &recorder{})
	err := c.Post(context.Background(), "/api/x", map[string]any{}, nil)
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Code != "EMAIL_NOT_VERIFIED" || !strings.Contains(err.Error(), "not verified") {
		t.Fatalf("err = %v", err)
	}
	err = c.Get(context.Background(), "/api/x", nil)
	if !strings.Contains(err.Error(), "authentication failed (invalid API key)") {
		t.Errorf("err = %v", err)
	}
}

func TestNewValidation(t *testing.T) {
	if _, err := New(Config{APIKey: ""}); err == nil {
		t.Error("missing key accepted")
	}
	for _, bad := range []string{"ftp://x", "app.ensafely.com", "https://", "https://x?y=1", "https://u:p@x"} {
		if _, err := New(Config{Endpoint: bad, APIKey: "ck_x"}); err == nil {
			t.Errorf("endpoint %q accepted", bad)
		}
	}
	c, err := New(Config{APIKey: "ck_x"})
	if err != nil {
		t.Fatal(err)
	}
	if c.Endpoint() != DefaultEndpoint {
		t.Errorf("default endpoint = %q", c.Endpoint())
	}
	if c.maxRetries != DefaultMaxRetries {
		t.Errorf("default retries = %d", c.maxRetries)
	}
	c, _ = New(Config{APIKey: "ck_x", MaxRetries: -1})
	if c.maxRetries != 0 {
		t.Errorf("negative retries = %d", c.maxRetries)
	}
}

func TestParseRetryAfter(t *testing.T) {
	now := time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		in   string
		want time.Duration
		ok   bool
	}{
		{"", 0, false},
		{"0", 0, true},
		{"61", 61 * time.Second, true},
		{"-1", 0, false},
		{"soon", 0, false},
		{now.Add(30 * time.Second).Format(http.TimeFormat), 30 * time.Second, true},
		{now.Add(-time.Minute).Format(http.TimeFormat), 0, true},
	}
	for _, tc := range cases {
		got, ok := parseRetryAfter(tc.in, now)
		if got != tc.want || ok != tc.ok {
			t.Errorf("parseRetryAfter(%q) = %v, %v; want %v, %v", tc.in, got, ok, tc.want, tc.ok)
		}
	}
}

func TestFullJitterRange(t *testing.T) {
	for i := 0; i < 1000; i++ {
		d := fullJitter(10 * time.Second)
		if d < 5*time.Second || d > 10*time.Second {
			t.Fatalf("jitter %v out of range", d)
		}
	}
}
