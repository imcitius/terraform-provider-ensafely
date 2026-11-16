// Package client is the HTTP client the Ensafely Terraform provider uses to
// call the tenant API (/api, documented in docs/api/openapi.yaml).
//
// It adds Bearer authentication, JSON encoding, bounded retries and typed
// errors. Retries follow these rules:
//
//   - 429 is retried for every method: the rate limiter rejects the request
//     before any handler runs. The wait honours Retry-After (seconds or
//     HTTP date) and otherwise uses exponential backoff with jitter.
//   - 502, 503 and 504 and transport errors are retried only for idempotent
//     methods (GET, HEAD, OPTIONS, PUT, DELETE) or requests marked with
//     Idempotent(), because a POST that reached the server may have created
//     something. A failed TCP dial is retried for every method: nothing was
//     sent.
//   - 500 is never retried. This API reports deterministic failures such as
//     duplicate names as 500.
//
// Retries stop at MaxRetries, when a single wait would exceed MaxWait, or
// when the context ends.
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Defaults for Config fields left zero.
const (
	DefaultEndpoint   = "https://app.ensafely.com"
	DefaultMaxRetries = 5
	DefaultMinBackoff = 1 * time.Second
	DefaultMaxBackoff = 30 * time.Second
	// DefaultMaxWait bounds a single Retry-After wait. The tenant creation
	// limiter uses a one-minute window, so its Retry-After never exceeds 61s.
	DefaultMaxWait        = 90 * time.Second
	DefaultRequestTimeout = 60 * time.Second
)

// Config configures a Client.
type Config struct {
	// Endpoint is the Ensafely base URL, e.g. https://app.ensafely.com.
	Endpoint string
	// APIKey is a tenant API key (ck_...). Provider writes need the
	// api_write scope.
	APIKey string
	// UserAgent is sent on every request.
	UserAgent string
	// HTTPClient overrides the transport. Its Timeout applies per attempt.
	HTTPClient *http.Client

	// MaxRetries is the number of retries after the first attempt. Zero
	// means DefaultMaxRetries; a negative value disables retries.
	MaxRetries int
	MinBackoff time.Duration
	MaxBackoff time.Duration
	// MaxWait is the longest single wait the client accepts from
	// Retry-After before giving up with the 429 error.
	MaxWait time.Duration

	// sleep and jitter are replaced in tests.
	sleep  func(context.Context, time.Duration) error
	jitter func(time.Duration) time.Duration
}

// Client calls the Ensafely tenant API. It is safe for concurrent use.
type Client struct {
	base       *url.URL
	apiKey     string
	userAgent  string
	http       *http.Client
	maxRetries int
	minBackoff time.Duration
	maxBackoff time.Duration
	maxWait    time.Duration
	sleep      func(context.Context, time.Duration) error
	jitter     func(time.Duration) time.Duration
}

// New validates cfg and returns a Client.
func New(cfg Config) (*Client, error) {
	endpoint := strings.TrimSpace(cfg.Endpoint)
	if endpoint == "" {
		endpoint = DefaultEndpoint
	}
	base, err := ParseEndpoint(endpoint)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(cfg.APIKey) == "" {
		return nil, errors.New("an Ensafely API key is required")
	}
	c := &Client{
		base:       base,
		apiKey:     strings.TrimSpace(cfg.APIKey),
		userAgent:  cfg.UserAgent,
		http:       cfg.HTTPClient,
		maxRetries: cfg.MaxRetries,
		minBackoff: cfg.MinBackoff,
		maxBackoff: cfg.MaxBackoff,
		maxWait:    cfg.MaxWait,
		sleep:      cfg.sleep,
		jitter:     cfg.jitter,
	}
	if c.http == nil {
		c.http = &http.Client{Timeout: DefaultRequestTimeout}
	}
	if c.userAgent == "" {
		c.userAgent = "terraform-provider-ensafely"
	}
	switch {
	case c.maxRetries == 0:
		c.maxRetries = DefaultMaxRetries
	case c.maxRetries < 0:
		c.maxRetries = 0
	}
	if c.minBackoff <= 0 {
		c.minBackoff = DefaultMinBackoff
	}
	if c.maxBackoff <= 0 {
		c.maxBackoff = DefaultMaxBackoff
	}
	if c.maxBackoff < c.minBackoff {
		c.maxBackoff = c.minBackoff
	}
	if c.maxWait <= 0 {
		c.maxWait = DefaultMaxWait
	}
	if c.sleep == nil {
		c.sleep = sleepContext
	}
	if c.jitter == nil {
		c.jitter = fullJitter
	}
	return c, nil
}

// ParseEndpoint validates an Ensafely base URL: http(s), a host, and no
// query or fragment. A trailing slash is removed.
func ParseEndpoint(raw string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return nil, fmt.Errorf("invalid endpoint %q: %w", raw, err)
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return nil, fmt.Errorf("invalid endpoint %q: scheme must be https or http", raw)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("invalid endpoint %q: missing host", raw)
	}
	if u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return nil, fmt.Errorf("invalid endpoint %q: must not contain credentials, a query or a fragment", raw)
	}
	u.Path = strings.TrimRight(u.Path, "/")
	u.RawPath = ""
	return u, nil
}

// Endpoint returns the normalised base URL.
func (c *Client) Endpoint() string { return c.base.String() }

// RequestOption adjusts a single request.
type RequestOption func(*requestOptions)

type requestOptions struct {
	idempotent bool
	query      url.Values
}

// Idempotent marks a POST or PATCH as safe to repeat, e.g. a create that
// carries a client-chosen ID. It enables 5xx and transport-error retries.
func Idempotent() RequestOption {
	return func(o *requestOptions) { o.idempotent = true }
}

// Query adds URL query parameters.
func Query(v url.Values) RequestOption {
	return func(o *requestOptions) { o.query = v }
}

// Get decodes the JSON response of GET path into out (which may be nil).
func (c *Client) Get(ctx context.Context, path string, out any, opts ...RequestOption) error {
	return c.Do(ctx, http.MethodGet, path, nil, out, opts...)
}

// Post sends in as JSON and decodes the response into out.
func (c *Client) Post(ctx context.Context, path string, in, out any, opts ...RequestOption) error {
	return c.Do(ctx, http.MethodPost, path, in, out, opts...)
}

// Put sends in as JSON and decodes the response into out.
func (c *Client) Put(ctx context.Context, path string, in, out any, opts ...RequestOption) error {
	return c.Do(ctx, http.MethodPut, path, in, out, opts...)
}

// Patch sends in as JSON and decodes the response into out.
func (c *Client) Patch(ctx context.Context, path string, in, out any, opts ...RequestOption) error {
	return c.Do(ctx, http.MethodPatch, path, in, out, opts...)
}

// Delete calls DELETE path and decodes any response body into out.
func (c *Client) Delete(ctx context.Context, path string, out any, opts ...RequestOption) error {
	return c.Do(ctx, http.MethodDelete, path, nil, out, opts...)
}

// PathEscape escapes one path segment, e.g. a name-keyed resource ID.
func PathEscape(segment string) string { return url.PathEscape(segment) }

// Do performs one API call with retries. path is relative to the endpoint
// and must start with "/". in (when non-nil) is encoded as JSON; a 2xx body
// is decoded into out when out is non-nil. Non-2xx responses return
// *APIError.
func (c *Client) Do(ctx context.Context, method, path string, in, out any, opts ...RequestOption) error {
	var o requestOptions
	for _, opt := range opts {
		opt(&o)
	}
	if !strings.HasPrefix(path, "/") {
		return fmt.Errorf("client: path %q must start with /", path)
	}

	var body []byte
	if in != nil {
		var err error
		if body, err = json.Marshal(in); err != nil {
			return fmt.Errorf("encode %s %s request: %w", method, path, err)
		}
	}
	// path is already escaped by the caller (see PathEscape); keep it as is
	// so an escaped "/" inside a name stays one segment.
	target := *c.base
	target.RawPath = c.base.EscapedPath() + path
	unescaped, err := url.PathUnescape(target.RawPath)
	if err != nil {
		return fmt.Errorf("client: invalid path %q: %w", path, err)
	}
	target.Path = unescaped
	if len(o.query) > 0 {
		target.RawQuery = o.query.Encode()
	}
	idempotent := o.idempotent || isIdempotentMethod(method)

	for attempt := 0; ; attempt++ {
		resp, err := c.send(ctx, method, target.String(), body)
		if err != nil {
			if ctx.Err() != nil {
				return fmt.Errorf("%s %s: %w", method, path, ctx.Err())
			}
			retryable := idempotent || isDialError(err)
			if !retryable || attempt >= c.maxRetries {
				return fmt.Errorf("%s %s: %w", method, path, err)
			}
			if werr := c.sleep(ctx, c.backoff(attempt)); werr != nil {
				return fmt.Errorf("%s %s: %w (while retrying after: %v)", method, path, werr, err)
			}
			continue
		}

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return decodeBody(method, path, resp, out)
		}

		raw, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBody))
		_ = resp.Body.Close()
		apiErr := parseAPIError(method, path, resp, raw)

		wait, retry := c.retryDecision(apiErr, idempotent, attempt)
		if !retry {
			return apiErr
		}
		if werr := c.sleep(ctx, wait); werr != nil {
			return fmt.Errorf("%w (while waiting to retry: %v)", apiErr, werr)
		}
	}
}

func (c *Client) send(ctx context.Context, method, target string, body []byte) (*http.Response, error) {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, target, reader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.userAgent)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return c.http.Do(req)
}

// retryDecision returns how long to wait before retrying apiErr, or false
// when the error is final.
func (c *Client) retryDecision(apiErr *APIError, idempotent bool, attempt int) (time.Duration, bool) {
	if attempt >= c.maxRetries {
		return 0, false
	}
	switch apiErr.StatusCode {
	case http.StatusTooManyRequests:
		// Rejected before any handler ran: safe for every method.
	case http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		if !idempotent {
			return 0, false
		}
	default:
		return 0, false
	}
	if apiErr.RetryAfter > 0 {
		if apiErr.RetryAfter > c.maxWait {
			return 0, false
		}
		return apiErr.RetryAfter, true
	}
	return c.backoff(attempt), true
}

// backoff is exponential (min * 2^attempt, capped at max) with jitter.
func (c *Client) backoff(attempt int) time.Duration {
	d := c.minBackoff
	for i := 0; i < attempt && d < c.maxBackoff; i++ {
		d *= 2
	}
	if d > c.maxBackoff {
		d = c.maxBackoff
	}
	return c.jitter(d)
}

// fullJitter returns a duration in [d/2, d].
func fullJitter(d time.Duration) time.Duration {
	if d <= 1 {
		return d
	}
	half := d / 2
	return half + rand.N(d-half+1)
}

func decodeBody(method, path string, resp *http.Response, out any) error {
	defer resp.Body.Close()
	if out == nil || resp.StatusCode == http.StatusNoContent {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("%s %s: read response: %w", method, path, err)
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return nil
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("%s %s: decode response: %w", method, path, err)
	}
	return nil
}

func isIdempotentMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodPut, http.MethodDelete:
		return true
	}
	return false
}

// isDialError reports a failure to open the connection, i.e. the request
// was never sent.
func isDialError(err error) bool {
	var op *net.OpError
	return errors.As(err, &op) && op.Op == "dial"
}

// parseRetryAfter accepts delay-seconds or an HTTP date (RFC 9110 §10.2.3).
func parseRetryAfter(v string, now time.Time) (time.Duration, bool) {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0, false
	}
	if secs, err := strconv.ParseInt(v, 10, 64); err == nil {
		if secs < 0 {
			return 0, false
		}
		return time.Duration(secs) * time.Second, true
	}
	if t, err := http.ParseTime(v); err == nil {
		d := t.Sub(now)
		if d < 0 {
			d = 0
		}
		return d, true
	}
	return 0, false
}

func sleepContext(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
