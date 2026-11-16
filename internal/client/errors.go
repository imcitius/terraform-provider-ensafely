package client

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Error codes the Ensafely API puts in the "error" or "code" field.
const (
	codeQuotaExceeded    = "QUOTA_EXCEEDED"
	codeEmailNotVerified = "EMAIL_NOT_VERIFIED"
)

// maxErrorBody bounds how much of an error response is read and kept.
const maxErrorBody = 64 << 10

// APIError is a non-2xx response from the Ensafely API.
//
// The API has no single error envelope (see docs/api/openapi.yaml). Most
// handlers return {"error": "..."}; quota denials return
// {"error": "QUOTA_EXCEEDED", "resource", "current", "limit", "hint"} or
// {"error": "QUOTA_EXCEEDED", "detail": {"current", "limit"}}; email
// verification returns {"error", "code": "EMAIL_NOT_VERIFIED"}; rate limiting
// returns 429 {"error", "retry_after"} with a Retry-After header.
type APIError struct {
	StatusCode int
	Method     string
	Path       string
	// Message is the server's "error" text, or the HTTP status text when the
	// body carries none.
	Message string
	// Code is a machine-readable code (QUOTA_EXCEEDED, EMAIL_NOT_VERIFIED, ...)
	// when the server sent one.
	Code string
	// Quota is set for QUOTA_EXCEEDED responses.
	Quota *QuotaDetail
	// RetryAfter is the server's Retry-After for 429/503 responses, zero when
	// absent.
	RetryAfter time.Duration
	// RequestID echoes the X-Request-ID response header for support requests.
	RequestID string
	// Body is the raw (bounded) response body.
	Body []byte
}

// QuotaDetail describes a plan limit that blocked a request.
type QuotaDetail struct {
	// Resource is the limited resource ("checks", "alert_channels", ...).
	// It is empty when the server did not name one (platform regions).
	Resource string
	Current  int64
	Limit    int64
	Hint     string
}

func (e *APIError) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s: ", e.Method, e.Path)
	switch {
	case e.Quota != nil:
		b.WriteString("plan quota exceeded")
		if e.Quota.Resource != "" {
			fmt.Fprintf(&b, " for %s", e.Quota.Resource)
		}
		fmt.Fprintf(&b, " (%d in use, plan limit %d)", e.Quota.Current, e.Quota.Limit)
		if e.Quota.Hint != "" {
			fmt.Fprintf(&b, ". %s", e.Quota.Hint)
		}
	case e.Code == codeEmailNotVerified:
		b.WriteString("the API key owner's email address is not verified; verify it in the Ensafely app before creating or modifying resources")
	case e.StatusCode == http.StatusUnauthorized:
		fmt.Fprintf(&b, "authentication failed (%s); check api_key / ENSAFELY_API_KEY", e.Message)
	case e.StatusCode == http.StatusForbidden:
		// Plan ineligibility ("not available on your plan"), role and key
		// scope denials all arrive as a plain 403 {"error": "..."}.
		fmt.Fprintf(&b, "forbidden: %s (the Tenant's plan may not include this feature, or the API key lacks the api_write scope, e.g. an api_read key used for apply)", e.Message)
	case e.StatusCode == http.StatusTooManyRequests:
		fmt.Fprintf(&b, "rate limited (%s)", e.Message)
		if e.RetryAfter > 0 {
			fmt.Fprintf(&b, ", server asked to retry after %s", e.RetryAfter)
		}
	default:
		fmt.Fprintf(&b, "HTTP %d: %s", e.StatusCode, e.Message)
	}
	if e.RequestID != "" {
		fmt.Fprintf(&b, " [request id %s]", e.RequestID)
	}
	return b.String()
}

// Summary is a short, user-facing title for diagnostics.
func (e *APIError) Summary() string {
	switch {
	case e.Quota != nil:
		return "Ensafely plan limit reached"
	case e.Code == codeEmailNotVerified:
		return "Ensafely email address not verified"
	case e.StatusCode == http.StatusUnauthorized:
		return "Ensafely authentication failed"
	case e.StatusCode == http.StatusForbidden:
		return "Ensafely request forbidden"
	case e.StatusCode == http.StatusNotFound:
		return "Ensafely resource not found"
	case e.StatusCode == http.StatusConflict:
		return "Ensafely resource conflict"
	case e.StatusCode == http.StatusTooManyRequests:
		return "Ensafely rate limit exceeded"
	case e.StatusCode >= 500:
		return "Ensafely server error"
	default:
		return "Ensafely API error"
	}
}

// parseAPIError builds an APIError from a non-2xx response body.
func parseAPIError(method, path string, resp *http.Response, body []byte) *APIError {
	e := &APIError{
		StatusCode: resp.StatusCode,
		Method:     method,
		Path:       path,
		RequestID:  resp.Header.Get("X-Request-ID"),
		Body:       body,
	}
	if d, ok := parseRetryAfter(resp.Header.Get("Retry-After"), time.Now()); ok {
		e.RetryAfter = d
	}

	var env struct {
		Error    string          `json:"error"`
		Message  string          `json:"message"`
		Code     string          `json:"code"`
		Resource string          `json:"resource"`
		Current  json.Number     `json:"current"`
		Limit    json.Number     `json:"limit"`
		Hint     string          `json:"hint"`
		Detail   json.RawMessage `json:"detail"`
	}
	if len(body) > 0 && json.Unmarshal(body, &env) == nil {
		e.Message = env.Error
		if e.Message == "" {
			e.Message = env.Message
		}
		e.Code = env.Code
		if env.Error == codeQuotaExceeded || env.Code == codeQuotaExceeded {
			e.Code = codeQuotaExceeded
			q := &QuotaDetail{Resource: env.Resource, Hint: env.Hint}
			q.Current, _ = env.Current.Int64()
			q.Limit, _ = env.Limit.Int64()
			var detail struct {
				Current json.Number `json:"current"`
				Limit   json.Number `json:"limit"`
			}
			if len(env.Detail) > 0 && json.Unmarshal(env.Detail, &detail) == nil {
				if v, err := detail.Current.Int64(); err == nil {
					q.Current = v
				}
				if v, err := detail.Limit.Int64(); err == nil {
					q.Limit = v
				}
			}
			e.Quota = q
		}
	} else if len(body) > 0 && !looksLikeHTML(body) {
		e.Message = strings.TrimSpace(string(body))
		if len(e.Message) > 512 {
			e.Message = e.Message[:512] + "..."
		}
	}
	if e.Message == "" {
		e.Message = http.StatusText(resp.StatusCode)
	}
	return e
}

func looksLikeHTML(body []byte) bool {
	s := strings.TrimSpace(strings.ToLower(string(body[:min(len(body), 64)])))
	return strings.HasPrefix(s, "<!doctype") || strings.HasPrefix(s, "<html")
}

func asAPIError(err error) (*APIError, bool) {
	var e *APIError
	ok := errors.As(err, &e)
	return e, ok
}

// IsNotFound reports whether err is an HTTP 404 from the API. Resource Read
// implementations remove the resource from state in that case.
func IsNotFound(err error) bool {
	e, ok := asAPIError(err)
	return ok && e.StatusCode == http.StatusNotFound
}

// IsQuotaExceeded reports whether err is a plan-limit (QUOTA_EXCEEDED) denial.
func IsQuotaExceeded(err error) bool {
	e, ok := asAPIError(err)
	return ok && e.Quota != nil
}

// IsConflict reports whether err is an HTTP 409.
func IsConflict(err error) bool {
	e, ok := asAPIError(err)
	return ok && e.StatusCode == http.StatusConflict
}

// IsRateLimited reports whether err is a 429 that survived all retries.
func IsRateLimited(err error) bool {
	e, ok := asAPIError(err)
	return ok && e.StatusCode == http.StatusTooManyRequests
}
