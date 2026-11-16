package acctest

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// Credentials identify the disposable Tenant created by Bootstrap.
type Credentials struct {
	TenantID string
	Email    string
	APIKey   string
}

// BootstrapOptions tune Bootstrap; zero values are fine.
type BootstrapOptions struct {
	HTTPClient *http.Client
	// VerifyTimeout bounds the wait for the verification email.
	VerifyTimeout time.Duration
	// Plan, when set, moves the test Tenant to this plan ID through the
	// platform admin API (PUT /api/admin/tenants/:id/plan). The free plan
	// allows one alert channel, which the default Email channel uses.
	Plan string
	// AdminEmail and AdminPassword identify the local platform admin used
	// for Plan. The account is signed up and verified when login fails; the
	// email must be listed in the app's ADMIN_EMAILS. Defaults match
	// packages/cloud/docker-compose.yml and the Playwright suite.
	AdminEmail, AdminPassword string
}

// Local platform admin of the e2e stack (ADMIN_EMAILS in
// packages/cloud/docker-compose.yml, shared with packages/cloud/e2e).
const (
	defaultAdminEmail    = "admin@test.com"
	defaultAdminPassword = "TestPass123!"
)

// verificationLink matches the token in the verification email body.
var verificationLink = regexp.MustCompile(`/verify-email\?token=([^"&\s<]+)`)

// Bootstrap creates a fresh Tenant on a local test app and returns an
// api_write API key for it. It signs up a unique owner, confirms the email
// through the test mailbox (GET /api/test/emails, available only with
// APP_ENV=test and ENABLE_TEST_ENDPOINTS=true) and creates the key with the
// owner's session.
//
// Bootstrap refuses non-local endpoints: it must never create Tenants on a
// shared or production deployment.
func Bootstrap(ctx context.Context, endpoint string, opts BootstrapOptions) (*Credentials, error) {
	b, opts, err := newBootstrapper(endpoint, opts)
	if err != nil {
		return nil, err
	}

	suffix, err := randomSuffix()
	if err != nil {
		return nil, err
	}
	creds := &Credentials{Email: "tf-acc+" + suffix + "@ensafely.test"}
	password := "tf-acc-" + suffix + "-Pw!"

	var signup struct {
		Token  string `json:"token"`
		Tenant struct {
			ID string `json:"id"`
		} `json:"tenant"`
	}
	if err := b.call(ctx, http.MethodPost, "/api/auth/signup", "", map[string]string{
		"name":        "Terraform acceptance",
		"email":       creds.Email,
		"password":    password,
		"tenant_name": "tf-acc-" + suffix,
	}, &signup, http.StatusCreated, http.StatusOK); err != nil {
		return nil, fmt.Errorf("sign up test Tenant: %w", err)
	}
	if signup.Token == "" || signup.Tenant.ID == "" {
		return nil, errors.New("sign up test Tenant: response has no token or tenant id")
	}
	creds.TenantID = signup.Tenant.ID

	token, err := b.verifyEmail(ctx, creds.Email, opts.VerifyTimeout)
	if err != nil {
		return nil, err
	}

	var key struct {
		Key string `json:"key"`
	}
	if err := b.call(ctx, http.MethodPost, "/api/api-keys", token, map[string]string{
		"name":  "terraform-acceptance",
		"scope": "api_write",
	}, &key, http.StatusCreated); err != nil {
		return nil, fmt.Errorf("create API key: %w", err)
	}
	if key.Key == "" {
		return nil, errors.New("create API key: response has no key")
	}
	creds.APIKey = key.Key

	if opts.Plan != "" {
		if opts.AdminEmail == "" {
			opts.AdminEmail, opts.AdminPassword = defaultAdminEmail, defaultAdminPassword
		}
		admin, err := b.adminSession(ctx, opts.AdminEmail, opts.AdminPassword, opts.VerifyTimeout)
		if err != nil {
			return nil, fmt.Errorf("platform admin %s: %w", opts.AdminEmail, err)
		}
		if err := b.call(ctx, http.MethodPut, "/api/admin/tenants/"+url.PathEscape(creds.TenantID)+"/plan", admin,
			map[string]string{"plan_id": opts.Plan}, nil, http.StatusOK); err != nil {
			return nil, fmt.Errorf("set test Tenant plan %q: %w", opts.Plan, err)
		}
	}
	return creds, nil
}

// newBootstrapper validates a local endpoint and fills option defaults.
func newBootstrapper(endpoint string, opts BootstrapOptions) (*bootstrapper, BootstrapOptions, error) {
	base, err := url.Parse(strings.TrimRight(endpoint, "/"))
	if err != nil || (base.Scheme != "http" && base.Scheme != "https") || base.Host == "" {
		return nil, opts, fmt.Errorf("invalid endpoint %q", endpoint)
	}
	if !isLocalHost(base.Hostname()) {
		return nil, opts, fmt.Errorf("refusing to bootstrap a test Tenant on non-local endpoint %q", endpoint)
	}
	hc := opts.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	if opts.VerifyTimeout <= 0 {
		opts.VerifyTimeout = 30 * time.Second
	}
	return &bootstrapper{base: base.String(), http: hc}, opts, nil
}

// adminSession logs in as the local platform admin, signing the account up
// (and verifying it through the test mailbox) on a fresh database.
func (b *bootstrapper) adminSession(ctx context.Context, email, password string, timeout time.Duration) (string, error) {
	var login struct {
		Token string `json:"token"`
	}
	err := b.call(ctx, http.MethodPost, "/api/auth/login", "", map[string]string{"email": email, "password": password}, &login, http.StatusOK)
	if err == nil && login.Token != "" {
		return login.Token, nil
	}
	var se *statusError
	if err != nil && (!errors.As(err, &se) || se.code != http.StatusUnauthorized) {
		return "", fmt.Errorf("log in: %w", err)
	}
	if err := b.call(ctx, http.MethodPost, "/api/auth/signup", "", map[string]string{
		"name":        "Terraform acceptance admin",
		"email":       email,
		"password":    password,
		"tenant_name": "tf-acc-admin",
	}, nil, http.StatusCreated, http.StatusOK); err != nil {
		return "", fmt.Errorf("log in failed and sign up failed (an existing account needs the expected password): %w", err)
	}
	return b.verifyEmail(ctx, email, timeout)
}

type bootstrapper struct {
	base string
	http *http.Client
}

func (b *bootstrapper) verifyEmail(ctx context.Context, email string, timeout time.Duration) (string, error) {
	deadline := time.Now().Add(timeout)
	for {
		var messages []struct {
			To   string `json:"to"`
			Body string `json:"body"`
		}
		err := b.call(ctx, http.MethodGet, "/api/test/emails", "", nil, &messages, http.StatusOK)
		var se *statusError
		if errors.As(err, &se) && se.code == http.StatusNotFound {
			return "", errors.New("the test mailbox /api/test/emails is not available; " +
				"run the app with APP_ENV=test and ENABLE_TEST_ENDPOINTS=true (make e2e-up sets both)")
		}
		if err != nil {
			return "", fmt.Errorf("read test mailbox: %w", err)
		}
		for _, m := range messages {
			if m.To != email {
				continue
			}
			if match := verificationLink.FindStringSubmatch(m.Body); match != nil {
				var verified struct {
					Token string `json:"token"`
				}
				if err := b.call(ctx, http.MethodPost, "/api/auth/verify-email", "",
					map[string]string{"token": match[1]}, &verified, http.StatusOK); err != nil {
					return "", fmt.Errorf("verify test email: %w", err)
				}
				if verified.Token == "" {
					return "", errors.New("verify test email: response has no token")
				}
				return verified.Token, nil
			}
		}
		if time.Now().After(deadline) {
			return "", fmt.Errorf("no verification email for %s within %s", email, timeout)
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(300 * time.Millisecond):
		}
	}
}

type statusError struct {
	code int
	body string
}

func (e *statusError) Error() string { return fmt.Sprintf("HTTP %d: %s", e.code, e.body) }

func (b *bootstrapper) call(ctx context.Context, method, path, token string, in, out any, want ...int) error {
	var body io.Reader
	if in != nil {
		data, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, b.base+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := b.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	ok := false
	for _, code := range want {
		ok = ok || resp.StatusCode == code
	}
	if !ok {
		return &statusError{code: resp.StatusCode, body: strings.TrimSpace(string(data))}
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(data, out)
}

func isLocalHost(host string) bool {
	switch host {
	case "localhost", "127.0.0.1", "::1", "host.docker.internal":
		return true
	}
	return strings.HasSuffix(host, ".localhost")
}

func randomSuffix() (string, error) {
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return fmt.Sprintf("%d-%s", time.Now().Unix(), hex.EncodeToString(b[:])), nil
}

// PlatformRegions are the Platform probe regions SeedPlatformRegions
// registers: the built-in Plans' default regions. A Free Tenant may select
// two of them, so all three exceed its limit.
var PlatformRegions = []string{"eu-paris", "us-washington", "ap-singapore"}

// SeedPlatformRegions makes regions selectable on a local test app by
// registering a platform probe token for each region that has none. A
// region is selectable once a non-revoked token exists; no Probe has to
// connect. It signs in as the local platform admin (opts.AdminEmail, default
// admin@test.com), signing it up and verifying it through the test mailbox on
// first use, and is idempotent. Like Bootstrap it refuses
// non-local endpoints.
func SeedPlatformRegions(ctx context.Context, endpoint string, regions []string, opts BootstrapOptions) error {
	b, opts, err := newBootstrapper(endpoint, opts)
	if err != nil {
		return err
	}
	if opts.AdminEmail == "" {
		opts.AdminEmail, opts.AdminPassword = defaultAdminEmail, defaultAdminPassword
	}
	token, err := b.adminSession(ctx, opts.AdminEmail, opts.AdminPassword, opts.VerifyTimeout)
	if err != nil {
		return fmt.Errorf("platform admin %s: %w", opts.AdminEmail, err)
	}
	var list struct {
		Tokens []struct {
			Region    string     `json:"region"`
			RevokedAt *time.Time `json:"revoked_at"`
		} `json:"edge_tokens"`
	}
	if err := b.call(ctx, http.MethodGet, "/api/admin/edge-tokens", token, nil, &list, http.StatusOK); err != nil {
		return fmt.Errorf("list platform probe tokens: %w", err)
	}
	have := map[string]bool{}
	for _, t := range list.Tokens {
		if t.RevokedAt == nil {
			have[t.Region] = true
		}
	}
	for _, region := range regions {
		if have[region] {
			continue
		}
		if err := b.call(ctx, http.MethodPost, "/api/admin/edge-tokens", token,
			map[string]string{"name": "tf-acc-" + region, "region": region}, nil, http.StatusCreated); err != nil {
			return fmt.Errorf("register platform region %s: %w", region, err)
		}
	}
	return nil
}
