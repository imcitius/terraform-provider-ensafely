package acctest

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// adminCalls records the platform admin requests of fakeApp.
type adminCalls struct {
	mu       sync.Mutex
	signups  []string
	planPath string
	planReq  map[string]any
}

// fakeApp mimics the signup → verification email → API key flow, and the
// platform admin login and plan override. Login fails until the admin has
// signed up.
func fakeApp(t *testing.T, mailbox bool) (*httptest.Server, *map[string]any, *adminCalls) {
	t.Helper()
	var mu sync.Mutex
	var email string
	keyReq := map[string]any{}
	admin := &adminCalls{}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/auth/signup", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		mu.Lock()
		email = body["email"]
		mu.Unlock()
		admin.mu.Lock()
		admin.signups = append(admin.signups, body["email"])
		admin.mu.Unlock()
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{"token": "jwt-unverified", "tenant": map[string]string{"id": "t-1"}})
	})
	mux.HandleFunc("GET /api/test/emails", func(w http.ResponseWriter, r *http.Request) {
		if !mailbox {
			http.NotFound(w, r)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		_ = json.NewEncoder(w).Encode([]map[string]string{
			{"to": "someone@else", "body": "/verify-email?token=wrong"},
			{"to": email, "body": `<a href="http://x/verify-email?token=tok-123">verify</a>`},
		})
	})
	mux.HandleFunc("POST /api/auth/verify-email", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["token"] != "tok-123" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"token": "jwt-verified"})
	})
	mux.HandleFunc("POST /api/api-keys", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer jwt-verified" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_ = json.NewDecoder(r.Body).Decode(&keyReq)
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]string{"key": "ck_test_key"})
	})
	mux.HandleFunc("POST /api/auth/login", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})
	mux.HandleFunc("PUT /api/admin/tenants/{id}/plan", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer jwt-verified" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		admin.mu.Lock()
		admin.planPath = r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&admin.planReq)
		admin.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]string{"message": "ok"})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, &keyReq, admin
}

func TestBootstrap(t *testing.T) {
	srv, keyReq, admin := fakeApp(t, true)
	creds, err := Bootstrap(context.Background(), srv.URL, BootstrapOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if admin.planPath != "" || len(admin.signups) != 1 {
		t.Errorf("no plan was requested, but admin calls = %+v", admin)
	}
	if creds.APIKey != "ck_test_key" || creds.TenantID != "t-1" || !strings.HasPrefix(creds.Email, "tf-acc+") {
		t.Errorf("creds = %+v", creds)
	}
	if (*keyReq)["scope"] != "api_write" {
		t.Errorf("key request = %v; provider tests need an api_write key", *keyReq)
	}
}

func TestBootstrapNeedsTestMailbox(t *testing.T) {
	srv, _, _ := fakeApp(t, false)
	_, err := Bootstrap(context.Background(), srv.URL, BootstrapOptions{VerifyTimeout: time.Second})
	if err == nil || !strings.Contains(err.Error(), "ENABLE_TEST_ENDPOINTS=true") {
		t.Fatalf("err = %v", err)
	}
}

func TestBootstrapRefusesRemoteEndpoints(t *testing.T) {
	for _, endpoint := range []string{"https://app.ensafely.com", "http://10.0.0.5:8090", "not a url"} {
		if _, err := Bootstrap(context.Background(), endpoint, BootstrapOptions{}); err == nil {
			t.Errorf("Bootstrap(%q) succeeded", endpoint)
		}
	}
}

// fakeAdminApp mimics admin sign-in (or first sign-up) and the platform probe
// token API. existing is the admin's state: "", "unverified" or "verified".
func fakeAdminApp(t *testing.T, existing string, tokens []map[string]any) (*httptest.Server, *[]string) {
	t.Helper()
	var mu sync.Mutex
	var created []string
	state := existing
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/auth/login", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if state == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"token": "jwt-admin"})
	})
	mux.HandleFunc("POST /api/auth/signup", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["email"] != defaultAdminEmail {
			t.Errorf("signup email = %q", body["email"])
		}
		mu.Lock()
		state = "unverified"
		mu.Unlock()
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{"token": "jwt-unverified", "tenant": map[string]string{"id": "t-admin"}})
	})
	mux.HandleFunc("GET /api/test/emails", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([]map[string]string{{"to": defaultAdminEmail, "body": "/verify-email?token=tok-admin"}})
	})
	mux.HandleFunc("POST /api/auth/verify-email", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"token": "jwt-admin"})
	})
	mux.HandleFunc("GET /api/admin/edge-tokens", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer jwt-admin" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"edge_tokens": tokens})
	})
	mux.HandleFunc("POST /api/admin/edge-tokens", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		mu.Lock()
		created = append(created, body["region"])
		mu.Unlock()
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]string{"id": "tok", "token": "pk_secret"})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, &created
}

func TestSeedPlatformRegions(t *testing.T) {
	regions := []string{"eu-paris", "us-washington", "ap-singapore"}
	for _, tc := range []struct {
		name     string
		admin    string
		tokens   []map[string]any
		wantMade []string
	}{
		{"first run signs the admin up", "", nil, regions},
		{"existing admin, missing and revoked regions", "verified", []map[string]any{
			{"region": "eu-paris"},
			{"region": "us-washington", "revoked_at": "2026-01-01T00:00:00Z"},
		}, []string{"us-washington", "ap-singapore"}},
		{"idempotent", "verified", []map[string]any{{"region": "eu-paris"}, {"region": "us-washington"}, {"region": "ap-singapore"}}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv, created := fakeAdminApp(t, tc.admin, tc.tokens)
			if err := SeedPlatformRegions(context.Background(), srv.URL, regions, BootstrapOptions{VerifyTimeout: time.Second}); err != nil {
				t.Fatal(err)
			}
			if strings.Join(*created, ",") != strings.Join(tc.wantMade, ",") {
				t.Errorf("created %v, want %v", *created, tc.wantMade)
			}
		})
	}
	if err := SeedPlatformRegions(context.Background(), "https://app.ensafely.com", regions, BootstrapOptions{}); err == nil {
		t.Error("seeding a non-local endpoint must fail")
	}
}

// TestBootstrapSetsPlan signs up the missing platform admin and moves the
// test Tenant to the requested plan.
func TestBootstrapSetsPlan(t *testing.T) {
	srv, _, admin := fakeApp(t, true)
	if _, err := Bootstrap(context.Background(), srv.URL, BootstrapOptions{Plan: "paid2"}); err != nil {
		t.Fatal(err)
	}
	if len(admin.signups) != 2 || admin.signups[1] != defaultAdminEmail {
		t.Errorf("signups = %v, want the test owner and then %s", admin.signups, defaultAdminEmail)
	}
	if admin.planPath != "/api/admin/tenants/t-1/plan" || admin.planReq["plan_id"] != "paid2" {
		t.Errorf("plan request = %s %v", admin.planPath, admin.planReq)
	}
}
