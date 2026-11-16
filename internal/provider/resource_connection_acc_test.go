package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	tfresource "github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"

	"github.com/imcitius/terraform-provider-ensafely/internal/acctest"
	"github.com/imcitius/terraform-provider-ensafely/internal/client"
)

// recordingProxy forwards to the acceptance app and records the JSON body of
// every write under prefix (default /api/connections). The API never returns
// secrets, so this is how the tests prove which secret the provider sent, and
// when.
type recordingProxy struct {
	prefix string
	mu     sync.Mutex
	writes []recordedRequest
}

func (p *recordingProxy) start(t *testing.T, target string) string {
	t.Helper()
	u, err := url.Parse(target)
	if err != nil {
		t.Fatal(err)
	}
	prefix := p.prefix
	if prefix == "" {
		prefix = "/api/connections"
	}
	proxy := &httputil.ReverseProxy{Rewrite: func(r *httputil.ProxyRequest) { r.SetURL(u) }}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodGet && strings.HasPrefix(req.URL.Path, prefix) {
			raw, _ := io.ReadAll(req.Body)
			req.Body = io.NopCloser(bytes.NewReader(raw))
			rec := recordedRequest{Method: req.Method, Path: req.URL.Path}
			_ = json.Unmarshal(raw, &rec.Body)
			p.mu.Lock()
			p.writes = append(p.writes, rec)
			p.mu.Unlock()
		}
		proxy.ServeHTTP(w, req)
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func (p *recordingProxy) since(n int) []recordedRequest {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]recordedRequest(nil), p.writes[n:]...)
}

func (p *recordingProxy) count() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.writes)
}

// noSecretInState fails when any secret appears in any stored attribute.
func noSecretInState(secrets ...string) func(*terraform.State) error {
	return func(s *terraform.State) error {
		for addr, rs := range s.RootModule().Resources {
			for k, v := range rs.Primary.Attributes {
				for _, secret := range secrets {
					if strings.Contains(v, secret) {
						return fmt.Errorf("%s.%s contains a password", addr, k)
					}
				}
			}
		}
		return nil
	}
}

func TestAccConnection(t *testing.T) {
	const pg, api = "ensafely_connection.pg", "ensafely_connection.api"
	suffix := time.Now().UnixNano()
	// Steps are built before PreCheck runs, so the proxy starts here. Without
	// TF_ACC the test is skipped and the proxy is never used.
	var proxy recordingProxy
	proxyURL := proxy.start(t, os.Getenv(EnvEndpoint))
	var c *client.Client
	ids := map[string]string{}

	config := func(name, host, password string, version int, pgParams string) string {
		return fmt.Sprintf(`
provider "ensafely" {
  endpoint = %q
}

resource "ensafely_connection" "pg" {
  name                = %q
  type                = "postgres"
  host                = %q
  port                = 5432
  username            = "checker"
  password_wo         = %q
  password_wo_version = %d
  params              = %s
}

resource "ensafely_connection" "api" {
  name               = "tf-acc-api-%d"
  type               = "http"
  headers_wo         = { "X-Token" = %q }
  headers_wo_version = %d
  params = {
    base_url = "https://api.example.com/health"
  }
}
`, proxyURL, name, host, password, version, pgParams, suffix, password+"-header", version)
	}
	name := fmt.Sprintf("tf-acc-pg-%d", suffix)
	initial := config(name, "db1.example.com", "first-secret", 1, `{ db_name = "app", ssl_mode = "require" }`)
	sameVersion := config(name, "db1.example.com", "second-secret", 1, `{ db_name = "app", ssl_mode = "require" }`)
	updated := config(name+"-renamed", "db2.example.com", "second-secret", 2, `{ db_name = "app2" }`)

	var mark int
	markWrites := func() { mark = proxy.count() }
	// sent finds the recorded write of the given type and checks the secret
	// it carried: the password for postgres, the X-Token header for http.
	sent := func(method, typ, want string) func(*terraform.State) error {
		return func(*terraform.State) error {
			for _, w := range proxy.since(mark) {
				addr := map[string]string{"postgres": pg, "http": api}[typ]
				if w.Method != method || w.Body["type"] != typ || (method == http.MethodPatch && !strings.HasSuffix(w.Path, "/"+ids[addr])) {
					continue
				}
				var got any
				ok := false
				if typ == "postgres" {
					got, ok = w.Body["password"]
				} else if params, _ := w.Body["params"].(map[string]any); params != nil {
					if h, _ := params["headers"].(map[string]any); h != nil {
						got, ok = h["X-Token"]
					}
				}
				if !ok || got != want {
					return fmt.Errorf("%s %s secret = %v (sent=%v), want %q", method, typ, got, ok, want)
				}
				return nil
			}
			return fmt.Errorf("no %s for the %s connection recorded", method, typ)
		}
	}
	saveIDs := func(s *terraform.State) error {
		for _, addr := range []string{pg, api} {
			ids[addr] = s.RootModule().Resources[addr].Primary.ID
		}
		return nil
	}
	apiState := func(addr string, check func(map[string]any) error) func(*terraform.State) error {
		return func(*terraform.State) error {
			var body map[string]any
			if err := c.Get(context.Background(), "/api/connections/"+ids[addr], &body); err != nil {
				return err
			}
			if _, ok := body["password"]; ok {
				return fmt.Errorf("API returned a password field")
			}
			return check(body)
		}
	}

	tfresource.Test(t, tfresource.TestCase{
		PreCheck: func() {
			acctest.PreCheck(t)
			var err error
			c, err = client.New(client.Config{Endpoint: os.Getenv(EnvEndpoint), APIKey: os.Getenv(EnvAPIKey)})
			if err != nil {
				t.Fatal(err)
			}
		},
		TerraformVersionChecks:   minimumTerraform,
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy: func(*terraform.State) error {
			for addr, id := range ids {
				err := c.Get(context.Background(), "/api/connections/"+id, nil)
				if !client.IsNotFound(err) {
					return fmt.Errorf("%s still exists after destroy (err=%v)", addr, err)
				}
			}
			return nil
		},
		Steps: []tfresource.TestStep{
			{
				// Create: the password is sent once and never stored.
				PreConfig: markWrites,
				Config:    initial,
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(pg, tfjsonpath.New("password_wo"), knownvalue.Null()),
					statecheck.ExpectKnownValue(pg, tfjsonpath.New("password_wo_version"), knownvalue.Int64Exact(1)),
					statecheck.ExpectKnownValue(pg, tfjsonpath.New("params").AtMapKey("ssl_mode"), knownvalue.StringExact("require")),
					statecheck.ExpectKnownValue(api, tfjsonpath.New("headers_wo"), knownvalue.Null()),
					statecheck.ExpectKnownValue(api, tfjsonpath.New("host"), knownvalue.Null()),
				},
				Check: tfresource.ComposeAggregateTestCheckFunc(
					saveIDs,
					sent(http.MethodPost, "postgres", "first-secret"),
					sent(http.MethodPost, "http", "first-secret-header"),
					noSecretInState("first-secret"),
					apiState(api, func(b map[string]any) error {
						// The API stores the header and returns it masked.
						params, _ := b["params"].(map[string]any)
						if h, _ := params["headers"].(map[string]any); h["X-Token"] != "****" {
							return fmt.Errorf("API params = %v", params)
						}
						return nil
					}),
					apiState(pg, func(b map[string]any) error {
						params, _ := b["params"].(map[string]any)
						if b["name"] != name || b["host"] != "db1.example.com" || params["db_name"] != "app" {
							return fmt.Errorf("API state = %v", b)
						}
						return nil
					}),
				),
			},
			{
				// A changed password with the same version is not detected
				// (write-only) and is not sent.
				PreConfig:        markWrites,
				Config:           sameVersion,
				ConfigPlanChecks: tfresource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()}},
				Check: func(*terraform.State) error {
					if w := proxy.since(mark); len(w) != 0 {
						return fmt.Errorf("unexpected writes: %+v", w)
					}
					return nil
				},
			},
			{
				// Bumping the versions rotates the password and the header;
				// other fields update in place (rename, host, removed param).
				PreConfig: markWrites,
				Config:    updated,
				ConfigPlanChecks: tfresource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
					plancheck.ExpectResourceAction(pg, plancheck.ResourceActionUpdate),
					plancheck.ExpectResourceAction(api, plancheck.ResourceActionUpdate),
				}},
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(pg, tfjsonpath.New("password_wo"), knownvalue.Null()),
					statecheck.ExpectKnownValue(pg, tfjsonpath.New("params").AtMapKey("ssl_mode"), knownvalue.Null()),
				},
				Check: tfresource.ComposeAggregateTestCheckFunc(
					sent(http.MethodPatch, "postgres", "second-secret"),
					sent(http.MethodPatch, "http", "second-secret-header"),
					noSecretInState("first-secret", "second-secret"),
					apiState(pg, func(b map[string]any) error {
						params, _ := b["params"].(map[string]any)
						if b["name"] != name+"-renamed" || b["host"] != "db2.example.com" || params["db_name"] != "app2" || params["ssl_mode"] != nil {
							return fmt.Errorf("API state = %v", b)
						}
						return nil
					}),
				),
			},
			{Config: updated, ConfigPlanChecks: tfresource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()}}},
			{
				// The version is configuration only; the API cannot return it.
				ResourceName:            pg,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"password_wo_version"},
			},
			{ResourceName: api, ImportState: true, ImportStateVerify: true, ImportStateVerifyIgnore: []string{"headers_wo_version"}},
		},
	})
}
