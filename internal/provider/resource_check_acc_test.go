package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-testing/compare"
	tfresource "github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"

	"github.com/imcitius/terraform-provider-ensafely/internal/acctest"
	"github.com/imcitius/terraform-provider-ensafely/internal/client"
)

const checkAddr = "ensafely_check.test"

func accClient(t *testing.T) *client.Client {
	t.Helper()
	c, err := client.New(client.Config{Endpoint: os.Getenv(EnvEndpoint), APIKey: os.Getenv(EnvAPIKey)})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func accProject(kind string) string {
	return fmt.Sprintf("tf-check-%s-%d", kind, time.Now().UnixNano())
}

// checkConfig renders one ensafely_check with the given body. HCL has no
// statement separator, so "; " in the compact test blocks becomes a newline.
func checkConfig(body string) string {
	body = strings.ReplaceAll(body, "; ", "\n")
	body = strings.ReplaceAll(body, "{ ", "{\n")
	body = strings.ReplaceAll(body, " }", "\n}")
	return "resource \"ensafely_check\" \"test\" {\n" + body + "\n}\n"
}

// checkDestroyed asserts that every ensafely_check in state is gone.
func checkDestroyed(t *testing.T) func(*terraform.State) error {
	return func(s *terraform.State) error {
		c := accClient(t)
		for _, rs := range s.RootModule().Resources {
			if rs.Type != "ensafely_check" {
				continue
			}
			err := c.Get(context.Background(), checkPath(rs.Primary.ID), nil)
			if err == nil {
				return fmt.Errorf("check %s still exists", rs.Primary.ID)
			}
			if !client.IsNotFound(err) {
				return err
			}
		}
		return nil
	}
}

type accTypeCase struct {
	block            string
	create, update   string
	createChecks     []statecheck.StateCheck
	updateChecks     []statecheck.StateCheck
	importIgnoreKeys []string
	// secrets must never appear in state (#115).
	secrets []string
	// createStored and updateStored, when set, report whether the API holds
	// the type's secret after the step.
	createStored, updateStored *bool
}

func ptrTo[T any](v T) *T { return &v }

// storedSecret reports whether the API holds the secret of a check type: a
// read returns "****" for a stored secret and omits it otherwise.
func storedSecret(block string, j *checkJSON) bool {
	masked := func(s *string) bool { return s != nil && *s == "****" }
	switch block {
	case "pgsql_query":
		return j.PgSQL != nil && masked(j.PgSQL.Password)
	case "mysql_query":
		return j.MySQL != nil && masked(j.MySQL.Password)
	case "redis":
		return masked(j.RedisPassword)
	case "smtp":
		return masked(j.SMTPPassword)
	case "mongodb":
		return masked(j.MongoDBURI)
	}
	return false
}

// accStepCheck asserts that no secret reached state and, when want is set,
// whether the API holds the type's secret.
func accStepCheck(t *testing.T, tc accTypeCase, want *bool) tfresource.TestCheckFunc {
	return func(s *terraform.State) error {
		if err := noSecretInState(tc.secrets...)(s); err != nil {
			return err
		}
		if want == nil {
			return nil
		}
		var body checkJSON
		if err := accClient(t).Get(context.Background(), checkPath(s.RootModule().Resources[checkAddr].Primary.ID), &body); err != nil {
			return err
		}
		if got := storedSecret(tc.block, &body); got != *want {
			return fmt.Errorf("%s: API holds the secret = %v, want %v", tc.block, got, *want)
		}
		return nil
	}
}

func blockPath(block, name string) tfjsonpath.Path { return tfjsonpath.New(block).AtMapKey(name) }

var accTypeCases = []accTypeCase{
	{
		block: "http",
		create: `http {
  url                   = "https://example.com/health"
  timeout               = "5s"
  answer                = "ok"
  answer_present        = true
  status_codes          = [200, 204]
  ssl_expiration_period = "720h"
  basic_auth_user       = "monitor"
}`,
		update: `http {
  url                   = "https://example.com/ready"
  status_codes          = [200]
  skip_check_ssl        = true
  stop_follow_redirects = true
}`,
		createChecks: []statecheck.StateCheck{
			statecheck.ExpectKnownValue(checkAddr, blockPath("http", "answer_present"), knownvalue.Bool(true)),
			statecheck.ExpectKnownValue(checkAddr, blockPath("http", "basic_auth_user"), knownvalue.StringExact("monitor")),
		},
		updateChecks: []statecheck.StateCheck{
			statecheck.ExpectKnownValue(checkAddr, blockPath("http", "answer"), knownvalue.Null()),
			statecheck.ExpectKnownValue(checkAddr, blockPath("http", "basic_auth_user"), knownvalue.Null()),
			statecheck.ExpectKnownValue(checkAddr, blockPath("http", "skip_check_ssl"), knownvalue.Bool(true)),
		},
	},
	{
		block:        "tcp",
		create:       `tcp { host = "example.com"; port = 443; timeout = "3s" }`,
		update:       `tcp { host = "example.org"; port = 8443 }`,
		createChecks: []statecheck.StateCheck{statecheck.ExpectKnownValue(checkAddr, blockPath("tcp", "port"), knownvalue.Int64Exact(443))},
		updateChecks: []statecheck.StateCheck{statecheck.ExpectKnownValue(checkAddr, blockPath("tcp", "timeout"), knownvalue.Null())},
	},
	{
		block:        "icmp",
		create:       `icmp { host = "example.com"; count = 3; timeout = "2s" }`,
		update:       `icmp { host = "example.org" }`,
		createChecks: []statecheck.StateCheck{statecheck.ExpectKnownValue(checkAddr, blockPath("icmp", "count"), knownvalue.Int64Exact(3))},
		updateChecks: []statecheck.StateCheck{statecheck.ExpectKnownValue(checkAddr, blockPath("icmp", "count"), knownvalue.Null())},
	},
	{
		block:        "dns",
		create:       `dns { domain = "example.com"; record_type = "MX"; expected = "mail"; host = "1.1.1.1:53"; timeout = "2s" }`,
		update:       `dns { domain = "example.org" }`,
		createChecks: []statecheck.StateCheck{statecheck.ExpectKnownValue(checkAddr, blockPath("dns", "record_type"), knownvalue.StringExact("MX"))},
		updateChecks: []statecheck.StateCheck{statecheck.ExpectKnownValue(checkAddr, blockPath("dns", "record_type"), knownvalue.Null())},
	},
	{
		block:        "ssl_cert",
		create:       `ssl_cert { host = "example.com"; port = 443; expiry_warning_days = 14; validate_chain = true; timeout = "4s" }`,
		update:       `ssl_cert { host = "example.org" }`,
		createChecks: []statecheck.StateCheck{statecheck.ExpectKnownValue(checkAddr, blockPath("ssl_cert", "validate_chain"), knownvalue.Bool(true))},
		updateChecks: []statecheck.StateCheck{statecheck.ExpectKnownValue(checkAddr, blockPath("ssl_cert", "validate_chain"), knownvalue.Bool(false))},
	},
	{
		block:        "domain_expiry",
		create:       `domain_expiry { domain = "example.com"; expiry_warning_days = 30; timeout = "10s" }`,
		update:       `domain_expiry { domain = "example.org" }`,
		createChecks: []statecheck.StateCheck{statecheck.ExpectKnownValue(checkAddr, blockPath("domain_expiry", "expiry_warning_days"), knownvalue.Int64Exact(30))},
		updateChecks: []statecheck.StateCheck{statecheck.ExpectKnownValue(checkAddr, blockPath("domain_expiry", "expiry_warning_days"), knownvalue.Null())},
	},
	{
		block:        "passive",
		create:       `passive { timeout = "15m" }`,
		update:       `passive {}`,
		createChecks: []statecheck.StateCheck{statecheck.ExpectKnownValue(checkAddr, blockPath("passive", "timeout"), knownvalue.StringExact("15m"))},
		updateChecks: []statecheck.StateCheck{statecheck.ExpectKnownValue(checkAddr, blockPath("passive", "timeout"), knownvalue.Null())},
	},
	// #115 types. Secrets are sent on create, rotated (version bump) or
	// cleared (bump without a value) on update.
	{
		block: "pgsql_query",
		create: `pgsql_query {
  host                = "db.example.com"
  port                = 6432
  username            = "monitor"
  db_name             = "shop"
  ssl_mode            = "require"
  query               = "SELECT 1"
  response            = "1"
  timeout             = "5s"
  password_wo         = "pg-secret-1"
  password_wo_version = 1
}`,
		update: `pgsql_query { host = "db.example.org"; password_wo = "pg-secret-2"; password_wo_version = 2 }`,
		createChecks: []statecheck.StateCheck{
			statecheck.ExpectKnownValue(checkAddr, blockPath("pgsql_query", "ssl_mode"), knownvalue.StringExact("require")),
			statecheck.ExpectKnownValue(checkAddr, blockPath("pgsql_query", "password_wo"), knownvalue.Null()),
			statecheck.ExpectKnownValue(checkAddr, blockPath("pgsql_query", "password_wo_version"), knownvalue.Int64Exact(1)),
		},
		updateChecks: []statecheck.StateCheck{
			statecheck.ExpectKnownValue(checkAddr, blockPath("pgsql_query", "username"), knownvalue.Null()),
			statecheck.ExpectKnownValue(checkAddr, blockPath("pgsql_query", "query"), knownvalue.Null()),
		},
		importIgnoreKeys: []string{"pgsql_query.password_wo_version"},
		secrets:          []string{"pg-secret-1", "pg-secret-2"},
		createStored:     ptrTo(true), updateStored: ptrTo(true),
	},
	{
		block: "mysql_query",
		create: `mysql_query {
  host                = "db.example.com"
  port                = 3307
  username            = "monitor"
  db_name             = "shop"
  query               = "SELECT 2"
  response            = "2"
  timeout             = "5s"
  password_wo         = "my-secret-1"
  password_wo_version = 1
}`,
		update: `mysql_query { host = "db.example.org"; password_wo_version = 2 }`,
		createChecks: []statecheck.StateCheck{
			statecheck.ExpectKnownValue(checkAddr, blockPath("mysql_query", "db_name"), knownvalue.StringExact("shop")),
		},
		updateChecks: []statecheck.StateCheck{
			statecheck.ExpectKnownValue(checkAddr, blockPath("mysql_query", "port"), knownvalue.Null()),
			statecheck.ExpectKnownValue(checkAddr, blockPath("mysql_query", "password_wo_version"), knownvalue.Int64Exact(2)),
		},
		importIgnoreKeys: []string{"mysql_query.password_wo_version"},
		secrets:          []string{"my-secret-1"},
		createStored:     ptrTo(true), updateStored: ptrTo(false),
	},
	{
		block:            "redis",
		create:           `redis { host = "cache.example.com"; port = 6380; db = 2; timeout = "2s"; password_wo = "redis-secret-1"; password_wo_version = 1 }`,
		update:           `redis { host = "cache.example.org"; password_wo = "redis-secret-1"; password_wo_version = 1 }`,
		createChecks:     []statecheck.StateCheck{statecheck.ExpectKnownValue(checkAddr, blockPath("redis", "db"), knownvalue.Int64Exact(2))},
		updateChecks:     []statecheck.StateCheck{statecheck.ExpectKnownValue(checkAddr, blockPath("redis", "db"), knownvalue.Null())},
		importIgnoreKeys: []string{"redis.password_wo_version"},
		secrets:          []string{"redis-secret-1"},
		createStored:     ptrTo(true), updateStored: ptrTo(true),
	},
	{
		block:  "mongodb",
		create: `mongodb { timeout = "5s"; uri_wo = "mongodb://monitor:mongo-secret-1@mongo.example.com:27017/app"; uri_wo_version = 1 }`,
		update: `mongodb { uri_wo = "mongodb://monitor:mongo-secret-2@mongo.example.com:27017/app"; uri_wo_version = 2 }`,
		createChecks: []statecheck.StateCheck{
			statecheck.ExpectKnownValue(checkAddr, blockPath("mongodb", "timeout"), knownvalue.StringExact("5s")),
			statecheck.ExpectKnownValue(checkAddr, blockPath("mongodb", "uri_wo"), knownvalue.Null()),
		},
		updateChecks:     []statecheck.StateCheck{statecheck.ExpectKnownValue(checkAddr, blockPath("mongodb", "timeout"), knownvalue.Null())},
		importIgnoreKeys: []string{"mongodb.uri_wo_version"},
		secrets:          []string{"mongo-secret-1", "mongo-secret-2", "mongo.example.com"},
		createStored:     ptrTo(true), updateStored: ptrTo(true),
	},
	{
		block:        "ssh",
		create:       `ssh { host = "bastion.example.com"; port = 2222; expect_banner = "OpenSSH"; timeout = "3s" }`,
		update:       `ssh { host = "bastion.example.org" }`,
		createChecks: []statecheck.StateCheck{statecheck.ExpectKnownValue(checkAddr, blockPath("ssh", "expect_banner"), knownvalue.StringExact("OpenSSH"))},
		updateChecks: []statecheck.StateCheck{statecheck.ExpectKnownValue(checkAddr, blockPath("ssh", "port"), knownvalue.Null())},
	},
	{
		block: "smtp",
		create: `smtp {
  host                = "mail.example.com"
  port                = 587
  starttls            = true
  username            = "monitor"
  timeout             = "5s"
  password_wo         = "smtp-secret-1"
  password_wo_version = 1
}`,
		update:           `smtp { host = "mail.example.org"; port = 25; password_wo_version = 2 }`,
		createChecks:     []statecheck.StateCheck{statecheck.ExpectKnownValue(checkAddr, blockPath("smtp", "starttls"), knownvalue.Bool(true))},
		updateChecks:     []statecheck.StateCheck{statecheck.ExpectKnownValue(checkAddr, blockPath("smtp", "username"), knownvalue.Null())},
		importIgnoreKeys: []string{"smtp.password_wo_version"},
		secrets:          []string{"smtp-secret-1"},
		createStored:     ptrTo(true), updateStored: ptrTo(false),
	},
	{
		block:        "grpc_health",
		create:       `grpc_health { host = "grpc.example.com:443"; use_tls = true; timeout = "2s" }`,
		update:       `grpc_health { host = "grpc.example.org:50051" }`,
		createChecks: []statecheck.StateCheck{statecheck.ExpectKnownValue(checkAddr, blockPath("grpc_health", "use_tls"), knownvalue.Bool(true))},
		updateChecks: []statecheck.StateCheck{statecheck.ExpectKnownValue(checkAddr, blockPath("grpc_health", "use_tls"), knownvalue.Bool(false))},
	},
	{
		block:        "websocket",
		create:       `websocket { url = "wss://ws.example.com/socket"; timeout = "4s" }`,
		update:       `websocket { url = "wss://ws.example.org/socket" }`,
		createChecks: []statecheck.StateCheck{statecheck.ExpectKnownValue(checkAddr, blockPath("websocket", "timeout"), knownvalue.StringExact("4s"))},
		updateChecks: []statecheck.StateCheck{statecheck.ExpectKnownValue(checkAddr, blockPath("websocket", "url"), knownvalue.StringExact("wss://ws.example.org/socket"))},
	},
}

// TestAccCheckTypes runs create → empty plan → update → import → destroy for
// every type block (#114). Create sets the common fields, update changes
// some and returns others to null (inherit).
func TestAccCheckTypes(t *testing.T) {
	for _, tc := range accTypeCases {
		t.Run(tc.block, func(t *testing.T) {
			project := accProject(tc.block)
			create := checkConfig(fmt.Sprintf(`
  name              = "tf %[1]s"
  project           = %[2]q
  group             = "acc"
  description       = "created by terraform"
  enabled           = false
  interval          = "10m"
  severity          = "warning"
  alert_channels    = ["tf-acc-a", "tf-acc-b"]
  re_alert_interval = "2h"
  retry_count       = 2
  retry_interval    = "10s"
  edge_min_unhealthy = 2
  %[3]s`, tc.block, project, tc.create))
			update := checkConfig(fmt.Sprintf(`
  name     = "tf %[1]s renamed"
  project  = %[2]q
  interval = "15m"
  severity = "info"
  %[3]s`, tc.block, project, tc.update))
			createChecks := append([]statecheck.StateCheck{
				statecheck.ExpectKnownValue(checkAddr, tfjsonpath.New("enabled"), knownvalue.Bool(false)),
				statecheck.ExpectKnownValue(checkAddr, tfjsonpath.New("retry_count"), knownvalue.Int64Exact(2)),
				statecheck.ExpectKnownValue(checkAddr, tfjsonpath.New("alert_channels"), knownvalue.SetExact([]knownvalue.Check{
					knownvalue.StringExact("tf-acc-a"), knownvalue.StringExact("tf-acc-b")})),
			}, tc.createChecks...)
			updateChecks := append([]statecheck.StateCheck{
				statecheck.ExpectKnownValue(checkAddr, tfjsonpath.New("enabled"), knownvalue.Bool(true)),
				statecheck.ExpectKnownValue(checkAddr, tfjsonpath.New("group"), knownvalue.Null()),
				statecheck.ExpectKnownValue(checkAddr, tfjsonpath.New("alert_channels"), knownvalue.Null()),
				statecheck.ExpectKnownValue(checkAddr, tfjsonpath.New("retry_count"), knownvalue.Null()),
				statecheck.ExpectKnownValue(checkAddr, tfjsonpath.New("re_alert_interval"), knownvalue.Null()),
			}, tc.updateChecks...)
			for _, b := range checkTypes {
				if b.block != tc.block {
					createChecks = append(createChecks, statecheck.ExpectKnownValue(checkAddr, tfjsonpath.New(b.block), knownvalue.Null()))
				}
			}
			tfresource.Test(t, tfresource.TestCase{
				PreCheck:                 func() { acctest.PreCheck(t) },
				TerraformVersionChecks:   minimumTerraform,
				ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
				CheckDestroy:             checkDestroyed(t),
				Steps: []tfresource.TestStep{
					// Create; the framework also asserts an empty plan after apply.
					{Config: create, ConfigStateChecks: createChecks, Check: accStepCheck(t, tc, tc.createStored)},
					// Refresh + plan with no change.
					{Config: create, ConfigPlanChecks: tfresource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()}}},
					{
						Config: update,
						ConfigPlanChecks: tfresource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
							plancheck.ExpectResourceAction(checkAddr, plancheck.ResourceActionUpdate)}},
						ConfigStateChecks: updateChecks,
						Check:             accStepCheck(t, tc, tc.updateStored),
					},
					{ResourceName: checkAddr, ImportState: true, ImportStateVerify: true, ImportStateVerifyIgnore: tc.importIgnoreKeys},
					{Config: update, ConfigPlanChecks: tfresource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()}}},
				},
			})
		})
	}
}

// TestAccCheckTypeChangeReplaces checks that switching the type block
// replaces the check, while a change inside the block is in place.
func TestAccCheckTypeChangeReplaces(t *testing.T) {
	project := accProject("replace")
	config := func(block string) string {
		return checkConfig(fmt.Sprintf("name = \"tf replace\"\nproject = %q\nseverity = \"warning\"\n%s", project, block))
	}
	var firstID string
	tfresource.Test(t, tfresource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		TerraformVersionChecks:   minimumTerraform,
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             checkDestroyed(t),
		Steps: []tfresource.TestStep{
			{
				Config: config(`tcp { host = "example.com"; port = 443 }`),
				Check: func(s *terraform.State) error {
					firstID = s.RootModule().Resources[checkAddr].Primary.ID
					return nil
				},
			},
			{
				Config: config(`tcp { host = "example.com"; port = 8443 }`),
				ConfigPlanChecks: tfresource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
					plancheck.ExpectResourceAction(checkAddr, plancheck.ResourceActionUpdate)}},
			},
			{
				Config: config(`icmp { host = "example.com" }`),
				ConfigPlanChecks: tfresource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
					plancheck.ExpectResourceAction(checkAddr, plancheck.ResourceActionDestroyBeforeCreate)}},
				Check: func(s *terraform.State) error {
					if id := s.RootModule().Resources[checkAddr].Primary.ID; id == firstID {
						return fmt.Errorf("type change kept check %s", id)
					}
					if err := accClient(t).Get(context.Background(), checkPath(firstID), nil); !client.IsNotFound(err) {
						return fmt.Errorf("replaced check %s still exists (err=%v)", firstID, err)
					}
					return nil
				},
			},
		},
	})
}

// TestAccCheckInheritsDefaults checks that a check leaving inheritable
// fields null stores no overrides, and that changing the Tenant's check
// defaults produces no diff (#110, #114).
func TestAccCheckInheritsDefaults(t *testing.T) {
	project := accProject("inherit")
	config := checkConfig(fmt.Sprintf("name = \"tf inherit\"\nproject = %q\ntcp { host = \"example.com\"; port = 443 }", project))
	var c *client.Client
	var original json.RawMessage
	var id string
	tfresource.Test(t, tfresource.TestCase{
		PreCheck: func() {
			acctest.PreCheck(t)
			c = accClient(t)
			if err := c.Get(context.Background(), "/api/settings/check-defaults", &original); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := c.Put(context.Background(), "/api/settings/check-defaults", original, nil); err != nil {
					t.Errorf("restore check defaults: %v", err)
				}
			})
		},
		TerraformVersionChecks:   minimumTerraform,
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             checkDestroyed(t),
		Steps: []tfresource.TestStep{
			{
				Config: config,
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(checkAddr, tfjsonpath.New("interval"), knownvalue.Null()),
					statecheck.ExpectKnownValue(checkAddr, tfjsonpath.New("severity"), knownvalue.Null()),
					statecheck.ExpectKnownValue(checkAddr, tfjsonpath.New("alert_channels"), knownvalue.Null()),
					statecheck.ExpectKnownValue(checkAddr, tfjsonpath.New("retry_count"), knownvalue.Null()),
				},
				Check: func(s *terraform.State) error {
					id = s.RootModule().Resources[checkAddr].Primary.ID
					var stored map[string]any
					if err := c.Get(context.Background(), checkPath(id), &stored); err != nil {
						return err
					}
					for _, field := range []string{"duration", "severity", "alert_channels", "re_alert_interval", "retry_count", "retry_interval", "escalation_policy_name"} {
						if v, ok := stored[field]; ok && v != "" {
							return fmt.Errorf("check stores %s = %v; an inherited field must not be materialized", field, v)
						}
					}
					return nil
				},
			},
			{
				PreConfig: func() {
					defaults := map[string]any{
						"check_interval": "7m", "re_alert_interval": "3h", "severity": "info", "retry_count": 4,
						"retry_interval": "20s", "alert_channels": []string{"tf-acc-default"},
					}
					if err := c.Put(context.Background(), "/api/settings/check-defaults", defaults, nil); err != nil {
						t.Fatal(err)
					}
				},
				Config:           config,
				ConfigPlanChecks: tfresource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()}},
			},
		},
	})
}

// TestAccCheckWriteOnlySecrets checks the http secrets through Terraform
// and the API: they never reach state, an unchanged version sends nothing,
// a bump sends the new value, and a bump without a value clears it.
func TestAccCheckWriteOnlySecrets(t *testing.T) {
	project := accProject("secrets")
	config := func(secrets string) string {
		return checkConfig(fmt.Sprintf(`
name     = "tf secrets"
project  = %q
severity = "warning"
http {
  url             = "https://example.com"
  basic_auth_user = "monitor"
  %s
}`, project, secrets))
	}
	stored := func(wantPassword bool, wantHeaders ...string) func(*terraform.State) error {
		return func(s *terraform.State) error {
			var body checkJSON
			if err := accClient(t).Get(context.Background(), checkPath(s.RootModule().Resources[checkAddr].Primary.ID), &body); err != nil {
				return err
			}
			hasPassword := body.Auth != nil && body.Auth.Password != nil && *body.Auth.Password != ""
			if hasPassword != wantPassword {
				return fmt.Errorf("stored password present = %v, want %v", hasPassword, wantPassword)
			}
			var names []string
			if body.Headers != nil {
				for _, h := range *body.Headers {
					for name := range h {
						names = append(names, name)
					}
				}
			}
			if strings.Join(names, ",") != strings.Join(wantHeaders, ",") {
				return fmt.Errorf("stored headers %v, want %v", names, wantHeaders)
			}
			return nil
		}
	}
	noSecretInState := func(secrets ...string) func(*terraform.State) error {
		return func(s *terraform.State) error {
			for key, value := range s.RootModule().Resources[checkAddr].Primary.Attributes {
				for _, secret := range secrets {
					if strings.Contains(value, secret) {
						return fmt.Errorf("state attribute %s contains a secret", key)
					}
				}
			}
			return nil
		}
	}
	tfresource.Test(t, tfresource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		TerraformVersionChecks:   minimumTerraform,
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             checkDestroyed(t),
		Steps: []tfresource.TestStep{
			{
				Config: config(`
  basic_auth_password_wo         = "first-password"
  basic_auth_password_wo_version = 1
  headers_wo                     = { "X-Api-Key" = "first-key" }
  headers_wo_version             = 1`),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(checkAddr, blockPath("http", "basic_auth_password_wo"), knownvalue.Null()),
					statecheck.ExpectKnownValue(checkAddr, blockPath("http", "headers_wo"), knownvalue.Null()),
					statecheck.ExpectKnownValue(checkAddr, blockPath("http", "basic_auth_password_wo_version"), knownvalue.Int64Exact(1)),
				},
				Check: tfresource.ComposeTestCheckFunc(stored(true, "X-Api-Key"), noSecretInState("first-password", "first-key")),
			},
			// New values without a version bump: nothing to do.
			{
				Config: config(`
  basic_auth_password_wo         = "second-password"
  basic_auth_password_wo_version = 1
  headers_wo                     = { "X-Other" = "second-key" }
  headers_wo_version             = 1`),
				ConfigPlanChecks: tfresource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()}},
			},
			// Bump the header version only: new headers, password kept.
			{
				Config: config(`
  basic_auth_password_wo         = "second-password"
  basic_auth_password_wo_version = 1
  headers_wo                     = { "X-Other" = "second-key" }
  headers_wo_version             = 2`),
				ConfigPlanChecks: tfresource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
					plancheck.ExpectResourceAction(checkAddr, plancheck.ResourceActionUpdate)}},
				Check: tfresource.ComposeTestCheckFunc(stored(true, "X-Other"), noSecretInState("second-password", "second-key")),
			},
			// Remove the password and bump its version: the secret is cleared.
			{
				Config: config(`
  basic_auth_password_wo_version = 2
  headers_wo                     = { "X-Other" = "second-key" }
  headers_wo_version             = 2`),
				Check: stored(false, "X-Other"),
			},
			{
				ResourceName: checkAddr, ImportState: true, ImportStateVerify: true,
				ImportStateVerifyIgnore: []string{"http.basic_auth_password_wo_version", "http.headers_wo_version"},
			},
		},
	})
}

// TestAccCheckDataSource reads a managed check by UUID.
func TestAccCheckDataSource(t *testing.T) {
	project := accProject("data")
	config := checkConfig(fmt.Sprintf(`
name     = "tf data"
project  = %q
severity = "warning"
interval = "10m"
dns { domain = "example.com"; record_type = "TXT" }`, project)) + `
data "ensafely_check" "test" {
  id = ensafely_check.test.id
}
`
	tfresource.Test(t, tfresource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		TerraformVersionChecks:   minimumTerraform,
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             checkDestroyed(t),
		Steps: []tfresource.TestStep{{
			Config: config,
			ConfigStateChecks: []statecheck.StateCheck{
				statecheck.ExpectKnownValue("data.ensafely_check.test", tfjsonpath.New("type"), knownvalue.StringExact("dns")),
				statecheck.ExpectKnownValue("data.ensafely_check.test", tfjsonpath.New("interval"), knownvalue.StringExact("10m")),
				statecheck.ExpectKnownValue("data.ensafely_check.test", tfjsonpath.New("retry_count"), knownvalue.Null()),
				statecheck.ExpectKnownValue("data.ensafely_check.test", blockPath("dns", "record_type"), knownvalue.StringExact("TXT")),
				statecheck.ExpectKnownValue("data.ensafely_check.test", tfjsonpath.New("http"), knownvalue.Null()),
				statecheck.CompareValuePairs("data.ensafely_check.test", tfjsonpath.New("id"), checkAddr, tfjsonpath.New("id"), compare.ValuesSame()),
			},
		}},
	})
}

// TestAccCheckConnection covers connection_id (#115): a pgsql_query check
// that takes host and credentials from an ensafely_connection round-trips
// with an empty plan, updates in place, imports, switches to inline
// credentials and back (clearing the stored inline password), and rejects
// inline credentials together with connection_id.
func TestAccCheckConnection(t *testing.T) {
	project := accProject("connection")
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	connection := fmt.Sprintf(`
resource "ensafely_connection" "db" {
  name                = "tf-acc-check-db-%s"
  type                = "postgres"
  host                = "db.example.com"
  port                = 5432
  username            = "monitor"
  password_wo         = "conn-secret-1"
  password_wo_version = 1
  params = {
    db_name = "shop"
  }
}
`, suffix)
	config := func(body string) string {
		return connection + checkConfig(fmt.Sprintf("name = \"tf connection\"\nproject = %q\nseverity = \"warning\"\n%s", project, body))
	}
	viaConnection := config(`connection_id = ensafely_connection.db.id
pgsql_query { query = "SELECT 1" }`)
	viaConnectionUpdated := config(`connection_id = ensafely_connection.db.id
pgsql_query { query = "SELECT 2"; password_wo_version = 1 }`)
	inline := config(`pgsql_query {
  host                = "db.example.org"
  username            = "inline"
  query               = "SELECT 2"
  password_wo         = "inline-secret-1"
  password_wo_version = 1
}`)
	stored := func(wantConnection bool, wantPassword bool) tfresource.TestCheckFunc {
		return func(s *terraform.State) error {
			var body checkJSON
			if err := accClient(t).Get(context.Background(), checkPath(s.RootModule().Resources[checkAddr].Primary.ID), &body); err != nil {
				return err
			}
			want := ""
			if wantConnection {
				want = s.RootModule().Resources["ensafely_connection.db"].Primary.ID
			}
			got := ""
			if body.ConnectionID != nil {
				got = *body.ConnectionID
			}
			if got != want {
				return fmt.Errorf("stored connection_id = %q, want %q", got, want)
			}
			if has := storedSecret("pgsql_query", &body); has != wantPassword {
				return fmt.Errorf("stored inline password = %v, want %v", has, wantPassword)
			}
			return nil
		}
	}
	sameConnection := statecheck.CompareValuePairs(checkAddr, tfjsonpath.New("connection_id"),
		"ensafely_connection.db", tfjsonpath.New("id"), compare.ValuesSame())
	tfresource.Test(t, tfresource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		TerraformVersionChecks:   minimumTerraform,
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             checkDestroyed(t),
		Steps: []tfresource.TestStep{
			// Inline credentials together with connection_id are rejected.
			{
				Config: config(`connection_id = "6c1f0e8a-2b7d-4c3e-9f10-8a2b3c4d5e6f"
pgsql_query { username = "inline"; password_wo = "x"; password_wo_version = 1 }`),
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`Conflicting credentials`),
			},
			{
				Config: viaConnection,
				ConfigStateChecks: []statecheck.StateCheck{
					sameConnection,
					statecheck.ExpectKnownValue(checkAddr, blockPath("pgsql_query", "host"), knownvalue.Null()),
				},
				Check: tfresource.ComposeTestCheckFunc(stored(true, false), noSecretInState("conn-secret-1")),
			},
			{Config: viaConnection, ConfigPlanChecks: tfresource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()}}},
			{
				Config: viaConnectionUpdated,
				ConfigPlanChecks: tfresource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
					plancheck.ExpectResourceAction(checkAddr, plancheck.ResourceActionUpdate)}},
				ConfigStateChecks: []statecheck.StateCheck{sameConnection,
					statecheck.ExpectKnownValue(checkAddr, blockPath("pgsql_query", "query"), knownvalue.StringExact("SELECT 2"))},
				Check: stored(true, false),
			},
			{ResourceName: checkAddr, ImportState: true, ImportStateVerify: true,
				ImportStateVerifyIgnore: []string{"pgsql_query.password_wo_version"}},
			{Config: viaConnectionUpdated, ConfigPlanChecks: tfresource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()}}},
			// Inline credentials: the reference is removed and the password is
			// sent although its version is unchanged.
			{
				Config: inline,
				ConfigPlanChecks: tfresource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
					plancheck.ExpectResourceAction(checkAddr, plancheck.ResourceActionUpdate)}},
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(checkAddr, tfjsonpath.New("connection_id"), knownvalue.Null())},
				Check: tfresource.ComposeTestCheckFunc(stored(false, true), noSecretInState("inline-secret-1", "conn-secret-1")),
			},
			{Config: inline, ConfigPlanChecks: tfresource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()}}},
			// Back to the Connection: the inline password is cleared.
			{
				Config:            viaConnectionUpdated,
				ConfigStateChecks: []statecheck.StateCheck{sameConnection},
				Check:             stored(true, false),
			},
			{Config: viaConnectionUpdated, ConfigPlanChecks: tfresource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()}}},
		},
	})
}
