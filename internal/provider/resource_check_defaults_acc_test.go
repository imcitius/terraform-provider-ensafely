package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"testing"

	tfresource "github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"

	"github.com/imcitius/terraform-provider-ensafely/internal/acctest"
	"github.com/imcitius/terraform-provider-ensafely/internal/client"
)

const checkDefaultsAddr = "ensafely_check_defaults.test"

// checkDefaultsServerView is the full GET response, for assertions on the
// effective values next to the stored overrides.
type checkDefaultsServerView struct {
	Timeouts  map[string]string          `json:"timeouts"`
	Overrides map[string]json.RawMessage `json:"overrides"`
}

func readCheckDefaults(c *client.Client) (checkDefaultsServerView, error) {
	var v checkDefaultsServerView
	err := c.Get(context.Background(), checkDefaultsPath, &v)
	return v, err
}

// preserveCheckDefaults saves the Tenant's stored overrides and restores them
// after the test: destroy resets them, which also drops the provisioned
// Email channel other tests may rely on.
func preserveCheckDefaults(t *testing.T, c *client.Client) {
	t.Helper()
	before, err := readCheckDefaults(c)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := c.Put(context.Background(), checkDefaultsPath, before.Overrides, nil); err != nil {
			t.Errorf("restore check defaults: %v", err)
		}
	})
}

// expectOverrides compares the stored overrides with want (JSON values; a
// missing key must be null) and checks that the effective view still has
// the built-in timeouts the UI shows.
//
// c points at the test's client, which PreCheck creates.
func expectOverrides(c **client.Client, want map[string]string) tfresource.TestCheckFunc {
	return func(*terraform.State) error {
		v, err := readCheckDefaults(*c)
		if err != nil {
			return err
		}
		for _, key := range slices.Sorted(maps.Keys(v.Overrides)) {
			got, exp := string(v.Overrides[key]), want[key]
			if exp == "" {
				exp = "null"
			}
			if !jsonEqual(got, exp) {
				return fmt.Errorf("overrides.%s = %s, want %s", key, got, exp)
			}
		}
		for _, typ := range []string{"dns", "tcp", "default"} {
			if v.Timeouts[typ] == "" {
				return fmt.Errorf("effective timeouts lost built-in %q: %v", typ, v.Timeouts)
			}
		}
		return nil
	}
}

func jsonEqual(a, b string) bool {
	var x, y any
	if json.Unmarshal([]byte(a), &x) != nil || json.Unmarshal([]byte(b), &y) != nil {
		return false
	}
	xs, _ := json.Marshal(x)
	ys, _ := json.Marshal(y)
	return string(xs) == string(ys)
}

func checkDefaultsConfig(body string) string {
	return fmt.Sprintf("resource \"ensafely_check_defaults\" \"test\" {\n%s\n}\n", body)
}

// TestAccCheckDefaults runs create → empty plan → update → import → destroy
// (reset) for ensafely_check_defaults (#120): an explicit retry_count = 0 is
// not inheritance, removing attributes returns them to null, built-in
// timeouts never enter state, a removed timeout entry does not reappear, and
// destroy resets every override.
func TestAccCheckDefaults(t *testing.T) {
	var c *client.Client
	tfresource.Test(t, tfresource.TestCase{
		PreCheck: func() {
			acctest.PreCheck(t)
			c = accClient(t)
			preserveCheckDefaults(t, c)
		},
		TerraformVersionChecks:   minimumTerraform,
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy: func(s *terraform.State) error {
			if err := expectOverrides(&c, nil)(s); err != nil {
				return fmt.Errorf("destroy did not reset the check defaults: %w", err)
			}
			return nil
		},
		Steps: []tfresource.TestStep{
			// Create. The framework also asserts an empty plan after apply,
			// so 0 must not read back as null.
			{
				Config: checkDefaultsConfig(`
  retry_count       = 0
  retry_interval    = "10s"
  check_interval    = "2m"
  timeouts          = { http = "7s", tcp = "8s" }
  re_alert_interval = "1h"
  severity          = "warning"
  alert_channels    = ["Email"]
  escalation_policy = "tf-acc-policy"`),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(checkDefaultsAddr, tfjsonpath.New("id"), knownvalue.StringExact("current")),
					statecheck.ExpectKnownValue(checkDefaultsAddr, tfjsonpath.New("retry_count"), knownvalue.Int64Exact(0)),
					statecheck.ExpectKnownValue(checkDefaultsAddr, tfjsonpath.New("timeouts"), knownvalue.MapExact(map[string]knownvalue.Check{
						"http": knownvalue.StringExact("7s"), "tcp": knownvalue.StringExact("8s"),
					})),
				},
				Check: expectOverrides(&c, map[string]string{
					"retry_count": "0", "retry_interval": `"10s"`, "check_interval": `"2m"`, "timeouts": `{"http":"7s","tcp":"8s"}`,
					"re_alert_interval": `"1h"`, "severity": `"warning"`, "alert_channels": `["Email"]`, "escalation_policy": `"tf-acc-policy"`,
				}),
			},
			// Update: removed attributes and the removed tcp timeout become
			// null and stay out of state.
			{
				Config: checkDefaultsConfig(`
  timeouts = { http = "7s" }
  severity = "info"`),
				ConfigPlanChecks: tfresource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{plancheck.ExpectResourceAction(checkDefaultsAddr, plancheck.ResourceActionUpdate)},
				},
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(checkDefaultsAddr, tfjsonpath.New("retry_count"), knownvalue.Null()),
					statecheck.ExpectKnownValue(checkDefaultsAddr, tfjsonpath.New("alert_channels"), knownvalue.Null()),
					statecheck.ExpectKnownValue(checkDefaultsAddr, tfjsonpath.New("timeouts"), knownvalue.MapExact(map[string]knownvalue.Check{
						"http": knownvalue.StringExact("7s"),
					})),
				},
				Check: expectOverrides(&c, map[string]string{"timeouts": `{"http":"7s"}`, "severity": `"info"`}),
			},
			// A change made outside Terraform (the settings editor) shows up
			// as drift and is reverted.
			{
				PreConfig: func() {
					v, err := readCheckDefaults(c)
					if err != nil {
						t.Fatal(err)
					}
					body := maps.Clone(v.Overrides)
					body["severity"] = json.RawMessage(`"critical"`)
					if err := c.Put(context.Background(), checkDefaultsPath, body, nil); err != nil {
						t.Fatal(err)
					}
				},
				Config: checkDefaultsConfig(`
  timeouts = { http = "7s" }
  severity = "info"`),
				ConfigPlanChecks: tfresource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{plancheck.ExpectResourceAction(checkDefaultsAddr, plancheck.ResourceActionUpdate)},
				},
				Check: expectOverrides(&c, map[string]string{"timeouts": `{"http":"7s"}`, "severity": `"info"`}),
			},
			{
				ResourceName:                         checkDefaultsAddr,
				ImportState:                          true,
				ImportStateId:                        "current",
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: "id",
			},
			// Destroy runs automatically after the last step.
		},
	})
}

// TestAccCheckDefaultsInheritedByChecks is the shared T4/T10 test (#114,
// #120): changing ensafely_check_defaults produces no diff on a Check that
// leaves its inherited fields null.
func TestAccCheckDefaultsInheritedByChecks(t *testing.T) {
	project := accProject("defaults")
	config := func(defaults string) string {
		return checkDefaultsConfig(defaults) +
			checkConfig(fmt.Sprintf("name = \"tf defaults\"\nproject = %q\ntcp { host = \"example.com\"; port = 443 }", project))
	}
	noCheckChange := []plancheck.PlanCheck{
		plancheck.ExpectResourceAction(checkDefaultsAddr, plancheck.ResourceActionUpdate),
		plancheck.ExpectResourceAction(checkAddr, plancheck.ResourceActionNoop),
	}
	tfresource.Test(t, tfresource.TestCase{
		PreCheck: func() {
			acctest.PreCheck(t)
			preserveCheckDefaults(t, accClient(t))
		},
		TerraformVersionChecks:   minimumTerraform,
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             checkDestroyed(t),
		Steps: []tfresource.TestStep{
			{
				Config: config(`
  severity       = "warning"
  retry_count    = 2
  check_interval = "5m"`),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(checkAddr, tfjsonpath.New("severity"), knownvalue.Null()),
					statecheck.ExpectKnownValue(checkAddr, tfjsonpath.New("retry_count"), knownvalue.Null()),
					statecheck.ExpectKnownValue(checkAddr, tfjsonpath.New("interval"), knownvalue.Null()),
				},
			},
			// Changing every inherited default: only the defaults change.
			{
				Config: config(`
  severity          = "info"
  retry_count       = 4
  retry_interval    = "20s"
  check_interval    = "7m"
  re_alert_interval = "3h"
  alert_channels    = ["tf-acc-default"]`),
				ConfigPlanChecks: tfresource.ConfigPlanChecks{
					PreApply:             noCheckChange,
					PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
				},
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(checkAddr, tfjsonpath.New("severity"), knownvalue.Null()),
					statecheck.ExpectKnownValue(checkAddr, tfjsonpath.New("alert_channels"), knownvalue.Null()),
				},
			},
			// Removing the defaults again (back to built-ins): still no diff.
			{
				Config: config(`
  severity = "critical"`),
				ConfigPlanChecks: tfresource.ConfigPlanChecks{
					PreApply:             noCheckChange,
					PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
				},
			},
		},
	})
}
