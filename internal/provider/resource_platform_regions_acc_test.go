package provider

import (
	"context"
	"fmt"
	"regexp"
	"slices"
	"strings"
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

const platformRegionsAddr = "ensafely_platform_regions.test"

// acc-bootstrap registers acctest.PlatformRegions before it creates the
// shared acceptance Tenant. That Tenant is on the unlimited seed plan, so the
// region tests run on their own Free-plan Tenant (two regions, default
// eu-paris); see useFreeTenant.

// useFreeTenant creates a disposable Tenant on the signup (Free) plan and
// points the provider and accClient at it for the rest of t. Call it from
// PreCheck, after acctest.PreCheck.
func useFreeTenant(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	creds, err := acctest.Bootstrap(ctx, acctest.Endpoint(), acctest.BootstrapOptions{})
	if err != nil {
		t.Fatalf("create a Free-plan test Tenant: %v", err)
	}
	t.Setenv(EnvAPIKey, creds.APIKey)
}

func platformRegionsConfig(regions ...string) string {
	quoted := make([]string, len(regions))
	for i, r := range regions {
		quoted[i] = fmt.Sprintf("%q", r)
	}
	return fmt.Sprintf("resource \"ensafely_platform_regions\" \"test\" {\n  regions = [%s]\n}\n", strings.Join(quoted, ", "))
}

func selectedRegions(c *client.Client) ([]string, error) {
	var out platformRegionsJSON
	if err := c.Get(context.Background(), platformRegionsPath, &out); err != nil {
		return nil, err
	}
	return slices.Sorted(slices.Values(out.Regions)), nil
}

// expectSelectedRegions checks the server's selection; c points at the
// test's client, which PreCheck creates.
func expectSelectedRegions(c **client.Client, want ...string) tfresource.TestCheckFunc {
	return func(*terraform.State) error {
		got, err := selectedRegions(*c)
		if err != nil {
			return err
		}
		if want = slices.Sorted(slices.Values(want)); !slices.Equal(got, want) {
			return fmt.Errorf("selected regions = %v, want %v", got, want)
		}
		return nil
	}
}

func regionSet(regions ...string) knownvalue.Check {
	checks := make([]knownvalue.Check, len(regions))
	for i, r := range regions {
		checks[i] = knownvalue.StringExact(r)
	}
	return knownvalue.SetExact(checks)
}

// TestAccPlatformRegions runs create → empty plan → update → import →
// destroy for ensafely_platform_regions (#120). Selecting more regions than
// the Free plan allows fails with a readable error, and destroy restores the
// Plan's default regions.
func TestAccPlatformRegions(t *testing.T) {
	var c *client.Client
	tfresource.Test(t, tfresource.TestCase{
		PreCheck: func() {
			acctest.PreCheck(t)
			useFreeTenant(t)
			c = accClient(t)
			before, err := selectedRegions(c)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := c.Put(context.Background(), platformRegionsPath, platformRegionsJSON{Regions: append([]string{}, before...)}, nil); err != nil {
					t.Errorf("restore platform regions: %v", err)
				}
			})
		},
		TerraformVersionChecks:   minimumTerraform,
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy: func(s *terraform.State) error {
			if err := expectSelectedRegions(&c, "eu-paris")(s); err != nil {
				return fmt.Errorf("destroy did not restore the Free plan default: %w", err)
			}
			return nil
		},
		Steps: []tfresource.TestStep{
			{
				Config: platformRegionsConfig("us-washington", "ap-singapore"),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(platformRegionsAddr, tfjsonpath.New("id"), knownvalue.StringExact("current")),
					statecheck.ExpectKnownValue(platformRegionsAddr, tfjsonpath.New("regions"), regionSet("us-washington", "ap-singapore")),
				},
				Check: expectSelectedRegions(&c, "us-washington", "ap-singapore"),
			},
			// An empty set selects no Platform regions.
			{
				Config: platformRegionsConfig(),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(platformRegionsAddr, tfjsonpath.New("regions"), knownvalue.SetSizeExact(0)),
				},
				Check: expectSelectedRegions(&c),
			},
			{
				Config: platformRegionsConfig("ap-singapore"),
				ConfigPlanChecks: tfresource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{plancheck.ExpectResourceAction(platformRegionsAddr, plancheck.ResourceActionUpdate)},
				},
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(platformRegionsAddr, tfjsonpath.New("regions"), regionSet("ap-singapore")),
				},
				Check: expectSelectedRegions(&c, "ap-singapore"),
			},
			{
				ResourceName:                         platformRegionsAddr,
				ImportState:                          true,
				ImportStateId:                        "current",
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: "id",
			},
			{
				Config:      platformRegionsConfig("eu-paris", "us-washington", "ap-singapore"),
				ExpectError: regexp.MustCompile(`plan\s+limit\s+reached(?s:.*)allows\s+at\s+most\s+2\s+platform\s+regions,\s+but\s+this\s+configuration\s+selects\s+3`),
			},
			{
				Config:      platformRegionsConfig("tf-acc-nowhere"),
				ExpectError: regexp.MustCompile(`Unknown\s+platform\s+region(?s:.*)tf-acc-nowhere(?s:.*)ensafely_platform_regions_available`),
			},
			// The failed applies changed nothing. Destroy runs afterwards.
			{
				Config:           platformRegionsConfig("ap-singapore"),
				ConfigPlanChecks: tfresource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()}},
				Check:            expectSelectedRegions(&c, "ap-singapore"),
			},
		},
	})
}

// TestAccPlatformRegionsAvailableDataSource lists the selectable regions and
// the plan limit.
func TestAccPlatformRegionsAvailableDataSource(t *testing.T) {
	const addr = "data.ensafely_platform_regions_available.all"
	tfresource.Test(t, tfresource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t); useFreeTenant(t) },
		TerraformVersionChecks:   minimumTerraform,
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []tfresource.TestStep{{
			Config: `data "ensafely_platform_regions_available" "all" {}`,
			ConfigStateChecks: []statecheck.StateCheck{
				statecheck.ExpectKnownValue(addr, tfjsonpath.New("limit"), knownvalue.Int64Exact(2)),
				statecheck.ExpectKnownValue(addr, tfjsonpath.New("names"), knownvalue.SetPartial([]knownvalue.Check{
					knownvalue.StringExact("eu-paris"), knownvalue.StringExact("us-washington"), knownvalue.StringExact("ap-singapore"),
				})),
				statecheck.ExpectKnownValue(addr, tfjsonpath.New("regions"), knownvalue.ListPartial(map[int]knownvalue.Check{
					0: knownvalue.ObjectExact(map[string]knownvalue.Check{
						"name": knownvalue.NotNull(), "connected": knownvalue.Bool(false),
					}),
				})),
			},
		}},
	})
}
