package provider

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	tfresource "github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
	"github.com/hashicorp/terraform-plugin-testing/tfversion"

	"github.com/imcitius/terraform-provider-ensafely/internal/acctest"
)

// testProvider adds test-only resources to the real provider.
type testProvider struct {
	*Provider
	extra []func() resource.Resource
}

func (p *testProvider) Resources(ctx context.Context) []func() resource.Resource {
	return append(p.Provider.Resources(ctx), p.extra...)
}

// testAccProtoV6ProviderFactories serves the provider in-process. Resource
// tests (T4–T10) use it with acctest.PreCheck and the create → empty plan →
// update → import → destroy sequence shown in TestAccWriteOnlyProbe.
var testAccProtoV6ProviderFactories = map[string]func() (tfprotov6.ProviderServer, error){
	TypeName: providerserver.NewProtocol6WithError(&testProvider{
		Provider: &Provider{version: "acctest"},
		extra:    []func() resource.Resource{newWriteOnlyProbe},
	}),
}

// minimumTerraform is the oldest Terraform the provider supports: write-only
// attributes need 1.11 (#110).
var minimumTerraform = []tfversion.TerraformVersionCheck{tfversion.SkipBelow(tfversion.Version1_11_0)}

func sha(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func probeConfig(name, secret string, version int) string {
	return fmt.Sprintf(`
resource "ensafely_writeonly_probe" "test" {
  name              = %q
  secret_wo         = %q
  secret_wo_version = %d
}
`, name, secret, version)
}

// TestAccWriteOnlyProbe checks the write-only secret pattern (#113) through
// Terraform core and the real API: the secret never reaches plan or state, a
// changed secret without a version bump is an empty plan, a bump sends the
// new value, and import works.
func TestAccWriteOnlyProbe(t *testing.T) {
	const addr = "ensafely_writeonly_probe.test"
	tfresource.Test(t, tfresource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		TerraformVersionChecks:   minimumTerraform,
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []tfresource.TestStep{
			// Create. The framework also asserts an empty plan after apply.
			{
				Config: probeConfig("probe", "first-secret", 1),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(addr, tfjsonpath.New("id"), knownvalue.StringExact("probe")),
					statecheck.ExpectKnownValue(addr, tfjsonpath.New("secret_wo"), knownvalue.Null()),
					statecheck.ExpectKnownValue(addr, tfjsonpath.New("secret_sha256"), knownvalue.StringExact(sha("first-secret"))),
				},
			},
			// New secret, same version: nothing to do.
			{
				Config: probeConfig("probe", "second-secret", 1),
				ConfigPlanChecks: tfresource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
				},
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(addr, tfjsonpath.New("secret_sha256"), knownvalue.StringExact(sha("first-secret"))),
				},
			},
			// Version bump: in-place update that sends the new secret.
			{
				Config: probeConfig("probe", "second-secret", 2),
				ConfigPlanChecks: tfresource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{plancheck.ExpectResourceAction(addr, plancheck.ResourceActionUpdate)},
				},
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(addr, tfjsonpath.New("secret_wo"), knownvalue.Null()),
					statecheck.ExpectKnownValue(addr, tfjsonpath.New("secret_sha256"), knownvalue.StringExact(sha("second-secret"))),
				},
			},
			// Import by name. Secrets and their versions cannot be read back.
			{
				ResourceName:                         addr,
				ImportState:                          true,
				ImportStateId:                        "probe",
				ImportStateVerify:                    true,
				ImportStateVerifyIdentifierAttribute: "id",
				ImportStateVerifyIgnore:              []string{"secret_wo_version", "secret_sha256"},
			},
			// Destroy runs automatically after the last step.
		},
	})
}

// TestAccProviderRejectsInvalidKey checks that an authentication failure
// surfaces as a clear diagnostic rather than a generic HTTP error.
func TestAccProviderRejectsInvalidKey(t *testing.T) {
	tfresource.Test(t, tfresource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		TerraformVersionChecks:   minimumTerraform,
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []tfresource.TestStep{{
			Config: `
provider "ensafely" {
  api_key = "ck_not_a_real_key"
}
` + probeConfig("probe-invalid-key", "s", 1),
			ExpectError: regexp.MustCompile(`(?s)Ensafely authentication failed.*api_key`),
		}},
	})
}
