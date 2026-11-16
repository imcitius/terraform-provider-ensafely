package provider

import (
	"context"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	tfresource "github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/imcitius/terraform-provider-ensafely/internal/acctest"
	"github.com/imcitius/terraform-provider-ensafely/internal/client"
)

func TestAccEscalationPolicy(t *testing.T) {
	const addr = "ensafely_escalation_policy.test"
	name := fmt.Sprintf("tf oncall %d", time.Now().UnixNano())
	var c *client.Client
	var databaseID int64
	type savedPolicy struct {
		ID    int64                `json:"id"`
		Name  string               `json:"name"`
		Steps []escalationStepJSON `json:"steps"`
	}
	config := func(policyName string, steps []escalationStepJSON) string {
		var b strings.Builder
		fmt.Fprintf(&b, "resource \"ensafely_escalation_policy\" \"test\" {\n name = %q\n", policyName)
		for _, step := range steps {
			fmt.Fprintf(&b, " step {\n channel = %q\n delay_min = %d\n }\n", step.Channel, step.DelayMin)
		}
		b.WriteString("}\n")
		return b.String()
	}
	check := func(steps []escalationStepJSON) tfresource.TestCheckFunc {
		checks := []tfresource.TestCheckFunc{
			tfresource.TestCheckResourceAttr(addr, "id", name),
			tfresource.TestCheckResourceAttr(addr, "name", name),
			tfresource.TestCheckResourceAttr(addr, "step.#", fmt.Sprint(len(steps))),
			func(_ *terraform.State) error {
				var body savedPolicy
				if err := c.Get(context.Background(), escalationPolicyPath(name), &body); err != nil {
					return err
				}
				if body.Name != name || !reflect.DeepEqual(body.Steps, steps) {
					return fmt.Errorf("persisted policy = %+v; want ordered steps %+v", body, steps)
				}
				if body.ID == 0 {
					return fmt.Errorf("missing persisted ID")
				}
				if databaseID == 0 {
					databaseID = body.ID
				}
				if body.ID != databaseID {
					return fmt.Errorf("in-place update replaced database ID: %d -> %d", databaseID, body.ID)
				}
				return nil
			},
		}
		for i, step := range steps {
			checks = append(checks, tfresource.TestCheckResourceAttr(addr, fmt.Sprintf("step.%d.channel", i), step.Channel), tfresource.TestCheckResourceAttr(addr, fmt.Sprintf("step.%d.delay_min", i), fmt.Sprint(step.DelayMin)))
		}
		return tfresource.ComposeAggregateTestCheckFunc(checks...)
	}
	initial := []escalationStepJSON{{"primary", 0}, {"backup", 5}, {"primary", 10}}
	reordered := []escalationStepJSON{initial[1], initial[0], initial[2]}
	added := append(append([]escalationStepJSON{}, reordered...), escalationStepJSON{"third", 20})
	removed := []escalationStepJSON{added[3], added[0]}
	update := func(steps []escalationStepJSON) tfresource.TestStep {
		return tfresource.TestStep{
			Config:           config(name, steps),
			ConfigPlanChecks: tfresource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{plancheck.ExpectResourceAction(addr, plancheck.ResourceActionUpdate)}},
			Check:            check(steps),
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
		CheckDestroy: func(_ *terraform.State) error {
			var body savedPolicy
			err := c.Get(context.Background(), escalationPolicyPath(name), &body)
			if client.IsNotFound(err) {
				return nil
			}
			if err != nil {
				return err
			}
			return fmt.Errorf("policy still exists after destroy: %+v", body)
		},
		Steps: []tfresource.TestStep{
			{Config: config(name, initial), Check: check(initial)},
			{Config: config(name, initial), ConfigPlanChecks: tfresource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()}}},
			update(reordered), update(added), update(removed),
			{ResourceName: addr, ImportState: true, ImportStateId: name, ImportStateVerify: true},
			{Config: config(name, removed), ConfigPlanChecks: tfresource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()}}},
			// Verify replacement is visible without applying a different policy name.
			{Config: config(name+" renamed", removed), PlanOnly: true, ExpectNonEmptyPlan: true, ConfigPlanChecks: tfresource.ConfigPlanChecks{PostApplyPreRefresh: []plancheck.PlanCheck{plancheck.ExpectResourceAction(addr, plancheck.ResourceActionDestroyBeforeCreate)}}},
		},
	})
}
