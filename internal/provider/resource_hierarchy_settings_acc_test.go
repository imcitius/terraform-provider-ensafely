package provider

import (
	"context"
	"fmt"
	"os"
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

func TestAccProjectSettings(t *testing.T) { testAccHierarchySettings(t, false) }
func TestAccGroupSettings(t *testing.T)   { testAccHierarchySettings(t, true) }

func testAccHierarchySettings(t *testing.T, group bool) {
	t.Helper()
	project := fmt.Sprintf("tf settings %d", time.Now().UnixNano())
	kind, id, apiPath := "project", project, "/api/project-settings/"+client.PathEscape(project)
	groupConfig := ""
	if group {
		kind, id = "group", project+"/database"
		apiPath = "/api/group-settings/" + client.PathEscape(project) + "/database"
		groupConfig = `group = "database"`
	}
	addr := "ensafely_" + kind + "_settings.test"
	config := func(fields string) string {
		return fmt.Sprintf("resource %q \"test\" {\n project = %q\n %s\n %s\n}\n", "ensafely_"+kind+"_settings", project, groupConfig, fields)
	}
	initial := config("enabled = false\nduration = \"1m\"\nre_alert_interval = \"2h\"")
	updated := config("duration = \"3m\"")
	var c *client.Client
	var maintenanceUntil string
	type response struct {
		hierarchySettingsJSON
		MaintenanceUntil  *string `json:"maintenance_until"`
		MaintenanceReason string  `json:"maintenance_reason"`
	}
	read := func() (response, error) {
		var body response
		err := c.Get(context.Background(), apiPath, &body)
		return body, err
	}
	checkMaintenance := func() error {
		body, err := read()
		if err != nil {
			return err
		}
		if body.MaintenanceUntil == nil || *body.MaintenanceUntil != maintenanceUntil || body.MaintenanceReason != "UI maintenance" {
			return fmt.Errorf("maintenance changed: %+v", body)
		}
		return nil
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
			body, err := read()
			if err != nil {
				return err
			}
			if body.Enabled != nil || body.Duration != nil || body.ReAlertInterval != nil {
				return fmt.Errorf("destroy did not reset overrides: %+v", body)
			}
			return checkMaintenance()
		},
		Steps: []tfresource.TestStep{
			{
				Config: initial,
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(addr, tfjsonpath.New("id"), knownvalue.StringExact(id)),
					statecheck.ExpectKnownValue(addr, tfjsonpath.New("enabled"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(addr, tfjsonpath.New("duration"), knownvalue.StringExact("1m")),
					statecheck.ExpectKnownValue(addr, tfjsonpath.New("re_alert_interval"), knownvalue.StringExact("2h")),
				},
			},
			{
				// Exercise the same endpoint used by the UI, without changing HCL.
				PreConfig: func() {
					if err := c.Post(context.Background(), apiPath+"/maintenance", map[string]string{"duration": "1h", "reason": "UI maintenance"}, nil); err != nil {
						t.Fatal(err)
					}
					body, err := read()
					if err != nil {
						t.Fatal(err)
					}
					if body.MaintenanceUntil == nil {
						t.Fatal("maintenance was not set")
					}
					maintenanceUntil = *body.MaintenanceUntil
				},
				Config:           initial,
				ConfigPlanChecks: tfresource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()}},
			},
			{
				Config:           updated,
				ConfigPlanChecks: tfresource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{plancheck.ExpectResourceAction(addr, plancheck.ResourceActionUpdate)}},
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(addr, tfjsonpath.New("enabled"), knownvalue.Null()),
					statecheck.ExpectKnownValue(addr, tfjsonpath.New("duration"), knownvalue.StringExact("3m")),
					statecheck.ExpectKnownValue(addr, tfjsonpath.New("re_alert_interval"), knownvalue.Null()),
				},
				Check: func(_ *terraform.State) error { return checkMaintenance() },
			},
			{ResourceName: addr, ImportState: true, ImportStateId: id, ImportStateVerify: true},
			{Config: updated, ConfigPlanChecks: tfresource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()}}},
		},
	})
}
