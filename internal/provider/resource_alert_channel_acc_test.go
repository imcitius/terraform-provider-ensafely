package provider

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"reflect"
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

const channelAddr = "ensafely_alert_channel.test"

// notSent marks a config key the provider must leave out of a write.
type notSentT struct{}

var notSent = notSentT{}

// accChannelCase is one type block run through create → empty plan (secret
// changed, same version) → update (versions bumped) → empty plan → import →
// destroy.
type accChannelCase struct {
	block string
	// Block bodies, one attribute per line.
	create, sameVersion, update string
	// Config keys of the recorded POST and PUT. A value of notSent requires
	// the key to be absent from the request.
	createSent, updateSent map[string]any
	// Config keys of the API read after create and update. Secrets read as
	// "****"; nil requires the key to be absent or empty.
	createAPI, updateAPI map[string]any
	// Every secret value used; none may reach state.
	secrets []string
}

var accChannelCases = []accChannelCase{
	{
		block:     "email",
		create:    `to = ["b@example.com", "a@example.com"]`,
		update:    `to = ["c@example.com"]`,
		createAPI: map[string]any{"to": []any{"a@example.com", "b@example.com"}},
		updateAPI: map[string]any{"to": []any{"c@example.com"}},
	},
	{
		block:       "telegram",
		create:      "chat_id = \"-1001\"\nbot_token_wo = \"tg-first\"\nbot_token_wo_version = 1",
		sameVersion: "chat_id = \"-1001\"\nbot_token_wo = \"tg-second\"\nbot_token_wo_version = 1",
		update:      "chat_id = \"-1002\"\nbot_token_wo = \"tg-second\"\nbot_token_wo_version = 2",
		createSent:  map[string]any{"chat_id": "-1001", "bot_token": "tg-first"},
		updateSent:  map[string]any{"chat_id": "-1002", "bot_token": "tg-second"},
		createAPI:   map[string]any{"chat_id": "-1001", "bot_token": apiSecretMask},
		updateAPI:   map[string]any{"chat_id": "-1002", "bot_token": apiSecretMask},
		secrets:     []string{"tg-first", "tg-second"},
	},
	{
		block: "slack",
		create: "default_channel = \"C01\"\nbot_token_wo = \"xoxb-first\"\nbot_token_wo_version = 1\n" +
			"signing_secret_wo = \"sign-first\"\nsigning_secret_wo_version = 1",
		sameVersion: "default_channel = \"C01\"\nbot_token_wo = \"xoxb-second\"\nbot_token_wo_version = 1\n" +
			"signing_secret_wo = \"sign-first\"\nsigning_secret_wo_version = 1",
		// Only the bumped secret is sent; the other one is kept by the API.
		update: "default_channel = \"C02\"\nbot_token_wo = \"xoxb-second\"\nbot_token_wo_version = 2\n" +
			"signing_secret_wo = \"sign-first\"\nsigning_secret_wo_version = 1",
		createSent: map[string]any{"bot_token": "xoxb-first", "signing_secret": "sign-first", "webhook_url": notSent},
		updateSent: map[string]any{"default_channel": "C02", "bot_token": "xoxb-second", "signing_secret": notSent},
		createAPI:  map[string]any{"default_channel": "C01", "bot_token": apiSecretMask, "signing_secret": apiSecretMask, "webhook_url": nil},
		updateAPI:  map[string]any{"default_channel": "C02", "bot_token": apiSecretMask, "signing_secret": apiSecretMask},
		secrets:    []string{"xoxb-first", "xoxb-second", "sign-first"},
	},
	{
		block:       "discord",
		create:      "app_id = \"111\"\ndefault_channel = \"222\"\nbot_token_wo = \"dc-first\"\nbot_token_wo_version = 1",
		sameVersion: "app_id = \"111\"\ndefault_channel = \"222\"\nbot_token_wo = \"dc-second\"\nbot_token_wo_version = 1",
		// Removing app_id removes it from the API config.
		update:     "default_channel = \"333\"\nbot_token_wo = \"dc-second\"\nbot_token_wo_version = 2",
		createSent: map[string]any{"app_id": "111", "bot_token": "dc-first"},
		updateSent: map[string]any{"app_id": notSent, "bot_token": "dc-second"},
		createAPI:  map[string]any{"app_id": "111", "default_channel": "222", "bot_token": apiSecretMask},
		updateAPI:  map[string]any{"app_id": nil, "default_channel": "333", "bot_token": apiSecretMask},
		secrets:    []string{"dc-first", "dc-second"},
	},
	{
		block: "webhook",
		create: "method = \"POST\"\ncontent_type = \"application/json\"\nbody_template = " + fmt.Sprintf("%q", `{"m":"{{.Message}}"}`) + "\n" +
			"url_wo = \"https://example.com/hook?token=url-first\"\nurl_wo_version = 1\n" +
			"secret_wo = \"hmac-first\"\nsecret_wo_version = 1\n" +
			"headers_wo = { \"X-Token\" = \"hdr-first\" }\nheaders_wo_version = 1",
		sameVersion: "method = \"POST\"\ncontent_type = \"application/json\"\nbody_template = " + fmt.Sprintf("%q", `{"m":"{{.Message}}"}`) + "\n" +
			"url_wo = \"https://example.com/hook?token=url-first\"\nurl_wo_version = 1\n" +
			"secret_wo = \"hmac-second\"\nsecret_wo_version = 1\n" +
			"headers_wo = { \"X-Token\" = \"hdr-first\" }\nheaders_wo_version = 1",
		// Rotate the HMAC secret, clear the headers (removed + version
		// bumped), keep the URL; change and remove plain fields.
		update: "method = \"PUT\"\nrecovery_template = " + fmt.Sprintf("%q", `{"ok":true}`) + "\n" +
			"url_wo = \"https://example.com/hook?token=url-first\"\nurl_wo_version = 1\n" +
			"secret_wo = \"hmac-second\"\nsecret_wo_version = 2\n" +
			"headers_wo_version = 2",
		createSent: map[string]any{"url": "https://example.com/hook?token=url-first", "secret": "hmac-first",
			"headers": map[string]any{"X-Token": "hdr-first"}},
		updateSent: map[string]any{"method": "PUT", "url": notSent, "secret": "hmac-second", "headers": map[string]any{}, "content_type": notSent},
		createAPI: map[string]any{"method": "POST", "content_type": "application/json", "body_template": `{"m":"{{.Message}}"}`,
			"url": apiSecretMask, "secret": apiSecretMask, "headers": map[string]any{"X-Token": apiSecretMask}},
		updateAPI: map[string]any{"method": "PUT", "content_type": nil, "body_template": nil, "recovery_template": `{"ok":true}`,
			"url": apiSecretMask, "secret": apiSecretMask, "headers": nil},
		secrets: []string{"url-first", "hmac-first", "hmac-second", "hdr-first"},
	},
}

func channelConfigHCL(endpoint, name, block, body string) string {
	return fmt.Sprintf(`
provider "ensafely" {
  endpoint = %q
}

resource "ensafely_alert_channel" "test" {
  name = %q
  %s {
%s
  }
}
`, endpoint, name, block, body)
}

// emptyConfigValue reports whether a read config value counts as unset.
func emptyConfigValue(v any) bool {
	switch v := v.(type) {
	case nil:
		return true
	case string:
		return v == ""
	case []any:
		return len(v) == 0
	case map[string]any:
		return len(v) == 0
	}
	return false
}

func compareChannelConfig(what string, got, want map[string]any) error {
	for k, w := range want {
		g, present := got[k]
		switch {
		case w == notSent:
			if present {
				return fmt.Errorf("%s: %s must not be sent, got %#v", what, k, g)
			}
		case w == nil:
			if !emptyConfigValue(g) {
				return fmt.Errorf("%s: %s = %#v, want unset", what, k, g)
			}
		case !reflect.DeepEqual(g, w):
			return fmt.Errorf("%s: %s = %#v, want %#v", what, k, g, w)
		}
	}
	return nil
}

// TestAccAlertChannelTypes runs every type block through create → empty plan
// → update → import → destroy (#116). A recording proxy proves which secrets
// the provider sent; the API read proves what the server stored (secrets
// masked); state never holds a secret.
func TestAccAlertChannelTypes(t *testing.T) {
	for _, tc := range accChannelCases {
		t.Run(tc.block, func(t *testing.T) {
			// Steps are built before PreCheck runs, so the proxy starts
			// here. Without TF_ACC the test is skipped and it is unused.
			proxy := recordingProxy{prefix: "/api/alert-channels"}
			proxyURL := proxy.start(t, os.Getenv(EnvEndpoint))
			name := fmt.Sprintf("tf-acc-%s-%d", tc.block, time.Now().UnixNano())
			var c *client.Client
			var mark int
			markWrites := func() { mark = proxy.count() }
			sent := func(method string, want map[string]any) func(*terraform.State) error {
				return func(*terraform.State) error {
					writes := proxy.since(mark)
					if len(writes) != 1 || writes[0].Method != method {
						return fmt.Errorf("writes = %+v, want one %s", writes, method)
					}
					w := writes[0]
					if w.Body["type"] != tc.block || (method == http.MethodPost && w.Body["name"] != name) {
						return fmt.Errorf("request = %+v", w)
					}
					cfg, _ := w.Body["config"].(map[string]any)
					return compareChannelConfig(method+" config", cfg, want)
				}
			}
			stored := func(want map[string]any) func(*terraform.State) error {
				return func(*terraform.State) error {
					var body struct {
						Name   string         `json:"name"`
						Type   string         `json:"type"`
						Config map[string]any `json:"config"`
					}
					if err := c.Get(context.Background(), alertChannelPath(name), &body); err != nil {
						return err
					}
					if body.Name != name || body.Type != tc.block {
						return fmt.Errorf("API channel = %+v", body)
					}
					return compareChannelConfig("API config", body.Config, want)
				}
			}
			noWrites := func(*terraform.State) error {
				if w := proxy.since(mark); len(w) != 0 {
					return fmt.Errorf("unexpected writes: %+v", w)
				}
				return nil
			}
			otherBlocksNull := []statecheck.StateCheck{
				statecheck.ExpectKnownValue(channelAddr, tfjsonpath.New("id"), knownvalue.StringExact(name)),
			}
			var versionKeys []string
			ct, _ := channelTypeByBlock(tc.block)
			for _, s := range ct.secrets {
				otherBlocksNull = append(otherBlocksNull,
					statecheck.ExpectKnownValue(channelAddr, blockPath(tc.block, s.wo()), knownvalue.Null()))
				versionKeys = append(versionKeys, tc.block+".0."+s.woVersion(), tc.block+"."+s.woVersion())
			}
			for _, other := range channelTypes {
				if other.block != tc.block {
					otherBlocksNull = append(otherBlocksNull,
						statecheck.ExpectKnownValue(channelAddr, tfjsonpath.New(other.block), knownvalue.Null()))
				}
			}

			create := channelConfigHCL(proxyURL, name, tc.block, tc.create)
			update := channelConfigHCL(proxyURL, name, tc.block, tc.update)
			sameVersion := create
			if tc.sameVersion != "" {
				sameVersion = channelConfigHCL(proxyURL, name, tc.block, tc.sameVersion)
			}
			tfresource.Test(t, tfresource.TestCase{
				PreCheck: func() {
					acctest.PreCheck(t)
					c = accClient(t)
				},
				TerraformVersionChecks:   minimumTerraform,
				ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
				CheckDestroy: func(*terraform.State) error {
					err := c.Get(context.Background(), alertChannelPath(name), nil)
					if client.IsNotFound(err) {
						return nil
					}
					return fmt.Errorf("alert channel %q still exists after destroy (err=%v)", name, err)
				},
				Steps: []tfresource.TestStep{
					{
						// Create; the framework also asserts an empty plan
						// after apply.
						PreConfig:         markWrites,
						Config:            create,
						ConfigStateChecks: otherBlocksNull,
						Check: tfresource.ComposeAggregateTestCheckFunc(
							sent(http.MethodPost, tc.createSent),
							stored(tc.createAPI),
							noSecretInState(tc.secrets...),
						),
					},
					{
						// A changed secret with the same version is not
						// detected (write-only) and not sent.
						PreConfig:        markWrites,
						Config:           sameVersion,
						ConfigPlanChecks: tfresource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()}},
						Check:            noWrites,
					},
					{
						// Plain fields change in place; bumped versions
						// rotate (or clear) their secrets.
						PreConfig: markWrites,
						Config:    update,
						ConfigPlanChecks: tfresource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
							plancheck.ExpectResourceAction(channelAddr, plancheck.ResourceActionUpdate)}},
						ConfigStateChecks: otherBlocksNull,
						Check: tfresource.ComposeAggregateTestCheckFunc(
							sent(http.MethodPut, tc.updateSent),
							stored(tc.updateAPI),
							noSecretInState(tc.secrets...),
						),
					},
					{Config: update, ConfigPlanChecks: tfresource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()}}},
					{
						// The API cannot return the versions.
						ResourceName:            channelAddr,
						ImportState:             true,
						ImportStateId:           name,
						ImportStateVerify:       true,
						ImportStateVerifyIgnore: versionKeys,
					},
				},
			})
		})
	}
}

// TestAccAlertChannelRename checks that renaming a channel replaces it and
// shows the referencing Check's change in the same plan. The Check's
// alert_channels is an in-place attribute, so the Check is updated, not
// recreated, and keeps its ID.
func TestAccAlertChannelRename(t *testing.T) {
	const addr = "ensafely_alert_channel.test"
	suffix := time.Now().UnixNano()
	oldName := fmt.Sprintf("tf-acc-rename-%d", suffix)
	newName := oldName + "-new"
	project := accProject("channel-rename")
	config := func(name string) string {
		return fmt.Sprintf(`
resource "ensafely_alert_channel" "test" {
  name = %q
  email {
    to = ["ops@example.com"]
  }
}
`, name) + checkConfig(fmt.Sprintf("name = \"tf channel ref\"\nproject = %q\nalert_channels = [ensafely_alert_channel.test.name]\ntcp { host = \"example.com\"; port = 443 }", project))
	}
	var c *client.Client
	var checkID string
	tfresource.Test(t, tfresource.TestCase{
		PreCheck: func() {
			acctest.PreCheck(t)
			c = accClient(t)
		},
		TerraformVersionChecks:   minimumTerraform,
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy: func(s *terraform.State) error {
			for _, n := range []string{oldName, newName} {
				if err := c.Get(context.Background(), alertChannelPath(n), nil); !client.IsNotFound(err) {
					return fmt.Errorf("alert channel %q still exists after destroy (err=%v)", n, err)
				}
			}
			return checkDestroyed(t)(s)
		},
		Steps: []tfresource.TestStep{
			{
				Config: config(oldName),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(checkAddr, tfjsonpath.New("alert_channels"),
						knownvalue.SetExact([]knownvalue.Check{knownvalue.StringExact(oldName)})),
				},
				Check: func(s *terraform.State) error {
					checkID = s.RootModule().Resources[checkAddr].Primary.ID
					return nil
				},
			},
			{
				Config: config(newName),
				ConfigPlanChecks: tfresource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
					plancheck.ExpectResourceAction(addr, plancheck.ResourceActionDestroyBeforeCreate),
					plancheck.ExpectResourceAction(checkAddr, plancheck.ResourceActionUpdate),
					plancheck.ExpectKnownValue(checkAddr, tfjsonpath.New("alert_channels"),
						knownvalue.SetExact([]knownvalue.Check{knownvalue.StringExact(newName)})),
				}},
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(addr, tfjsonpath.New("id"), knownvalue.StringExact(newName)),
					statecheck.ExpectKnownValue(checkAddr, tfjsonpath.New("alert_channels"),
						knownvalue.SetExact([]knownvalue.Check{knownvalue.StringExact(newName)})),
				},
				Check: func(s *terraform.State) error {
					if id := s.RootModule().Resources[checkAddr].Primary.ID; id != checkID {
						return fmt.Errorf("check was recreated: %s -> %s", checkID, id)
					}
					if err := c.Get(context.Background(), alertChannelPath(oldName), nil); !client.IsNotFound(err) {
						return fmt.Errorf("old channel %q still exists (err=%v)", oldName, err)
					}
					return nil
				},
			},
			{Config: config(newName), ConfigPlanChecks: tfresource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()}}},
		},
	})
}

// TestAccAlertChannelTypeChangeReplaces checks that switching the type block
// replaces the channel.
func TestAccAlertChannelTypeChangeReplaces(t *testing.T) {
	name := fmt.Sprintf("tf-acc-type-%d", time.Now().UnixNano())
	config := func(block string) string {
		return fmt.Sprintf("resource \"ensafely_alert_channel\" \"test\" {\n  name = %q\n%s\n}\n", name, strings.ReplaceAll(block, "; ", "\n"))
	}
	tfresource.Test(t, tfresource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		TerraformVersionChecks:   minimumTerraform,
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []tfresource.TestStep{
			{Config: config("email {\n to = [\"ops@example.com\"]\n}")},
			{
				Config: config("telegram {\n chat_id = \"-1001\"\n bot_token_wo = \"tg-type\"\n bot_token_wo_version = 1\n}"),
				ConfigPlanChecks: tfresource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
					plancheck.ExpectResourceAction(channelAddr, plancheck.ResourceActionDestroyBeforeCreate)}},
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(channelAddr, tfjsonpath.New("email"), knownvalue.Null()),
					statecheck.ExpectKnownValue(channelAddr, blockPath("telegram", "chat_id"), knownvalue.StringExact("-1001")),
				},
			},
		},
	})
}
