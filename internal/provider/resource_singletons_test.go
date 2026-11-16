package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/imcitius/terraform-provider-ensafely/internal/client"
)

func resourceSchema(t *testing.T, r resource.Resource) resource.SchemaResponse {
	t.Helper()
	var resp resource.SchemaResponse
	r.Schema(context.Background(), resource.SchemaRequest{}, &resp)
	if diags := resp.Schema.ValidateImplementation(context.Background()); diags.HasError() {
		t.Fatal(diags)
	}
	return resp
}

func emptyState(t *testing.T, r resource.Resource) tfsdk.State {
	t.Helper()
	s := resourceSchema(t, r).Schema
	return tfsdk.State{Schema: s, Raw: tftypes.NewValue(s.Type().TerraformType(context.Background()), nil)}
}

// TestCheckDefaultsSchema: every default is optional and never computed, so
// a null attribute stays null and the built-in never enters state (#110).
func TestCheckDefaultsSchema(t *testing.T) {
	s := resourceSchema(t, newCheckDefaultsResource()).Schema
	for name, a := range s.Attributes {
		if name == "id" {
			continue
		}
		if !a.IsOptional() || a.IsComputed() || a.IsRequired() {
			t.Errorf("%s must be optional and not computed", name)
		}
	}
	want := []string{"alert_channels", "check_interval", "escalation_policy", "id", "re_alert_interval", "retry_count", "retry_interval", "severity", "timeouts"}
	if got := slices.Sorted(maps.Keys(s.Attributes)); !slices.Equal(got, want) {
		t.Errorf("attributes = %v, want %v", got, want)
	}
	if !strings.Contains(s.MarkdownDescription, "Destroy resets every default") {
		t.Error("the description must document that destroy resets the defaults")
	}
}

func TestCheckDefaultsMapping(t *testing.T) {
	ctx := context.Background()
	zero := int64(0)
	str := func(s string) *string { return &s }

	// Explicit zero and set values round-trip; "" from the server is null.
	var diags diag.Diagnostics
	m := checkDefaultsModelFromAPI(ctx, checkDefaultsViewJSON{Overrides: &checkDefaultsOverridesJSON{
		RetryCount: &zero, Severity: str("warning"), RetryInterval: str(""),
		Timeouts: map[string]string{"http": "7s"}, AlertChannels: []string{"Email"},
	}}, &diags)
	if diags.HasError() {
		t.Fatal(diags)
	}
	if m.ID.ValueString() != "current" || m.RetryCount.IsNull() || m.RetryCount.ValueInt64() != 0 {
		t.Fatalf("retry_count 0 must stay explicit: %+v", m)
	}
	if !m.RetryInterval.IsNull() || !m.CheckInterval.IsNull() || !m.EscalationPolicy.IsNull() {
		t.Fatalf("unset strings must be null: %+v", m)
	}
	payload := m.payload(ctx, &diags)
	want := checkDefaultsOverridesJSON{RetryCount: &zero, Severity: str("warning"), Timeouts: map[string]string{"http": "7s"}, AlertChannels: []string{"Email"}}
	if diags.HasError() || !reflect.DeepEqual(payload, want) {
		t.Fatalf("payload = %+v, want %+v", payload, want)
	}
	// Every key is sent, so a removed attribute clears its override.
	raw, _ := json.Marshal(payload)
	for _, key := range []string{"retry_interval", "check_interval", "re_alert_interval", "escalation_policy"} {
		if !strings.Contains(string(raw), `"`+key+`":null`) {
			t.Errorf("payload %s must send %s as null", raw, key)
		}
	}

	// All-null overrides (a fresh or reset Tenant) are null attributes.
	m = checkDefaultsModelFromAPI(ctx, checkDefaultsViewJSON{Overrides: &checkDefaultsOverridesJSON{}}, &diags)
	if !m.RetryCount.IsNull() || !m.Timeouts.IsNull() || !m.AlertChannels.IsNull() || diags.HasError() {
		t.Fatalf("empty overrides = %+v, %v", m, diags)
	}

	// A server without the overrides object cannot be managed safely.
	checkDefaultsModelFromAPI(ctx, checkDefaultsViewJSON{}, &diags)
	if !diags.HasError() || !strings.Contains(diags[0].Detail(), "older than this provider") {
		t.Fatalf("missing overrides must fail: %v", diags)
	}
}

func TestCheckDefaultsLifecycle(t *testing.T) {
	ctx := context.Background()
	var puts []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path != checkDefaultsPath {
			t.Errorf("path = %s", req.URL.Path)
		}
		body, _ := io.ReadAll(req.Body)
		if req.Method == http.MethodPut {
			puts = append(puts, string(body))
		}
		w.Header().Set("Content-Type", "application/json")
		// The effective view carries built-in timeouts that must not reach state.
		_, _ = fmt.Fprint(w, `{"retry_count":3,"timeouts":{"http":"3s","tcp":"5s"},"overrides":{"retry_count":3,"retry_interval":null,"check_interval":null,"timeouts":null,"re_alert_interval":null,"severity":null,"alert_channels":null,"escalation_policy":null}}`)
	}))
	defer srv.Close()
	r := &checkDefaultsResource{}
	var err error
	if r.client, err = client.New(client.Config{Endpoint: srv.URL, APIKey: "ck_test", MaxRetries: -1}); err != nil {
		t.Fatal(err)
	}

	imported := resource.ImportStateResponse{State: emptyState(t, r)}
	r.ImportState(ctx, resource.ImportStateRequest{ID: "current"}, &imported)
	read := resource.ReadResponse{State: imported.State}
	r.Read(ctx, resource.ReadRequest{State: imported.State}, &read)
	if read.Diagnostics.HasError() {
		t.Fatal(read.Diagnostics)
	}
	var m checkDefaultsModel
	read.State.Get(ctx, &m)
	if m.RetryCount.ValueInt64() != 3 || !m.Timeouts.IsNull() {
		t.Fatalf("read = %+v; effective timeouts must not enter state", m)
	}

	deleted := resource.DeleteResponse{State: read.State}
	r.Delete(ctx, resource.DeleteRequest{State: read.State}, &deleted)
	if deleted.Diagnostics.HasError() || len(puts) != 1 || puts[0] != "{}" {
		t.Fatalf("destroy must PUT {} (reset), got %v %v", puts, deleted.Diagnostics)
	}

	bad := resource.ImportStateResponse{State: emptyState(t, r)}
	r.ImportState(ctx, resource.ImportStateRequest{ID: "default"}, &bad)
	if !bad.Diagnostics.HasError() || !strings.Contains(bad.Diagnostics[0].Detail(), `"current"`) {
		t.Fatalf("import ID other than current must fail: %v", bad.Diagnostics)
	}
}

func TestDurationMapValidator(t *testing.T) {
	mapOf := func(kv map[string]attr.Value) types.Map {
		return types.MapValueMust(types.StringType, kv)
	}
	for _, tc := range []struct {
		name  string
		value types.Map
		err   string
	}{
		{"null", types.MapNull(types.StringType), ""},
		{"valid", mapOf(map[string]attr.Value{"http": types.StringValue("5s"), "default": types.StringValue("1m")}), ""},
		{"unknown value", mapOf(map[string]attr.Value{"http": types.StringUnknown()}), ""},
		{"empty map", mapOf(map[string]attr.Value{}), "Empty map"},
		{"empty value", mapOf(map[string]attr.Value{"http": types.StringValue("")}), "Empty value"},
		{"empty key", mapOf(map[string]attr.Value{"": types.StringValue("5s")}), "Empty key"},
		{"not a duration", mapOf(map[string]attr.Value{"http": types.StringValue("soon")}), "Invalid duration"},
		{"zero", mapOf(map[string]attr.Value{"http": types.StringValue("0s")}), "Invalid duration"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var resp validator.MapResponse
			durationMap{}.ValidateMap(context.Background(), validator.MapRequest{Path: path.Root("timeouts"), ConfigValue: tc.value}, &resp)
			if tc.err == "" && resp.Diagnostics.HasError() {
				t.Fatal(resp.Diagnostics)
			}
			if tc.err != "" && (!resp.Diagnostics.HasError() || resp.Diagnostics[0].Summary() != tc.err) {
				t.Fatalf("diagnostics = %v, want %q", resp.Diagnostics, tc.err)
			}
		})
	}
}

// regionsServer fakes the platform regions API; a putStatus other than 200
// makes PUT fail with putBody.
func regionsServer(t *testing.T, putStatus int, putBody string) (*client.Client, *[]string) {
	t.Helper()
	var calls []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		body, _ := io.ReadAll(req.Body)
		calls = append(calls, req.Method+" "+req.URL.Path+" "+string(body))
		w.Header().Set("Content-Type", "application/json")
		switch {
		case req.Method == http.MethodPut && putStatus != http.StatusOK:
			w.WriteHeader(putStatus)
			_, _ = fmt.Fprint(w, putBody)
		case req.URL.Path == platformRegionsAvailablePath:
			_, _ = fmt.Fprint(w, `{"regions":[{"region":"eu-paris","connected":true},{"region":"us-washington","connected":false}]}`)
		case req.Method == http.MethodDelete:
			_, _ = fmt.Fprint(w, `{"regions":["eu-paris"],"quota":{"current":1,"limit":2}}`)
		default:
			_, _ = fmt.Fprint(w, `{"regions":["us-washington","eu-paris"],"quota":{"current":2,"limit":2}}`)
		}
	}))
	t.Cleanup(srv.Close)
	c, err := client.New(client.Config{Endpoint: srv.URL, APIKey: "ck_test", MaxRetries: -1})
	if err != nil {
		t.Fatal(err)
	}
	return c, &calls
}

func regionsPlan(t *testing.T, r resource.Resource, regions ...string) tfsdk.Plan {
	t.Helper()
	state := emptyState(t, r)
	set, _ := types.SetValueFrom(context.Background(), types.StringType, append([]string{}, regions...))
	if diags := state.Set(context.Background(), platformRegionsModel{ID: types.StringUnknown(), Regions: set}); diags.HasError() {
		t.Fatal(diags)
	}
	return tfsdk.Plan{Schema: state.Schema, Raw: state.Raw}
}

func TestPlatformRegionsLifecycle(t *testing.T) {
	ctx := context.Background()
	r := &platformRegionsResource{}
	var calls *[]string
	r.client, calls = regionsServer(t, http.StatusOK, "")

	create := resource.CreateResponse{State: emptyState(t, r)}
	r.Create(ctx, resource.CreateRequest{Plan: regionsPlan(t, r, "eu-paris", "us-washington")}, &create)
	if create.Diagnostics.HasError() {
		t.Fatal(create.Diagnostics)
	}
	var m platformRegionsModel
	create.State.Get(ctx, &m)
	var got []string
	m.Regions.ElementsAs(ctx, &got, false)
	if m.ID.ValueString() != "current" || len(got) != 2 {
		t.Fatalf("state = %+v", m)
	}
	if (*calls)[0] != `PUT /api/platform-regions {"regions":["eu-paris","us-washington"]}` {
		t.Fatalf("create sent %q", (*calls)[0])
	}

	// An empty set is a valid selection and is sent as [].
	update := resource.UpdateResponse{State: create.State}
	r.Update(ctx, resource.UpdateRequest{Plan: regionsPlan(t, r), State: create.State}, &update)
	if update.Diagnostics.HasError() || (*calls)[1] != `PUT /api/platform-regions {"regions":[]}` {
		t.Fatalf("empty update sent %q: %v", (*calls)[1], update.Diagnostics)
	}

	deleted := resource.DeleteResponse{State: create.State}
	r.Delete(ctx, resource.DeleteRequest{State: create.State}, &deleted)
	if deleted.Diagnostics.HasError() || (*calls)[2] != "DELETE /api/platform-regions " {
		t.Fatalf("destroy must call DELETE (reset to plan defaults), got %q: %v", (*calls)[2], deleted.Diagnostics)
	}
}

func TestPlatformRegionsErrors(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		status     int
		summary    string
		detail     []string
	}{
		{"plan limit", `{"error":"QUOTA_EXCEEDED","detail":{"current":3,"limit":2}}`, http.StatusForbidden,
			"Ensafely plan limit reached", []string{"allows at most 2 platform regions", "selects 3 (a, b, c)", "upgrade the plan"}},
		{"plan without regions", `{"error":"Platform regions not available on your plan"}`, http.StatusForbidden,
			"Platform regions not available on this plan", []string{"does not include Platform regions"}},
		{"unknown region", `{"error":"unknown region: c"}`, http.StatusBadRequest,
			"Unknown platform region", []string{"unknown region: c", "ensafely_platform_regions_available"}},
		{"other", `{"error":"boom"}`, http.StatusInternalServerError, "Ensafely server error", []string{"boom"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &platformRegionsResource{}
			r.client, _ = regionsServer(t, tc.status, tc.body)
			resp := resource.CreateResponse{State: emptyState(t, r)}
			r.Create(context.Background(), resource.CreateRequest{Plan: regionsPlan(t, r, "a", "b", "c")}, &resp)
			if !resp.Diagnostics.HasError() {
				t.Fatal("create must fail")
			}
			d := resp.Diagnostics[0]
			if d.Summary() != tc.summary {
				t.Errorf("summary = %q, want %q", d.Summary(), tc.summary)
			}
			for _, want := range tc.detail {
				if !strings.Contains(d.Detail(), want) {
					t.Errorf("detail %q lacks %q", d.Detail(), want)
				}
			}
		})
	}
}

func TestPlatformRegionsAvailableDataSource(t *testing.T) {
	ctx := context.Background()
	d := &platformRegionsAvailableDataSource{}
	d.client, _ = regionsServer(t, http.StatusOK, "")
	var schemaResp datasource.SchemaResponse
	d.Schema(ctx, datasource.SchemaRequest{}, &schemaResp)
	if diags := schemaResp.Schema.ValidateImplementation(ctx); diags.HasError() {
		t.Fatal(diags)
	}
	resp := datasource.ReadResponse{State: tfsdk.State{Schema: schemaResp.Schema,
		Raw: tftypes.NewValue(schemaResp.Schema.Type().TerraformType(ctx), nil)}}
	d.Read(ctx, datasource.ReadRequest{}, &resp)
	if resp.Diagnostics.HasError() {
		t.Fatal(resp.Diagnostics)
	}
	var out struct {
		Regions []struct {
			Name      string `tfsdk:"name"`
			Connected bool   `tfsdk:"connected"`
		} `tfsdk:"regions"`
		Names []string `tfsdk:"names"`
		Limit int64    `tfsdk:"limit"`
	}
	if diags := resp.State.Get(ctx, &out); diags.HasError() {
		t.Fatal(diags)
	}
	if len(out.Regions) != 2 || out.Regions[0].Name != "eu-paris" || !out.Regions[0].Connected || out.Regions[1].Connected {
		t.Errorf("regions = %+v", out.Regions)
	}
	if len(out.Names) != 2 || out.Limit != 2 {
		t.Errorf("names = %v, limit = %d", out.Names, out.Limit)
	}
}
