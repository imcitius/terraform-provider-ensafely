package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
	"github.com/imcitius/terraform-provider-ensafely/internal/client"
)

func policyState(t *testing.T, r *escalationPolicyResource) tfsdk.State {
	t.Helper()
	var resp resource.SchemaResponse
	r.Schema(context.Background(), resource.SchemaRequest{}, &resp)
	if d := resp.Schema.ValidateImplementation(context.Background()); d.HasError() {
		t.Fatal(d)
	}
	return tfsdk.State{Schema: resp.Schema, Raw: tftypes.NewValue(resp.Schema.Type().TerraformType(context.Background()), nil)}
}

func policyPlan(t *testing.T, r *escalationPolicyResource, name string, steps ...escalationStepJSON) tfsdk.Plan {
	t.Helper()
	state := policyState(t, r)
	var resp resource.CreateResponse
	m := escalationPolicyFromJSON(context.Background(), escalationPolicyJSON{Name: name, Steps: steps}, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		t.Fatal(resp.Diagnostics)
	}
	if d := state.Set(context.Background(), m); d.HasError() {
		t.Fatal(d)
	}
	return tfsdk.Plan{Schema: state.Schema, Raw: state.Raw}
}

func TestEscalationPolicyLifecycle(t *testing.T) {
	ctx := context.Background()
	r := &escalationPolicyResource{}
	name := "oncall ?#% café"
	const escapedPath = "/api/escalation-policies/oncall%20%3F%23%25%20caf%C3%A9"
	var stored escalationPolicyJSON
	var writes []escalationPolicyJSON
	var methods []string
	deleted := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		methods = append(methods, req.Method)
		want := escapedPath
		if req.Method == http.MethodPost {
			want = "/api/escalation-policies"
		}
		if req.URL.EscapedPath() != want || req.URL.RawQuery != "" {
			t.Errorf("unexpected URL: %s", req.URL)
		}
		w.Header().Set("Content-Type", "application/json")
		switch req.Method {
		case http.MethodPost, http.MethodPut:
			var body map[string]json.RawMessage
			if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
				t.Error(err)
			}
			if len(body) != 2 || body["name"] == nil || body["steps"] == nil {
				t.Errorf("unexpected write fields: %v", body)
			}
			raw, _ := json.Marshal(body)
			if err := json.Unmarshal(raw, &stored); err != nil {
				t.Error(err)
			}
			writes = append(writes, stored)
			if req.Method == http.MethodPost {
				w.WriteHeader(http.StatusCreated)
			}
		case http.MethodGet:
		case http.MethodDelete:
			deleted = true
			_, _ = fmt.Fprint(w, `{"message":"deleted"}`)
			return
		default:
			t.Errorf("unexpected method: %s", req.Method)
		}
		// The database ID must never become the Terraform identity.
		_ = json.NewEncoder(w).Encode(map[string]any{"id": 42, "name": stored.Name, "steps": stored.Steps, "created_at": "2026-01-01T00:00:00Z"})
	}))
	defer srv.Close()
	var err error
	r.client, err = client.New(client.Config{Endpoint: srv.URL, APIKey: "ck_test", MaxRetries: -1})
	if err != nil {
		t.Fatal(err)
	}
	initial := []escalationStepJSON{{"primary", 0}, {"backup", 5}, {"primary", 10}}
	create := resource.CreateResponse{State: policyState(t, r)}
	r.Create(ctx, resource.CreateRequest{Plan: policyPlan(t, r, name, initial...)}, &create)
	if create.Diagnostics.HasError() {
		t.Fatal(create.Diagnostics)
	}
	if !reflect.DeepEqual(stored.Steps, initial) {
		t.Fatalf("create steps: %+v", stored.Steps)
	}
	var id string
	if d := create.State.GetAttribute(ctx, path.Root("id"), &id); d.HasError() || id != name {
		t.Fatalf("identity = %q, %v", id, d)
	}
	read := resource.ReadResponse{State: create.State}
	r.Read(ctx, resource.ReadRequest{State: create.State}, &read)
	if read.Diagnostics.HasError() || !read.State.Raw.Equal(create.State.Raw) {
		t.Fatalf("read differs: %v", read.Diagnostics)
	}

	state := create.State
	for _, steps := range [][]escalationStepJSON{
		{{"backup", 5}, {"primary", 0}, {"primary", 10}},                // reorder, including nonmonotonic delays
		{{"backup", 5}, {"primary", 0}, {"primary", 10}, {"third", 20}}, // add
		{{"third", 20}}, // remove
	} {
		update := resource.UpdateResponse{State: state}
		r.Update(ctx, resource.UpdateRequest{State: state, Plan: policyPlan(t, r, name, steps...)}, &update)
		if update.Diagnostics.HasError() {
			t.Fatal(update.Diagnostics)
		}
		if !reflect.DeepEqual(stored.Steps, steps) {
			t.Fatalf("updated steps: %+v; want %+v", stored.Steps, steps)
		}
		state = update.State
	}
	if len(writes) != 4 {
		t.Fatalf("writes = %d", len(writes))
	}
	imported := resource.ImportStateResponse{State: policyState(t, r)}
	r.ImportState(ctx, resource.ImportStateRequest{ID: name}, &imported)
	if imported.Diagnostics.HasError() {
		t.Fatal(imported.Diagnostics)
	}
	read = resource.ReadResponse{State: imported.State}
	r.Read(ctx, resource.ReadRequest{State: imported.State}, &read)
	if read.Diagnostics.HasError() || !read.State.Raw.Equal(state.Raw) {
		t.Fatalf("import differs: %v", read.Diagnostics)
	}
	del := resource.DeleteResponse{State: state}
	r.Delete(ctx, resource.DeleteRequest{State: state}, &del)
	if del.Diagnostics.HasError() || !deleted {
		t.Fatalf("delete failed: %v", del.Diagnostics)
	}
	if !reflect.DeepEqual(methods, []string{"POST", "GET", "PUT", "PUT", "PUT", "GET", "DELETE"}) {
		t.Fatalf("methods = %v", methods)
	}
}

func TestEscalationPolicyErrors(t *testing.T) {
	for _, status := range []int{400, 401, 403, 404, 409, 500} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				w.WriteHeader(status)
				_, _ = fmt.Fprint(w, `{"error":"policy request rejected"}`)
			}))
			defer srv.Close()
			c, err := client.New(client.Config{Endpoint: srv.URL, APIKey: "ck_test", MaxRetries: -1})
			if err != nil {
				t.Fatal(err)
			}
			r := &escalationPolicyResource{client: c}
			ctx := context.Background()
			plan := policyPlan(t, r, "oncall", escalationStepJSON{"alerts", 0})
			state := tfsdk.State{Schema: plan.Schema, Raw: plan.Raw}
			create := resource.CreateResponse{State: policyState(t, r)}
			r.Create(ctx, resource.CreateRequest{Plan: plan}, &create)
			if !create.Diagnostics.HasError() || !create.State.Raw.IsNull() {
				t.Fatal("failed create must not record state")
			}
			if !strings.Contains(create.Diagnostics.Errors()[0].Detail(), "policy request rejected") {
				t.Fatal("API detail lost")
			}
			update := resource.UpdateResponse{State: state}
			r.Update(ctx, resource.UpdateRequest{Plan: plan, State: state}, &update)
			if !update.Diagnostics.HasError() || !update.State.Raw.Equal(state.Raw) {
				t.Fatal("failed update must preserve state")
			}
			read := resource.ReadResponse{State: state}
			r.Read(ctx, resource.ReadRequest{State: state}, &read)
			del := resource.DeleteResponse{State: state}
			r.Delete(ctx, resource.DeleteRequest{State: state}, &del)
			if status == 404 {
				if read.Diagnostics.HasError() || !read.State.Raw.IsNull() || del.Diagnostics.HasError() {
					t.Fatal("404 must remove state / allow delete")
				}
			} else if !read.Diagnostics.HasError() || !read.State.Raw.Equal(state.Raw) || !del.Diagnostics.HasError() {
				t.Fatal("failed read/delete must report error and preserve state")
			}
		})
	}
}

func TestEscalationPolicyValidation(t *testing.T) {
	r := &escalationPolicyResource{}
	for _, tc := range []struct {
		name      string
		steps     []escalationStepJSON
		wantError bool
	}{
		{"oncall", []escalationStepJSON{{"alerts", 0}}, false},
		{"", []escalationStepJSON{{"alerts", 0}}, true},
		{"oncall", nil, true},
		{"oncall", []escalationStepJSON{{"", 0}}, true},
		{"oncall", []escalationStepJSON{{"alerts", -1}}, true},
	} {
		plan := policyPlan(t, r, tc.name, tc.steps...)
		var resp resource.ValidateConfigResponse
		r.ValidateConfig(context.Background(), resource.ValidateConfigRequest{Config: tfsdk.Config{Schema: plan.Schema, Raw: plan.Raw}}, &resp)
		if resp.Diagnostics.HasError() != tc.wantError {
			t.Errorf("%+v: %v", tc, resp.Diagnostics)
		}
	}
	// Validation must defer references/dynamic blocks whose values are not known yet.
	for _, steps := range []types.List{
		types.ListUnknown(escalationStepType),
		types.ListValueMust(escalationStepType, []attr.Value{types.ObjectUnknown(escalationStepType.AttrTypes)}),
		types.ListValueMust(escalationStepType, []attr.Value{types.ObjectValueMust(escalationStepType.AttrTypes, map[string]attr.Value{"channel": types.StringUnknown(), "delay_min": types.Int64Unknown()})}),
	} {
		state := policyState(t, r)
		if d := state.Set(context.Background(), escalationPolicyModel{Name: types.StringUnknown(), Steps: steps}); d.HasError() {
			t.Fatal(d)
		}
		var resp resource.ValidateConfigResponse
		r.ValidateConfig(context.Background(), resource.ValidateConfigRequest{Config: tfsdk.Config{Schema: state.Schema, Raw: state.Raw}}, &resp)
		if resp.Diagnostics.HasError() {
			t.Fatal(resp.Diagnostics)
		}
	}
	imported := resource.ImportStateResponse{State: policyState(t, r)}
	r.ImportState(context.Background(), resource.ImportStateRequest{ID: ""}, &imported)
	if !imported.Diagnostics.HasError() {
		t.Fatal("empty import must fail")
	}
}
