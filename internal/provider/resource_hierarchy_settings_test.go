package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/imcitius/terraform-provider-ensafely/internal/client"
)

func settingsState(t *testing.T, r *hierarchySettingsResource) tfsdk.State {
	t.Helper()
	var resp resource.SchemaResponse
	r.Schema(context.Background(), resource.SchemaRequest{}, &resp)
	if diags := resp.Schema.ValidateImplementation(context.Background()); diags.HasError() {
		t.Fatal(diags)
	}
	return tfsdk.State{Schema: resp.Schema, Raw: tftypes.NewValue(resp.Schema.Type().TerraformType(context.Background()), nil)}
}

func settingsImport(t *testing.T, r *hierarchySettingsResource, id string) tfsdk.State {
	t.Helper()
	resp := resource.ImportStateResponse{State: settingsState(t, r)}
	r.ImportState(context.Background(), resource.ImportStateRequest{ID: id}, &resp)
	if resp.Diagnostics.HasError() {
		t.Fatal(resp.Diagnostics)
	}
	return resp.State
}

func setSettingsAttribute(t *testing.T, state *tfsdk.State, name string, value any) {
	t.Helper()
	if diags := state.SetAttribute(context.Background(), path.Root(name), value); diags.HasError() {
		t.Fatal(diags)
	}
}

func TestHierarchySettingsLifecycle(t *testing.T) {
	for _, group := range []bool{false, true} {
		t.Run(fmt.Sprintf("group=%v", group), func(t *testing.T) {
			ctx := context.Background()
			r := &hierarchySettingsResource{group: group}
			id, wantPath := "prod ?#% café", "/api/project-settings/prod%20%3F%23%25%20caf%C3%A9"
			if group {
				id += "/db & redis"
				wantPath = "/api/group-settings/prod%20%3F%23%25%20caf%C3%A9/db%20&%20redis"
			}
			var stored map[string]any
			status := http.StatusOK
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				if req.URL.EscapedPath() != wantPath {
					t.Errorf("path = %q, want %q", req.URL.EscapedPath(), wantPath)
				}
				w.Header().Set("Content-Type", "application/json")
				if status != http.StatusOK {
					w.WriteHeader(status)
					_, _ = fmt.Fprint(w, `{"error":"read or reset failed"}`)
					return
				}
				switch req.Method {
				case http.MethodPut:
					if err := json.NewDecoder(req.Body).Decode(&stored); err != nil {
						t.Error(err)
					}
					_, _ = fmt.Fprint(w, `{"message":"updated"}`)
				case http.MethodGet:
					body := map[string]any{"maintenance_until": "2030-01-01T00:00:00Z", "maintenance_reason": "UI window", "updated_at": "2026-01-01T00:00:00Z"}
					for k, v := range stored {
						body[k] = v
					}
					_ = json.NewEncoder(w).Encode(body)
				default:
					t.Errorf("unexpected method %s", req.Method)
				}
			}))
			defer srv.Close()
			var err error
			r.client, err = client.New(client.Config{Endpoint: srv.URL, APIKey: "ck_test", MaxRetries: -1})
			if err != nil {
				t.Fatal(err)
			}
			state := settingsImport(t, r, id)
			var schemaResp resource.SchemaResponse
			r.Schema(ctx, resource.SchemaRequest{}, &schemaResp)
			for _, name := range []string{"enabled", "duration", "re_alert_interval"} {
				a := schemaResp.Schema.Attributes[name]
				if !a.IsOptional() || a.IsComputed() {
					t.Fatalf("%s must be optional, not computed", name)
				}
			}
			setSettingsAttribute(t, &state, "enabled", types.BoolValue(false))
			setSettingsAttribute(t, &state, "duration", types.StringValue(""))
			create := resource.CreateResponse{State: settingsState(t, r)}
			r.Create(ctx, resource.CreateRequest{Plan: tfsdk.Plan{Schema: state.Schema, Raw: state.Raw}}, &create)
			if create.Diagnostics.HasError() {
				t.Fatal(create.Diagnostics)
			}
			if !reflect.DeepEqual(stored, map[string]any{"enabled": false, "duration": "", "re_alert_interval": nil}) {
				t.Fatalf("create payload = %#v", stored)
			}
			read := resource.ReadResponse{State: create.State}
			r.Read(ctx, resource.ReadRequest{State: create.State}, &read)
			if read.Diagnostics.HasError() || !read.State.Raw.Equal(create.State.Raw) {
				t.Fatalf("maintenance affected state: %v", read.Diagnostics)
			}

			// Explicit false/empty strings survive; null clears them rather than
			// preserving the prior value or materializing inherited defaults.
			state = create.State
			setSettingsAttribute(t, &state, "enabled", types.BoolNull())
			setSettingsAttribute(t, &state, "duration", types.StringNull())
			setSettingsAttribute(t, &state, "re_alert_interval", types.StringValue("2h"))
			update := resource.UpdateResponse{State: create.State}
			r.Update(ctx, resource.UpdateRequest{Plan: tfsdk.Plan{Schema: state.Schema, Raw: state.Raw}, State: create.State}, &update)
			if update.Diagnostics.HasError() {
				t.Fatal(update.Diagnostics)
			}
			if !reflect.DeepEqual(stored, map[string]any{"enabled": nil, "duration": nil, "re_alert_interval": "2h"}) {
				t.Fatalf("update payload = %#v", stored)
			}
			imported := settingsImport(t, r, id)
			read = resource.ReadResponse{State: imported}
			r.Read(ctx, resource.ReadRequest{State: imported}, &read)
			if read.Diagnostics.HasError() || !read.State.Raw.Equal(update.State.Raw) {
				t.Fatalf("import differs: %v", read.Diagnostics)
			}

			status = http.StatusInternalServerError
			read = resource.ReadResponse{State: update.State}
			r.Read(ctx, resource.ReadRequest{State: update.State}, &read)
			if !read.Diagnostics.HasError() || !read.State.Raw.Equal(update.State.Raw) {
				t.Fatal("failed read must preserve state")
			}
			failedDelete := resource.DeleteResponse{State: update.State}
			r.Delete(ctx, resource.DeleteRequest{State: update.State}, &failedDelete)
			if !failedDelete.Diagnostics.HasError() {
				t.Fatal("failed reset must not report success")
			}
			status = http.StatusOK
			deleted := resource.DeleteResponse{State: update.State}
			r.Delete(ctx, resource.DeleteRequest{State: update.State}, &deleted)
			if deleted.Diagnostics.HasError() {
				t.Fatal(deleted.Diagnostics)
			}
			if !reflect.DeepEqual(stored, map[string]any{"enabled": nil, "duration": nil, "re_alert_interval": nil}) {
				t.Fatalf("reset payload = %#v", stored)
			}

			// Missing database rows are 200/null, so keep a managed resource.
			read = resource.ReadResponse{State: update.State}
			r.Read(ctx, resource.ReadRequest{State: update.State}, &read)
			if read.Diagnostics.HasError() || read.State.Raw.IsNull() {
				t.Fatalf("null overrides removed resource: %v", read.Diagnostics)
			}
			status = http.StatusNotFound
			r.Read(ctx, resource.ReadRequest{State: update.State}, &read)
			if read.Diagnostics.HasError() || !read.State.Raw.IsNull() {
				t.Fatal("404 must remove state")
			}
		})
	}
}

func TestHierarchySettingsInvalidImport(t *testing.T) {
	for _, tc := range []struct {
		group bool
		id    string
	}{
		{false, ""}, {false, "p/g"}, {true, ""}, {true, "p"}, {true, "/g"}, {true, "p/"}, {true, "p/g/extra"},
	} {
		r := &hierarchySettingsResource{group: tc.group}
		resp := resource.ImportStateResponse{State: settingsState(t, r)}
		r.ImportState(context.Background(), resource.ImportStateRequest{ID: tc.id}, &resp)
		if !resp.Diagnostics.HasError() {
			t.Errorf("group=%v import %q must fail", tc.group, tc.id)
		}
	}
}
