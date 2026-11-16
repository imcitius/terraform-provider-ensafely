package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/imcitius/terraform-provider-ensafely/internal/client"
)

const testConnectionID = "0b6f1f7e-4c4e-4f5b-9a63-2f4d3c2b1a00"

// fakeConnectionAPI is an in-memory /api/connections with the server's secret
// rules (internal/secret): the password is never returned, header values and
// base_url passwords are masked on read, and omitted headers or an omitted
// password-bearing base_url are kept on PATCH. It records request bodies, so
// tests can see exactly what the provider sent.
type fakeConnectionAPI struct {
	t        *testing.T
	mu       sync.Mutex
	stored   map[string]any // unmasked ConnectionRead body, without password
	password *string
	requests []recordedRequest
	status   int    // non-zero: every request fails with this status
	errBody  string // body for status
}

type recordedRequest struct {
	Method string
	Path   string
	Body   map[string]any
}

func (f *fakeConnectionAPI) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	rec := recordedRequest{Method: req.Method, Path: req.URL.EscapedPath()}
	if req.Body != nil && req.ContentLength != 0 {
		if err := json.NewDecoder(req.Body).Decode(&rec.Body); err != nil {
			f.t.Errorf("decode %s %s: %v", req.Method, rec.Path, err)
		}
	}
	f.requests = append(f.requests, rec)
	w.Header().Set("Content-Type", "application/json")
	if f.status != 0 {
		w.WriteHeader(f.status)
		_, _ = fmt.Fprint(w, f.errBody)
		return
	}
	write := func(status int) {
		masked := map[string]any{}
		for k, v := range f.stored {
			masked[k] = v
		}
		params := map[string]any{}
		for k, v := range f.stored["params"].(map[string]any) {
			params[k] = v
		}
		if h, ok := params[paramHeaders].(map[string]any); ok {
			m := map[string]any{}
			for k, v := range h {
				m[k] = apiSecretMask
				if v == "" {
					m[k] = ""
				}
			}
			params[paramHeaders] = m
		}
		if s, ok := params[paramBaseURL].(string); ok && urlHasPassword(s) {
			params[paramBaseURL] = "https://user:" + apiSecretMask + "@" + s[strings.LastIndex(s, "@")+1:]
		}
		masked["params"] = params
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(masked)
	}
	store := func(body map[string]any) {
		if pw, ok := body["password"].(string); ok {
			f.password = &pw
		}
		params := map[string]any{} // a copy: rec.Body must stay as sent
		if in, ok := body["params"].(map[string]any); ok {
			for k, v := range in {
				params[k] = v
			}
		}
		if f.stored != nil {
			old := f.stored["params"].(map[string]any)
			if _, ok := params[paramHeaders]; !ok && old[paramHeaders] != nil {
				params[paramHeaders] = old[paramHeaders]
			}
			if s, ok := old[paramBaseURL].(string); ok && urlHasPassword(s) && params[paramBaseURL] == nil {
				params[paramBaseURL] = s
			}
		}
		next := map[string]any{"id": testConnectionID, "tenant_id": "tenant"}
		for k, v := range body {
			if k == "password" || v == nil {
				continue // nil pointers are omitted (omitempty)
			}
			next[k] = v
		}
		next["params"] = params
		f.stored = next
	}
	switch {
	case req.Method == http.MethodPost && rec.Path == "/api/connections":
		f.stored = nil
		store(rec.Body)
		write(http.StatusCreated)
	case rec.Path != "/api/connections/"+testConnectionID || f.stored == nil:
		w.WriteHeader(http.StatusNotFound)
		_, _ = fmt.Fprint(w, `{"error":"connection not found"}`)
	case req.Method == http.MethodGet:
		write(http.StatusOK)
	case req.Method == http.MethodPatch:
		store(rec.Body)
		write(http.StatusOK)
	case req.Method == http.MethodDelete:
		f.stored = nil
		w.WriteHeader(http.StatusNoContent)
	default:
		f.t.Errorf("unexpected %s %s", req.Method, rec.Path)
	}
}

func (f *fakeConnectionAPI) last(method string) recordedRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := len(f.requests) - 1; i >= 0; i-- {
		if f.requests[i].Method == method {
			return f.requests[i]
		}
	}
	f.t.Fatalf("no %s request recorded", method)
	return recordedRequest{}
}

func (f *fakeConnectionAPI) storedParams() map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.stored["params"].(map[string]any)
}

func newTestConnectionResource(t *testing.T) (*connectionResource, *fakeConnectionAPI) {
	t.Helper()
	api := &fakeConnectionAPI{t: t}
	srv := httptest.NewServer(api)
	t.Cleanup(srv.Close)
	c, err := client.New(client.Config{Endpoint: srv.URL, APIKey: "ck_test", MaxRetries: -1})
	if err != nil {
		t.Fatal(err)
	}
	return &connectionResource{client: c}, api
}

func connectionSchema(t *testing.T) resource.SchemaResponse {
	t.Helper()
	var resp resource.SchemaResponse
	(&connectionResource{}).Schema(context.Background(), resource.SchemaRequest{}, &resp)
	if diags := resp.Schema.ValidateImplementation(context.Background()); diags.HasError() {
		t.Fatal(diags)
	}
	return resp
}

func emptyConnectionState(t *testing.T) tfsdk.State {
	t.Helper()
	s := connectionSchema(t).Schema
	return tfsdk.State{Schema: s, Raw: tftypes.NewValue(s.Type().TerraformType(context.Background()), nil)}
}

// connectionValue encodes m with the resource schema, for use as plan,
// config or state.
func connectionValue(t *testing.T, m connectionModel) tftypes.Value {
	t.Helper()
	state := emptyConnectionState(t)
	if diags := state.Set(context.Background(), m); diags.HasError() {
		t.Fatal(diags)
	}
	return state.Raw
}

func connectionFromState(t *testing.T, state tfsdk.State) connectionModel {
	t.Helper()
	var m connectionModel
	if diags := state.Get(context.Background(), &m); diags.HasError() {
		t.Fatal(diags)
	}
	return m
}

// connParams builds a params object; zero-value fields are null.
func connParams(t *testing.T, p connectionParamsModel) types.Object {
	t.Helper()
	v, diags := types.ObjectValueFrom(context.Background(), connectionParamsAttrTypes(), p)
	if diags.HasError() {
		t.Fatal(diags)
	}
	return v
}

func headersValue(h map[string]string) types.Map {
	elems := map[string]attr.Value{}
	for k, v := range h {
		elems[k] = types.StringValue(v)
	}
	return types.MapValueMust(types.StringType, elems)
}

func baseConnection() connectionModel {
	return connectionModel{
		ID:                types.StringUnknown(),
		Name:              types.StringValue("prod-db"),
		Type:              types.StringValue("postgres"),
		Host:              types.StringValue("db.example.com"),
		Port:              types.Int64Value(5432),
		Username:          types.StringValue("checker"),
		PasswordWO:        types.StringNull(),
		PasswordWOVersion: types.Int64Value(1),
		HeadersWO:         types.MapNull(types.StringType),
		HeadersWOVersion:  types.Int64Null(),
		Params:            types.ObjectNull(connectionParamsAttrTypes()),
	}
}

// applyConnection runs Create (prior == nil) or Update with the given
// configuration; write-only values come from cfg and are null in the plan.
func applyConnection(t *testing.T, r *connectionResource, prior *tfsdk.State, cfg connectionModel) tfsdk.State {
	t.Helper()
	ctx := context.Background()
	plan := cfg
	plan.clearWriteOnly()
	schema := connectionSchema(t).Schema
	if prior == nil {
		resp := resource.CreateResponse{State: emptyConnectionState(t)}
		r.Create(ctx, resource.CreateRequest{
			Plan:   tfsdk.Plan{Schema: schema, Raw: connectionValue(t, plan)},
			Config: tfsdk.Config{Schema: schema, Raw: connectionValue(t, cfg)},
		}, &resp)
		if resp.Diagnostics.HasError() {
			t.Fatal(resp.Diagnostics)
		}
		return resp.State
	}
	plan.ID = connectionFromState(t, *prior).ID
	cfg.ID = types.StringNull()
	resp := resource.UpdateResponse{State: *prior}
	r.Update(ctx, resource.UpdateRequest{
		State:  *prior,
		Plan:   tfsdk.Plan{Schema: schema, Raw: connectionValue(t, plan)},
		Config: tfsdk.Config{Schema: schema, Raw: connectionValue(t, cfg)},
	}, &resp)
	if resp.Diagnostics.HasError() {
		t.Fatal(resp.Diagnostics)
	}
	return resp.State
}

// readConnection runs Read and requires it to reproduce state (empty plan).
func readConnection(t *testing.T, r *connectionResource, state tfsdk.State) {
	t.Helper()
	read := resource.ReadResponse{State: state}
	r.Read(context.Background(), resource.ReadRequest{State: state}, &read)
	if read.Diagnostics.HasError() {
		t.Fatal(read.Diagnostics)
	}
	if !read.State.Raw.Equal(state.Raw) {
		t.Fatalf("read differs from applied state:\n%v\n%v", read.State.Raw, state.Raw)
	}
}

func assertNoSecret(t *testing.T, state tfsdk.State, secrets ...string) {
	t.Helper()
	for _, secret := range secrets {
		if strings.Contains(state.Raw.String(), secret) {
			t.Fatalf("secret %q found in state: %s", secret, state.Raw)
		}
	}
	m := connectionFromState(t, state)
	if !m.PasswordWO.IsNull() || !m.HeadersWO.IsNull() {
		t.Fatal("write-only attributes must be null in state")
	}
}

func TestConnectionSchema(t *testing.T) {
	s := connectionSchema(t).Schema
	for _, name := range []string{"password_wo", "headers_wo"} {
		a := s.Attributes[name]
		if !a.IsWriteOnly() || !a.IsOptional() || a.IsComputed() {
			t.Fatalf("%s must be optional, write-only and not computed", name)
		}
	}
	for name, a := range s.Attributes {
		if a.IsComputed() && name != "id" {
			t.Errorf("%s is computed; only the server-assigned id may be", name)
		}
	}
	for _, name := range []string{"password", "headers"} {
		if _, ok := s.Attributes[name]; ok {
			t.Fatalf("no stored %s attribute is allowed", name)
		}
	}
}

func TestConnectionPasswordLifecycle(t *testing.T) {
	ctx := context.Background()
	r, api := newTestConnectionResource(t)

	// Create: the password comes from config (it is null in the plan).
	cfg := baseConnection()
	cfg.Params = connParams(t, connectionParamsModel{DBName: types.StringValue("app"), SSLMode: types.StringValue("require")})
	cfg.PasswordWO = types.StringValue("first-secret")
	state := applyConnection(t, r, nil, cfg)
	want := map[string]any{
		"name": "prod-db", "type": "postgres", "host": "db.example.com", "port": float64(5432),
		"username": "checker", "password": "first-secret",
		"params": map[string]any{"db_name": "app", "ssl_mode": "require"},
	}
	if got := api.last(http.MethodPost).Body; !reflect.DeepEqual(got, want) {
		t.Fatalf("create payload = %#v\nwant %#v", got, want)
	}
	assertNoSecret(t, state, "first-secret")
	if id := connectionFromState(t, state).ID.ValueString(); id != testConnectionID {
		t.Fatalf("id = %s", id)
	}
	readConnection(t, r, state)

	// A params key set outside Terraform survives an update.
	api.mu.Lock()
	api.stored["params"].(map[string]any)["custom"] = map[string]any{"x": 1.0}
	api.mu.Unlock()

	// Same version: the changed password is not sent, other fields are.
	cfg.Host = types.StringNull()
	cfg.Params = connParams(t, connectionParamsModel{DBName: types.StringValue("app2")})
	cfg.PasswordWO = types.StringValue("second-secret")
	state = applyConnection(t, r, &state, cfg)
	body := api.last(http.MethodPatch).Body
	if _, sent := body["password"]; sent {
		t.Fatalf("password sent without a version change: %#v", body)
	}
	if body["host"] != nil || !reflect.DeepEqual(body["params"], map[string]any{"db_name": "app2", "custom": map[string]any{"x": 1.0}}) {
		t.Fatalf("update payload = %#v", body)
	}
	if *api.password != "first-secret" {
		t.Fatal("password changed without a version bump")
	}

	// Version bump: the new password is sent (rotation) and not stored.
	cfg.PasswordWOVersion = types.Int64Value(2)
	state = applyConnection(t, r, &state, cfg)
	if got := api.last(http.MethodPatch).Body["password"]; got != "second-secret" {
		t.Fatalf("rotated password = %#v", got)
	}
	assertNoSecret(t, state, "first-secret", "second-secret")

	// Version bump with no password: the stored password is cleared.
	cfg.PasswordWO = types.StringNull()
	cfg.PasswordWOVersion = types.Int64Value(3)
	state = applyConnection(t, r, &state, cfg)
	if got, sent := api.last(http.MethodPatch).Body["password"]; !sent || got != "" {
		t.Fatalf("clear password payload = %#v", api.last(http.MethodPatch).Body)
	}
	readConnection(t, r, state)

	// Import by UUID then Read fills every non-secret field.
	imp := resource.ImportStateResponse{State: emptyConnectionState(t)}
	r.ImportState(ctx, resource.ImportStateRequest{ID: testConnectionID}, &imp)
	if imp.Diagnostics.HasError() {
		t.Fatal(imp.Diagnostics)
	}
	read := resource.ReadResponse{State: imp.State}
	r.Read(ctx, resource.ReadRequest{State: imp.State}, &read)
	if read.Diagnostics.HasError() {
		t.Fatal(read.Diagnostics)
	}
	wantImported := connectionFromState(t, state)
	wantImported.PasswordWOVersion = types.Int64Null()
	if got := connectionFromState(t, read.State); !reflect.DeepEqual(got, wantImported) {
		t.Fatalf("imported = %+v\nwant %+v", got, wantImported)
	}

	// Delete, then Read drops the missing connection from state.
	del := resource.DeleteResponse{}
	r.Delete(ctx, resource.DeleteRequest{State: state}, &del)
	if del.Diagnostics.HasError() {
		t.Fatal(del.Diagnostics)
	}
	read = resource.ReadResponse{State: state}
	r.Read(ctx, resource.ReadRequest{State: state}, &read)
	if read.Diagnostics.HasError() || !read.State.Raw.IsNull() {
		t.Fatalf("404 must remove the resource: %v", read.Diagnostics)
	}
	// A second delete (already gone) succeeds.
	r.Delete(ctx, resource.DeleteRequest{State: state}, &del)
	if del.Diagnostics.HasError() {
		t.Fatal(del.Diagnostics)
	}
}

func TestConnectionHeadersLifecycle(t *testing.T) {
	r, api := newTestConnectionResource(t)
	cfg := connectionModel{
		Name: types.StringValue("api"), Type: types.StringValue("http"),
		Params:            connParams(t, connectionParamsModel{BaseURL: types.StringValue("https://api.example.com")}),
		HeadersWO:         headersValue(map[string]string{"X-Token": "header-secret"}),
		HeadersWOVersion:  types.Int64Value(1),
		PasswordWO:        types.StringNull(),
		PasswordWOVersion: types.Int64Null(),
	}
	state := applyConnection(t, r, nil, cfg)
	if got := api.last(http.MethodPost).Body["params"]; !reflect.DeepEqual(got, map[string]any{
		"base_url": "https://api.example.com", "headers": map[string]any{"X-Token": "header-secret"},
	}) {
		t.Fatalf("create params = %#v", got)
	}
	if _, sent := api.last(http.MethodPost).Body["password"]; sent {
		t.Fatal("a null password must be omitted on create")
	}
	assertNoSecret(t, state, "header-secret")
	// The API masks header values on read; nothing about them is in state.
	readConnection(t, r, state)

	// Same version: headers are omitted (the API keeps them).
	cfg.HeadersWO = headersValue(map[string]string{"X-Token": "other"})
	cfg.Params = connParams(t, connectionParamsModel{BaseURL: types.StringValue("https://api2.example.com")})
	state = applyConnection(t, r, &state, cfg)
	if _, sent := api.last(http.MethodPatch).Body["params"].(map[string]any)[paramHeaders]; sent {
		t.Fatalf("headers sent without a version change: %#v", api.last(http.MethodPatch).Body)
	}
	if got := api.storedParams()[paramHeaders]; !reflect.DeepEqual(got, map[string]any{"X-Token": "header-secret"}) {
		t.Fatalf("stored headers = %#v", got)
	}

	// Version bump replaces the whole map; null then clears it.
	cfg.HeadersWOVersion = types.Int64Value(2)
	state = applyConnection(t, r, &state, cfg)
	if got := api.storedParams()[paramHeaders]; !reflect.DeepEqual(got, map[string]any{"X-Token": "other"}) {
		t.Fatalf("rotated headers = %#v", got)
	}
	cfg.HeadersWO = types.MapNull(types.StringType)
	cfg.HeadersWOVersion = types.Int64Value(3)
	state = applyConnection(t, r, &state, cfg)
	if got := api.last(http.MethodPatch).Body["params"].(map[string]any)[paramHeaders]; !reflect.DeepEqual(got, map[string]any{}) {
		t.Fatalf("clear headers payload = %#v", got)
	}
	readConnection(t, r, state)
	assertNoSecret(t, state, "header-secret", "other")
}

// A base_url with a password set outside Terraform is masked on read and kept
// by the API when omitted; removing it from configuration must clear it.
func TestConnectionBaseURLWithPasswordIsRemoved(t *testing.T) {
	r, api := newTestConnectionResource(t)
	cfg := connectionModel{
		Name: types.StringValue("api"), Type: types.StringValue("http"),
		Params:    types.ObjectNull(connectionParamsAttrTypes()),
		HeadersWO: types.MapNull(types.StringType), PasswordWO: types.StringNull(),
	}
	state := applyConnection(t, r, nil, cfg)
	api.mu.Lock()
	api.stored["params"] = map[string]any{"base_url": "https://user:pw@api.example.com"}
	api.mu.Unlock()

	read := resource.ReadResponse{State: state}
	r.Read(context.Background(), resource.ReadRequest{State: state}, &read)
	if read.Diagnostics.HasError() {
		t.Fatal(read.Diagnostics)
	}
	assertNoSecret(t, read.State, ":pw@")
	if got := connectionFromState(t, read.State).Params; got.IsNull() {
		t.Fatal("drift (masked base_url) must be visible")
	}

	state = applyConnection(t, r, &read.State, cfg)
	if got := api.last(http.MethodPatch).Body["params"]; !reflect.DeepEqual(got, map[string]any{"base_url": ""}) {
		t.Fatalf("payload params = %#v", got)
	}
	readConnection(t, r, state)
	if !connectionFromState(t, state).Params.IsNull() {
		t.Fatal("params must be null again")
	}
}

func TestConnectionParamsMapping(t *testing.T) {
	ctx := context.Background()
	null := types.ObjectNull(connectionParamsAttrTypes())
	tests := []struct {
		name       string
		params     string
		prior      types.Object
		wantNull   bool
		want       connectionParamsModel
		unmodelled []string
	}{
		{name: "server default", params: `{}`, prior: null, wantNull: true},
		{name: "absent", params: ``, prior: null, wantNull: true},
		{name: "empty block stays empty", params: `{}`, prior: connParams(t, connectionParamsModel{}), want: connectionParamsModel{}},
		{
			name:       "http, masked headers are not state",
			params:     `{"base_url":"https://api.example.com","headers":{"X-Env":"****"},"other":true}`,
			prior:      null,
			want:       connectionParamsModel{BaseURL: types.StringValue("https://api.example.com")},
			unmodelled: []string{"other"},
		},
		{
			name:       "mongo, wrong-typed key is unmodelled",
			params:     `{"db_name":"app","replica_set":"rs0","auth_source":"admin","ssl_mode":5}`,
			prior:      null,
			want:       connectionParamsModel{DBName: types.StringValue("app"), ReplicaSet: types.StringValue("rs0"), AuthSource: types.StringValue("admin")},
			unmodelled: []string{"ssl_mode"},
		},
		{name: "empty string is kept", params: `{"db_name":""}`, prior: null, want: connectionParamsModel{DBName: types.StringValue("")}},
		{name: "cleared base_url is null", params: `{"base_url":""}`, prior: null, wantNull: true},
		{name: "configured empty base_url is kept", params: `{"base_url":""}`, prior: connParams(t, connectionParamsModel{BaseURL: types.StringValue("")}), want: connectionParamsModel{BaseURL: types.StringValue("")}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := connectionModel{Params: tc.prior}
			var diags diag.Diagnostics
			m.fromAPI(ctx, connectionJSON{ID: testConnectionID, Name: "n", Type: "http", Params: json.RawMessage(tc.params)}, &diags)
			if diags.HasError() {
				t.Fatal(diags)
			}
			if tc.wantNull {
				if !m.Params.IsNull() {
					t.Fatalf("params = %v, want null", m.Params)
				}
			} else if want := connParams(t, tc.want); !m.Params.Equal(want) {
				t.Fatalf("params = %v\nwant %v", m.Params, want)
			}
			keys := []string{}
			for k := range unmodelledParams(json.RawMessage(tc.params)) {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			if tc.unmodelled == nil {
				tc.unmodelled = []string{}
			}
			if !reflect.DeepEqual(keys, tc.unmodelled) {
				t.Fatalf("unmodelled = %v, want %v", keys, tc.unmodelled)
			}
		})
	}
}

func TestConnectionPayloadNulls(t *testing.T) {
	ctx := context.Background()
	m := connectionModel{
		Name: types.StringValue("api"), Type: types.StringValue("http"),
		Host: types.StringNull(), Port: types.Int64Null(), Username: types.StringValue(""),
		Params: types.ObjectNull(connectionParamsAttrTypes()),
	}
	var d diag.Diagnostics
	raw, err := json.Marshal(m.payload(ctx, connectionSecrets{}, nil, &d))
	if err != nil || d.HasError() {
		t.Fatal(err, d)
	}
	// host/port are sent as null (PATCH replaces them); password and params
	// are omitted (the server keeps the password and stores params {});
	// an explicit empty username survives.
	want := `{"name":"api","type":"http","host":null,"port":null,"username":""}`
	if string(raw) != want {
		t.Fatalf("payload = %s\nwant %s", raw, want)
	}
}

func TestConnectionErrors(t *testing.T) {
	ctx := context.Background()
	r, api := newTestConnectionResource(t)
	m := baseConnection()
	m.ID = types.StringValue(testConnectionID)
	state := tfsdk.State{Schema: connectionSchema(t).Schema, Raw: connectionValue(t, m)}

	api.status = http.StatusConflict
	api.errBody = `{"error":"connection is in use by one or more checks","checks":[{"uuid":"c-1","name":"orders db"}]}`
	del := resource.DeleteResponse{}
	r.Delete(ctx, resource.DeleteRequest{State: state}, &del)
	if !del.Diagnostics.HasError() {
		t.Fatal("409 must fail destroy")
	}
	if detail := del.Diagnostics[0].Detail(); !strings.Contains(detail, "orders db (c-1)") || !strings.Contains(detail, "connection_id") {
		t.Fatalf("detail = %s", detail)
	}

	api.status = http.StatusInternalServerError
	api.errBody = `{"error":"failed to get connection"}`
	read := resource.ReadResponse{State: state}
	r.Read(ctx, resource.ReadRequest{State: state}, &read)
	if !read.Diagnostics.HasError() || read.State.Raw.IsNull() {
		t.Fatal("a 500 on read must fail and keep state")
	}

	for _, id := range []string{"", "prod-db", testConnectionID + "/x"} {
		imp := resource.ImportStateResponse{State: emptyConnectionState(t)}
		r.ImportState(ctx, resource.ImportStateRequest{ID: id}, &imp)
		if !imp.Diagnostics.HasError() {
			t.Fatalf("import %q must fail", id)
		}
	}
}

func TestConnectionValidateConfig(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name   string
		mutate func(*connectionModel)
		err    string
	}{
		{name: "valid", mutate: func(*connectionModel) {}},
		{name: "valid without secrets", mutate: func(m *connectionModel) {
			m.PasswordWO = types.StringNull()
			m.PasswordWOVersion = types.Int64Null()
		}},
		{name: "unknown values", mutate: func(m *connectionModel) {
			m.Name = types.StringUnknown()
			m.Type = types.StringUnknown()
			m.HeadersWO = types.MapUnknown(types.StringType)
			m.HeadersWOVersion = types.Int64Value(1)
			m.Params = types.ObjectUnknown(connectionParamsAttrTypes())
		}},
		{name: "username in base_url", mutate: func(m *connectionModel) {
			m.Params = connParams(t, connectionParamsModel{BaseURL: types.StringValue("https://user@api.example.com")})
		}},
		{name: "empty name", mutate: func(m *connectionModel) { m.Name = types.StringValue(" ") }, err: "Invalid connection name"},
		{name: "bad type", mutate: func(m *connectionModel) { m.Type = types.StringValue("redis") }, err: "Invalid connection type"},
		{name: "password without version", mutate: func(m *connectionModel) { m.PasswordWOVersion = types.Int64Null() }, err: "Missing password_wo_version"},
		{name: "headers without version", mutate: func(m *connectionModel) {
			m.HeadersWO = headersValue(map[string]string{"A": "b"})
		}, err: "Missing headers_wo_version"},
		{name: "masked password", mutate: func(m *connectionModel) { m.PasswordWO = types.StringValue("****") }, err: "Invalid password"},
		{name: "masked header", mutate: func(m *connectionModel) {
			m.HeadersWO = headersValue(map[string]string{"A": "****"})
			m.HeadersWOVersion = types.Int64Value(1)
		}, err: "Invalid header value"},
		{name: "password in base_url", mutate: func(m *connectionModel) {
			m.Params = connParams(t, connectionParamsModel{BaseURL: types.StringValue("https://user:pw@api.example.com/x")})
		}, err: "Password in base_url"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := baseConnection()
			m.ID = types.StringNull()
			m.PasswordWO = types.StringValue("s")
			tc.mutate(&m)
			resp := resource.ValidateConfigResponse{}
			s := connectionSchema(t).Schema
			(&connectionResource{}).ValidateConfig(ctx, resource.ValidateConfigRequest{Config: tfsdk.Config{Schema: s, Raw: connectionValue(t, m)}}, &resp)
			if tc.err == "" {
				if resp.Diagnostics.HasError() {
					t.Fatal(resp.Diagnostics)
				}
				return
			}
			if !resp.Diagnostics.HasError() || resp.Diagnostics[0].Summary() != tc.err {
				t.Fatalf("diagnostics = %v, want %q", resp.Diagnostics, tc.err)
			}
		})
	}
}
