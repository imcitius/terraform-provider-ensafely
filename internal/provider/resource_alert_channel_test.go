package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/imcitius/terraform-provider-ensafely/internal/client"
)

// Secret keys per channel type, as in the cloud's internal/secret table.
var fakeChannelSecrets = map[string][]string{
	"telegram": {"bot_token"},
	"slack":    {"bot_token", "signing_secret", "webhook_url"},
	"email":    {"smtp_password"},
	"discord":  {"bot_token"},
	"webhook":  {"url", "secret"},
	"teams":    {"webhook_url"},
}

type fakeChannel struct {
	Type   string
	Config map[string]any
}

// fakeChannelAPI is an in-memory /api/alert-channels with the server's
// secret contract: reads mask secrets as "****"; on PUT an omitted secret of
// the same type is kept, "****" keeps, "" (or {} for headers) clears, and all
// other keys are replaced by the request. The default "Email" channel cannot
// be deleted.
type fakeChannelAPI struct {
	t        *testing.T
	mu       sync.Mutex
	channels map[string]*fakeChannel
	requests []recordedRequest
}

func (f *fakeChannelAPI) ServeHTTP(w http.ResponseWriter, req *http.Request) {
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
	fail := func(status int, msg string) {
		w.WriteHeader(status)
		_, _ = fmt.Fprintf(w, `{"error":%q}`, msg)
	}
	const prefix = "/api/alert-channels/"
	if req.Method == http.MethodPost && rec.Path == "/api/alert-channels" {
		name, _ := rec.Body["name"].(string)
		if _, ok := f.channels[name]; ok {
			fail(http.StatusConflict, "resource already exists")
			return
		}
		typ, _ := rec.Body["type"].(string)
		cfg, err := f.resolve(typ, rec.Body["config"], nil)
		if err != nil {
			fail(http.StatusBadRequest, err.Error())
			return
		}
		f.channels[name] = &fakeChannel{Type: typ, Config: cfg}
		w.WriteHeader(http.StatusCreated)
		_, _ = fmt.Fprintf(w, `{"message":"Alert channel created","name":%q}`, name)
		return
	}
	if !strings.HasPrefix(rec.Path, prefix) {
		f.t.Errorf("unexpected %s %s", req.Method, rec.Path)
		fail(http.StatusNotFound, "not found")
		return
	}
	name := strings.TrimPrefix(req.URL.Path, prefix)
	ch, ok := f.channels[name]
	if !ok {
		fail(http.StatusNotFound, "Alert channel not found")
		return
	}
	switch req.Method {
	case http.MethodGet:
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id": 1, "name": name, "type": ch.Type, "config": maskChannel(ch.Config),
			"created_at": "2026-11-14T00:00:00Z", "updated_at": "2026-11-14T00:00:00Z",
		})
	case http.MethodPut:
		typ, _ := rec.Body["type"].(string)
		if typ == "" {
			typ = ch.Type
		}
		var stored map[string]any
		if typ == ch.Type {
			stored = ch.Config
		}
		cfg, err := f.resolve(typ, rec.Body["config"], stored)
		if err != nil {
			fail(http.StatusBadRequest, err.Error())
			return
		}
		f.channels[name] = &fakeChannel{Type: typ, Config: cfg}
		_, _ = fmt.Fprintf(w, `{"message":"Alert channel updated","name":%q}`, name)
	case http.MethodDelete:
		if name == "Email" && ch.Type == "email" {
			fail(http.StatusForbidden, "cannot delete the default Email alert channel")
			return
		}
		delete(f.channels, name)
		_, _ = fmt.Fprint(w, `{"message":"deleted"}`)
	default:
		f.t.Errorf("unexpected %s %s", req.Method, rec.Path)
	}
}

func (f *fakeChannelAPI) resolve(typ string, incoming any, stored map[string]any) (map[string]any, error) {
	in, _ := incoming.(map[string]any)
	cfg := map[string]any{}
	for k, v := range in {
		cfg[k] = v
	}
	for _, k := range fakeChannelSecrets[typ] {
		v, present := cfg[k]
		old, _ := stored[k].(string)
		switch {
		case !present || v == nil || v == apiSecretMask:
			if v == apiSecretMask && old == "" {
				return nil, fmt.Errorf("config.%s is the mask placeholder but no stored value exists", k)
			}
			if old != "" {
				cfg[k] = old
			} else {
				delete(cfg, k)
			}
		}
	}
	if typ == "webhook" {
		old, _ := stored["headers"].(map[string]any)
		switch h := cfg["headers"].(type) {
		case nil:
			if len(old) > 0 {
				cfg["headers"] = old
			} else {
				delete(cfg, "headers")
			}
		case map[string]any:
			for k, v := range h {
				if v == apiSecretMask {
					h[k] = old[k]
				}
			}
		}
	}
	return cfg, nil
}

func maskChannel(cfg map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range cfg {
		out[k] = v
	}
	for _, keys := range fakeChannelSecrets {
		for _, k := range keys {
			if s, ok := out[k].(string); ok && s != "" {
				out[k] = apiSecretMask
			}
		}
	}
	if h, ok := out["headers"].(map[string]any); ok {
		m := map[string]any{}
		for k := range h {
			m[k] = apiSecretMask
		}
		out["headers"] = m
	}
	return out
}

func (f *fakeChannelAPI) stored(name string) *fakeChannel {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.channels[name]
}

func (f *fakeChannelAPI) mark() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.requests)
}

func (f *fakeChannelAPI) writesSince(n int) []recordedRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []recordedRequest
	for _, r := range f.requests[n:] {
		if r.Method != http.MethodGet {
			out = append(out, r)
		}
	}
	return out
}

func newTestAlertChannelResource(t *testing.T) (*alertChannelResource, *fakeChannelAPI) {
	t.Helper()
	api := &fakeChannelAPI{t: t, channels: map[string]*fakeChannel{
		"Email": {Type: "email", Config: map[string]any{"to": []any{"owner@example.com"}}},
	}}
	srv := httptest.NewServer(api)
	t.Cleanup(srv.Close)
	c, err := client.New(client.Config{Endpoint: srv.URL, APIKey: "ck_test", MaxRetries: -1})
	if err != nil {
		t.Fatal(err)
	}
	return &alertChannelResource{client: c}, api
}

// channelValues are the attributes of one block; missing attributes are null.
type channelValues map[string]any // string, []string, map[string]string or int

func blockObject(t *testing.T, ct channelType, vals channelValues) types.Object {
	t.Helper()
	attrs := map[string]attr.Value{}
	for name, typ := range ct.attrTypes() {
		v, ok := vals[name]
		switch typ := typ.(type) {
		case types.SetType:
			attrs[name] = types.SetNull(types.StringType)
			if ok {
				attrs[name] = types.SetValueMust(types.StringType, stringValues(v.([]string)))
			}
		case types.MapType:
			attrs[name] = types.MapNull(types.StringType)
			if ok {
				elems := map[string]attr.Value{}
				for k, s := range v.(map[string]string) {
					elems[k] = types.StringValue(s)
				}
				attrs[name] = types.MapValueMust(types.StringType, elems)
			}
		default:
			if typ == types.Int64Type {
				attrs[name] = types.Int64Null()
				if ok {
					attrs[name] = types.Int64Value(int64(v.(int)))
				}
				continue
			}
			attrs[name] = types.StringNull()
			if ok {
				attrs[name] = types.StringValue(v.(string))
			}
		}
	}
	for k := range vals {
		if _, ok := attrs[k]; !ok {
			t.Fatalf("block %s has no attribute %s", ct.block, k)
		}
	}
	return types.ObjectValueMust(ct.attrTypes(), attrs)
}

func stringValues(in []string) []attr.Value {
	out := make([]attr.Value, len(in))
	for i, s := range in {
		out[i] = types.StringValue(s)
	}
	return out
}

func channelModel(t *testing.T, name, block string, vals channelValues) alertChannelModel {
	t.Helper()
	m := alertChannelModel{ID: types.StringUnknown(), Name: types.StringValue(name), Blocks: map[string]types.Object{}}
	for _, ct := range channelTypes {
		m.Blocks[ct.block] = types.ObjectNull(ct.attrTypes())
		if ct.block == block {
			m.Blocks[ct.block] = blockObject(t, ct, vals)
		}
	}
	return m
}

func channelSchemaT(t *testing.T) resource.SchemaResponse {
	t.Helper()
	var resp resource.SchemaResponse
	(&alertChannelResource{}).Schema(context.Background(), resource.SchemaRequest{}, &resp)
	if diags := resp.Schema.ValidateImplementation(context.Background()); diags.HasError() {
		t.Fatal(diags)
	}
	return resp
}

func emptyChannelState(t *testing.T) tfsdk.State {
	t.Helper()
	s := channelSchemaT(t).Schema
	return tfsdk.State{Schema: s, Raw: tftypes.NewValue(s.Type().TerraformType(context.Background()), nil)}
}

func channelRaw(t *testing.T, m alertChannelModel) tftypes.Value {
	t.Helper()
	state := emptyChannelState(t)
	var diags = state.SetAttribute(context.Background(), path.Root("name"), m.Name)
	m.write(context.Background(), &state, &diags)
	if diags.HasError() {
		t.Fatal(diags)
	}
	return state.Raw
}

func channelFromState(t *testing.T, state tfsdk.State) alertChannelModel {
	t.Helper()
	var d diag.Diagnostics
	m := readAlertChannelModel(context.Background(), state, &d)
	if d.HasError() {
		t.Fatal(d)
	}
	return m
}

// applyChannel runs Create (prior == nil) or Update with cfg; write-only
// values are null in the plan, as Terraform sends them.
func applyChannel(t *testing.T, r *alertChannelResource, prior *tfsdk.State, cfg alertChannelModel) (tfsdk.State, diag.Diagnostics) {
	t.Helper()
	ctx := context.Background()
	plan := cfg
	plan.Blocks = map[string]types.Object{}
	for k, v := range cfg.Blocks {
		plan.Blocks[k] = v
	}
	var d diag.Diagnostics
	plan.clearWriteOnly(&d)
	plan.ID = cfg.Name
	cfg.ID = types.StringNull()
	s := channelSchemaT(t).Schema
	if prior == nil {
		resp := resource.CreateResponse{State: emptyChannelState(t)}
		r.Create(ctx, resource.CreateRequest{
			Plan:   tfsdk.Plan{Schema: s, Raw: channelRaw(t, plan)},
			Config: tfsdk.Config{Schema: s, Raw: channelRaw(t, cfg)},
		}, &resp)
		return resp.State, resp.Diagnostics
	}
	resp := resource.UpdateResponse{State: *prior}
	r.Update(ctx, resource.UpdateRequest{
		State:  *prior,
		Plan:   tfsdk.Plan{Schema: s, Raw: channelRaw(t, plan)},
		Config: tfsdk.Config{Schema: s, Raw: channelRaw(t, cfg)},
	}, &resp)
	return resp.State, resp.Diagnostics
}

func mustApplyChannel(t *testing.T, r *alertChannelResource, prior *tfsdk.State, cfg alertChannelModel) tfsdk.State {
	t.Helper()
	state, diags := applyChannel(t, r, prior, cfg)
	if diags.HasError() {
		t.Fatal(diags)
	}
	return state
}

func readChannel(t *testing.T, r *alertChannelResource, state tfsdk.State) resource.ReadResponse {
	t.Helper()
	resp := resource.ReadResponse{State: state}
	r.Read(context.Background(), resource.ReadRequest{State: state}, &resp)
	return resp
}

// requireStableRead runs Read and requires it to reproduce state (an empty
// plan after apply).
func requireStableRead(t *testing.T, r *alertChannelResource, state tfsdk.State) {
	t.Helper()
	read := readChannel(t, r, state)
	if read.Diagnostics.HasError() {
		t.Fatal(read.Diagnostics)
	}
	if !read.State.Raw.Equal(state.Raw) {
		t.Fatalf("read differs from applied state:\n%v\n%v", read.State.Raw, state.Raw)
	}
}

// stateStrings returns every string value in state (attribute values only,
// not the schema's attribute names).
func stateStrings(t *testing.T, state tfsdk.State) []string {
	t.Helper()
	var out []string
	err := tftypes.Walk(state.Raw, func(_ *tftypes.AttributePath, v tftypes.Value) (bool, error) {
		if v.IsKnown() && !v.IsNull() && v.Type().Is(tftypes.String) {
			var s string
			if err := v.As(&s); err != nil {
				return false, err
			}
			out = append(out, s)
		}
		return true, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func requireNoSecretInState(t *testing.T, state tfsdk.State, secrets ...string) {
	t.Helper()
	values := stateStrings(t, state)
	for _, s := range secrets {
		for _, v := range values {
			if strings.Contains(v, s) {
				t.Fatalf("secret %q found in state value %q", s, v)
			}
		}
	}
	m := channelFromState(t, state)
	for _, ct := range channelTypes {
		for _, s := range ct.secrets {
			if v := objAttr(m.Blocks[ct.block], s.wo()); v != nil && !v.IsNull() {
				t.Fatalf("%s.%s must be null in state", ct.block, s.wo())
			}
		}
	}
}

func TestAlertChannelSchema(t *testing.T) {
	s := channelSchemaT(t).Schema
	for name, a := range s.Attributes {
		if a.IsComputed() && name != "id" {
			t.Errorf("%s is computed; only id may be", name)
		}
	}
	if len(s.Blocks) != 5 {
		t.Fatalf("blocks = %d, want email, telegram, slack, discord, webhook", len(s.Blocks))
	}
	for _, ct := range channelTypes {
		b := s.Blocks[ct.block]
		if b == nil {
			t.Fatalf("missing %s block", ct.block)
		}
		for _, sec := range ct.secrets {
			a := b.GetNestedObject().GetAttributes()[sec.wo()]
			if a == nil || !a.IsWriteOnly() || !a.IsOptional() || a.IsComputed() {
				t.Fatalf("%s.%s must be optional, write-only and not computed", ct.block, sec.wo())
			}
			if _, ok := b.GetNestedObject().GetAttributes()[sec.name]; ok {
				t.Fatalf("%s.%s: no stored secret attribute is allowed", ct.block, sec.name)
			}
			v := b.GetNestedObject().GetAttributes()[sec.woVersion()]
			if v == nil || v.IsWriteOnly() || v.IsSensitive() {
				t.Fatalf("%s.%s must be a plain attribute", ct.block, sec.woVersion())
			}
		}
		for name, a := range b.GetNestedObject().GetAttributes() {
			if a.IsComputed() || a.IsRequired() {
				t.Errorf("%s.%s must be optional and not computed", ct.block, name)
			}
		}
	}
}

// TestAlertChannelTypes maps every type block to the API request and back:
// create sends the expected config, a read reproduces the state, and no
// secret reaches state.
func TestAlertChannelTypes(t *testing.T) {
	cases := []struct {
		block   string
		vals    channelValues
		want    map[string]any
		secrets []string
	}{
		{
			block: "email",
			vals:  channelValues{"to": []string{"b@example.com", "a@example.com"}},
			want:  map[string]any{"to": []any{"a@example.com", "b@example.com"}},
		},
		{
			block: "telegram",
			vals:  channelValues{"chat_id": "-100123", "bot_token_wo": "tg-secret", "bot_token_wo_version": 1},
			want:  map[string]any{"chat_id": "-100123", "bot_token": "tg-secret"},
		},
		{
			block: "slack",
			vals: channelValues{"default_channel": "C01", "bot_token_wo": "xoxb-secret", "bot_token_wo_version": 1,
				"signing_secret_wo": "sign-secret", "signing_secret_wo_version": 3},
			want: map[string]any{"default_channel": "C01", "bot_token": "xoxb-secret", "signing_secret": "sign-secret"},
		},
		{
			block: "slack",
			vals:  channelValues{"webhook_url_wo": "https://hooks.slack.com/services/secret", "webhook_url_wo_version": 1},
			want:  map[string]any{"webhook_url": "https://hooks.slack.com/services/secret"},
		},
		{
			block: "discord",
			vals:  channelValues{"app_id": "123", "default_channel": "456", "bot_token_wo": "dc-secret", "bot_token_wo_version": 1},
			want:  map[string]any{"app_id": "123", "default_channel": "456", "bot_token": "dc-secret"},
		},
		{
			block: "webhook",
			vals: channelValues{"method": "PUT", "content_type": "application/json", "body_template": `{"m":"{{.Message}}"}`,
				"recovery_template": `{"r":true}`, "url_wo": "https://example.com/hook?token=url-secret", "url_wo_version": 1,
				"secret_wo": "hmac-secret", "secret_wo_version": 1, "headers_wo": map[string]string{"X-Token": "hdr-secret"}, "headers_wo_version": 1},
			want: map[string]any{"method": "PUT", "content_type": "application/json", "body_template": `{"m":"{{.Message}}"}`,
				"recovery_template": `{"r":true}`, "url": "https://example.com/hook?token=url-secret", "secret": "hmac-secret",
				"headers": map[string]any{"X-Token": "hdr-secret"}},
		},
	}
	for i, tc := range cases {
		t.Run(fmt.Sprintf("%s-%d", tc.block, i), func(t *testing.T) {
			r, api := newTestAlertChannelResource(t)
			state := mustApplyChannel(t, r, nil, channelModel(t, "ops", tc.block, tc.vals))
			post := api.writesSince(0)[0]
			if post.Method != http.MethodPost || post.Body["name"] != "ops" || post.Body["type"] != tc.block {
				t.Fatalf("request = %+v", post)
			}
			if !reflect.DeepEqual(post.Body["config"], tc.want) {
				t.Fatalf("config = %#v, want %#v", post.Body["config"], tc.want)
			}
			m := channelFromState(t, state)
			if m.ID.ValueString() != "ops" {
				t.Fatalf("id = %v", m.ID)
			}
			requireNoSecretInState(t, state, channelSecretValues(tc.vals)...)
			requireStableRead(t, r, state)

			// Import: Read from just the name gives the same state except
			// the versions, which the API cannot return.
			imported := emptyChannelState(t)
			ir := resource.ImportStateResponse{State: imported}
			r.ImportState(context.Background(), resource.ImportStateRequest{ID: "ops"}, &ir)
			if ir.Diagnostics.HasError() {
				t.Fatal(ir.Diagnostics)
			}
			read := readChannel(t, r, ir.State)
			if read.Diagnostics.HasError() {
				t.Fatal(read.Diagnostics)
			}
			want := channelModel(t, "ops", tc.block, withoutSecrets(tc.vals))
			want.ID = types.StringValue("ops")
			if got := read.State.Raw; !got.Equal(channelRaw(t, want)) {
				t.Fatalf("imported state:\n%v\nwant\n%v", got, channelRaw(t, want))
			}
		})
	}
}

// channelSecretValues lists the write-only values of vals.
func channelSecretValues(vals channelValues) []string {
	var out []string
	for k, v := range vals {
		if !strings.HasSuffix(k, "_wo") {
			continue
		}
		switch v := v.(type) {
		case string:
			out = append(out, v)
		case map[string]string:
			for _, s := range v {
				out = append(out, s)
			}
		}
	}
	return out
}

func withoutSecrets(vals channelValues) channelValues {
	out := channelValues{}
	for k, v := range vals {
		if !strings.HasSuffix(k, "_wo") && !strings.HasSuffix(k, "_wo_version") {
			out[k] = v
		}
	}
	return out
}

func TestAlertChannelSecretRotation(t *testing.T) {
	r, api := newTestAlertChannelResource(t)
	vals := channelValues{"method": "POST", "url_wo": "https://example.com/a", "url_wo_version": 1,
		"secret_wo": "first-secret", "secret_wo_version": 1, "headers_wo": map[string]string{"X-A": "first-header"}, "headers_wo_version": 1}
	state := mustApplyChannel(t, r, nil, channelModel(t, "hook", "webhook", vals))

	// A changed secret with the same version is not sent, and the server
	// keeps the stored value.
	mark := api.mark()
	vals["secret_wo"] = "second-secret"
	vals["method"] = "PATCH"
	state = mustApplyChannel(t, r, &state, channelModel(t, "hook", "webhook", vals))
	put := api.writesSince(mark)[0]
	cfg := put.Body["config"].(map[string]any)
	if put.Method != http.MethodPut || put.Path != "/api/alert-channels/hook" || cfg["method"] != "PATCH" {
		t.Fatalf("request = %+v", put)
	}
	for _, k := range []string{"url", "secret", "headers"} {
		if _, ok := cfg[k]; ok {
			t.Fatalf("unchanged version must omit %s: %v", k, cfg)
		}
	}
	if got := api.stored("hook").Config["secret"]; got != "first-secret" {
		t.Fatalf("stored secret = %v", got)
	}

	// Bumping the version sends the new value.
	mark = api.mark()
	vals["secret_wo_version"] = 2
	state = mustApplyChannel(t, r, &state, channelModel(t, "hook", "webhook", vals))
	cfg = api.writesSince(mark)[0].Body["config"].(map[string]any)
	if cfg["secret"] != "second-secret" || cfg["url"] != nil || cfg["headers"] != nil {
		t.Fatalf("config = %v", cfg)
	}
	if got := api.stored("hook").Config; got["secret"] != "second-secret" || got["url"] != "https://example.com/a" {
		t.Fatalf("stored = %v", got)
	}
	requireNoSecretInState(t, state, "first-secret", "second-secret", "first-header")
	requireStableRead(t, r, state)

	// Removing a secret and bumping its version clears it.
	mark = api.mark()
	delete(vals, "secret_wo")
	delete(vals, "headers_wo")
	vals["secret_wo_version"] = 3
	vals["headers_wo_version"] = 2
	state = mustApplyChannel(t, r, &state, channelModel(t, "hook", "webhook", vals))
	cfg = api.writesSince(mark)[0].Body["config"].(map[string]any)
	if cfg["secret"] != "" || !reflect.DeepEqual(cfg["headers"], map[string]any{}) {
		t.Fatalf("config = %v", cfg)
	}
	if got := api.stored("hook").Config; got["secret"] != "" || !reflect.DeepEqual(got["headers"], map[string]any{}) || got["url"] != "https://example.com/a" {
		t.Fatalf("stored = %v", got)
	}
	requireStableRead(t, r, state)
}

func TestAlertChannelUnsetFieldsAndUnmodelledKeys(t *testing.T) {
	r, api := newTestAlertChannelResource(t)
	state := mustApplyChannel(t, r, nil, channelModel(t, "ops", "email", channelValues{"to": []string{"a@example.com"}}))

	// Settings this schema does not model (legacy SMTP) are kept on update;
	// an empty modelled value written outside Terraform reads as null.
	api.channels["ops"].Config["smtp_host"] = "smtp.example.com"
	api.channels["ops"].Config["smtp_password"] = "smtp-secret"
	requireStableRead(t, r, state)
	mark := api.mark()
	state = mustApplyChannel(t, r, &state, channelModel(t, "ops", "email", channelValues{"to": []string{"b@example.com"}}))
	cfg := api.writesSince(mark)[0].Body["config"].(map[string]any)
	if cfg["smtp_host"] != "smtp.example.com" || cfg["smtp_password"] != apiSecretMask {
		t.Fatalf("unmodelled keys not preserved: %v", cfg)
	}
	if got := api.stored("ops").Config; got["smtp_password"] != "smtp-secret" || !reflect.DeepEqual(got["to"], []any{"b@example.com"}) {
		t.Fatalf("stored = %v", got)
	}

	// Removing an optional field removes it from the API config.
	discord := channelValues{"app_id": "1", "default_channel": "2"}
	dstate := mustApplyChannel(t, r, nil, channelModel(t, "dc", "discord", discord))
	delete(discord, "app_id")
	dstate = mustApplyChannel(t, r, &dstate, channelModel(t, "dc", "discord", discord))
	if _, ok := api.stored("dc").Config["app_id"]; ok {
		t.Fatalf("app_id not removed: %v", api.stored("dc").Config)
	}
	api.channels["dc"].Config["app_id"] = ""
	requireStableRead(t, r, dstate)
}

func TestAlertChannelReadDrift(t *testing.T) {
	r, api := newTestAlertChannelResource(t)
	state := mustApplyChannel(t, r, nil, channelModel(t, "ops", "telegram",
		channelValues{"chat_id": "1", "bot_token_wo": "s", "bot_token_wo_version": 4}))

	// A type changed outside Terraform shows up as the other block, which
	// plans a replacement.
	api.channels["ops"] = &fakeChannel{Type: "discord", Config: map[string]any{"default_channel": "9", "bot_token": "x"}}
	read := readChannel(t, r, state)
	if read.Diagnostics.HasError() {
		t.Fatal(read.Diagnostics)
	}
	m := channelFromState(t, read.State)
	if !m.Blocks["telegram"].IsNull() || m.Blocks["discord"].IsNull() {
		t.Fatalf("blocks = %v", m.Blocks)
	}
	if v := objAttr(m.Blocks["discord"], "bot_token_wo_version"); !v.IsNull() {
		t.Fatalf("version of another type must not carry over: %v", v)
	}

	// Unsupported types cannot be managed.
	api.channels["ops"] = &fakeChannel{Type: "teams", Config: map[string]any{"webhook_url": "x"}}
	read = readChannel(t, r, state)
	if !read.Diagnostics.HasError() || !strings.Contains(read.Diagnostics[0].Detail(), `type "teams"`) {
		t.Fatalf("diags = %v", read.Diagnostics)
	}

	// A deleted channel is removed from state.
	delete(api.channels, "ops")
	read = readChannel(t, r, state)
	if read.Diagnostics.HasError() || !read.State.Raw.IsNull() {
		t.Fatalf("read after delete: %v %v", read.Diagnostics, read.State.Raw)
	}
}

func TestAlertChannelCreateConflict(t *testing.T) {
	r, _ := newTestAlertChannelResource(t)
	_, diags := applyChannel(t, r, nil, channelModel(t, "Email", "email", channelValues{"to": []string{"a@example.com"}}))
	if !diags.HasError() || !strings.Contains(fmt.Sprint(diags), "terraform import") {
		t.Fatalf("diags = %v", diags)
	}
}

func TestAlertChannelDelete(t *testing.T) {
	r, api := newTestAlertChannelResource(t)
	state := mustApplyChannel(t, r, nil, channelModel(t, "ops", "email", channelValues{"to": []string{"a@example.com"}}))
	del := func(state tfsdk.State) resource.DeleteResponse {
		resp := resource.DeleteResponse{State: state}
		r.Delete(context.Background(), resource.DeleteRequest{State: state}, &resp)
		return resp
	}
	if resp := del(state); resp.Diagnostics.HasError() || api.stored("ops") != nil {
		t.Fatalf("delete: %v", resp.Diagnostics)
	}
	if resp := del(state); resp.Diagnostics.HasError() {
		t.Fatalf("delete of a missing channel must succeed: %v", resp.Diagnostics)
	}
	m := channelModel(t, "Email", "email", channelValues{"to": []string{"owner@example.com"}})
	m.ID = types.StringValue("Email")
	resp := del(tfsdk.State{Schema: channelSchemaT(t).Schema, Raw: channelRaw(t, m)})
	if !resp.Diagnostics.HasError() || !strings.Contains(resp.Diagnostics[0].Detail(), "destroy = false") {
		t.Fatalf("diags = %v", resp.Diagnostics)
	}
}

func TestAlertChannelImportID(t *testing.T) {
	r := &alertChannelResource{}
	for _, id := range []string{"", "  ", "a/b"} {
		resp := resource.ImportStateResponse{State: emptyChannelState(t)}
		r.ImportState(context.Background(), resource.ImportStateRequest{ID: id}, &resp)
		if !resp.Diagnostics.HasError() {
			t.Errorf("import %q: expected an error", id)
		}
	}
}

func TestAlertChannelModifyPlanID(t *testing.T) {
	s := channelSchemaT(t).Schema
	m := channelModel(t, "renamed", "email", channelValues{"to": []string{"a@example.com"}})
	m.ID = types.StringValue("old")
	plan := tfsdk.Plan{Schema: s, Raw: channelRaw(t, m)}
	resp := resource.ModifyPlanResponse{Plan: plan}
	(&alertChannelResource{}).ModifyPlan(context.Background(), resource.ModifyPlanRequest{Plan: plan}, &resp)
	var id types.String
	resp.Plan.GetAttribute(context.Background(), path.Root("id"), &id)
	if resp.Diagnostics.HasError() || id.ValueString() != "renamed" {
		t.Fatalf("id = %v, %v", id, resp.Diagnostics)
	}
}

func TestAlertChannelValidateConfig(t *testing.T) {
	s := channelSchemaT(t).Schema
	validate := func(m alertChannelModel) []string {
		resp := resource.ValidateConfigResponse{}
		(&alertChannelResource{}).ValidateConfig(context.Background(),
			resource.ValidateConfigRequest{Config: tfsdk.Config{Schema: s, Raw: channelRaw(t, m)}}, &resp)
		var out []string
		for _, d := range resp.Diagnostics {
			out = append(out, d.Summary())
		}
		return out
	}
	ok := channelModel(t, "ops", "telegram", channelValues{"chat_id": "1", "bot_token_wo": "t", "bot_token_wo_version": 1})
	if got := validate(ok); len(got) != 0 {
		t.Fatalf("valid config: %v", got)
	}
	none := channelModel(t, "ops", "", nil)
	two := channelModel(t, "ops", "email", channelValues{"to": []string{"a@example.com"}})
	two.Blocks["telegram"] = blockObject(t, channelTypes[1], channelValues{"chat_id": "1"})
	cases := map[string]struct {
		m    alertChannelModel
		want string
	}{
		"no block":       {none, "Invalid alert channel type"},
		"two blocks":     {two, "Invalid alert channel type"},
		"slash name":     {channelModel(t, "a/b", "email", channelValues{"to": []string{"a@example.com"}}), "Invalid alert channel name"},
		"missing to":     {channelModel(t, "ops", "email", nil), "Missing required argument"},
		"empty to":       {channelModel(t, "ops", "email", channelValues{"to": []string{}}), "Invalid to"},
		"missing chat":   {channelModel(t, "ops", "telegram", nil), "Missing required argument"},
		"empty string":   {channelModel(t, "ops", "discord", channelValues{"app_id": ""}), "Invalid app_id"},
		"no version":     {channelModel(t, "ops", "slack", channelValues{"bot_token_wo": "x"}), "Missing bot_token_wo_version"},
		"mask secret":    {channelModel(t, "ops", "slack", channelValues{"bot_token_wo": "****", "bot_token_wo_version": 1}), "Invalid bot_token_wo"},
		"empty secret":   {channelModel(t, "ops", "slack", channelValues{"bot_token_wo": "", "bot_token_wo_version": 1}), "Invalid bot_token_wo"},
		"mask header":    {channelModel(t, "ops", "webhook", channelValues{"headers_wo": map[string]string{"A": "****"}, "headers_wo_version": 1}), "Invalid header value"},
		"bad method":     {channelModel(t, "ops", "webhook", channelValues{"method": "DELETE"}), "Invalid method"},
		"bad url scheme": {channelModel(t, "ops", "webhook", channelValues{"url_wo": "ftp://x", "url_wo_version": 1}), "Invalid webhook URL"},
	}
	for name, tc := range cases {
		if got := validate(tc.m); !slices.Contains(got, tc.want) {
			t.Errorf("%s: diagnostics %v, want %q", name, got, tc.want)
		}
	}
}
