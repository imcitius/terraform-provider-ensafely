package provider

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	rschema "github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/imcitius/terraform-provider-ensafely/internal/client"
)

// unknown marks an attribute value as unknown in configure().
const unknown = "\x00unknown"

// configure runs Provider.Configure with the given attribute values; nil
// pointers are null.
func configure(t *testing.T, apiKey, endpoint *string) *provider.ConfigureResponse {
	t.Helper()
	p := &Provider{version: "test"}
	var sresp provider.SchemaResponse
	p.Schema(context.Background(), provider.SchemaRequest{}, &sresp)
	if sresp.Diagnostics.HasError() {
		t.Fatal(sresp.Diagnostics)
	}
	val := func(s *string) tftypes.Value {
		switch {
		case s == nil:
			return tftypes.NewValue(tftypes.String, nil)
		case *s == unknown:
			return tftypes.NewValue(tftypes.String, tftypes.UnknownValue)
		default:
			return tftypes.NewValue(tftypes.String, *s)
		}
	}
	raw := tftypes.NewValue(tftypes.Object{AttributeTypes: map[string]tftypes.Type{
		"api_key": tftypes.String, "endpoint": tftypes.String,
	}}, map[string]tftypes.Value{"api_key": val(apiKey), "endpoint": val(endpoint)})
	req := provider.ConfigureRequest{
		TerraformVersion: "1.11.0",
		Config:           tfsdk.Config{Schema: sresp.Schema, Raw: raw},
	}
	var resp provider.ConfigureResponse
	p.Configure(context.Background(), req, &resp)
	return &resp
}

func ptr(s string) *string { return &s }

func TestProviderSchemaAndMetadata(t *testing.T) {
	p := &Provider{version: "1.2.3"}
	var meta provider.MetadataResponse
	p.Metadata(context.Background(), provider.MetadataRequest{}, &meta)
	if meta.TypeName != "ensafely" || meta.Version != "1.2.3" {
		t.Errorf("metadata = %+v", meta)
	}
	var s provider.SchemaResponse
	p.Schema(context.Background(), provider.SchemaRequest{}, &s)
	if diags := s.Schema.ValidateImplementation(context.Background()); diags.HasError() {
		t.Fatal(diags)
	}
	key := s.Schema.Attributes["api_key"]
	if !key.IsSensitive() || !key.IsOptional() {
		t.Error("api_key must be optional and sensitive")
	}
	if !strings.Contains(s.Schema.MarkdownDescription, "api_write") || !strings.Contains(s.Schema.MarkdownDescription, "api_read") {
		t.Error("provider description must name the api_write and api_read scopes")
	}
}

func TestConfigureFromArguments(t *testing.T) {
	t.Setenv(EnvAPIKey, "ck_env")
	t.Setenv(EnvEndpoint, "http://env.example")
	resp := configure(t, ptr("ck_arg"), ptr("https://arg.example/"))
	if resp.Diagnostics.HasError() {
		t.Fatal(resp.Diagnostics)
	}
	c, ok := resp.ResourceData.(*client.Client)
	if !ok || resp.DataSourceData != resp.ResourceData {
		t.Fatalf("provider data = %T", resp.ResourceData)
	}
	if c.Endpoint() != "https://arg.example" {
		t.Errorf("endpoint = %q; arguments must win over the environment", c.Endpoint())
	}
}

func TestConfigureFromEnvironment(t *testing.T) {
	var auth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth = r.Header.Get("Authorization")
		_, _ = fmt.Fprint(w, `{}`)
	}))
	defer srv.Close()
	t.Setenv(EnvAPIKey, "ck_from_env")
	t.Setenv(EnvEndpoint, srv.URL)
	resp := configure(t, nil, nil)
	if resp.Diagnostics.HasError() {
		t.Fatal(resp.Diagnostics)
	}
	c := resp.ResourceData.(*client.Client)
	if err := c.Get(context.Background(), "/api/settings/check-defaults", nil); err != nil {
		t.Fatal(err)
	}
	if auth != "Bearer ck_from_env" {
		t.Errorf("Authorization = %q", auth)
	}
}

func TestConfigureDefaultEndpoint(t *testing.T) {
	t.Setenv(EnvAPIKey, "ck_x")
	t.Setenv(EnvEndpoint, "")
	resp := configure(t, nil, nil)
	if resp.Diagnostics.HasError() {
		t.Fatal(resp.Diagnostics)
	}
	if got := resp.ResourceData.(*client.Client).Endpoint(); got != "https://app.ensafely.com" {
		t.Errorf("endpoint = %q", got)
	}
}

func TestConfigureErrors(t *testing.T) {
	cases := []struct {
		name             string
		apiKey, endpoint *string
		env              string
		want             string
	}{
		{"missing key", nil, nil, "", "Missing Ensafely API key"},
		{"blank key", ptr("  "), nil, "ck_env", "Missing Ensafely API key"},
		{"unknown key", ptr(unknown), nil, "", "Unknown Ensafely API key"},
		{"unknown endpoint", ptr("ck_x"), ptr(unknown), "", "Unknown Ensafely endpoint"},
		{"bad endpoint", ptr("ck_x"), ptr("app.ensafely.com"), "", "Invalid Ensafely endpoint"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(EnvAPIKey, tc.env)
			t.Setenv(EnvEndpoint, "")
			resp := configure(t, tc.apiKey, tc.endpoint)
			if !resp.Diagnostics.HasError() {
				t.Fatal("expected an error")
			}
			if got := resp.Diagnostics.Errors()[0].Summary(); got != tc.want {
				t.Errorf("summary = %q, want %q", got, tc.want)
			}
			if resp.ResourceData != nil {
				t.Error("no client may be returned on error")
			}
		})
	}
}

func TestAddAPIErrorKeepsQuotaDetail(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = fmt.Fprint(w, `{"error":"QUOTA_EXCEEDED","resource":"checks","current":3,"limit":3,"hint":"Purchase an additional package to increase your limit"}`)
	}))
	defer srv.Close()
	c, err := client.New(client.Config{Endpoint: srv.URL, APIKey: "ck_x"})
	if err != nil {
		t.Fatal(err)
	}
	err = c.Post(context.Background(), "/api/check-definitions", map[string]any{}, nil)

	var diags diag.Diagnostics
	addAPIError(&diags, `create check "web"`, fmt.Errorf("wrapped: %w", err))
	if len(diags) != 1 {
		t.Fatalf("diags = %v", diags)
	}
	d := diags[0]
	if d.Summary() != "Ensafely plan limit reached" {
		t.Errorf("summary = %q", d.Summary())
	}
	for _, want := range []string{`create check "web"`, "checks (3 in use, plan limit 3)", "Upgrade the Tenant's plan"} {
		if !strings.Contains(d.Detail(), want) {
			t.Errorf("detail %q lacks %q", d.Detail(), want)
		}
	}

	diags = nil
	addAPIError(&diags, "read check", errors.New("dial tcp: refused"))
	if diags[0].Summary() != "Ensafely API request failed" {
		t.Errorf("summary = %q", diags[0].Summary())
	}
}

func TestRemoveIfNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/gone") {
			w.WriteHeader(http.StatusNotFound)
			_, _ = fmt.Fprint(w, `{"error":"not found"}`)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = fmt.Fprint(w, `{"error":"boom"}`)
	}))
	defer srv.Close()
	c, _ := client.New(client.Config{Endpoint: srv.URL, APIKey: "ck_x"})

	sch := rschema.Schema{Attributes: map[string]rschema.Attribute{"id": rschema.StringAttribute{Computed: true}}}
	newResp := func() *resource.ReadResponse {
		raw := tftypes.NewValue(tftypes.Object{AttributeTypes: map[string]tftypes.Type{"id": tftypes.String}},
			map[string]tftypes.Value{"id": tftypes.NewValue(tftypes.String, "x")})
		return &resource.ReadResponse{State: tfsdk.State{Schema: sch, Raw: raw}}
	}

	resp := newResp()
	err := c.Get(context.Background(), "/api/check-definitions/gone", nil)
	if !removeIfNotFound(context.Background(), err, resp) {
		t.Fatal("404 must be handled")
	}
	if !resp.State.Raw.IsNull() || resp.Diagnostics.HasError() {
		t.Errorf("state %v diags %v; want removed without error", resp.State.Raw, resp.Diagnostics)
	}

	resp = newResp()
	err = c.Get(context.Background(), "/api/check-definitions/other", nil)
	if removeIfNotFound(context.Background(), err, resp) || resp.State.Raw.IsNull() {
		t.Error("non-404 errors must keep state")
	}
}

func TestClientFromProviderData(t *testing.T) {
	var diags diag.Diagnostics
	if clientFromProviderData(nil, &diags) != nil || diags.HasError() {
		t.Error("nil provider data is not an error (unconfigured provider)")
	}
	clientFromProviderData("nope", &diags)
	if !diags.HasError() {
		t.Error("wrong provider data type must be an error")
	}
}
