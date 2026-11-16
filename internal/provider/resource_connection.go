package provider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/imcitius/terraform-provider-ensafely/internal/client"
)

// connectionResource implements ensafely_connection (GitHub #118): a
// reusable, server-identified set of host/port/credentials that Checks
// reference through connection_id.
//
// Secrets follow the #110 pair pattern. The API never returns the password
// and masks header values (`****`, package internal/secret in the cloud), so
// both are write-only: `password_wo` and `headers_wo`, each sent on create and
// on update only when its `_wo_version` changes. Omitting them on update makes
// the API keep the stored value.
type connectionResource struct {
	client *client.Client
}

var (
	_ resource.ResourceWithConfigure      = (*connectionResource)(nil)
	_ resource.ResourceWithImportState    = (*connectionResource)(nil)
	_ resource.ResourceWithValidateConfig = (*connectionResource)(nil)
)

func newConnectionResource() resource.Resource { return &connectionResource{} }

// connectionTypes are the values the API accepts for `type`.
var connectionTypes = []string{"postgres", "mysql", "mongo", "http"}

// connectionStringParams are the non-secret string keys of the API's `params`
// object (docs/api/openapi.yaml, ConnectionParams). `headers` is managed by
// headers_wo. Any other key is unmodelled: it is not stored in state and is
// preserved on update.
var connectionStringParams = []string{"db_name", "ssl_mode", "replica_set", "auth_source", "base_url"}

const (
	paramHeaders = "headers"
	paramBaseURL = "base_url"
	// apiSecretMask is what the API returns for a stored secret, and accepts
	// as "keep the stored value". It is never a valid new secret.
	apiSecretMask = "****"
)

var uuidPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

type connectionModel struct {
	ID                types.String `tfsdk:"id"`
	Name              types.String `tfsdk:"name"`
	Type              types.String `tfsdk:"type"`
	Host              types.String `tfsdk:"host"`
	Port              types.Int64  `tfsdk:"port"`
	Username          types.String `tfsdk:"username"`
	PasswordWO        types.String `tfsdk:"password_wo"`
	PasswordWOVersion types.Int64  `tfsdk:"password_wo_version"`
	HeadersWO         types.Map    `tfsdk:"headers_wo"`
	HeadersWOVersion  types.Int64  `tfsdk:"headers_wo_version"`
	Params            types.Object `tfsdk:"params"`
}

type connectionParamsModel struct {
	DBName     types.String `tfsdk:"db_name"`
	SSLMode    types.String `tfsdk:"ssl_mode"`
	ReplicaSet types.String `tfsdk:"replica_set"`
	AuthSource types.String `tfsdk:"auth_source"`
	BaseURL    types.String `tfsdk:"base_url"`
}

func connectionParamsAttrTypes() map[string]attr.Type {
	out := map[string]attr.Type{}
	for _, k := range connectionStringParams {
		out[k] = types.StringType
	}
	return out
}

func (pm *connectionParamsModel) fields() map[string]*types.String {
	return map[string]*types.String{
		"db_name":     &pm.DBName,
		"ssl_mode":    &pm.SSLMode,
		"replica_set": &pm.ReplicaSet,
		"auth_source": &pm.AuthSource,
		paramBaseURL:  &pm.BaseURL,
	}
}

func (r *connectionResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_connection"
}

func (r *connectionResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages a Connection: reusable host, port and credentials that Checks reference with `connection_id`. " +
			"Rotating the password here updates every Check that uses the Connection. " +
			"The password and HTTP headers are write-only (Terraform 1.11 or newer): they are never stored in plan or state, " +
			"and are sent on create and whenever their `_wo_version` changes.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Server-assigned Connection ID (UUID). Use it as a Check's `connection_id`, and to import.",
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"name": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Connection name, unique in the Tenant. Renaming updates the Connection in place.",
			},
			"type": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Protocol: `postgres`, `mysql`, `mongo` or `http`. Changing it updates the Connection in place.",
			},
			"host": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Server host name or address. HTTP connections usually set `params.base_url` instead.",
			},
			"port": schema.Int64Attribute{
				Optional:            true,
				MarkdownDescription: "Server port.",
			},
			"username": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "User name. For `http`, a username with a password is sent as basic auth; a password without a username is sent as a Bearer token.",
			},
			"password_wo": schema.StringAttribute{
				Optional:  true,
				WriteOnly: true,
				Sensitive: true,
				MarkdownDescription: "Password or token. Write-only: never stored in plan or state, and never returned by the API. " +
					"Requires `password_wo_version`; changing only this value does not send it.",
			},
			"password_wo_version": schema.Int64Attribute{
				Optional: true,
				MarkdownDescription: "Change this number to send `password_wo` again (rotate it). If `password_wo` is null when the " +
					"version changes, the stored password is cleared.",
			},
			"headers_wo": schema.MapAttribute{
				Optional:    true,
				WriteOnly:   true,
				Sensitive:   true,
				ElementType: types.StringType,
				MarkdownDescription: "Extra request headers (`http`). Write-only, because the API treats header values as secrets " +
					"and returns them masked. Requires `headers_wo_version`; the whole map is sent and replaces the stored headers.",
			},
			"headers_wo_version": schema.Int64Attribute{
				Optional: true,
				MarkdownDescription: "Change this number to send `headers_wo` again. If `headers_wo` is null when the version " +
					"changes, the stored headers are removed.",
			},
			"params": schema.SingleNestedAttribute{
				Optional:            true,
				MarkdownDescription: "Protocol-specific settings. Keys set outside Terraform that this schema does not model are preserved on update.",
				Attributes: map[string]schema.Attribute{
					"db_name":     schema.StringAttribute{Optional: true, MarkdownDescription: "Database name (`postgres`, `mysql`, `mongo`)."},
					"ssl_mode":    schema.StringAttribute{Optional: true, MarkdownDescription: "PostgreSQL `sslmode`, for example `require` (`postgres`)."},
					"replica_set": schema.StringAttribute{Optional: true, MarkdownDescription: "Replica set name (`mongo`)."},
					"auth_source": schema.StringAttribute{Optional: true, MarkdownDescription: "Authentication database (`mongo`)."},
					"base_url": schema.StringAttribute{Optional: true, MarkdownDescription: "Base URL used when a Check has no URL of its own (`http`). " +
						"Must not contain a password: use `username` and `password_wo`."},
				},
			},
		},
	}
}

func (r *connectionResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.client = clientFromProviderData(req.ProviderData, &resp.Diagnostics)
}

func (r *connectionResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var m connectionModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if known(m.Name) && strings.TrimSpace(m.Name.ValueString()) == "" {
		resp.Diagnostics.AddAttributeError(path.Root("name"), "Invalid connection name", "The name must not be empty.")
	}
	if known(m.Type) && !validConnectionType(m.Type.ValueString()) {
		resp.Diagnostics.AddAttributeError(path.Root("type"), "Invalid connection type",
			fmt.Sprintf("Expected one of %s, got %q.", strings.Join(connectionTypes, ", "), m.Type.ValueString()))
	}
	// Without a version a secret could never be rotated: Terraform does not
	// detect changes to write-only values.
	if !m.PasswordWO.IsNull() && m.PasswordWOVersion.IsNull() {
		resp.Diagnostics.AddAttributeError(path.Root("password_wo_version"), "Missing password_wo_version",
			"Set password_wo_version together with password_wo, and change it whenever the password changes.")
	}
	if !m.HeadersWO.IsNull() && m.HeadersWOVersion.IsNull() {
		resp.Diagnostics.AddAttributeError(path.Root("headers_wo_version"), "Missing headers_wo_version",
			"Set headers_wo_version together with headers_wo, and change it whenever the headers change.")
	}
	if known(m.PasswordWO) && m.PasswordWO.ValueString() == apiSecretMask {
		resp.Diagnostics.AddAttributeError(path.Root("password_wo"), "Invalid password",
			"`****` is the API's placeholder for a stored secret and cannot be used as a password.")
	}
	if !m.HeadersWO.IsNull() && !m.HeadersWO.IsUnknown() {
		for k, v := range m.HeadersWO.Elements() {
			if s, ok := v.(types.String); ok && known(s) && s.ValueString() == apiSecretMask {
				resp.Diagnostics.AddAttributeError(path.Root("headers_wo").AtMapKey(k), "Invalid header value",
					"`****` is the API's placeholder for a stored secret and cannot be used as a header value.")
			}
		}
	}
	if !m.Params.IsNull() && !m.Params.IsUnknown() {
		var pm connectionParamsModel
		resp.Diagnostics.Append(m.Params.As(ctx, &pm, basetypes.ObjectAsOptions{})...)
		if known(pm.BaseURL) && urlHasPassword(pm.BaseURL.ValueString()) {
			resp.Diagnostics.AddAttributeError(path.Root("params").AtName(paramBaseURL), "Password in base_url",
				"The API masks URL passwords, so they cannot be managed in state. Remove the password from base_url "+
					"and set username and password_wo instead (sent as basic auth).")
		}
	}
}

func known(v interface {
	IsNull() bool
	IsUnknown() bool
}) bool {
	return !v.IsNull() && !v.IsUnknown()
}

func validConnectionType(t string) bool {
	for _, v := range connectionTypes {
		if t == v {
			return true
		}
	}
	return false
}

// urlHasPassword mirrors the API's rule (internal/secret): a non-empty
// password in scheme://user:password@host. It also works on strings that
// net/url rejects.
func urlHasPassword(s string) bool {
	i := strings.Index(s, "://")
	if i < 0 {
		return false
	}
	auth := s[i+3:]
	if j := strings.IndexAny(auth, "/?#"); j >= 0 {
		auth = auth[:j]
	}
	at := strings.LastIndex(auth, "@")
	if at < 0 {
		return false
	}
	colon := strings.Index(auth[:at], ":")
	return colon >= 0 && colon < at-1
}

// connectionPayload is the API's ConnectionWrite. PATCH replaces every field
// except the secrets: a nil Password, or params without `headers`, keeps the
// stored value; "" (or an empty headers map) clears it.
type connectionPayload struct {
	Name     string         `json:"name"`
	Type     string         `json:"type"`
	Host     *string        `json:"host"`
	Port     *int64         `json:"port"`
	Username *string        `json:"username"`
	Password *string        `json:"password,omitempty"`
	Params   map[string]any `json:"params,omitempty"`
}

// connectionJSON is the API's ConnectionRead.
type connectionJSON struct {
	ID       string          `json:"id"`
	Name     string          `json:"name"`
	Type     string          `json:"type"`
	Host     *string         `json:"host"`
	Port     *int64          `json:"port"`
	Username *string         `json:"username"`
	Params   json.RawMessage `json:"params"`
}

// connectionSecrets are the write-only values to send. A nil field is
// omitted, so the API keeps what it stores.
type connectionSecrets struct {
	password *string
	headers  map[string]string
}

// payload builds the request body. current is the server's params before an
// update (nil on create): keys the schema does not model are kept.
func (m connectionModel) payload(ctx context.Context, secrets connectionSecrets, current json.RawMessage, diags *diag.Diagnostics) connectionPayload {
	p := connectionPayload{
		Name:     m.Name.ValueString(),
		Type:     m.Type.ValueString(),
		Host:     m.Host.ValueStringPointer(),
		Port:     m.Port.ValueInt64Pointer(),
		Username: m.Username.ValueStringPointer(),
		Password: secrets.password,
	}
	params := map[string]any{}
	for k, v := range unmodelledParams(current) {
		params[k] = v
	}
	if !m.Params.IsNull() && !m.Params.IsUnknown() {
		var pm connectionParamsModel
		diags.Append(m.Params.As(ctx, &pm, basetypes.ObjectAsOptions{})...)
		for k, v := range pm.fields() {
			if !v.IsNull() && !v.IsUnknown() {
				params[k] = v.ValueString()
			}
		}
	}
	// The API keeps a stored base_url that has a password when base_url is
	// omitted; only "" removes it. Configuration cannot set such a URL.
	if _, set := params[paramBaseURL]; !set {
		if s, ok := paramString(decodeParams(current)[paramBaseURL]); ok && urlHasPassword(s) {
			params[paramBaseURL] = ""
		}
	}
	if secrets.headers != nil {
		params[paramHeaders] = secrets.headers
	}
	if len(params) > 0 {
		p.Params = params
	}
	return p
}

// unmodelledParams returns the params keys the schema does not represent,
// including documented keys whose value has an unexpected JSON type. headers
// is never echoed back: its values arrive masked and the API keeps the stored
// headers when the key is omitted.
func unmodelledParams(raw json.RawMessage) map[string]json.RawMessage {
	out := map[string]json.RawMessage{}
	for k, v := range decodeParams(raw) {
		if k == paramHeaders {
			continue
		}
		if _, ok := paramString(v); ok && isStringParam(k) {
			continue
		}
		out[k] = v
	}
	return out
}

func decodeParams(raw json.RawMessage) map[string]json.RawMessage {
	var all map[string]json.RawMessage
	if len(raw) == 0 || json.Unmarshal(raw, &all) != nil {
		return nil
	}
	return all
}

func isStringParam(k string) bool {
	for _, s := range connectionStringParams {
		if s == k {
			return true
		}
	}
	return false
}

func paramString(v json.RawMessage) (string, bool) {
	var s string
	if len(v) == 0 || string(v) == "null" || json.Unmarshal(v, &s) != nil {
		return "", false
	}
	return s, true
}

// fromAPI copies the server's view into m. m.Params is the value already in
// state: when the server has none of the modelled keys, an empty params block
// in configuration stays empty instead of turning into null.
func (m *connectionModel) fromAPI(ctx context.Context, body connectionJSON, diags *diag.Diagnostics) {
	m.ID = types.StringValue(body.ID)
	m.Name = types.StringValue(body.Name)
	m.Type = types.StringValue(body.Type)
	m.Host = types.StringPointerValue(body.Host)
	m.Port = types.Int64PointerValue(body.Port)
	m.Username = types.StringPointerValue(body.Username)

	var prior connectionParamsModel
	if !m.Params.IsNull() && !m.Params.IsUnknown() {
		diags.Append(m.Params.As(ctx, &prior, basetypes.ObjectAsOptions{})...)
	}
	var pm connectionParamsModel
	found := false
	all := decodeParams(body.Params)
	for k, field := range pm.fields() {
		*field = types.StringNull()
		if s, ok := paramString(all[k]); ok {
			*field = types.StringValue(s)
			found = true
		}
	}
	// Removing a base_url that had a password leaves "" on the server.
	if pm.BaseURL.ValueString() == "" && !pm.BaseURL.IsNull() && prior.BaseURL.IsNull() {
		pm.BaseURL = types.StringNull()
		found = false
		for _, f := range pm.fields() {
			found = found || !f.IsNull()
		}
	}
	if !found && (m.Params.IsNull() || m.Params.IsUnknown()) {
		m.Params = types.ObjectNull(connectionParamsAttrTypes())
		return
	}
	v, d := types.ObjectValueFrom(ctx, connectionParamsAttrTypes(), pm)
	diags.Append(d...)
	m.Params = v
}

// clearWriteOnly nulls the write-only attributes before saving state.
func (m *connectionModel) clearWriteOnly() {
	m.PasswordWO = types.StringNull()
	m.HeadersWO = types.MapNull(types.StringType)
}

// configHeaders reads headers_wo from configuration (write-only values are
// null in the plan). It returns nil when unset.
func configHeaders(ctx context.Context, v types.Map, diags *diag.Diagnostics) map[string]string {
	if v.IsNull() || v.IsUnknown() {
		return nil
	}
	out := map[string]string{}
	diags.Append(v.ElementsAs(ctx, &out, false)...)
	return out
}

func connectionPath(id string) string { return "/api/connections/" + client.PathEscape(id) }

func (r *connectionResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan, config connectionModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}
	secrets := connectionSecrets{
		password: config.PasswordWO.ValueStringPointer(),
		headers:  configHeaders(ctx, config.HeadersWO, &resp.Diagnostics),
	}
	body := plan.payload(ctx, secrets, nil, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	var created connectionJSON
	if err := r.client.Post(ctx, "/api/connections", body, &created); err != nil {
		addAPIError(&resp.Diagnostics, fmt.Sprintf("create connection %q", body.Name), err)
		return
	}
	if created.ID == "" {
		resp.Diagnostics.AddError("Invalid Ensafely API response", "The create connection response has no id.")
		return
	}
	plan.ID = types.StringValue(created.ID)
	plan.clearWriteOnly()
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *connectionResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state connectionModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	var body connectionJSON
	if err := r.client.Get(ctx, connectionPath(state.ID.ValueString()), &body); err != nil {
		if !removeIfNotFound(ctx, err, resp) {
			addAPIError(&resp.Diagnostics, fmt.Sprintf("read connection %q", state.ID.ValueString()), err)
		}
		return
	}
	state.fromAPI(ctx, body, &resp.Diagnostics)
	state.clearWriteOnly()
	resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
}

func (r *connectionResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state, config connectionModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}
	id := state.ID.ValueString()

	// PATCH replaces params; read them to keep keys this schema does not model.
	var current connectionJSON
	if err := r.client.Get(ctx, connectionPath(id), &current); err != nil {
		addAPIError(&resp.Diagnostics, fmt.Sprintf("read connection %q before update", id), err)
		return
	}

	// A secret is sent only when its version changes; null then clears it.
	// Otherwise it is omitted and the API keeps the stored value.
	var secrets connectionSecrets
	if !plan.PasswordWOVersion.Equal(state.PasswordWOVersion) {
		cleared := ""
		secrets.password = &cleared
		if !config.PasswordWO.IsNull() {
			secrets.password = config.PasswordWO.ValueStringPointer()
		}
	}
	if !plan.HeadersWOVersion.Equal(state.HeadersWOVersion) {
		secrets.headers = map[string]string{}
		if h := configHeaders(ctx, config.HeadersWO, &resp.Diagnostics); h != nil {
			secrets.headers = h
		}
	}
	body := plan.payload(ctx, secrets, current.Params, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.Patch(ctx, connectionPath(id), body, nil); err != nil {
		addAPIError(&resp.Diagnostics, fmt.Sprintf("update connection %q", body.Name), err)
		return
	}
	plan.ID = state.ID
	plan.clearWriteOnly()
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *connectionResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state connectionModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	err := r.client.Delete(ctx, connectionPath(state.ID.ValueString()), nil)
	switch {
	case err == nil:
	case client.IsNotFound(err):
		tflog.Warn(ctx, "Ensafely connection already deleted", map[string]any{"id": state.ID.ValueString()})
	case client.IsConflict(err):
		resp.Diagnostics.AddError("Ensafely connection is in use", connectionInUseDetail(state.Name.ValueString(), err))
	default:
		addAPIError(&resp.Diagnostics, fmt.Sprintf("delete connection %q", state.Name.ValueString()), err)
	}
}

// connectionInUseDetail lists the Checks named in the API's 409 response.
func connectionInUseDetail(name string, err error) string {
	detail := fmt.Sprintf("Unable to delete connection %q: %s", name, err)
	var apiErr *client.APIError
	if !errors.As(err, &apiErr) {
		return detail
	}
	var body struct {
		Checks []struct {
			UUID string `json:"uuid"`
			Name string `json:"name"`
		} `json:"checks"`
	}
	if json.Unmarshal(apiErr.Body, &body) == nil && len(body.Checks) > 0 {
		detail += "\n\nChecks that still reference it:"
		for _, c := range body.Checks {
			detail += fmt.Sprintf("\n  - %s (%s)", c.Name, c.UUID)
		}
	}
	return detail + "\n\nRemove connection_id from these Checks, or delete them, before destroying the connection."
}

func (r *connectionResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	if !uuidPattern.MatchString(req.ID) {
		resp.Diagnostics.AddError("Invalid connection import ID",
			fmt.Sprintf("Expected the connection's UUID (shown in the Ensafely app and the API), got %q.", req.ID))
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), req.ID)...)
}
