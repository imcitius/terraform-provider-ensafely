package provider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/objectplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/imcitius/terraform-provider-ensafely/internal/client"
)

// ensafely_alert_channel (GitHub #116): a name-keyed, polymorphic resource
// with exactly one type block. The API (`/api/alert-channels`, see
// docs/api/openapi.yaml) stores the config as JSON and applies the secret
// contract (cloud internal/secret): secret keys read back as "****"; on PUT an
// omitted secret keeps the stored value, "" (or {} for headers) clears it, and
// every other key of the stored config is replaced by the request.

type channelFieldKind int

const (
	channelString channelFieldKind = iota
	channelStringSet
)

// channelField is a plain (non-secret) config key.
type channelField struct {
	name     string // Terraform attribute name and API config key
	kind     channelFieldKind
	required bool // enforced by ValidateConfig (see channelBlockSchema)
	oneOf    []string
	desc     string
}

// channelSecret is a secret config key, exposed as the write-only pair
// `<name>_wo` + `<name>_wo_version`.
type channelSecret struct {
	name  string // API config key
	isMap bool   // map of secret strings (webhook headers)
	desc  string
}

func (s channelSecret) wo() string        { return s.name + "_wo" }
func (s channelSecret) woVersion() string { return s.name + "_wo_version" }

// channelType is one type block. The block name equals the API type.
type channelType struct {
	block   string
	desc    string
	fields  []channelField
	secrets []channelSecret
}

var webhookMethods = []string{"GET", "POST", "PUT", "PATCH"}

// channelTypes are the channel types this provider manages (#116). Secret key
// lists match the cloud's channelFields table for these types; email's legacy
// smtp_* settings are not modelled (cloud email is platform delivery to `to`).
var channelTypes = []channelType{
	{
		block: "email",
		desc:  "Email delivered by Ensafely to the listed recipients.",
		fields: []channelField{
			{name: "to", kind: channelStringSet, required: true, desc: "Recipient email addresses (at least one)."},
		},
	},
	{
		block: "telegram",
		desc:  "Telegram bot message to a chat.",
		fields: []channelField{
			{name: "chat_id", required: true, desc: "Chat, group or channel ID, for example `-1001234567890`."},
		},
		secrets: []channelSecret{{name: "bot_token", desc: "Telegram bot token."}},
	},
	{
		block: "slack",
		desc:  "Slack app (bot token) or, as a legacy fallback, a Slack incoming webhook.",
		fields: []channelField{
			{name: "default_channel", desc: "Channel ID (`C01ABCDEF`) or name that receives alerts. Required by the Slack app."},
		},
		secrets: []channelSecret{
			{name: "bot_token", desc: "Slack app bot token (`xoxb-...`)."},
			{name: "signing_secret", desc: "Slack app signing secret, used to verify interactive requests."},
			{name: "webhook_url", desc: "Legacy incoming-webhook URL, used only when no bot token is set."},
		},
	},
	{
		block: "discord",
		desc:  "Discord bot message to a channel.",
		fields: []channelField{
			{name: "app_id", desc: "Discord application ID."},
			{name: "default_channel", desc: "Discord channel ID that receives alerts."},
		},
		secrets: []channelSecret{{name: "bot_token", desc: "Discord bot token."}},
	},
	{
		block: "webhook",
		desc:  "HTTP request to any endpoint.",
		fields: []channelField{
			{name: "method", oneOf: webhookMethods, desc: "HTTP method: `GET`, `POST`, `PUT` or `PATCH`. The server uses `POST` when unset."},
			{name: "content_type", desc: "`Content-Type` header of the request."},
			{name: "body_template", desc: "Go template for the alert body. Unset sends the default JSON payload."},
			{name: "recovery_template", desc: "Go template for the recovery body. Unset sends the default JSON payload."},
		},
		secrets: []channelSecret{
			{name: "url", desc: "Endpoint URL (`http://` or `https://`). The API treats it as a secret, because webhook URLs often carry tokens."},
			{name: "secret", desc: "HMAC signing secret; the signature is sent in `X-Webhook-Signature`."},
			{name: "headers", isMap: true, desc: "Extra request headers. The whole map is sent and replaces the stored headers."},
		},
	},
}

func channelTypeByBlock(block string) (channelType, bool) {
	for _, t := range channelTypes {
		if t.block == block {
			return t, true
		}
	}
	return channelType{}, false
}

func channelBlockList() string {
	names := make([]string, len(channelTypes))
	for i, t := range channelTypes {
		names[i] = "`" + t.block + "`"
	}
	return strings.Join(names, ", ")
}

func (t channelType) attrTypes() map[string]attr.Type {
	out := map[string]attr.Type{}
	for _, f := range t.fields {
		if f.kind == channelStringSet {
			out[f.name] = types.SetType{ElemType: types.StringType}
		} else {
			out[f.name] = types.StringType
		}
	}
	for _, s := range t.secrets {
		if s.isMap {
			out[s.wo()] = types.MapType{ElemType: types.StringType}
		} else {
			out[s.wo()] = types.StringType
		}
		out[s.woVersion()] = types.Int64Type
	}
	return out
}

// modelledKeys are the config keys this block manages; others found on the
// server are preserved on update.
func (t channelType) modelledKeys() []string {
	var keys []string
	for _, f := range t.fields {
		keys = append(keys, f.name)
	}
	for _, s := range t.secrets {
		keys = append(keys, s.name)
	}
	return keys
}

func (t channelType) resourceBlock() schema.SingleNestedBlock {
	attrs := map[string]schema.Attribute{}
	for _, f := range t.fields {
		// Terraform rejects a required attribute inside an absent single
		// nested block, so required fields are optional in the schema and
		// enforced by ValidateConfig.
		desc := f.desc
		if f.required {
			desc = "Required. " + desc
		}
		if f.kind == channelStringSet {
			attrs[f.name] = schema.SetAttribute{ElementType: types.StringType, Optional: true, MarkdownDescription: desc}
		} else {
			attrs[f.name] = schema.StringAttribute{Optional: true, MarkdownDescription: desc}
		}
	}
	for _, s := range t.secrets {
		desc := s.desc + " Write-only (Terraform 1.11 or newer): never stored in plan or state, and returned masked by the API. " +
			"Requires `" + s.woVersion() + "`; it is sent on create and on update only when the version changes."
		if s.isMap {
			attrs[s.wo()] = schema.MapAttribute{ElementType: types.StringType, Optional: true, WriteOnly: true, Sensitive: true, MarkdownDescription: desc}
		} else {
			attrs[s.wo()] = schema.StringAttribute{Optional: true, WriteOnly: true, Sensitive: true, MarkdownDescription: desc}
		}
		attrs[s.woVersion()] = schema.Int64Attribute{Optional: true,
			MarkdownDescription: "Change this number to send `" + s.wo() + "` again (rotate it). If `" + s.wo() +
				"` is null when the version changes, the stored value is cleared."}
	}
	return schema.SingleNestedBlock{
		MarkdownDescription: t.desc + " Changing the channel type replaces the channel.",
		Attributes:          attrs,
		PlanModifiers: []planmodifier.Object{objectplanmodifier.RequiresReplaceIf(
			func(_ context.Context, req planmodifier.ObjectRequest, resp *objectplanmodifier.RequiresReplaceIfFuncResponse) {
				resp.RequiresReplace = req.StateValue.IsNull() != req.PlanValue.IsNull()
			},
			"Changing the channel type replaces the channel.", "Changing the channel type replaces the channel.")},
	}
}

type alertChannelResource struct {
	client *client.Client
}

var (
	_ resource.ResourceWithConfigure      = (*alertChannelResource)(nil)
	_ resource.ResourceWithImportState    = (*alertChannelResource)(nil)
	_ resource.ResourceWithValidateConfig = (*alertChannelResource)(nil)
	_ resource.ResourceWithModifyPlan     = (*alertChannelResource)(nil)
)

func newAlertChannelResource() resource.Resource { return &alertChannelResource{} }

// alertChannelModel holds the blocks generically as objects, keyed by
// channelType.block.
type alertChannelModel struct {
	ID     types.String
	Name   types.String
	Blocks map[string]types.Object
}

func alertChannelSchema() schema.Schema {
	blocks := map[string]schema.Block{}
	for _, t := range channelTypes {
		blocks[t.block] = t.resourceBlock()
	}
	return schema.Schema{
		MarkdownDescription: "Manages an Ensafely alert channel: where alerts of the Checks that list it in `alert_channels` are sent. " +
			"The name is the channel's identity: renaming replaces the channel, and Checks that reference it by name show the change in the same plan. " +
			"Exactly one type block (" + channelBlockList() + ") is required; changing the type replaces the channel. " +
			"Every secret (bot tokens, webhook URLs, the webhook secret and headers) is write-only (Terraform 1.11 or newer): " +
			"never stored in plan or state, and sent on create and whenever its `_wo_version` changes. " +
			"The API returns secrets masked, so changes made to them outside Terraform are not detected. Import with the channel name.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The channel name (the resource ID).",
			},
			"name": schema.StringAttribute{
				Required: true,
				MarkdownDescription: "Channel name, unique in the Tenant. Checks reference the channel by this name. " +
					"Changing it replaces the channel. Must not contain `/`.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
		},
		Blocks: blocks,
	}
}

func (r *alertChannelResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_alert_channel"
}

func (r *alertChannelResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = alertChannelSchema()
}

func (r *alertChannelResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.client = clientFromProviderData(req.ProviderData, &resp.Diagnostics)
}

// getter is satisfied by tfsdk.Config, tfsdk.Plan and tfsdk.State.
type getter interface {
	GetAttribute(ctx context.Context, p path.Path, target interface{}) diag.Diagnostics
}

func readAlertChannelModel(ctx context.Context, src getter, diags *diag.Diagnostics) alertChannelModel {
	m := alertChannelModel{Blocks: map[string]types.Object{}}
	diags.Append(src.GetAttribute(ctx, path.Root("id"), &m.ID)...)
	diags.Append(src.GetAttribute(ctx, path.Root("name"), &m.Name)...)
	for _, t := range channelTypes {
		var o types.Object
		diags.Append(src.GetAttribute(ctx, path.Root(t.block), &o)...)
		m.Blocks[t.block] = o
	}
	return m
}

// setter is satisfied by tfsdk.Plan and tfsdk.State.
type setter interface {
	SetAttribute(ctx context.Context, p path.Path, val interface{}) diag.Diagnostics
}

func (m alertChannelModel) write(ctx context.Context, dst setter, diags *diag.Diagnostics) {
	diags.Append(dst.SetAttribute(ctx, path.Root("id"), m.ID)...)
	diags.Append(dst.SetAttribute(ctx, path.Root("name"), m.Name)...)
	for _, t := range channelTypes {
		o, ok := m.Blocks[t.block]
		if !ok {
			o = types.ObjectNull(t.attrTypes())
		}
		diags.Append(dst.SetAttribute(ctx, path.Root(t.block), o)...)
	}
}

// activeType returns the single set block. ok is false when none or several
// blocks are set, or a block is unknown.
func (m alertChannelModel) activeType() (t channelType, obj types.Object, ok bool) {
	n := 0
	for _, ct := range channelTypes {
		o := m.Blocks[ct.block]
		if o.IsUnknown() {
			return channelType{}, types.Object{}, false
		}
		if !o.IsNull() {
			t, obj, n = ct, o, n+1
		}
	}
	return t, obj, n == 1
}

func objAttr(o types.Object, name string) attr.Value {
	if o.IsNull() || o.IsUnknown() {
		return nil
	}
	return o.Attributes()[name]
}

func attrString(v attr.Value) (string, bool) {
	s, ok := v.(types.String)
	if !ok || s.IsNull() || s.IsUnknown() {
		return "", false
	}
	return s.ValueString(), true
}

func validChannelName(name string) error {
	if strings.TrimSpace(name) == "" {
		return fmt.Errorf("the name must not be empty")
	}
	if strings.Contains(name, "/") {
		return fmt.Errorf("the name must not contain '/', got %q", name)
	}
	return nil
}

func (r *alertChannelResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	m := readAlertChannelModel(ctx, req.Config, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	if known(m.Name) {
		if err := validChannelName(m.Name.ValueString()); err != nil {
			resp.Diagnostics.AddAttributeError(path.Root("name"), "Invalid alert channel name", err.Error())
		}
	}
	set := 0
	for _, t := range channelTypes {
		o := m.Blocks[t.block]
		if o.IsUnknown() {
			return // blocks with unknown values are validated again at apply
		}
		if o.IsNull() {
			continue
		}
		set++
		validateChannelBlock(t, o, &resp.Diagnostics)
	}
	if set != 1 {
		resp.Diagnostics.AddError("Invalid alert channel type",
			fmt.Sprintf("Exactly one type block (%s) is required, got %d.", channelBlockList(), set))
	}
}

func validateChannelBlock(t channelType, o types.Object, diags *diag.Diagnostics) {
	attrs := o.Attributes()
	at := func(name string) path.Path { return path.Root(t.block).AtName(name) }
	for _, f := range t.fields {
		v := attrs[f.name]
		if v.IsUnknown() {
			continue
		}
		if v.IsNull() {
			if f.required {
				diags.AddAttributeError(at(f.name), "Missing required argument",
					fmt.Sprintf("The %s block requires %s.", t.block, f.name))
			}
			continue
		}
		switch f.kind {
		case channelStringSet:
			set := v.(types.Set)
			if len(set.Elements()) == 0 {
				diags.AddAttributeError(at(f.name), "Invalid "+f.name, "Set at least one value, or omit the argument.")
			}
			for _, e := range set.Elements() {
				if s, ok := attrString(e); ok && strings.TrimSpace(s) == "" {
					diags.AddAttributeError(at(f.name), "Invalid "+f.name, "Values must not be empty.")
				}
			}
		default:
			s, _ := attrString(v)
			switch {
			case strings.TrimSpace(s) == "":
				diags.AddAttributeError(at(f.name), "Invalid "+f.name,
					"The value must not be empty. Omit the argument to leave it unset.")
			case len(f.oneOf) > 0 && !slices.Contains(f.oneOf, s):
				diags.AddAttributeError(at(f.name), "Invalid "+f.name,
					fmt.Sprintf("Expected one of %s, got %q.", strings.Join(f.oneOf, ", "), s))
			}
		}
	}
	for _, s := range t.secrets {
		v, ver := attrs[s.wo()], attrs[s.woVersion()]
		if !v.IsNull() && ver.IsNull() {
			diags.AddAttributeError(at(s.woVersion()), "Missing "+s.woVersion(),
				fmt.Sprintf("Set %s together with %s, and change it whenever the secret changes.", s.woVersion(), s.wo()))
		}
		if v.IsNull() || v.IsUnknown() {
			continue
		}
		if s.isMap {
			for k, e := range v.(types.Map).Elements() {
				if str, ok := attrString(e); ok && str == apiSecretMask {
					diags.AddAttributeError(at(s.wo()).AtMapKey(k), "Invalid header value",
						"`****` is the API's placeholder for a stored secret and cannot be used as a value.")
				}
			}
			continue
		}
		str, _ := attrString(v)
		switch {
		case str == apiSecretMask:
			diags.AddAttributeError(at(s.wo()), "Invalid "+s.wo(),
				"`****` is the API's placeholder for a stored secret and cannot be used as a value.")
		case str == "":
			diags.AddAttributeError(at(s.wo()), "Invalid "+s.wo(),
				"The value must not be empty. To clear the secret, remove "+s.wo()+" and change "+s.woVersion()+".")
		case t.block == "webhook" && s.name == "url" && !strings.HasPrefix(str, "http://") && !strings.HasPrefix(str, "https://"):
			diags.AddAttributeError(at(s.wo()), "Invalid webhook URL", "The URL must start with http:// or https://.")
		}
	}
}

// ModifyPlan keeps id equal to name, so a rename (which replaces the
// resource) plans the new id instead of the old one.
func (r *alertChannelResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	if req.Plan.Raw.IsNull() {
		return
	}
	var name types.String
	resp.Diagnostics.Append(req.Plan.GetAttribute(ctx, path.Root("name"), &name)...)
	if resp.Diagnostics.HasError() {
		return
	}
	id := types.StringUnknown()
	if !name.IsUnknown() {
		id = name
	}
	resp.Diagnostics.Append(resp.Plan.SetAttribute(ctx, path.Root("id"), id)...)
}

type alertChannelJSON struct {
	Name   string          `json:"name"`
	Type   string          `json:"type"`
	Config json.RawMessage `json:"config"`
}

type alertChannelPayload struct {
	Name   string         `json:"name,omitempty"`
	Type   string         `json:"type"`
	Config map[string]any `json:"config"`
}

// channelConfig builds the API config of the active block. Plain fields come
// from plan; secrets from config, and only those listed in send (nil: create,
// send every set secret). An entry in send with a null config value clears the
// secret. Keys of current that the block does not model are preserved.
func channelConfig(ctx context.Context, t channelType, plan, config types.Object, send map[string]bool, current map[string]json.RawMessage, diags *diag.Diagnostics) map[string]any {
	out := map[string]any{}
	modelled := t.modelledKeys()
	for k, v := range current {
		if !slices.Contains(modelled, k) {
			out[k] = v
		}
	}
	for _, f := range t.fields {
		v := objAttr(plan, f.name)
		if v == nil || v.IsNull() || v.IsUnknown() {
			continue
		}
		if f.kind == channelStringSet {
			var list []string
			diags.Append(v.(types.Set).ElementsAs(ctx, &list, false)...)
			slices.Sort(list)
			out[f.name] = list
			continue
		}
		s, _ := attrString(v)
		out[f.name] = s
	}
	for _, s := range t.secrets {
		v := objAttr(config, s.wo())
		isSet := v != nil && !v.IsNull() && !v.IsUnknown()
		if send != nil && !send[s.name] {
			continue
		}
		switch {
		case isSet && s.isMap:
			m := map[string]string{}
			diags.Append(v.(types.Map).ElementsAs(ctx, &m, false)...)
			out[s.name] = m
		case isSet:
			str, _ := attrString(v)
			out[s.name] = str
		case send == nil: // create: nothing to send
		case s.isMap:
			out[s.name] = map[string]string{}
		default:
			out[s.name] = ""
		}
	}
	return out
}

// rotatedSecrets lists the secrets whose _wo_version differs between plan and
// state.
func rotatedSecrets(t channelType, plan, state types.Object) map[string]bool {
	out := map[string]bool{}
	for _, s := range t.secrets {
		p, st := objAttr(plan, s.woVersion()), objAttr(state, s.woVersion())
		if p == nil || st == nil || !p.Equal(st) {
			out[s.name] = true
		}
	}
	return out
}

// channelBlockFromAPI maps an API config to the block object. Write-only
// values are null; versions are kept from prior (the state's block of the
// same type), because the API cannot return them. Empty strings and empty
// lists read as null, so an unset field never causes a diff.
func channelBlockFromAPI(ctx context.Context, t channelType, raw json.RawMessage, prior types.Object, diags *diag.Diagnostics) types.Object {
	cfg := decodeParams(raw)
	attrs := map[string]attr.Value{}
	for _, f := range t.fields {
		if f.kind == channelStringSet {
			var list []string
			v := types.SetNull(types.StringType)
			if len(cfg[f.name]) > 0 && json.Unmarshal(cfg[f.name], &list) == nil && len(list) > 0 {
				var d diag.Diagnostics
				v, d = types.SetValueFrom(ctx, types.StringType, list)
				diags.Append(d...)
			}
			attrs[f.name] = v
			continue
		}
		v := types.StringNull()
		if s, ok := paramString(cfg[f.name]); ok && s != "" {
			v = types.StringValue(s)
		}
		attrs[f.name] = v
	}
	for _, s := range t.secrets {
		if s.isMap {
			attrs[s.wo()] = types.MapNull(types.StringType)
		} else {
			attrs[s.wo()] = types.StringNull()
		}
		ver := types.Int64Null()
		if p, ok := objAttr(prior, s.woVersion()).(types.Int64); ok && !p.IsUnknown() {
			ver = p
		}
		attrs[s.woVersion()] = ver
	}
	o, d := types.ObjectValue(t.attrTypes(), attrs)
	diags.Append(d...)
	return o
}

// clearWriteOnly nulls the write-only attributes of every block.
func (m *alertChannelModel) clearWriteOnly(diags *diag.Diagnostics) {
	for _, t := range channelTypes {
		o := m.Blocks[t.block]
		if o.IsNull() || o.IsUnknown() {
			continue
		}
		attrs := map[string]attr.Value{}
		for k, v := range o.Attributes() {
			attrs[k] = v
		}
		for _, s := range t.secrets {
			if s.isMap {
				attrs[s.wo()] = types.MapNull(types.StringType)
			} else {
				attrs[s.wo()] = types.StringNull()
			}
		}
		v, d := types.ObjectValue(t.attrTypes(), attrs)
		diags.Append(d...)
		m.Blocks[t.block] = v
	}
}

func alertChannelPath(name string) string { return "/api/alert-channels/" + client.PathEscape(name) }

func (r *alertChannelResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	plan := readAlertChannelModel(ctx, req.Plan, &resp.Diagnostics)
	config := readAlertChannelModel(ctx, req.Config, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	t, planBlock, ok := plan.activeType()
	if !ok {
		resp.Diagnostics.AddError("Invalid alert channel type", "Exactly one type block ("+channelBlockList()+") is required.")
		return
	}
	name := plan.Name.ValueString()
	body := alertChannelPayload{
		Name:   name,
		Type:   t.block,
		Config: channelConfig(ctx, t, planBlock, config.Blocks[t.block], nil, nil, &resp.Diagnostics),
	}
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.Post(ctx, "/api/alert-channels", body, nil); err != nil {
		addAPIError(&resp.Diagnostics, fmt.Sprintf("create alert channel %q", name), err)
		if client.IsConflict(err) {
			resp.Diagnostics.AddError("Alert channel already exists",
				fmt.Sprintf("An alert channel named %q already exists in the Tenant. Import it with "+
					"`terraform import <address> %s`, or choose another name.", name, name))
		}
		return
	}
	plan.ID = plan.Name
	plan.clearWriteOnly(&resp.Diagnostics)
	plan.write(ctx, &resp.State, &resp.Diagnostics)
}

func (r *alertChannelResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	state := readAlertChannelModel(ctx, req.State, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	name := state.ID.ValueString()
	if name == "" {
		name = state.Name.ValueString()
	}
	var body alertChannelJSON
	if err := r.client.Get(ctx, alertChannelPath(name), &body); err != nil {
		if !removeIfNotFound(ctx, err, resp) {
			addAPIError(&resp.Diagnostics, fmt.Sprintf("read alert channel %q", name), err)
		}
		return
	}
	t, ok := channelTypeByBlock(body.Type)
	if !ok {
		resp.Diagnostics.AddError("Unsupported alert channel type",
			fmt.Sprintf("Alert channel %q has type %q. This provider manages the types %s; manage this channel in the Ensafely app.",
				name, body.Type, channelBlockList()))
		return
	}
	if body.Name != "" {
		name = body.Name
	}
	next := alertChannelModel{ID: types.StringValue(name), Name: types.StringValue(name), Blocks: map[string]types.Object{}}
	for _, ct := range channelTypes {
		next.Blocks[ct.block] = types.ObjectNull(ct.attrTypes())
	}
	next.Blocks[t.block] = channelBlockFromAPI(ctx, t, body.Config, state.Blocks[t.block], &resp.Diagnostics)
	next.write(ctx, &resp.State, &resp.Diagnostics)
}

func (r *alertChannelResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	plan := readAlertChannelModel(ctx, req.Plan, &resp.Diagnostics)
	state := readAlertChannelModel(ctx, req.State, &resp.Diagnostics)
	config := readAlertChannelModel(ctx, req.Config, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	t, planBlock, ok := plan.activeType()
	if !ok {
		resp.Diagnostics.AddError("Invalid alert channel type", "Exactly one type block ("+channelBlockList()+") is required.")
		return
	}
	name := state.Name.ValueString()

	// Read the current config so keys this schema does not model survive the
	// PUT, which replaces every non-secret key.
	var current alertChannelJSON
	if err := r.client.Get(ctx, alertChannelPath(name), &current); err != nil {
		addAPIError(&resp.Diagnostics, fmt.Sprintf("read alert channel %q before update", name), err)
		return
	}
	var keep map[string]json.RawMessage
	if current.Type == t.block {
		keep = decodeParams(current.Config)
	}
	body := alertChannelPayload{
		Type:   t.block,
		Config: channelConfig(ctx, t, planBlock, config.Blocks[t.block], rotatedSecrets(t, planBlock, state.Blocks[t.block]), keep, &resp.Diagnostics),
	}
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.Put(ctx, alertChannelPath(name), body, nil); err != nil {
		addAPIError(&resp.Diagnostics, fmt.Sprintf("update alert channel %q", name), err)
		return
	}
	plan.ID = state.Name
	plan.clearWriteOnly(&resp.Diagnostics)
	plan.write(ctx, &resp.State, &resp.Diagnostics)
}

func (r *alertChannelResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	state := readAlertChannelModel(ctx, req.State, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	name := state.Name.ValueString()
	err := r.client.Delete(ctx, alertChannelPath(name), nil)
	var apiErr *client.APIError
	switch {
	case err == nil:
	case client.IsNotFound(err):
		tflog.Warn(ctx, "Ensafely alert channel already deleted", map[string]any{"name": name})
	case errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusForbidden && name == defaultEmailChannel:
		resp.Diagnostics.AddError("The default Email channel cannot be deleted",
			fmt.Sprintf("Unable to delete alert channel %q: %s\n\nEvery Tenant keeps its default Email channel. "+
				"Stop managing it without deleting it: remove the resource with a `removed` block "+
				"(`lifecycle { destroy = false }`) or `terraform state rm`.", name, err))
	default:
		addAPIError(&resp.Diagnostics, fmt.Sprintf("delete alert channel %q", name), err)
	}
}

// defaultEmailChannel is the Email channel the cloud creates for every
// Tenant; the API refuses to delete it.
const defaultEmailChannel = "Email"

func (r *alertChannelResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	if err := validChannelName(req.ID); err != nil {
		resp.Diagnostics.AddError("Invalid alert channel import ID",
			fmt.Sprintf("Expected the alert channel name: %s.", err))
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), req.ID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("name"), req.ID)...)
}
