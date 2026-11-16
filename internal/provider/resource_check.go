package provider

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net/http"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/imcitius/terraform-provider-ensafely/internal/client"
)

const checksPath = "/api/check-definitions"

func checkPath(uuid string) string { return checksPath + "/" + client.PathEscape(uuid) }

type checkResource struct {
	client *client.Client
}

var (
	_ resource.ResourceWithConfigure      = (*checkResource)(nil)
	_ resource.ResourceWithImportState    = (*checkResource)(nil)
	_ resource.ResourceWithValidateConfig = (*checkResource)(nil)
)

func newCheckResource() resource.Resource { return &checkResource{} }

func (r *checkResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_check"
}

func (r *checkResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = checkResourceSchema()
}

func (r *checkResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.client = clientFromProviderData(req.ProviderData, &resp.Diagnostics)
}

// attributeSource is tfsdk.Config, tfsdk.Plan or tfsdk.State.
type attributeSource interface {
	GetAttribute(context.Context, path.Path, any) diag.Diagnostics
}

// readCheckValues reads every mapped attribute and type block.
func readCheckValues(ctx context.Context, src attributeSource, diags *diag.Diagnostics) checkValues {
	v := checkValues{attrs: map[string]attr.Value{}, blocks: map[string]types.Object{}}
	for _, f := range commonCheckFields {
		val := f.kind.attrType().ValueType(ctx)
		diags.Append(src.GetAttribute(ctx, path.Root(f.name), &val)...)
		v.attrs[f.name] = val
	}
	var enabled types.Bool
	diags.Append(src.GetAttribute(ctx, path.Root(enabledAttr), &enabled)...)
	v.attrs[enabledAttr] = enabled
	var connectionID types.String
	diags.Append(src.GetAttribute(ctx, path.Root(connectionIDAttr), &connectionID)...)
	v.attrs[connectionIDAttr] = connectionID
	for _, t := range checkTypes {
		var obj types.Object
		diags.Append(src.GetAttribute(ctx, path.Root(t.block), &obj)...)
		v.blocks[t.block] = obj
	}
	return v
}

func writeCheckState(ctx context.Context, state *tfsdk.State, id string, v checkValues, diags *diag.Diagnostics) {
	diags.Append(state.SetAttribute(ctx, path.Root("id"), id)...)
	for name, val := range v.attrs {
		diags.Append(state.SetAttribute(ctx, path.Root(name), val)...)
	}
	for name, obj := range v.blocks {
		diags.Append(state.SetAttribute(ctx, path.Root(name), obj)...)
	}
}

func (r *checkResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	blocks := map[string]types.Object{}
	for _, t := range checkTypes {
		var obj types.Object
		resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root(t.block), &obj)...)
		blocks[t.block] = obj
	}
	var connectionID types.String
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root(connectionIDAttr), &connectionID)...)
	if resp.Diagnostics.HasError() {
		return
	}
	validateCheckConfig(connectionID, blocks, &resp.Diagnostics)
}

// configBlockAttrs returns the configuration of the active block; it holds
// the write-only values, which are always null in the plan.
func configBlockAttrs(ctx context.Context, config tfsdk.Config, t checkType, diags *diag.Diagnostics) map[string]attr.Value {
	var obj types.Object
	diags.Append(config.GetAttribute(ctx, path.Root(t.block), &obj)...)
	if obj.IsNull() || obj.IsUnknown() {
		return nil
	}
	return obj.Attributes()
}

func (r *checkResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	plan := readCheckValues(ctx, req.Plan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	t, _, ok := plan.activeBlock()
	if !ok {
		resp.Diagnostics.AddError("Missing check type block", "Exactly one check type block ("+checkTypeBlockList()+") is required.")
		return
	}
	secrets := secretsToSend(t, configBlockAttrs(ctx, req.Config, t, &resp.Diagnostics), nil, true,
		connectionUse{plan: plan.usesConnection()})
	id, err := newUUID()
	if err != nil {
		resp.Diagnostics.AddError("Unable to generate a check UUID", err.Error())
		return
	}
	body, diags := plan.toAPI(id, secrets)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	out, err := r.create(ctx, body)
	if err != nil {
		addAPIError(&resp.Diagnostics, "create check", err)
		return
	}
	if out.UUID != id {
		resp.Diagnostics.AddError("Unexpected check UUID", fmt.Sprintf("The API created check %q instead of the requested %q.", out.UUID, id))
		return
	}
	r.saveResponse(ctx, out, plan, &resp.State, &resp.Diagnostics)
}

// create posts a check with the provider-chosen UUID. The UUID makes the
// create idempotent: the POST may be retried, and when an attempt fails after
// an earlier one reached the server (which reports the duplicate UUID as an
// error), the check that exists under the UUID is the one this request made.
func (r *checkResource) create(ctx context.Context, body checkJSON) (*checkJSON, error) {
	var out checkJSON
	err := r.client.Post(ctx, checksPath, body, &out, client.Idempotent())
	if err == nil {
		return &out, nil
	}
	var apiErr *client.APIError
	if errors.As(err, &apiErr) && apiErr.StatusCode < http.StatusInternalServerError && apiErr.StatusCode != http.StatusConflict {
		return nil, err // a definite rejection such as validation, quota or auth
	}
	var existing checkJSON
	if getErr := r.client.Get(ctx, checkPath(body.UUID), &existing); getErr == nil {
		tflog.Info(ctx, "Check create failed after an earlier attempt created it; using the existing check", map[string]any{"uuid": body.UUID, "error": err.Error()})
		return &existing, nil
	}
	return nil, err
}

func (r *checkResource) saveResponse(ctx context.Context, out *checkJSON, prior checkValues, state *tfsdk.State, diags *diag.Diagnostics) {
	values, d := checkValuesFromAPI(out, prior, true)
	diags.Append(d...)
	if diags.HasError() {
		return
	}
	writeCheckState(ctx, state, out.UUID, values, diags)
}

func (r *checkResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var id types.String
	resp.Diagnostics.Append(req.State.GetAttribute(ctx, path.Root("id"), &id)...)
	prior := readCheckValues(ctx, req.State, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	var out checkJSON
	if err := r.client.Get(ctx, checkPath(id.ValueString()), &out); err != nil {
		if !removeIfNotFound(ctx, err, resp) {
			addAPIError(&resp.Diagnostics, "read check", err)
		}
		return
	}
	r.saveResponse(ctx, &out, prior, &resp.State, &resp.Diagnostics)
}

func (r *checkResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var id types.String
	resp.Diagnostics.Append(req.State.GetAttribute(ctx, path.Root("id"), &id)...)
	plan := readCheckValues(ctx, req.Plan, &resp.Diagnostics)
	state := readCheckValues(ctx, req.State, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	t, _, ok := plan.activeBlock()
	if !ok {
		resp.Diagnostics.AddError("Missing check type block", "Exactly one check type block ("+checkTypeBlockList()+") is required.")
		return
	}
	var stateAttrs map[string]attr.Value
	if obj := state.blocks[t.block]; !obj.IsNull() && !obj.IsUnknown() {
		stateAttrs = obj.Attributes()
	}
	secrets := secretsToSend(t, configBlockAttrs(ctx, req.Config, t, &resp.Diagnostics), stateAttrs, false,
		connectionUse{plan: plan.usesConnection(), state: state.usesConnection()})
	body, diags := plan.toAPI("", secrets)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	var out checkJSON
	if err := r.client.Put(ctx, checkPath(id.ValueString()), body, &out); err != nil {
		addAPIError(&resp.Diagnostics, "update check", err)
		return
	}
	r.saveResponse(ctx, &out, plan, &resp.State, &resp.Diagnostics)
}

func (r *checkResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var id types.String
	resp.Diagnostics.Append(req.State.GetAttribute(ctx, path.Root("id"), &id)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.Delete(ctx, checkPath(id.ValueString()), nil); err != nil && !client.IsNotFound(err) {
		addAPIError(&resp.Diagnostics, "delete check", err)
	}
}

func (r *checkResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	if !isUUID(req.ID) {
		resp.Diagnostics.AddError("Invalid check import ID", "Expected the check UUID, for example 123e4567-e89b-12d3-a456-426614174000.")
		return
	}
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

// newUUID returns a random (version 4) UUID.
func newUUID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

func isUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, c := range s {
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
				return false
			}
		}
	}
	return true
}
