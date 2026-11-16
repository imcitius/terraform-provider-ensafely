package provider

import (
	"context"
	"crypto/sha256"
	"encoding/hex"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/imcitius/terraform-provider-ensafely/internal/client"
)

// writeOnlyProbe is a test-only resource (never registered in the shipped
// provider) that checks the #110 secret pattern end to end through Terraform
// core: `secret_wo` is write-only (never in plan or state) and
// `secret_wo_version` is the plain number that triggers sending a new value.
//
// The probe stores sha256(secret) so the test can prove which value the
// provider received without the value itself reaching state. Create and Read
// call the real API with the configured key, so the probe also proves
// provider configuration and Bearer auth against the acceptance app.
type writeOnlyProbe struct {
	client *client.Client
}

type writeOnlyProbeModel struct {
	ID              types.String `tfsdk:"id"`
	Name            types.String `tfsdk:"name"`
	SecretWO        types.String `tfsdk:"secret_wo"`
	SecretWOVersion types.Int64  `tfsdk:"secret_wo_version"`
	SecretSHA256    types.String `tfsdk:"secret_sha256"`
}

var (
	_ resource.ResourceWithConfigure   = (*writeOnlyProbe)(nil)
	_ resource.ResourceWithImportState = (*writeOnlyProbe)(nil)
	_ resource.ResourceWithModifyPlan  = (*writeOnlyProbe)(nil)
)

func newWriteOnlyProbe() resource.Resource { return &writeOnlyProbe{} }

func (r *writeOnlyProbe) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_writeonly_probe"
}

func (r *writeOnlyProbe) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"name": schema.StringAttribute{
				Required:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"secret_wo": schema.StringAttribute{
				Optional:  true,
				WriteOnly: true,
				Sensitive: true,
			},
			"secret_wo_version": schema.Int64Attribute{
				Optional: true,
			},
			"secret_sha256": schema.StringAttribute{
				Computed:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
		},
	}
}

func (r *writeOnlyProbe) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.client = clientFromProviderData(req.ProviderData, &resp.Diagnostics)
}

// ModifyPlan marks the hash unknown only when the version changes: a changed
// secret with the same version must produce an empty plan.
func (r *writeOnlyProbe) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	if req.State.Raw.IsNull() || req.Plan.Raw.IsNull() {
		return
	}
	var planVersion, stateVersion types.Int64
	resp.Diagnostics.Append(req.Plan.GetAttribute(ctx, path.Root("secret_wo_version"), &planVersion)...)
	resp.Diagnostics.Append(req.State.GetAttribute(ctx, path.Root("secret_wo_version"), &stateVersion)...)
	if !planVersion.Equal(stateVersion) {
		resp.Diagnostics.Append(resp.Plan.SetAttribute(ctx, path.Root("secret_sha256"), types.StringUnknown())...)
	}
}

func (r *writeOnlyProbe) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan writeOnlyProbeModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	var secret types.String
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("secret_wo"), &secret)...)
	if resp.Diagnostics.HasError() {
		return
	}
	// The secret is read from config: write-only values are null in the plan.
	if err := r.client.Get(ctx, "/api/settings/check-defaults", nil); err != nil {
		addAPIError(&resp.Diagnostics, "create probe", err)
		return
	}
	plan.ID = plan.Name
	plan.SecretSHA256 = hashOf(secret)
	plan.SecretWO = types.StringNull()
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *writeOnlyProbe) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state writeOnlyProbeModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.Get(ctx, "/api/settings/check-defaults", nil); err != nil {
		if removeIfNotFound(ctx, err, resp) {
			return
		}
		addAPIError(&resp.Diagnostics, "read probe", err)
		return
	}
	if state.Name.IsNull() {
		state.Name = state.ID // after import
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
}

func (r *writeOnlyProbe) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state writeOnlyProbeModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	var secret types.String
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("secret_wo"), &secret)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if !plan.SecretWOVersion.Equal(state.SecretWOVersion) {
		plan.SecretSHA256 = hashOf(secret)
	} else {
		plan.SecretSHA256 = state.SecretSHA256
	}
	plan.SecretWO = types.StringNull()
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *writeOnlyProbe) Delete(context.Context, resource.DeleteRequest, *resource.DeleteResponse) {}

func (r *writeOnlyProbe) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), req.ID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("name"), req.ID)...)
}

func hashOf(secret types.String) types.String {
	if secret.IsNull() || secret.IsUnknown() {
		return types.StringNull()
	}
	sum := sha256.Sum256([]byte(secret.ValueString()))
	return types.StringValue(hex.EncodeToString(sum[:]))
}
