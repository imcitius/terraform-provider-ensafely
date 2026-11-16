package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"

	"github.com/imcitius/terraform-provider-ensafely/internal/client"
)

type escalationPolicyResource struct{ client *client.Client }

var (
	_ resource.ResourceWithConfigure      = (*escalationPolicyResource)(nil)
	_ resource.ResourceWithImportState    = (*escalationPolicyResource)(nil)
	_ resource.ResourceWithValidateConfig = (*escalationPolicyResource)(nil)
)

func newEscalationPolicyResource() resource.Resource { return &escalationPolicyResource{} }

func (r *escalationPolicyResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_escalation_policy"
}

func (r *escalationPolicyResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages a name-keyed escalation policy with ordered steps. Reordering, adding or removing steps updates the policy in place. Renaming replaces it.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed: true, MarkdownDescription: "The policy name (not the API's numeric database ID).",
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"name": schema.StringAttribute{
				Required: true, MarkdownDescription: "Nonempty policy name. Changing it replaces the resource.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
		},
		Blocks: map[string]schema.Block{
			"step": schema.ListNestedBlock{
				MarkdownDescription: "Ordered escalation steps. At least one is required. Order and repeated channels are preserved.",
				NestedObject: schema.NestedBlockObject{Attributes: map[string]schema.Attribute{
					"channel":   schema.StringAttribute{Required: true, MarkdownDescription: "Nonempty alert channel name."},
					"delay_min": schema.Int64Attribute{Required: true, MarkdownDescription: "Nonnegative whole minutes after the initial failure; zero means immediately."},
				}},
			},
		},
	}
}

func (r *escalationPolicyResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.client = clientFromProviderData(req.ProviderData, &resp.Diagnostics)
}

type escalationPolicyModel struct {
	ID    types.String `tfsdk:"id"`
	Name  types.String `tfsdk:"name"`
	Steps types.List   `tfsdk:"step"`
}

type escalationStepModel struct {
	Channel  types.String `tfsdk:"channel"`
	DelayMin types.Int64  `tfsdk:"delay_min"`
}

var escalationStepType = types.ObjectType{AttrTypes: map[string]attr.Type{
	"channel": types.StringType, "delay_min": types.Int64Type,
}}

type escalationPolicyJSON struct {
	Name  string               `json:"name"`
	Steps []escalationStepJSON `json:"steps"`
}

type escalationStepJSON struct {
	Channel  string `json:"channel"`
	DelayMin int64  `json:"delay_min"`
}

func (r *escalationPolicyResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var m escalationPolicyModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if !m.Name.IsUnknown() && !m.Name.IsNull() && m.Name.ValueString() == "" {
		resp.Diagnostics.AddAttributeError(path.Root("name"), "Invalid policy name", "Use a nonempty policy name.")
	}
	if m.Steps.IsUnknown() {
		return
	}
	if len(m.Steps.Elements()) == 0 {
		resp.Diagnostics.AddAttributeError(path.Root("step"), "Missing escalation steps", "At least one step block is required.")
		return
	}
	// Dynamic blocks and resource references can be unknown during validation.
	for i, element := range m.Steps.Elements() {
		if element.IsUnknown() || element.IsNull() {
			continue
		}
		var step escalationStepModel
		resp.Diagnostics.Append(element.(types.Object).As(ctx, &step, basetypes.ObjectAsOptions{})...)
		p := path.Root("step").AtListIndex(i)
		if !step.Channel.IsUnknown() && !step.Channel.IsNull() && step.Channel.ValueString() == "" {
			resp.Diagnostics.AddAttributeError(p.AtName("channel"), "Invalid step channel", "Use a nonempty alert channel name.")
		}
		if !step.DelayMin.IsUnknown() && !step.DelayMin.IsNull() && step.DelayMin.ValueInt64() < 0 {
			resp.Diagnostics.AddAttributeError(p.AtName("delay_min"), "Invalid step delay", "delay_min must be a nonnegative whole number of minutes.")
		}
	}
}

func (m escalationPolicyModel) payload(ctx context.Context, diags *diag.Diagnostics) escalationPolicyJSON {
	var steps []escalationStepModel
	diags.Append(m.Steps.ElementsAs(ctx, &steps, false)...)
	body := escalationPolicyJSON{Name: m.Name.ValueString(), Steps: make([]escalationStepJSON, len(steps))}
	for i, step := range steps {
		body.Steps[i] = escalationStepJSON{Channel: step.Channel.ValueString(), DelayMin: step.DelayMin.ValueInt64()}
	}
	return body
}

func escalationPolicyFromJSON(ctx context.Context, body escalationPolicyJSON, diags *diag.Diagnostics) escalationPolicyModel {
	steps := make([]escalationStepModel, len(body.Steps))
	for i, step := range body.Steps {
		steps[i] = escalationStepModel{Channel: types.StringValue(step.Channel), DelayMin: types.Int64Value(step.DelayMin)}
	}
	list, d := types.ListValueFrom(ctx, escalationStepType, steps)
	diags.Append(d...)
	return escalationPolicyModel{ID: types.StringValue(body.Name), Name: types.StringValue(body.Name), Steps: list}
}

func escalationPolicyPath(name string) string {
	return "/api/escalation-policies/" + client.PathEscape(name)
}

func (r *escalationPolicyResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var m escalationPolicyModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	body := m.payload(ctx, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	var saved escalationPolicyJSON
	if err := r.client.Post(ctx, "/api/escalation-policies", body, &saved); err != nil {
		addAPIError(&resp.Diagnostics, "create escalation policy", err)
		return
	}
	m = escalationPolicyFromJSON(ctx, saved, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

func (r *escalationPolicyResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var m escalationPolicyModel
	resp.Diagnostics.Append(req.State.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	var body escalationPolicyJSON
	if err := r.client.Get(ctx, escalationPolicyPath(m.Name.ValueString()), &body); err != nil {
		if !removeIfNotFound(ctx, err, resp) {
			addAPIError(&resp.Diagnostics, "read escalation policy", err)
		}
		return
	}
	m = escalationPolicyFromJSON(ctx, body, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

func (r *escalationPolicyResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var m escalationPolicyModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	body := m.payload(ctx, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	var saved escalationPolicyJSON
	if err := r.client.Put(ctx, escalationPolicyPath(m.Name.ValueString()), body, &saved); err != nil {
		addAPIError(&resp.Diagnostics, "update escalation policy", err)
		return
	}
	m = escalationPolicyFromJSON(ctx, saved, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

func (r *escalationPolicyResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var m escalationPolicyModel
	resp.Diagnostics.Append(req.State.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.Delete(ctx, escalationPolicyPath(m.Name.ValueString()), nil); err != nil && !client.IsNotFound(err) {
		addAPIError(&resp.Diagnostics, "delete escalation policy", err)
	}
}

func (r *escalationPolicyResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	if req.ID == "" {
		resp.Diagnostics.AddError("Invalid escalation policy import ID", "Expected a nonempty policy name.")
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), req.ID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("name"), req.ID)...)
}
