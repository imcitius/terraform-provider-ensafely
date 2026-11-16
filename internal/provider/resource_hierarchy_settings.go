package provider

import (
	"context"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/imcitius/terraform-provider-ensafely/internal/client"
)

// Both endpoints replace the same three nullable overrides. Maintenance and
// updated_at are deliberately excluded from requests and Terraform state.
type hierarchySettingsResource struct {
	client *client.Client
	group  bool
}

var (
	_ resource.ResourceWithConfigure      = (*hierarchySettingsResource)(nil)
	_ resource.ResourceWithImportState    = (*hierarchySettingsResource)(nil)
	_ resource.ResourceWithValidateConfig = (*hierarchySettingsResource)(nil)
)

func newProjectSettingsResource() resource.Resource { return &hierarchySettingsResource{} }
func newGroupSettingsResource() resource.Resource   { return &hierarchySettingsResource{group: true} }

func (r *hierarchySettingsResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_project_settings"
	if r.group {
		resp.TypeName = req.ProviderTypeName + "_group_settings"
	}
}

func (r *hierarchySettingsResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages stored settings overrides. Omitted settings inherit. Destroy resets overrides to null; it does not delete the project or group. Maintenance windows are not managed and are preserved on update and destroy.",
		Attributes: map[string]schema.Attribute{
			"id":                schema.StringAttribute{Computed: true, MarkdownDescription: "Import identifier: project, or project/group for group settings.", PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}},
			"project":           schema.StringAttribute{Required: true, MarkdownDescription: "Project name (nonempty, without slashes). Changing it replaces the resource.", PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()}},
			"enabled":           schema.BoolAttribute{Optional: true, MarkdownDescription: "Enabled override. Omit or set null to inherit; false disables checks at this level."},
			"duration":          schema.StringAttribute{Optional: true, MarkdownDescription: "Check interval override, for example 1m. Omit or set null to inherit."},
			"re_alert_interval": schema.StringAttribute{Optional: true, MarkdownDescription: "Re-alert interval override, for example 1h. Omit or set null to inherit."},
		},
	}
	if r.group {
		resp.Schema.Attributes["group"] = schema.StringAttribute{Required: true, MarkdownDescription: "Group name (nonempty, without slashes). Changing it replaces the resource.", PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()}}
	}
}

func (r *hierarchySettingsResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.client = clientFromProviderData(req.ProviderData, &resp.Diagnostics)
}

func (r *hierarchySettingsResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	names := []string{"project"}
	if r.group {
		names = append(names, "group")
	}
	for _, name := range names {
		var value types.String
		resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root(name), &value)...)
		if !value.IsNull() && !value.IsUnknown() && !validHierarchyName(value.ValueString()) {
			resp.Diagnostics.AddAttributeError(path.Root(name), "Invalid settings key", "Use a nonempty name without slashes.")
		}
	}
}

func validHierarchyName(name string) bool { return name != "" && !strings.Contains(name, "/") }

type hierarchySettingsJSON struct {
	Enabled         *bool   `json:"enabled"`
	Duration        *string `json:"duration"`
	ReAlertInterval *string `json:"re_alert_interval"`
}

type hierarchySettingsModel struct {
	project, group            types.String
	enabled                   types.Bool
	duration, reAlertInterval types.String
}

type settingsAttributes interface {
	GetAttribute(context.Context, path.Path, any) diag.Diagnostics
}

// Read attributes individually because the project schema has no group field.
func (r *hierarchySettingsResource) model(ctx context.Context, source settingsAttributes, diags *diag.Diagnostics) hierarchySettingsModel {
	var m hierarchySettingsModel
	diags.Append(source.GetAttribute(ctx, path.Root("project"), &m.project)...)
	if r.group {
		diags.Append(source.GetAttribute(ctx, path.Root("group"), &m.group)...)
	}
	diags.Append(source.GetAttribute(ctx, path.Root("enabled"), &m.enabled)...)
	diags.Append(source.GetAttribute(ctx, path.Root("duration"), &m.duration)...)
	diags.Append(source.GetAttribute(ctx, path.Root("re_alert_interval"), &m.reAlertInterval)...)
	return m
}

func (m hierarchySettingsModel) payload() hierarchySettingsJSON {
	return hierarchySettingsJSON{Enabled: m.enabled.ValueBoolPointer(), Duration: m.duration.ValueStringPointer(), ReAlertInterval: m.reAlertInterval.ValueStringPointer()}
}

func (r *hierarchySettingsResource) apiPath(m hierarchySettingsModel) string {
	if r.group {
		return "/api/group-settings/" + client.PathEscape(m.project.ValueString()) + "/" + client.PathEscape(m.group.ValueString())
	}
	return "/api/project-settings/" + client.PathEscape(m.project.ValueString())
}

func (r *hierarchySettingsResource) save(ctx context.Context, m hierarchySettingsModel, state *tfsdk.State, diags *diag.Diagnostics) {
	id := m.project.ValueString()
	diags.Append(state.SetAttribute(ctx, path.Root("project"), m.project)...)
	if r.group {
		id += "/" + m.group.ValueString()
		diags.Append(state.SetAttribute(ctx, path.Root("group"), m.group)...)
	}
	diags.Append(state.SetAttribute(ctx, path.Root("id"), id)...)
	diags.Append(state.SetAttribute(ctx, path.Root("enabled"), m.enabled)...)
	diags.Append(state.SetAttribute(ctx, path.Root("duration"), m.duration)...)
	diags.Append(state.SetAttribute(ctx, path.Root("re_alert_interval"), m.reAlertInterval)...)
}

func (r *hierarchySettingsResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	m := r.model(ctx, req.Plan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.Put(ctx, r.apiPath(m), m.payload(), nil); err != nil {
		addAPIError(&resp.Diagnostics, "create settings", err)
		return
	}
	r.save(ctx, m, &resp.State, &resp.Diagnostics)
}

func (r *hierarchySettingsResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	m := r.model(ctx, req.State, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	var body hierarchySettingsJSON
	if err := r.client.Get(ctx, r.apiPath(m), &body); err != nil {
		if !removeIfNotFound(ctx, err, resp) {
			addAPIError(&resp.Diagnostics, "read settings", err)
		}
		return
	}
	m.enabled = types.BoolPointerValue(body.Enabled)
	m.duration = types.StringPointerValue(body.Duration)
	m.reAlertInterval = types.StringPointerValue(body.ReAlertInterval)
	r.save(ctx, m, &resp.State, &resp.Diagnostics)
}

func (r *hierarchySettingsResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	m := r.model(ctx, req.Plan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.Put(ctx, r.apiPath(m), m.payload(), nil); err != nil {
		addAPIError(&resp.Diagnostics, "update settings", err)
		return
	}
	r.save(ctx, m, &resp.State, &resp.Diagnostics)
}

func (r *hierarchySettingsResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	m := r.model(ctx, req.State, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	// No DELETE exists. Explicit nulls restore inheritance and leave maintenance
	// untouched, exactly as a regular settings write does on the server.
	if err := r.client.Put(ctx, r.apiPath(m), hierarchySettingsJSON{}, nil); err != nil {
		addAPIError(&resp.Diagnostics, "reset settings", err)
	}
}

func (r *hierarchySettingsResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	project, group := req.ID, ""
	if r.group {
		var found bool
		project, group, found = strings.Cut(req.ID, "/")
		if !found || !validHierarchyName(group) {
			resp.Diagnostics.AddError("Invalid group settings import ID", "Expected <project>/<group>, with nonempty names without slashes.")
			return
		}
	}
	if !validHierarchyName(project) {
		resp.Diagnostics.AddError("Invalid project settings import ID", "Expected a nonempty project name without slashes.")
		return
	}
	r.save(ctx, hierarchySettingsModel{project: types.StringValue(project), group: types.StringValue(group)}, &resp.State, &resp.Diagnostics)
}
