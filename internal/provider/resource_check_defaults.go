package provider

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/imcitius/terraform-provider-ensafely/internal/client"
)

const checkDefaultsPath = "/api/settings/check-defaults"

// singletonID is the state and import ID of the Tenant-wide singletons
// (ensafely_check_defaults, ensafely_platform_regions).
const singletonID = "current"

// checkDefaultsResource manages the Tenant's stored check-defaults
// overrides (#120). Every attribute maps to one key of the API's
// `overrides` document (docs/api/README.md, "Check defaults: stored versus
// effective"): null means "not overridden", so the built-in default applies
// and never enters state.
type checkDefaultsResource struct {
	client *client.Client
}

var (
	_ resource.ResourceWithConfigure   = (*checkDefaultsResource)(nil)
	_ resource.ResourceWithImportState = (*checkDefaultsResource)(nil)
)

func newCheckDefaultsResource() resource.Resource { return &checkDefaultsResource{} }

type checkDefaultsModel struct {
	ID               types.String `tfsdk:"id"`
	RetryCount       types.Int64  `tfsdk:"retry_count"`
	RetryInterval    types.String `tfsdk:"retry_interval"`
	CheckInterval    types.String `tfsdk:"check_interval"`
	Timeouts         types.Map    `tfsdk:"timeouts"`
	ReAlertInterval  types.String `tfsdk:"re_alert_interval"`
	Severity         types.String `tfsdk:"severity"`
	AlertChannels    types.Set    `tfsdk:"alert_channels"`
	EscalationPolicy types.String `tfsdk:"escalation_policy"`
}

// checkDefaultsOverridesJSON is the stored document. PUT sends every key;
// null clears an override.
type checkDefaultsOverridesJSON struct {
	RetryCount       *int64            `json:"retry_count"`
	RetryInterval    *string           `json:"retry_interval"`
	CheckInterval    *string           `json:"check_interval"`
	Timeouts         map[string]string `json:"timeouts"`
	ReAlertInterval  *string           `json:"re_alert_interval"`
	Severity         *string           `json:"severity"`
	AlertChannels    []string          `json:"alert_channels"`
	EscalationPolicy *string           `json:"escalation_policy"`
}

// checkDefaultsViewJSON is the GET/PUT response. The top-level effective
// values are not read: they include built-ins that are not overrides.
type checkDefaultsViewJSON struct {
	Overrides *checkDefaultsOverridesJSON `json:"overrides"`
}

func (r *checkDefaultsResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_check_defaults"
}

func (r *checkDefaultsResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	inherit := " Omit or set null to use the built-in default."
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages the Tenant's check defaults: the values a Check inherits when it leaves a setting null. " +
			"One per Tenant. Creating it replaces the stored defaults with this configuration; an omitted attribute is " +
			"not overridden and uses the built-in default. Checks that leave a setting null follow changes here " +
			"without a diff on the `ensafely_check`.\n\n" +
			"**Destroy resets every default to the built-in value.** This also removes the `Email` default alert " +
			"channel that a new Tenant is provisioned with, so Checks without their own `alert_channels` stop alerting " +
			"until channels are set again. Import with ID `current`.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{Computed: true, MarkdownDescription: "Always `current`.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}},
			"retry_count": schema.Int64Attribute{Optional: true,
				MarkdownDescription: "Retries before a failure is reported. `0` is an explicit \"no retries\"." + inherit + " (0)",
				Validators:          []validator.Int64{int64Range{min: 0}}},
			"retry_interval": schema.StringAttribute{Optional: true,
				MarkdownDescription: "Wait between retries, for example `10s`." + inherit,
				Validators:          []validator.String{stringCheck{duration: true}}},
			"check_interval": schema.StringAttribute{Optional: true,
				MarkdownDescription: "Check interval, for example `1m`." + inherit,
				Validators:          []validator.String{stringCheck{duration: true}}},
			"timeouts": schema.MapAttribute{Optional: true, ElementType: types.StringType,
				MarkdownDescription: "Timeout per check type (`http`, `tcp`, `dns`, ...; `default` applies to types without an entry), " +
					"for example `{ http = \"5s\" }`. Only the listed types are overridden; the others keep their built-in timeout." + inherit,
				Validators: []validator.Map{durationMap{}}},
			"re_alert_interval": schema.StringAttribute{Optional: true,
				MarkdownDescription: "Interval between repeated alerts while a check stays unhealthy, for example `1h`." + inherit,
				Validators:          []validator.String{stringCheck{duration: true}}},
			"severity": schema.StringAttribute{Optional: true,
				MarkdownDescription: "Alert severity: `critical`, `warning` or `info`." + inherit,
				Validators:          []validator.String{stringCheck{oneOf: []string{"critical", "warning", "info"}}}},
			"alert_channels": schema.SetAttribute{Optional: true, ElementType: types.StringType,
				MarkdownDescription: "Alert channel names Checks alert by default. Omit or set null for no default channels.",
				Validators:          []validator.Set{setCheck{}}},
			"escalation_policy": schema.StringAttribute{Optional: true,
				MarkdownDescription: "Escalation policy name." + inherit,
				Validators:          []validator.String{stringCheck{}}},
		},
	}
}

func (r *checkDefaultsResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.client = clientFromProviderData(req.ProviderData, &resp.Diagnostics)
}

// payload converts the plan to the stored document. Validators reject the
// empty values the server would store as null ("", [] and {}), so the
// response always matches the plan.
func (m checkDefaultsModel) payload(ctx context.Context, diags *diag.Diagnostics) checkDefaultsOverridesJSON {
	out := checkDefaultsOverridesJSON{
		RetryCount:       m.RetryCount.ValueInt64Pointer(),
		RetryInterval:    m.RetryInterval.ValueStringPointer(),
		CheckInterval:    m.CheckInterval.ValueStringPointer(),
		ReAlertInterval:  m.ReAlertInterval.ValueStringPointer(),
		Severity:         m.Severity.ValueStringPointer(),
		EscalationPolicy: m.EscalationPolicy.ValueStringPointer(),
	}
	if !m.Timeouts.IsNull() {
		diags.Append(m.Timeouts.ElementsAs(ctx, &out.Timeouts, false)...)
	}
	if !m.AlertChannels.IsNull() {
		diags.Append(m.AlertChannels.ElementsAs(ctx, &out.AlertChannels, false)...)
	}
	return out
}

// checkDefaultsModelFromAPI maps a response's overrides to state.
func checkDefaultsModelFromAPI(ctx context.Context, view checkDefaultsViewJSON, diags *diag.Diagnostics) checkDefaultsModel {
	m := checkDefaultsModel{ID: types.StringValue(singletonID), Timeouts: types.MapNull(types.StringType), AlertChannels: types.SetNull(types.StringType)}
	o := view.Overrides
	if o == nil {
		diags.AddError("Unsupported Ensafely server",
			"The check defaults response has no \"overrides\" object. The server is older than this provider; upgrade it before managing ensafely_check_defaults.")
		return m
	}
	m.RetryCount = types.Int64PointerValue(o.RetryCount)
	m.RetryInterval = nullableString(o.RetryInterval)
	m.CheckInterval = nullableString(o.CheckInterval)
	m.ReAlertInterval = nullableString(o.ReAlertInterval)
	m.Severity = nullableString(o.Severity)
	m.EscalationPolicy = nullableString(o.EscalationPolicy)
	var d diag.Diagnostics
	if len(o.Timeouts) > 0 {
		m.Timeouts, d = types.MapValueFrom(ctx, types.StringType, o.Timeouts)
		diags.Append(d...)
	}
	if len(o.AlertChannels) > 0 {
		m.AlertChannels, d = types.SetValueFrom(ctx, types.StringType, o.AlertChannels)
		diags.Append(d...)
	}
	return m
}

// nullableString maps the server's "not overridden" ("" or null) to null.
func nullableString(p *string) types.String {
	if p == nil || *p == "" {
		return types.StringNull()
	}
	return types.StringValue(*p)
}

// write replaces the stored document with plan and returns the saved state.
func (r *checkDefaultsResource) write(ctx context.Context, plan checkDefaultsModel, diags *diag.Diagnostics) (checkDefaultsModel, bool) {
	body := plan.payload(ctx, diags)
	if diags.HasError() {
		return checkDefaultsModel{}, false
	}
	var saved checkDefaultsViewJSON
	if err := r.client.Put(ctx, checkDefaultsPath, body, &saved); err != nil {
		addAPIError(diags, "write check defaults", err)
		return checkDefaultsModel{}, false
	}
	m := checkDefaultsModelFromAPI(ctx, saved, diags)
	return m, !diags.HasError()
}

func (r *checkDefaultsResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan checkDefaultsModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if m, ok := r.write(ctx, plan, &resp.Diagnostics); ok {
		resp.Diagnostics.Append(resp.State.Set(ctx, m)...)
	}
}

func (r *checkDefaultsResource) Read(ctx context.Context, _ resource.ReadRequest, resp *resource.ReadResponse) {
	var view checkDefaultsViewJSON
	if err := r.client.Get(ctx, checkDefaultsPath, &view); err != nil {
		addAPIError(&resp.Diagnostics, "read check defaults", err)
		return
	}
	m := checkDefaultsModelFromAPI(ctx, view, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, m)...)
}

func (r *checkDefaultsResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan checkDefaultsModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if m, ok := r.write(ctx, plan, &resp.Diagnostics); ok {
		resp.Diagnostics.Append(resp.State.Set(ctx, m)...)
	}
}

// Delete resets every override: PUT {} restores the built-in defaults.
func (r *checkDefaultsResource) Delete(ctx context.Context, _ resource.DeleteRequest, resp *resource.DeleteResponse) {
	if err := r.client.Put(ctx, checkDefaultsPath, struct{}{}, nil); err != nil {
		addAPIError(&resp.Diagnostics, "reset check defaults", err)
	}
}

func (r *checkDefaultsResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	importSingleton(ctx, "check defaults", req, resp)
}

// importSingleton accepts only the ID "current": there is one object per
// Tenant, chosen by the API key.
func importSingleton(ctx context.Context, what string, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	if req.ID != singletonID {
		resp.Diagnostics.AddError("Invalid import ID",
			fmt.Sprintf("The Tenant's %s are a singleton; import them with ID %q, got %q.", what, singletonID, req.ID))
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), singletonID)...)
}

// durationMap requires a nonempty map of nonempty keys to positive Go
// durations. The server stores {} and "" entries as "not overridden", which
// Terraform would report as an inconsistent result.
type durationMap struct{}

func (durationMap) Description(context.Context) string {
	return "a nonempty map of check types to positive Go durations"
}
func (v durationMap) MarkdownDescription(ctx context.Context) string { return v.Description(ctx) }

func (durationMap) ValidateMap(_ context.Context, req validator.MapRequest, resp *validator.MapResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	elems := req.ConfigValue.Elements()
	if len(elems) == 0 {
		resp.Diagnostics.AddAttributeError(req.Path, "Empty map", "Omit the attribute (or set null) instead of an empty map.")
		return
	}
	for k, e := range elems {
		p := req.Path.AtMapKey(k)
		if k == "" {
			resp.Diagnostics.AddAttributeError(p, "Empty key", "Use a check type such as http, tcp or default.")
			continue
		}
		s, ok := e.(types.String)
		if !ok || s.IsUnknown() {
			continue
		}
		if s.IsNull() || s.ValueString() == "" {
			resp.Diagnostics.AddAttributeError(p, "Empty value", "Remove the entry instead of setting an empty timeout.")
			continue
		}
		if d, err := time.ParseDuration(s.ValueString()); err != nil || d <= 0 {
			resp.Diagnostics.AddAttributeError(p, "Invalid duration", fmt.Sprintf("%q is not a positive Go duration such as 3s or 1m.", s.ValueString()))
		}
	}
}
