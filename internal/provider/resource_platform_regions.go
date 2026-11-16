package provider

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	dsschema "github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/imcitius/terraform-provider-ensafely/internal/client"
)

const (
	platformRegionsPath          = "/api/platform-regions"
	platformRegionsAvailablePath = "/api/platform-regions/available"
)

// platformRegionsResource manages the Tenant's selected Platform probe
// regions (#120). PUT replaces the selection; destroy calls DELETE, which
// restores the Plan's default regions.
type platformRegionsResource struct {
	client *client.Client
}

var (
	_ resource.ResourceWithConfigure   = (*platformRegionsResource)(nil)
	_ resource.ResourceWithImportState = (*platformRegionsResource)(nil)
)

func newPlatformRegionsResource() resource.Resource { return &platformRegionsResource{} }

type platformRegionsModel struct {
	ID      types.String `tfsdk:"id"`
	Regions types.Set    `tfsdk:"regions"`
}

// platformRegionsJSON is the GET/PUT/DELETE response and the PUT body
// (regions only).
type platformRegionsJSON struct {
	Regions []string `json:"regions"`
	Quota   *struct {
		Current int `json:"current"`
		Limit   int `json:"limit"`
	} `json:"quota,omitempty"`
}

func (r *platformRegionsResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_platform_regions"
}

func (r *platformRegionsResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages the Platform probe regions selected for the Tenant: the Ensafely-operated regions its " +
			"`saas_only` and `multi_region` Checks run in. One per Tenant; creating it replaces the current selection. " +
			"The Plan limits how many regions can be selected (Free 2, Pro 5, Enterprise unlimited); selecting more fails " +
			"with a plan-limit error. List selectable regions with the `ensafely_platform_regions_available` data source.\n\n" +
			"**Destroy resets the selection to the Plan's default regions** (those currently served by a Probe), not to " +
			"an empty selection. Import with ID `current`.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{Computed: true, MarkdownDescription: "Always `current`.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}},
			"regions": schema.SetAttribute{Required: true, ElementType: types.StringType,
				MarkdownDescription: "Selected region names, for example `[\"eu-paris\", \"us-washington\"]`. An empty set " +
					"selects no Platform regions (Checks then run only on the Tenant's own Probes).",
				Validators: []validator.Set{nonemptyElements{}}},
		},
	}
}

func (r *platformRegionsResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.client = clientFromProviderData(req.ProviderData, &resp.Diagnostics)
}

func platformRegionsModelFromAPI(ctx context.Context, out platformRegionsJSON, diags *diag.Diagnostics) platformRegionsModel {
	regions := out.Regions
	if regions == nil {
		regions = []string{}
	}
	set, d := types.SetValueFrom(ctx, types.StringType, regions)
	diags.Append(d...)
	return platformRegionsModel{ID: types.StringValue(singletonID), Regions: set}
}

func (r *platformRegionsResource) put(ctx context.Context, plan platformRegionsModel, diags *diag.Diagnostics) (platformRegionsModel, bool) {
	var regions []string
	diags.Append(plan.Regions.ElementsAs(ctx, &regions, false)...)
	if diags.HasError() {
		return platformRegionsModel{}, false
	}
	if regions == nil {
		// The API requires the key: [] clears the selection, null is a 400.
		regions = []string{}
	}
	var out platformRegionsJSON
	if err := r.client.Put(ctx, platformRegionsPath, platformRegionsJSON{Regions: regions}, &out); err != nil {
		addPlatformRegionsError(diags, regions, err)
		return platformRegionsModel{}, false
	}
	m := platformRegionsModelFromAPI(ctx, out, diags)
	return m, !diags.HasError()
}

// addPlatformRegionsError explains the region-specific denials: the plan
// limit, a plan without Platform regions, and an unknown region.
func addPlatformRegionsError(diags *diag.Diagnostics, regions []string, err error) {
	var apiErr *client.APIError
	if errors.As(err, &apiErr) {
		switch {
		case apiErr.Quota != nil:
			diags.AddError("Ensafely plan limit reached",
				fmt.Sprintf("The Tenant's plan allows at most %d platform regions, but this configuration selects %d (%s). "+
					"Remove regions from ensafely_platform_regions or upgrade the plan.\n\n%s",
					apiErr.Quota.Limit, len(regions), strings.Join(regions, ", "), err))
			return
		case apiErr.StatusCode == http.StatusForbidden && strings.Contains(apiErr.Message, "not available on your plan"):
			diags.AddError("Platform regions not available on this plan",
				fmt.Sprintf("The Tenant's plan does not include Platform regions. Upgrade the plan, or remove ensafely_platform_regions.\n\n%s", err))
			return
		case apiErr.StatusCode == http.StatusBadRequest && strings.HasPrefix(apiErr.Message, "unknown region"):
			diags.AddError("Unknown platform region",
				fmt.Sprintf("%s. Use a region listed by the ensafely_platform_regions_available data source.\n\n%s", apiErr.Message, err))
			return
		}
	}
	addAPIError(diags, "update platform regions", err)
}

func (r *platformRegionsResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan platformRegionsModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if m, ok := r.put(ctx, plan, &resp.Diagnostics); ok {
		resp.Diagnostics.Append(resp.State.Set(ctx, m)...)
	}
}

func (r *platformRegionsResource) Read(ctx context.Context, _ resource.ReadRequest, resp *resource.ReadResponse) {
	var out platformRegionsJSON
	if err := r.client.Get(ctx, platformRegionsPath, &out); err != nil {
		addAPIError(&resp.Diagnostics, "read platform regions", err)
		return
	}
	m := platformRegionsModelFromAPI(ctx, out, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, m)...)
}

func (r *platformRegionsResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan platformRegionsModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if m, ok := r.put(ctx, plan, &resp.Diagnostics); ok {
		resp.Diagnostics.Append(resp.State.Set(ctx, m)...)
	}
}

// Delete restores the Plan's default regions (DELETE is idempotent).
func (r *platformRegionsResource) Delete(ctx context.Context, _ resource.DeleteRequest, resp *resource.DeleteResponse) {
	if err := r.client.Delete(ctx, platformRegionsPath, nil); err != nil {
		addAPIError(&resp.Diagnostics, "reset platform regions to the plan defaults", err)
	}
}

func (r *platformRegionsResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	importSingleton(ctx, "platform regions", req, resp)
}

// nonemptyElements rejects empty strings in a set; an empty set is allowed.
type nonemptyElements struct{}

func (nonemptyElements) Description(context.Context) string { return "a set of nonempty values" }
func (v nonemptyElements) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (nonemptyElements) ValidateSet(_ context.Context, req validator.SetRequest, resp *validator.SetResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	for _, e := range req.ConfigValue.Elements() {
		checkSetElement(e, setCheck{}, req.Path, &resp.Diagnostics)
	}
}

// Data source ensafely_platform_regions_available.

type platformRegionsAvailableDataSource struct {
	client *client.Client
}

var _ datasource.DataSourceWithConfigure = (*platformRegionsAvailableDataSource)(nil)

func newPlatformRegionsAvailableDataSource() datasource.DataSource {
	return &platformRegionsAvailableDataSource{}
}

var availableRegionAttrTypes = map[string]attr.Type{"name": types.StringType, "connected": types.BoolType}

func (d *platformRegionsAvailableDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_platform_regions_available"
}

func (d *platformRegionsAvailableDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = dsschema.Schema{
		MarkdownDescription: "Lists the Platform probe regions the Tenant can select in `ensafely_platform_regions`, " +
			"and the Plan's limit.",
		Attributes: map[string]dsschema.Attribute{
			"regions": dsschema.ListNestedAttribute{Computed: true,
				MarkdownDescription: "Selectable regions, ordered by name.",
				NestedObject: dsschema.NestedAttributeObject{Attributes: map[string]dsschema.Attribute{
					"name":      dsschema.StringAttribute{Computed: true, MarkdownDescription: "Region name, for example `eu-paris`."},
					"connected": dsschema.BoolAttribute{Computed: true, MarkdownDescription: "Whether a Probe in the region is connected now."},
				}}},
			"names": dsschema.SetAttribute{Computed: true, ElementType: types.StringType,
				MarkdownDescription: "The region names alone, convenient for `regions = data.ensafely_platform_regions_available.x.names`."},
			"limit": dsschema.Int64Attribute{Computed: true,
				MarkdownDescription: "How many regions the Tenant's plan allows: `-1` is unlimited, `0` means the plan has no Platform regions."},
		},
	}
}

func (d *platformRegionsAvailableDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.client = clientFromProviderData(req.ProviderData, &resp.Diagnostics)
}

func (d *platformRegionsAvailableDataSource) Read(ctx context.Context, _ datasource.ReadRequest, resp *datasource.ReadResponse) {
	var available struct {
		Regions []struct {
			Region    string `json:"region"`
			Connected bool   `json:"connected"`
		} `json:"regions"`
	}
	if err := d.client.Get(ctx, platformRegionsAvailablePath, &available); err != nil {
		addAPIError(&resp.Diagnostics, "list available platform regions", err)
		return
	}
	var selected platformRegionsJSON
	if err := d.client.Get(ctx, platformRegionsPath, &selected); err != nil {
		addAPIError(&resp.Diagnostics, "read the platform region limit", err)
		return
	}
	objects := make([]attr.Value, 0, len(available.Regions))
	names := make([]string, 0, len(available.Regions))
	for _, r := range available.Regions {
		obj, diags := types.ObjectValue(availableRegionAttrTypes, map[string]attr.Value{
			"name": types.StringValue(r.Region), "connected": types.BoolValue(r.Connected),
		})
		resp.Diagnostics.Append(diags...)
		objects = append(objects, obj)
		names = append(names, r.Region)
	}
	list, diags := types.ListValue(types.ObjectType{AttrTypes: availableRegionAttrTypes}, objects)
	resp.Diagnostics.Append(diags...)
	nameSet, diags := types.SetValueFrom(ctx, types.StringType, names)
	resp.Diagnostics.Append(diags...)
	limit := types.Int64Null()
	if selected.Quota != nil {
		limit = types.Int64Value(int64(selected.Quota.Limit))
	}
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, struct {
		Regions types.List  `tfsdk:"regions"`
		Names   types.Set   `tfsdk:"names"`
		Limit   types.Int64 `tfsdk:"limit"`
	}{list, nameSet, limit})...)
}
