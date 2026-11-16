package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/imcitius/terraform-provider-ensafely/internal/client"
)

type checkDataSource struct {
	client *client.Client
}

var _ datasource.DataSourceWithConfigure = (*checkDataSource)(nil)

func newCheckDataSource() datasource.DataSource { return &checkDataSource{} }

func (d *checkDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_check"
}

func (d *checkDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = checkDataSourceSchema()
}

func (d *checkDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.client = clientFromProviderData(req.ProviderData, &resp.Diagnostics)
}

func (d *checkDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var id types.String
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("id"), &id)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if !isUUID(id.ValueString()) {
		resp.Diagnostics.AddAttributeError(path.Root("id"), "Invalid check ID", "Expected a check UUID.")
		return
	}
	var out checkJSON
	if err := d.client.Get(ctx, checkPath(id.ValueString()), &out); err != nil {
		addAPIError(&resp.Diagnostics, "read check", err)
		return
	}
	values := checkDataSourceValues(&out)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), out.UUID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("type"), out.Type)...)
	for name, val := range values.attrs {
		resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root(name), val)...)
	}
	for name, obj := range values.blocks {
		resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root(name), obj)...)
	}
}

// checkDataSourceValues maps a read for the data source. Unlike the
// resource, a type this provider does not manage is not an error: the type
// is reported and every type attribute is null.
func checkDataSourceValues(out *checkJSON) checkValues {
	values, diags := checkValuesFromAPI(out, checkValues{}, false)
	if diags.HasError() {
		// Only the unsupported-type error is possible here; the common
		// fields are still valid.
		for _, t := range checkTypes {
			values.blocks[t.block] = types.ObjectNull(t.attrTypes(false))
		}
	}
	return values
}
