// Package provider implements the Ensafely Terraform provider on
// terraform-plugin-framework.
//
// Design (GitHub #110): name-keyed resources, inheritable fields optional but
// not computed, write-only `<field>_wo` + `<field>_wo_version` secrets
// (Terraform >= 1.11), and import on every resource.
package provider

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/imcitius/terraform-provider-ensafely/internal/client"
)

// Environment variables read when the matching provider argument is unset.
const (
	EnvAPIKey   = "ENSAFELY_API_KEY"
	EnvEndpoint = "ENSAFELY_ENDPOINT"
)

// TypeName is the provider's resource prefix (ensafely_*).
const TypeName = "ensafely"

var _ provider.Provider = (*Provider)(nil)

// Provider is the Ensafely provider. Resource and data source constructors
// are appended by T4–T10 (#114–#120).
type Provider struct {
	version string
}

// New returns a constructor for the provider server.
func New(version string) func() provider.Provider {
	return func() provider.Provider { return &Provider{version: version} }
}

type providerModel struct {
	APIKey   types.String `tfsdk:"api_key"`
	Endpoint types.String `tfsdk:"endpoint"`
}

func (p *Provider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = TypeName
	resp.Version = p.version
}

func (p *Provider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manage Ensafely Checks, alerting and Probe regions as code. " +
			"Requires Terraform 1.11 or newer and a Tenant API key: `api_write` to apply, `api_read` for plan only.",
		Attributes: map[string]schema.Attribute{
			"api_key": schema.StringAttribute{
				MarkdownDescription: "Tenant API key (`ck_...`): the `api_write` scope to apply changes, " +
					"`api_read` for `terraform plan` only. " +
					"Can also be set with the `" + EnvAPIKey + "` environment variable.",
				Optional:  true,
				Sensitive: true,
			},
			"endpoint": schema.StringAttribute{
				MarkdownDescription: "Ensafely base URL. Defaults to `" + client.DefaultEndpoint + "`. " +
					"Can also be set with the `" + EnvEndpoint + "` environment variable.",
				Optional: true,
			},
		},
	}
}

func (p *Provider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var cfg providerModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if cfg.APIKey.IsUnknown() {
		resp.Diagnostics.AddAttributeError(path.Root("api_key"), "Unknown Ensafely API key",
			"The provider cannot be configured with an API key that is only known after apply. "+
				"Use a literal, a variable, or the "+EnvAPIKey+" environment variable.")
	}
	if cfg.Endpoint.IsUnknown() {
		resp.Diagnostics.AddAttributeError(path.Root("endpoint"), "Unknown Ensafely endpoint",
			"The provider cannot be configured with an endpoint that is only known after apply. "+
				"Use a literal, a variable, or the "+EnvEndpoint+" environment variable.")
	}
	if resp.Diagnostics.HasError() {
		return
	}

	apiKey := strings.TrimSpace(os.Getenv(EnvAPIKey))
	if !cfg.APIKey.IsNull() {
		apiKey = strings.TrimSpace(cfg.APIKey.ValueString())
	}
	endpoint := strings.TrimSpace(os.Getenv(EnvEndpoint))
	if !cfg.Endpoint.IsNull() {
		endpoint = strings.TrimSpace(cfg.Endpoint.ValueString())
	}
	if endpoint == "" {
		endpoint = client.DefaultEndpoint
	}

	if apiKey == "" {
		resp.Diagnostics.AddAttributeError(path.Root("api_key"), "Missing Ensafely API key",
			"Set the api_key provider argument or the "+EnvAPIKey+" environment variable to a Tenant "+
				"API key: api_write to apply changes, api_read for plan only. Create one in the Ensafely app under Account → API Keys.")
	}
	if _, err := client.ParseEndpoint(endpoint); err != nil {
		resp.Diagnostics.AddAttributeError(path.Root("endpoint"), "Invalid Ensafely endpoint", err.Error())
	}
	if resp.Diagnostics.HasError() {
		return
	}

	c, err := client.New(client.Config{
		Endpoint:  endpoint,
		APIKey:    apiKey,
		UserAgent: fmt.Sprintf("terraform-provider-ensafely/%s (+https://registry.terraform.io/providers/imcitius/ensafely) Terraform/%s", p.version, req.TerraformVersion),
	})
	if err != nil {
		resp.Diagnostics.AddError("Unable to create Ensafely API client", err.Error())
		return
	}
	resp.DataSourceData = c
	resp.ResourceData = c
}

func (p *Provider) Resources(context.Context) []func() resource.Resource {
	return []func() resource.Resource{newCheckResource, newConnectionResource, newProjectSettingsResource, newGroupSettingsResource, newEscalationPolicyResource, newAlertChannelResource, newCheckDefaultsResource, newPlatformRegionsResource}
}

func (p *Provider) DataSources(context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{newCheckDataSource, newPlatformRegionsAvailableDataSource}
}
