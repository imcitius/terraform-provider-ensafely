package provider

import (
	"context"
	"errors"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/imcitius/terraform-provider-ensafely/internal/client"
)

// clientFromProviderData converts ConfigureRequest.ProviderData for resources
// and data sources. It returns nil without a diagnostic while the provider is
// not configured yet (Terraform configures resources early during
// validation, before the provider itself).
func clientFromProviderData(data any, diags *diag.Diagnostics) *client.Client {
	if data == nil {
		return nil
	}
	c, ok := data.(*client.Client)
	if !ok {
		diags.AddError("Unexpected provider data",
			fmt.Sprintf("Expected *client.Client, got %T. This is a bug in the Ensafely provider.", data))
		return nil
	}
	return c
}

// addAPIError turns a client error into a diagnostic. action says what failed,
// e.g. `create check "web"`. Quota, plan, scope, auth and rate-limit errors
// keep the server's details (see client.APIError).
func addAPIError(diags *diag.Diagnostics, action string, err error) {
	summary := "Ensafely API request failed"
	detail := fmt.Sprintf("Unable to %s: %s", action, err)
	var apiErr *client.APIError
	if errors.As(err, &apiErr) {
		summary = apiErr.Summary()
		if apiErr.Quota != nil {
			detail += "\n\nUpgrade the Tenant's plan or buy an add-on to raise the limit, or remove resources that are no longer needed."
		}
	}
	diags.AddError(summary, detail)
}

// removeIfNotFound implements the 404 rule for Read: when the API reports the
// object as gone, it is dropped from state so the next plan recreates it. It
// returns true when err was a 404 and Read should return without error.
func removeIfNotFound(ctx context.Context, err error, resp *resource.ReadResponse) bool {
	if !client.IsNotFound(err) {
		return false
	}
	tflog.Warn(ctx, "Ensafely object not found; removing it from state", map[string]any{"error": err.Error()})
	resp.State.RemoveResource(ctx)
	return true
}
