// Command terraform-provider-ensafely is the Ensafely Terraform provider.
package main

// Registry docs: docs/ is generated from templates/, examples/ and the schema
// descriptions. Run `go generate` in this directory after changing any of
// them; scripts/release-tfprovider.sh --check fails when docs/ is stale.
//go:generate go run github.com/hashicorp/terraform-plugin-docs/cmd/tfplugindocs@v0.25.0 generate --provider-name ensafely
//go:generate go run github.com/hashicorp/terraform-plugin-docs/cmd/tfplugindocs@v0.25.0 validate --provider-name ensafely

import (
	"context"
	"flag"
	"log"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"

	"github.com/imcitius/terraform-provider-ensafely/internal/provider"
)

// version is set by the release build (-ldflags "-X main.version=...").
var version = "dev"

// Address is the provider's registry address: namespace imcitius, the owner
// of the public mirror github.com/imcitius/terraform-provider-ensafely
// (docs/operations/tfprovider-release.md).
const Address = "registry.terraform.io/imcitius/ensafely"

func main() {
	var debug bool
	flag.BoolVar(&debug, "debug", false, "run the provider with support for debuggers like delve")
	flag.Parse()

	err := providerserver.Serve(context.Background(), provider.New(version), providerserver.ServeOpts{
		Address: Address,
		Debug:   debug,
	})
	if err != nil {
		log.Fatal(err)
	}
}
