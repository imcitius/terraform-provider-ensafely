// Command acc-bootstrap registers the acceptance Platform regions
// (acctest.PlatformRegions), then creates a disposable Tenant and api_write
// API key on a local Ensafely test app, optionally moves it to another plan
// (-plan), and prints the key on stdout. It is used by
// scripts/tf-acceptance.sh; see package acctest.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/imcitius/terraform-provider-ensafely/internal/acctest"
)

func main() {
	endpoint := flag.String("endpoint", "http://localhost:8090", "local Ensafely test app")
	plan := flag.String("plan", "", "plan ID for the test Tenant, set through the local platform admin (empty keeps the signup plan)")
	flag.Parse()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	// Regions first, so the new Tenant is provisioned with its Plan's
	// default regions like a production Tenant.
	if err := acctest.SeedPlatformRegions(ctx, *endpoint, acctest.PlatformRegions, acctest.BootstrapOptions{}); err != nil {
		fmt.Fprintln(os.Stderr, "acc-bootstrap:", err)
		os.Exit(1)
	}
	creds, err := acctest.Bootstrap(ctx, *endpoint, acctest.BootstrapOptions{Plan: *plan})
	if err != nil {
		fmt.Fprintln(os.Stderr, "acc-bootstrap:", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "acc-bootstrap: Tenant %s (%s) ready on %s\n", creds.TenantID, creds.Email, *endpoint)
	fmt.Println(creds.APIKey)
}
