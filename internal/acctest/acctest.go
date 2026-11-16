// Package acctest holds the acceptance-test (TF_ACC=1) environment shared by
// the provider's resource tests, and the bootstrap that creates a Tenant and
// API key on a local test app.
//
// Acceptance tests never fall back to the production endpoint: both
// ENSAFELY_ENDPOINT and ENSAFELY_API_KEY must be set explicitly. The
// repository harness (scripts/tf-acceptance.sh, run by
// `scripts/verify.sh tf`) starts the app with `make e2e-up`, runs Bootstrap
// and exports both variables.
package acctest

import (
	"os"
	"testing"
)

// Variables read by PreCheck. They are the provider's own environment
// variables, so the provider under test configures itself from them.
const (
	EnvAPIKey   = "ENSAFELY_API_KEY"
	EnvEndpoint = "ENSAFELY_ENDPOINT"
)

// PreCheck fails the test when the acceptance environment is incomplete.
// terraform-plugin-testing already skips acceptance tests unless TF_ACC is
// set, so a missing variable here is a harness error, not a skip.
func PreCheck(t *testing.T) {
	t.Helper()
	for _, name := range []string{EnvEndpoint, EnvAPIKey} {
		if os.Getenv(name) == "" {
			t.Fatalf("%s must be set for acceptance tests; run scripts/verify.sh tf, which starts a local app and creates a test Tenant", name)
		}
	}
}

// Endpoint returns the endpoint under test.
func Endpoint() string { return os.Getenv(EnvEndpoint) }
