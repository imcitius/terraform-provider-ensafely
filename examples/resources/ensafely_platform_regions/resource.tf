# Run the Tenant's platform Checks from two regions (the Free plan allows two).
resource "ensafely_platform_regions" "current" {
  regions = ["eu-paris", "us-washington"]
}
