terraform {
  required_version = ">= 1.11"
  required_providers {
    ensafely = {
      source = "imcitius/ensafely"
    }
  }
}

# The key needs the api_write scope to apply; api_read is enough for plan.
# Prefer the ENSAFELY_API_KEY environment variable over a literal.
provider "ensafely" {
  # api_key  = var.ensafely_api_key
  # endpoint = "https://app.ensafely.com"
}
