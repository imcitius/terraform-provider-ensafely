resource "ensafely_alert_channel" "oncall_email" {
  name = "oncall-email"

  email {
    to = ["oncall@example.com", "sre@example.com"]
  }
}

resource "ensafely_alert_channel" "team_slack" {
  name = "team-slack"

  slack {
    default_channel = "C01ABCDEF"

    # Write-only: never stored in plan or state. Bump the version to rotate.
    bot_token_wo              = var.slack_bot_token
    bot_token_wo_version      = 1
    signing_secret_wo         = var.slack_signing_secret
    signing_secret_wo_version = 1
  }
}

resource "ensafely_alert_channel" "incident_hook" {
  name = "incident-hook"

  webhook {
    method       = "POST"
    content_type = "application/json"

    url_wo             = var.incident_hook_url
    url_wo_version     = 1
    secret_wo          = var.incident_hook_hmac
    secret_wo_version  = 1
    headers_wo         = { "X-Api-Key" = var.incident_hook_key }
    headers_wo_version = 1
  }
}

# Checks reference channels by name. Renaming a channel replaces it, and the
# referencing Check's alert_channels change appears in the same plan.
resource "ensafely_check" "api" {
  name           = "api"
  project        = "shop"
  alert_channels = [ensafely_alert_channel.team_slack.name]

  http {
    url = "https://api.example.com/health"
  }
}

# Ephemeral variables (Terraform 1.10+) can feed write-only arguments without
# ever being stored.
variable "slack_bot_token" {
  type      = string
  sensitive = true
  ephemeral = true
}

variable "slack_signing_secret" {
  type      = string
  sensitive = true
  ephemeral = true
}

variable "incident_hook_url" {
  type      = string
  sensitive = true
  ephemeral = true
}

variable "incident_hook_hmac" {
  type      = string
  sensitive = true
  ephemeral = true
}

variable "incident_hook_key" {
  type      = string
  sensitive = true
  ephemeral = true
}
