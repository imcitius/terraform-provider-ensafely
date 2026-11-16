variable "orders_db_password" {
  type      = string
  sensitive = true
  # Ephemeral variables (Terraform 1.10+) can feed write-only arguments
  # without ever being stored.
  ephemeral = true
}

resource "ensafely_connection" "orders_db" {
  name     = "orders-db"
  type     = "postgres"
  host     = "db.example.com"
  port     = 5432
  username = "checker"

  # Write-only: never stored in plan or state. Bump the version to rotate.
  password_wo         = var.orders_db_password
  password_wo_version = 1

  params = {
    db_name  = "orders"
    ssl_mode = "require"
  }
}

resource "ensafely_connection" "status_api" {
  name = "status-api"
  type = "http"

  # Header values are secrets in the API (returned masked), so they are
  # write-only too. Bump the version to send a changed map.
  headers_wo         = { "X-Api-Key" = var.status_api_key }
  headers_wo_version = 1

  params = {
    base_url = "https://api.example.com/health"
  }
}

variable "status_api_key" {
  type      = string
  sensitive = true
  ephemeral = true
}
