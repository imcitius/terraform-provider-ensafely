resource "ensafely_check" "api" {
  name     = "Public API"
  project  = "production"
  group    = "api"
  interval = "1m"
  # Null inheritable fields (severity, alert_channels, retry_count, ...)
  # use the Tenant's check defaults.

  http {
    url          = "https://api.example.com/health"
    status_codes = [200]
    answer       = "ok"

    basic_auth_user                = "monitor"
    basic_auth_password_wo         = var.monitor_password
    basic_auth_password_wo_version = 1
  }
}

# Host and credentials come from a Connection instead of inline secrets.
resource "ensafely_connection" "orders_db" {
  name                = "orders-db"
  type                = "postgres"
  host                = "orders-db.internal"
  username            = "monitor"
  password_wo         = var.orders_db_password
  password_wo_version = 1
  params = {
    db_name = "orders"
  }
}

resource "ensafely_check" "orders_db" {
  name          = "Orders database"
  project       = "production"
  connection_id = ensafely_connection.orders_db.id

  pgsql_query {
    query    = "SELECT count(*) > 0 FROM orders"
    response = "true"
  }
}

resource "ensafely_check" "heartbeat" {
  name    = "Nightly backup"
  project = "production"

  passive {
    timeout = "25h"
  }
}
