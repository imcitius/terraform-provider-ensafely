# Tenant-wide defaults. Checks that leave these settings null inherit them.
resource "ensafely_check_defaults" "current" {
  check_interval    = "1m"
  retry_count       = 2
  retry_interval    = "10s"
  re_alert_interval = "1h"
  severity          = "warning"
  alert_channels    = ["Email"]

  # Only the listed check types are overridden; the others keep their
  # built-in timeout.
  timeouts = {
    http = "5s"
    dns  = "3s"
  }
}
