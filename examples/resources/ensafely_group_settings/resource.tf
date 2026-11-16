resource "ensafely_group_settings" "example" {
  project = "production"
  group   = "database"

  enabled           = true
  duration          = "1m"
  re_alert_interval = "1h"
}
