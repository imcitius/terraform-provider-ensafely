resource "ensafely_project_settings" "example" {
  project = "production"

  enabled           = true
  duration          = "1m"
  re_alert_interval = "1h"
}
