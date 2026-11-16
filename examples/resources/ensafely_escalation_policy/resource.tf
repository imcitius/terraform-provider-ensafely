# Channel names must identify alert channels in the same Tenant.
resource "ensafely_escalation_policy" "oncall" {
  name = "oncall"

  step {
    channel   = "team-slack"
    delay_min = 0
  }

  step {
    channel   = "oncall-pagerduty"
    delay_min = 5
  }
}
