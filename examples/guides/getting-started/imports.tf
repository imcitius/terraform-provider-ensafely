# Tenant singletons: the import ID is always "current".
import {
  to = ensafely_check_defaults.current
  id = "current"
}

import {
  to = ensafely_platform_regions.current
  id = "current"
}

# Name-keyed resources: the import ID is the name.
import {
  to = ensafely_alert_channel.oncall_email
  id = "oncall-email"
}

import {
  to = ensafely_escalation_policy.oncall
  id = "oncall"
}

# UUID-keyed resources.
import {
  to = ensafely_connection.orders_db
  id = "0b6f1f7e-4c4e-4f5b-9a63-2f4d3c2b1a00"
}

import {
  to = ensafely_check.api
  id = "123e4567-e89b-12d3-a456-426614174000"
}

# Settings overrides: "<project>" or "<project>/<group>".
import {
  to = ensafely_project_settings.production
  id = "production"
}

import {
  to = ensafely_group_settings.production_database
  id = "production/database"
}
