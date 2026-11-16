#!/usr/bin/env bash
# Writes imports.tf with one import block per Check, alert channel,
# escalation policy and Connection of the Tenant. Needs curl and jq; an
# api_read key is enough.
set -euo pipefail
endpoint="${ENSAFELY_ENDPOINT:-https://app.ensafely.com}"

get() {
  curl -fsS -H "Authorization: Bearer $ENSAFELY_API_KEY" "$endpoint$1"
}

# blocks TYPE PREFIX ID_FIELD: JSON array on stdin, import blocks on stdout.
blocks() {
  jq -r --arg type "$1" --arg prefix "$2" --arg key "$3" '.[] | .[$key] as $id |
    "import {\n  to = \($type).\($prefix)\($id | ascii_downcase | gsub("[^a-z0-9_]"; "_"))\n  id = \($id | tojson)\n}\n"'
}

{
  get /api/check-definitions | blocks ensafely_check check_ uuid
  get /api/alert-channels | blocks ensafely_alert_channel channel_ name
  get /api/escalation-policies | blocks ensafely_escalation_policy policy_ name
  get /api/connections | blocks ensafely_connection connection_ id
} > imports.tf
