---
page_title: "Getting started: API key, provider and importing a Tenant"
subcategory: ""
description: |-
  Create an Ensafely API key, configure the provider and bring an existing Tenant under Terraform management.
---

# Getting started

This guide takes an existing Ensafely Tenant from the app to Terraform:

1. create an API key with the right scope;
2. configure the provider;
3. import the existing configuration with `terraform plan -generate-config-out`;
4. add the write-only secrets that cannot be imported.

It needs Terraform 1.11 or newer (or OpenTofu 1.11 or newer).

## 1. Create an API key

In the Ensafely app open **Account → API Keys** and create a key. Choose the
scope by what the key will do:

| Scope | Label in the app | Use it for |
|---|---|---|
| `api_read` | API read-only | `terraform plan`, drift detection, `-generate-config-out`, CI plan jobs |
| `api_write` | API read-write | `terraform apply` and `terraform destroy` |

An `api_read` key can only send `GET` requests, so an apply with it fails with
**Ensafely request forbidden**. Agent keys, created on the Probes page for a
Tenant agent, cannot use the API at all. A legacy key (created before key
scopes existed) works until its cut-off date; replace it with a scoped key.

The key is shown once. Keep it in a secret store and expose it as an
environment variable:

```shell
export ENSAFELY_API_KEY='ck_...'
```

A key acts as the member who created it. When that member is removed from the
Tenant, their keys are disabled and Terraform reports `authentication failed`.

## 2. Configure the provider

```terraform
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
```

`api_key` and `endpoint` can also be set in the provider block; a value there
takes precedence over `ENSAFELY_API_KEY` and `ENSAFELY_ENDPOINT`. Run
`terraform init`.

## 3. Import the existing Tenant

Every resource supports import, so Terraform can generate the configuration
for what already exists. Write one `import` block per object:

```terraform
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
```

| Resource | Import ID | Where to find it |
|---|---|---|
| `ensafely_check` | Check UUID | `GET /api/check-definitions` (`uuid`) |
| `ensafely_alert_channel` | channel name | `GET /api/alert-channels` (`name`) |
| `ensafely_escalation_policy` | policy name | `GET /api/escalation-policies` (`name`) |
| `ensafely_connection` | Connection UUID | `GET /api/connections` (`id`) |
| `ensafely_project_settings` | `<project>` | project names of your Checks |
| `ensafely_group_settings` | `<project>/<group>` | project and group names of your Checks |
| `ensafely_check_defaults` | `current` | one per Tenant |
| `ensafely_platform_regions` | `current` | one per Tenant |

For a large Tenant, generate the blocks from the API. This script writes
`imports.tf` for every Check, alert channel, escalation policy and Connection;
it needs `curl` and `jq`, and an `api_read` key is enough:

```shell
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
```

Two names that differ only in characters other than letters, digits and `_`
map to the same resource name; rename one of the generated blocks.

Then let Terraform write the configuration:

```shell
terraform plan -generate-config-out=generated.tf
```

Review `generated.tf`. It is a starting point, not final configuration:

- **Write-only secrets are not imported.** The API never returns them, so
  `generated.tf` has no `*_wo` arguments. Until you add them, the server keeps
  the stored secrets.
- **Inherited settings stay null.** A Check that inherits its interval,
  severity or alert channels from the check defaults has no value for them in
  `generated.tf`; keep it that way, or the Check stops following the defaults.
- **Unmanaged Check types fail to import.** The provider manages the http,
  tcp, icmp, dns, ssl_cert, domain_expiry, passive, pgsql_query, mysql_query,
  redis, mongodb, ssh, smtp, grpc_health and websocket types. Remove the
  `import` blocks of other Checks (the error names the type).
- **The default `Email` channel** cannot be deleted. If you import it, keep it
  in configuration or remove it from state with
  `removed { lifecycle { destroy = false } }`.
- Replace literal IDs with references where it helps, for example
  `connection_id = ensafely_connection.orders_db.id` or
  `alert_channels = [ensafely_alert_channel.oncall_email.name]`.

Run `terraform plan` again until it shows only the imports and no changes,
then `terraform apply` with an `api_write` key to record them in state. The
`import` blocks can be deleted afterwards.

## 4. Add the secrets

Secrets are write-only pairs: `<field>_wo` holds the value, `<field>_wo_version`
is a number Terraform stores. A secret is sent on create and whenever its
version changes. After an import no version is stored yet, so adding both
arguments sends the secret once on the next apply:

```terraform
variable "orders_db_password" {
  type      = string
  sensitive = true
  ephemeral = true
}

resource "ensafely_connection" "orders_db" {
  # ... generated arguments ...

  password_wo         = var.orders_db_password
  password_wo_version = 1
}
```

To rotate a secret later, change the value and increment its version in the
same apply. Changing only the value sends nothing.

## OpenTofu

The provider works with OpenTofu 1.11 or newer, which supports write-only
arguments with the same semantics. Older OpenTofu versions reject the
configuration.
