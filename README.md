# atomic-cli

A command-line interface for managing Atomic instances, applications, users, and options.

## Table of Contents

- [Overview](#overview)
- [Installation](#installation)
  - [Prerequisites](#prerequisites)
  - [Install via Homebrew (macOS/Linux)](#install-via-homebrew-macoslinux)
  - [Download prebuilt binaries](#download-prebuilt-binaries)
  - [Building from Source](#building-from-source)
- [Configuration](#configuration)
  - [Environment Variables](#environment-variables)
  - [Credentials file (TOML or YAML)](#credentials-file-toml-or-yaml)
  - [Authentication](#authentication)
- [Global Options](#global-options)
- [Commands](#commands)
  - [Instance Management](#instance-management)
  - [Application Management](#application-management)
  - [User Management](#user-management)
  - [Plan Management](#plan-management)
  - [Price Management](#price-management)
  - [Category Management](#category-management)
  - [Audience Management](#audience-management)
  - [Access Token Management](#access-token-management)
  - [Asset Management](#asset-management)
  - [Job Management](#job-management)
  - [Option Management](#option-management)
  - [Database Management](#database-management)
  - [Import Command](#import-command)
  - [Migrate Command](#migrate-command)
  - [Stripe Management](#stripe-management)
  - [Session Diagnostics](#session-diagnostics)
  - [Cluster Status](#cluster-status)
  - [MCP Server](#mcp-server)
- [Output Formats](#output-formats)
- [Field Selection](#field-selection)
- [File Input](#file-input)
- [Examples](#examples)
- [Error Handling](#error-handling)
- [Version](#version)
- [License](#license)

## Overview

The `atomic-cli` is a powerful command-line tool for interacting with the Atomic platform. It provides comprehensive management capabilities for instances, applications, users, and options through an intuitive CLI interface.

## Installation

### Prerequisites

- Go 1.25 or later
- Access to an Atomic API endpoint

### Install via Homebrew (macOS/Linux)

```bash
brew tap libatomic/tap
brew install libatomic/tap/atomic-cli

# Upgrade later
brew upgrade libatomic/tap/atomic-cli
```

### Download prebuilt binaries

Prebuilt binaries are available on the GitHub releases page: [libatomic/atomic-cli releases](https://github.com/libatomic/atomic-cli/releases).

Steps:

- Download the archive for your OS/architecture
- Extract and move the `atomic-cli` binary into a directory on your `PATH` (for example `/usr/local/bin`)
- Make it executable if needed: `chmod +x /usr/local/bin/atomic-cli`

### Building from Source

```bash
git clone https://github.com/libatomic/atomic-cli.git
cd atomic-cli
go build -o atomic-cli cmd/atomic-cli/main.go
```

## Configuration

The CLI supports configuration through environment variables or command-line flags:

### Environment Variables

- `PASSPORT_ACCESS_TOKEN` - Your access token for authentication
- `PASSPORT_CLIENT_ID` - Your client ID for OAuth2 client credentials flow
- `PASSPORT_CLIENT_SECRET` - Your client secret for OAuth2 client credentials flow
- `PASSPORT_API_HOST` - The Passport API host (defaults to the client default)
- `PASSPORT_DB_SOURCE` - Used for direct connection to the Passport db rather than API

### Credentials file (TOML or YAML)

You can store one or more named profiles in a credentials file and switch between them with `--profile`. By default the CLI looks for `~/.atomic/credentials` and accepts either TOML or YAML (TOML is tried first; YAML is the fallback).

- Default path: `~/.atomic/credentials`
- Override path: `--credentials` / `-c`
- Select a profile: `--profile` / `-p` (default: `default`)
- Precedence per flag: command-line flag > environment variable > credentials file > compiled default

**Supported fields** under each profile section:

| Field | Flag equivalent | Notes |
|---|---|---|
| `host` | `--host` / `-h` | API host (e.g. `api.example.com` or `https://api.example.com`) |
| `access_token` | `--access_token` | Bearer token for access-token auth |
| `client_id` | `--client_id` | OAuth2 client ID for client-credentials auth |
| `client_secret` | `--client_secret` | OAuth2 client secret |
| `instance_id` | `-i` / `--instance_id` | Default target instance — accepts a base58 ID **or** an instance name/domain |
| `out_format` | `--out-format` / `-o` | Default output format for every command. Valid values: `table` (default), `json`, `json-pretty`, `jsonl` (alias `ndjson`). Override per-command with `-o ...`. |
| `stripe_key` | `--stripe-key` / `-k` (under `stripe` and `migrate`) | Default Stripe API key, used by `stripe ...` and `migrate substack` / `migrate map` |
| `stripe_livemode` | `--live-mode` (under `stripe`) | Allow live Stripe keys for the profile (boolean) |
| `db_source` | `--db_source` | Direct DB connection string (hidden flag; for internal use) |

**TOML example** (`~/.atomic/credentials`):

```toml
[default]
host = "api.atomic.example.com"
client_id = "your-client-id"
client_secret = "your-client-secret"
instance_id = "my.instance.example.com"
out_format = "json-pretty"

[staging]
host = "api.staging.atomic.example.com"
access_token = "at_XXXXXXXXXXXXXXXX"
instance_id = "CZ6psMmMo4BBCGyE2NyR2"
out_format = "table"
stripe_key = "sk_test_XXXXXXXXXXXXXXXX"
```

> **TOML strings must be quoted.** `host = foo.example.com` is a syntax error; use `host = "foo.example.com"`. If the file can't be parsed, the CLI prints a warning with the exact parser error and the line number so you can fix it.

**YAML example** (`~/.atomic/credentials`):

```yaml
default:
  host: api.atomic.example.com
  client_id: your-client-id
  client_secret: your-client-secret
  instance_id: my.instance.example.com
  out_format: json-pretty

staging:
  host: api.staging.atomic.example.com
  access_token: "at_XXXXXXXXXXXXXXXX"
  instance_id: CZ6psMmMo4BBCGyE2NyR2
  out_format: table
  stripe_key: "sk_test_XXXXXXXXXXXXXXXX"
```

**Usage:**

```bash
# Use the default profile
atomic-cli instance list

# Use a named profile
atomic-cli --profile staging instance list
atomic-cli -p staging instance list

# Specify a custom credentials file
atomic-cli --credentials /path/to/credentials instance list
```

**Instance lookup by name or domain:** the `instance_id` flag (and the `instance_id` field in a profile) accepts either a base58 ID like `CZ6psMmMo4BBCGyE2NyR2` or a name/domain like `my.instance.example.com`. When a non-ID value is supplied the CLI resolves it via `InstanceList` before running the command, so you can reference instances by their human-readable names in your profiles.

**Multi-profile troubleshooting:** if you add a profile and the CLI suddenly falls back to defaults, a parse error probably broke the whole file. Run with any command (e.g. `atomic-cli instance list`) — the CLI will print a `credentials:` warning pointing at the offending line.

### Authentication

The CLI supports two authentication methods:

1. **Access Token**: Use `--access-token` flag or `PASSPORT_ACCESS_TOKEN` environment variable
2. **Client Credentials**: Use `--client-id` and `--client-secret` flags or environment variables

## Global Options

| Option | Alias | Description | Default |
|------------------------|-------|----------------------------------------------|---------|
| `--access-token` | | Specify the access token | |
| `--client-id` | | Specify the client ID | |
| `--client-secret` | | Specify the client secret | |
| `--host` | | Specify the API host | Client default |
| `--out-format` | `-o` | Output format (table, json, json-pretty) | table |
| `--fields` | `-f` | Specify fields to display | |

## Commands

### Instance Management

Manage Atomic instances with the `instance` (or `inst`) command.

#### Create Instance

```bash
atomic-cli instance create <name> [options]
```

**Options:**
- `--title` - Set the instance display title
- `--description` - Set the instance description
- `--session_key` - Set the session key
- `--session_cookie` - Set the session cookie
- `--session_lifetime` - Set session lifetime in milliseconds (default: 3600)
- `--metadata` - Source file for instance metadata (JSON)
- `--origins` - Set allowed origins (comma-separated)
- `--domains` - Set allowed domains (comma-separated)
- `--parent_id` - Set the parent instance ID
- `--file` - Read instance parameters from JSON file

**Example:**
```bash
atomic-cli instance create my-instance \
  --title "My Instance" \
  --description "A test instance" \
  --domains "example.com,app.example.com"
```

#### Get Instance

```bash
atomic-cli instance get <instance-id>
```

**Example:**
```bash
atomic-cli instance get inst_1234567890abcdef
```

#### Update Instance

```bash
atomic-cli instance update <instance-id> [options]
```

**Options:** Same as create, plus:
- `--recreate_jobs` - Recreate the instance jobs

**Example:**
```bash
atomic-cli instance update inst_1234567890abcdef \
  --title "Updated Instance Title" \
  --recreate_jobs
```

#### List Instances

```bash
atomic-cli instance list [options]
```

**Options:**
- `--name` - Filter by instance name (regex)
- `--is_parent` - Show only parent instances
- `--has_parent` - Show only instances with a parent

**Example:**
```bash
atomic-cli instance list --name "test.*" --is_parent
```

#### Delete Instance

```bash
atomic-cli instance delete <instance-id>
```

**Example:**
```bash
atomic-cli instance delete inst_1234567890abcdef
```

### Application Management

Manage applications with the `application` (or `app`) command.

#### Create Application

```bash
atomic-cli application create [options]
```

**Options:**
- `--name` - Set the application name
- `--description` - Set the application description
- `--type` - Set the application type (default: web)
- `--token_lifetime` - Set token lifetime (default: 3600)
- `--refresh_token_lifetime` - Set refresh token lifetime (default: 3600)
- `--allowed_redirects` - Set allowed redirects
- `--allowed_grants` - Set allowed grants
- `--permissions` - Set permissions
- `--metadata` - Source file for application metadata (JSON)
- `--session_domain` - Set the session domain
- `--session_lifetime` - Set the session lifetime
- `--instance_id` - Set the instance ID

**Example:**
```bash
atomic-cli application create \
  --name "My Web App" \
  --type "web" \
  --instance_id inst_1234567890abcdef \
  --allowed_redirects "https://app.example.com/callback"
```

#### Get Application

```bash
atomic-cli application get <application-id> [options]
```

**Options:**
- `--instance_id` - Set the instance ID

**Example:**
```bash
atomic-cli application get app_1234567890abcdef
```

#### Update Application

```bash
atomic-cli application update <application-id> [options]
```

**Options:** Same as create

**Example:**
```bash
atomic-cli application update app_1234567890abcdef \
  --name "Updated App Name" \
  --description "Updated description"
```

#### List Applications

```bash
atomic-cli application list [options]
```

**Options:**
- `--instance_id` - Filter by instance ID
- `--name` - Filter by application name

**Example:**
```bash
atomic-cli application list --instance_id inst_1234567890abcdef
```

#### Delete Application

```bash
atomic-cli application delete <application-id>
```

**Example:**
```bash
atomic-cli application delete app_1234567890abcdef
```

### User Management

Manage users with the `user` (or `users`) command.

#### Create User

```bash
atomic-cli user create <login> [options]
```

Note: usernames (logins) must be valid email addresses.

**Options:**
- `--login` - Set the user login
- `--password` - Set the user password
- `--email` - Set the user email
- `--profile` - Set user profile from JSON file
- `--roles` - Set user roles (default: ["user"])
- `--metadata` - Set user metadata from JSON file
- `--stripe_account` - Set the user Stripe account
- `--suppress_events` - Suppress user events
- `--subscribe_default_plans` - Subscribe to default plans
- `--preferences` - Set user preferences from JSON file
- `--create_only` - Create the user only
- `--suppress_validation` - Suppress user validation
- `--suppress_parent_triggers` - Suppress parent triggers
- `--rebuild_audiences` - Rebuild the user audiences
- `--file` - Read user parameters from JSON file

**Example:**
```bash
atomic-cli user create \
  --password "securepassword123" \
  --roles "user,admin" \
  john.doe@example.com 
```

#### Get User

```bash
atomic-cli user get <user-id>
```

**Example:**
```bash
atomic-cli user get user_1234567890abcdef
```

#### Update User

```bash
atomic-cli user update <user-id> [options]
```

**Options:** Same as create (excluding create-specific flags)

**Example:**
```bash
atomic-cli user update user_1234567890abcdef \
  --email "newemail@example.com" \
  --roles "user,moderator"
```

#### List Users

```bash
atomic-cli user list [options]
```

**Options:**
- `--audience` - List by audience
- `--roles` - List by role
- `--status` - List by status
- `--login` - List by login
- `--stripe_account` - List by Stripe account
- `--limit` - Limit the number of users
- `--offset` - Offset the number of users
- `--expand` - Expand user fields
- `--instance_id` - Set the instance ID

**Example:**
```bash
atomic-cli user list \
  --roles "admin" \
  --limit 10
```

#### Delete User

```bash
atomic-cli user delete <user-id>
```

**Example:**
```bash
atomic-cli user delete user_1234567890abcdef
```

#### Import Users

Bulk-import users from a CSV file. The import is processed as a background job and supports subscriptions, Stripe customer linking, discounts, auto-subscribe plans, trials, teams, and notification preferences.

```bash
atomic-cli user import <file> [options]
```

All options can be provided via CLI flags, a JSON config file (`--config`), or both (CLI flags override config values).

**Options:**

| Option | Description | Default |
|---|---|---|
| `--config`, `-c` | JSON config file with import parameters | |
| `--mime_type` | MIME type of the import file | `text/csv` |
| `--source` | Import source identifier (atomic, ghost, substack, etc.) | `atomic` |
| `--dry_run` | Preview import without creating or updating users | `false` |
| `--ignore_created_at` | Ignore the `created_at` column from the CSV; users are created with the current timestamp at job runtime | `false` |
| `--existing_user_behavior` | Behavior for existing users: `skip` (leave the user alone and skip the record entirely), `merge` (update profile/roles/stripe **and** process subscriptions, plans, trials, and category opt-outs), `recreate` (delete and re-create from the import record), `retain` (leave the existing user untouched but still process the record's subscriptions, default plans, trial, and category opt-outs like `merge` would) | `merge` |
| `--validate_user_email` | Validate user email addresses | `false` |
| `--verify_user_email` | Override `email_verified` on all records (overrides each record's field when set) | `true` |
| `--user_event_options` | User event options: pipe-delimited flags (`LOG\|EMIT\|SYNC\|CHILDREN\|CONTEXT\|SUPPRESS`). Default is log-only for imports. Set to `LOG\|EMIT\|CONTEXT` for full event processing, or `SUPPRESS` to suppress all. | `LOG` |
| `--rebuild_audiences` | Rebuild audiences after import | `true` |
| `--import_audience_id` | Audience ID to add imported users to | |
| `--import_audience_behavior` | Audience behavior: `add_all_users`, `add_new_users`, `add_existing_users` | `add_all_users` |
| `--stripe_account_behavior` | Stripe account behavior: `existing`, `create`, `none` | `existing` |
| `--default_plan_behavior` | Default plan behavior: `all`, `non_subscribers`, `none` — controls both subscribe plans and instance defaults | `non_subscribers` |
| `--subscribe_plans` | Plan IDs to subscribe users to (repeatable) | |
| `--subscribe_behavior` | Subscribe behavior: `all_users`, `subscribers_only`, `non_subscribers_only`, `subscribers_skip_paid`, `none` | `all_users` |
| `--trial_plan_id` | Trial plan ID | |
| `--trial_price_id` | Trial price ID | |
| `--trial_end_at` | Trial end date/time | |
| `--trial_existing_users` | Apply trial to existing users without a subscription | `false` |
| `--trial_behavior` | Trial behavior: `all`, `non_subscribers`, `none` | `non_subscribers` |
| `--expired_subscription_behavior` | Behavior when `subscription_end_at` is in the past: `none` (skip the expired sub, still import the user), `trial` (start the user on a trial of the same plan for `--expired_subscription_trial_days`) | `none` |
| `--expired_subscription_trial_days` | Trial length (days) used when `--expired_subscription_behavior=trial` | `15` |
| `--discount_behavior` | Discount behavior: `aggregate` (shared instance coupons), `individual` (per-user coupons), `none` | `aggregate` |
| `--default_discount_percentage` | Default discount percentage for subscriptions | |
| `--default_discount_term` | Default discount term: `once`, `repeating`, `forever` | `forever` |
| `--default_discount_duration_days` | Default discount duration in days | |
| `--default_subscription_prorate` | Prorate subscriptions by default | `false` |
| `--default_subscription_anchor_date` | Default subscription anchor date (RFC3339, e.g. `2026-05-08T21:29:00Z`) | |
| `--create_teams` | Enable team import processing | `false` |
| `--team_limit_behavior` | Team seat limit behavior: `drop_admin`, `drop_user`, `expand_subscription` | `drop_admin` |
| `--job_event_options` | Event options for the job completed event: pipe-delimited flags (`LOG\|EMIT\|SYNC\|CHILDREN\|CONTEXT\|SUPPRESS`). Controls whether the completion event triggers emails, webhooks, etc. | |
| `--job_max_workers` | Override the per-job worker concurrency. Clamped to `[1, NumCPU]` and further capped by the server-side `UserImportMaxWorkers` (itself clamped to `[1, NumCPU]`, tunable via `ATOMIC_USER_IMPORT_WORKERS`). Leave unset to use the server default. | |
| `--abort_on_error_threshold` | Ratio of errored / processed records at which the import aborts (safety net for pathological runs — bad CSV, upstream outage). `0` aborts on any error, `1.0` disables the check, otherwise the import stops once the ratio crosses the threshold. The check is only evaluated after at least 100 records have been processed, so a single early failure can't trip it. When it fires, in-flight workers drain, the team second pass and audience rebuild are skipped, the report's status becomes `aborted` with a reason note, and the job row's `queue_error` carries the message. Created users and their subscriptions are retained. | `0.01` (1%) |
| `--user_import_skip` | Skip the first N records of the parsed CSV before importing. Must not exceed the parsed record count (the job fails if it does). Primarily a testing knob. | `0` |
| `--user_import_limit` | Process at most N records (applied after `--user_import_skip`). `0` means no limit; values larger than the remaining record count are silently capped. Primarily a testing knob. | `0` |
| `--wait` | Wait for the import job to complete, showing a progress bar. With `--verbose`, also streams job logs above the progress bar. On completion, prints total duration and a per-stage breakdown (duration and items/sec); also prints any `job.Errors` recorded by the handler, even when the queue status is `success`. **Ctrl+C detaches** the tail — the import keeps running on the server; use `atomic-cli job get <id> --wait` or `atomic-cli job cancel <id>` to manage it. | `false` |

**Examples:**

```bash
# Import with CLI flags
atomic-cli user import migrate_users.csv \
  -i inst_abc123 \
  --verify_user_email \
  --subscribe_plans plan_abc123 \
  --auto_subscribe_behavior all_users

# Import with a JSON config file
atomic-cli user import migrate_users.csv -i inst_abc123 -c import-config.json

# Config file overridden by CLI flag
atomic-cli user import migrate_users.csv -i inst_abc123 -c import-config.json --dry_run

# Import and wait for completion with progress bar and log streaming
atomic-cli user import migrate_users.csv -i inst_abc123 --wait --verbose
```

**Example config file (`import-config.json`):**

```json
{
  "dry_run": false,
  "verify_user_email": true,
  "default_plan_behavior": "all",
  "subscribe_plans": ["plan_abc123", "plan_def456"],
  "subscribe_behavior": "all_users",
  "create_teams": true,
  "team_limit_behavior": "drop_admin"
}
```

##### CSV Validation

Before calling the API, the CLI validates the input CSV locally — checking per-record structural validity and uniqueness on `login`, `email`, `phone_number`, and `stripe_customer_id`. If validation fails, the import is aborted with a summary. Run `migrate validate --verbose` for detailed per-row error reporting.

##### CSV Format

See [User Import Record CSV Format](#user-import-record-csv-format) for the full column reference.

**Team imports:** When `create_teams` is enabled on the import job (default `false`), records with a `team_key` are grouped. The team owner (`is_team_owner=true`) must have a subscription with `subscription_quantity > 1`. Team members (same `team_key`, `is_team_owner` not set) do not get their own subscription — instead they receive an entitlement to the team owner's subscription, consuming one seat. Records are automatically sorted so team owners are processed before their members. The owner occupies 1 seat; each team member consumes 1 additional seat. For the `migrate substack` command, subscriptions with `metadata["is_group"]="true"` are automatically marked as team owners with the Stripe subscription ID as the `team_key`.

**Team limit behavior** (`team_limit_behavior`, default `drop_admin`): controls what happens when the number of team members exceeds the subscription quantity.

| Behavior | Description |
|---|---|
| `drop_admin` | The first user over the limit causes the admin/owner's own entitlement to be dropped, freeing one seat for the member. Subsequent users over the limit are dropped (same as `drop_user`). |
| `drop_user` | Users over the seat limit are skipped entirely — no entitlement is created. |
| `expand_subscription` | The subscription quantity is automatically increased to accommodate all team members. |

All team capacity events (drops, expansions, orphaned members, failures) are logged in the job report under the "Team Entitlements" section. Orphaned team members (no matching owner for their `team_key`) are reported with the expected owner's login.

### Plan Management

Manage plans with the `plan` (or `plans`) command.

#### Create Plan

```bash
atomic-cli plan create <name> [options]
```

**Options:**

| Option | Description | Default |
|------------------------|----------------------------------------------|---------|
| `--file` | Read plan parameters from a JSON file | `false` |
| `--name` | Plan name | |
| `--description` | Plan description | |
| `--type` | Plan type: `free`, `paid`, `enterprise` | |
| `--active` | Set the plan as active | |
| `--hidden` | Set the plan as hidden | |
| `--default` | Set the plan as the default plan | |
| `--password` | Set the plan password | |
| `--image` | Set the plan image URL | |
| `--stripe_product` | Stripe product ID | |
| `--metadata` | Set plan metadata from a JSON file | |

**Example:**
```bash
atomic-cli -i inst_abc123 plan create "Premium" \
  --type paid \
  --active
```

#### Update Plan

```bash
atomic-cli plan update <plan_id> [options]
```

Accepts the same options as `create` (except `--file`, `--type`, and `--stripe_product`).

#### Get Plan

```bash
atomic-cli plan get <plan_id> [options]
```

**Options:**

| Option | Description |
|--------------|----------------------------------------------|
| `--expand` | Expand fields (`prices`, `categories`, `audiences`) |

#### List Plans

```bash
atomic-cli plan list [options]
```

**Options:**

| Option | Description | Default |
|--------------|----------------------------------------------|---------|
| `--type` | Filter by plan type (repeatable) | |
| `--hidden` | Include hidden plans | `false` |
| `--inactive` | Include inactive plans | `false` |
| `--limit` | Limit the number of results | |
| `--offset` | Pagination offset | |
| `--expand` | Expand fields (`prices`, `categories`, `audiences`) | |

#### Delete Plan

```bash
atomic-cli plan delete <plan_id>
```

#### Subscribe User to Plan

```bash
atomic-cli plan subscribe <plan_id> [options]
```

**Options:**

| Option | Description | Default |
|------------------------|----------------------------------------------|---------|
| `--user_id` | User ID to subscribe | *required* |
| `--price_id` | Specific price ID | |
| `--interval` | Subscription interval: `month`, `year` | |
| `--currency` | Subscription currency | |
| `--quantity` | Subscription quantity | `1` |
| `--no_prorate` | Do not prorate the subscription | `false` |
| `--no_entitlement` | Do not create entitlements | `false` |
| `--trial` | Start the subscription with a trial | `false` |
| `--password` | Plan password | |
| `--expand` | Expand fields | |

**Example:**
```bash
atomic-cli -i inst_abc123 plan subscribe plan_abc123 \
  --user_id user_xyz789 \
  --interval month \
  --currency usd
```

#### Import Plans

```bash
atomic-cli plan import <file.json> [--dry-run]
```

Imports plans with prices from a JSON array file. Each plan is created in the target instance with all nested prices. Categories are preserved.

### Price Management

Manage prices with the `price` (or `prices`) command.

#### Create Price

```bash
atomic-cli price create <name> [options]
```

**Options:**

| Option | Description | Default |
|------------------------|----------------------------------------------|---------|
| `--file` | Read price parameters from a JSON file | `false` |
| `--plan_id` | Plan ID this price belongs to | *required* |
| `--name` | Price name | |
| `--currency` | Price currency | `usd` |
| `--type` | Price type: `one_time`, `recurring` | `recurring` |
| `--amount` | Price amount in cents | |
| `--interval` | Recurring interval: `month`, `year` | |
| `--frequency` | Recurring frequency | `1` |
| `--active` | Set the price as active | |
| `--hidden` | Set the price as hidden | |
| `--metered` | Metered price | `false` |
| `--stripe_price` | Stripe price ID | |
| `--metadata` | Set price metadata from a JSON file | |

**Example:**
```bash
atomic-cli -i inst_abc123 price create "Monthly" \
  --plan_id plan_abc123 \
  --amount 999 \
  --interval month \
  --currency usd
```

#### Update Price

```bash
atomic-cli price update <price_id> [options]
```

**Options:**

| Option | Description |
|--------------|----------------------------------------------|
| `--name` | Price name |
| `--active` | Set the price as active |
| `--hidden` | Set the price as hidden |
| `--amount` | Price amount in cents |
| `--metadata` | Set price metadata from a JSON file |

#### Get Price

```bash
atomic-cli price get <price_id> [options]
```

**Options:**

| Option | Description |
|--------------|----------------------------------------------|
| `--expand` | Expand fields (`plan`) |

#### List Prices

```bash
atomic-cli price list [options]
```

**Options:**

| Option | Description |
|--------------|----------------------------------------------|
| `--plan_id` | Filter by plan ID |
| `--limit` | Limit the number of results |
| `--offset` | Pagination offset |

#### Delete Price

```bash
atomic-cli price delete <price_id>
```

### Category Management

Manage categories with the `category` (or `categories`) command.

#### Create Category

```bash
atomic-cli category create <name> [options]
```

**Options:**

| Option | Description | Default |
|--------------|----------------------------------------------|---------|
| `--file` | Read category parameters from a JSON file | `false` |
| `--name` | Category name | |
| `--description` | Category description | |
| `--active` | Set the category as active | `true` |
| `--hidden` | Set the category as hidden | `false` |

#### Update Category

```bash
atomic-cli category update <category_id> [options]
```

Accepts the same options as `create` (except `--file`).

#### Get Category

```bash
atomic-cli category get <category_id>
```

#### List Categories

```bash
atomic-cli category list [options]
```

**Options:**

| Option | Description |
|--------------|----------------------------------------------|
| `--limit` | Limit the number of results |
| `--offset` | Pagination offset |

#### Delete Category

```bash
atomic-cli category delete <category_id>
```

#### Import Categories

```bash
atomic-cli category import <file.json> [--dry-run]
```

Imports categories from a JSON array file. Each category's `instance_id` and `id` are ignored; categories are created in the instance specified by `-i`.

### Audience Management

Manage audiences with the `audience` (or `audiences`) command.

#### List Audiences

```bash
atomic-cli audience list [options]
```

**Options:**

| Option | Description | Default |
|--------------|----------------------------------------------|---------|
| `--internal` | Filter by internal audiences | |
| `--static` | Filter by static audiences | |
| `--limit` | Limit the number of results | |
| `--offset` | Pagination offset | |

#### Get Audience

```bash
atomic-cli audience get <audience_id>
```

#### Delete Audience

```bash
atomic-cli audience delete <audience_id>
```

#### Import Audiences

```bash
atomic-cli audience import <file.json> [--dry-run]
```

Imports non-internal audiences from a JSON array file. Internal audiences are automatically skipped. Each audience's expression filter (`expr`) is preserved.

### Access Token Management

Manage access tokens with the `access-token` (or `token`) command.

#### Create Access Token

```bash
atomic-cli access-token create [options]
```

**Options:**

| Option | Description | Default |
|------------------------|----------------------------------------------|---------|
| `--application_id` | Application ID to associate with the token | |
| `--user_id` | User ID to associate with the token | |
| `--scope` | Token scope | `openid, profile` |
| `--type` | Token type | `access` |
| `--expires_at` | Token expiration timestamp | |
| `--redirect_uri` | Redirect URI | |
| `--force` | Force create the token | `false` |
| `--stateless` | Create a stateless token | `false` |
| `--use_client_id` | Create using the client ID | `false` |
| `--additional_claims` | Path to a JSON file with additional claims | |

**Example:**
```bash
atomic-cli access-token create \
  --user_id user_1234567890abcdef \
  --scope "openid,profile,email" \
  --type access
```

#### Get Access Token

```bash
atomic-cli access-token get <token_id>
```

Returns the token details including claims and entitlements.

#### Revoke Access Token

```bash
atomic-cli access-token revoke <token_id> [options]
```

**Options:**
- `--delete` - Delete the token entirely instead of just revoking

### Asset Management

Manage assets with the `asset` (or `assets`, `a`) command. Requires the `--asset_volume` flag to specify the storage volume URI.

#### Create Asset

```bash
atomic-cli asset create <filename> [options]
```

**Options:**

| Option | Description | Default |
|------------------------|----------------------------------------------|---------|
| `--asset_volume` | URI of the asset volume | *required* |
| `--description` | Set the asset description | |
| `--mime_type` | Set the MIME type (auto-detected if omitted) | |
| `--type` | Set the asset type | `media` |
| `--public` | Make the asset publicly accessible | `false` |
| `--expires_at` | Set expiration timestamp | |
| `--metadata` | Set metadata from a JSON file | |
| `--categories` | Category IDs to associate with the asset | |

**Example:**
```bash
atomic-cli asset create photo.jpg \
  --asset_volume "s3://my-bucket" \
  --type media \
  --public
```

### Job Management

Manage background jobs with the `job` (or `jobs`) command.

#### Create Job

```bash
atomic-cli job create <type> [options]
```

**Options:**

| Option | Alias | Description | Default |
|------------------------|-------|----------------------------------------------|---------|
| `--params` | `-p` | Job parameters as a JSON string | *required* |
| `--state` | `-s` | Job state as a JSON string | |
| `--scheduled_at` | `-sa` | Schedule the job for a future timestamp | |
| `--file` | | Read job input from a JSON file | `false` |
| `--wait` | | Wait for the created job to complete, rendering a progress bar and (with `--verbose`) streaming logs. On success, prints total duration, a per-stage breakdown (duration and items/sec), and any non-fatal `job.Errors`. **Ctrl+C cancels the job** (the CLI created it, so it owns it). | `false` |

**Example:**
```bash
atomic-cli job create user_import \
  --params '{"file": "users.csv"}' \
  -i inst_abc123
```

#### Get Job

```bash
atomic-cli job get <job_id>
```

**Options:**

| Option | Alias | Description | Default |
|------------------------|-------|----------------------------------------------|---------|
| `--wait` | | Tail a running job until it terminates, rendering a progress bar and (with `--verbose`) streaming logs. On terminal state, prints total duration, a per-stage breakdown, and `job.Errors`. **Ctrl+C detaches the tail** without canceling the job — the job keeps running on the server. | `false` |

#### List Jobs

```bash
atomic-cli job list [options]
```

**Options:**

| Option | Alias | Description | Default |
|------------------------|-------|----------------------------------------------|---------|
| `--type` | `-t` | Filter by job type | |
| `--status` | `-s` | Filter by status | `scheduled` |
| `--offset` | | Pagination offset | |
| `--limit` | | Number of results | `5` |
| `--order_by` | | Sort order | |
| `--expand` | | Expand fields | |

**Example:**
```bash
atomic-cli job list --type user_import --status completed --limit 10
```

#### Cancel Job

```bash
atomic-cli job cancel <job_id>
```

**Options:**

| Option | Alias | Description | Default |
|------------------------|-------|----------------------------------------------|---------|
| `--wait` | | After requesting cancel, wait for the server to confirm the job reached a terminal state; streams logs with `--verbose`. **Ctrl+C detaches** without re-canceling (the cancel has already been requested). | `false` |

#### Restart Job

```bash
atomic-cli job restart <job_id>
```

### Option Management

Manage options with the `option` (or `options`) command.

#### List Options

```bash
atomic-cli option list [options]
```

**Options:**
- `--instance_id` - The instance id
- `--protected` - Include protected options

**Example:**
```bash
atomic-cli option list --instance_id inst_1234567890abcdef
```

#### Get Option

```bash
atomic-cli option get <name> [options]
```

**Options:**
- `--instance_id` - The instance id
- `--protected` - Include protected options
- `--value` - Print the option value JSON only

**Example:**
```bash
atomic-cli option get email.smtp.host --value
```

#### Create or Update Option

```bash
atomic-cli option create <name> <value> [options]
# Alias: option update
```

**Options:**
- `--instance_id` - The instance id
- `--force` - Force update even if protected
- `--file` - Read full input (including name and value) from JSON file
- `--validate` - Validate option value only

**Examples:**
```bash
# Simple JSON value
atomic-cli option create feature.flags '{"beta":true}'

# From file containing full input
atomic-cli option create --file option-input.json
```

#### Delete Option

```bash
atomic-cli option delete <name> [options]
```

**Options:**
- `--instance_id` - The instance id
- `--force` - Force delete even if protected

**Example:**
```bash
atomic-cli option delete feature.flags --force
```

### Database Management

Manage the Atomic database with the `db` command. Requires `--db_source` to be set.

#### Migrate Database

```bash
atomic-cli db migrate [options]
```

Initializes or updates database functions, tables, and views using Atlas schema migrations.

**Options:**

| Option | Description | Default |
|------------------------|----------------------------------------------|---------|
| `--create` | Create the database if it doesn't exist | `false` |
| `--apply` | Apply the migrations (without this flag, changes are shown as a dry run) | `false` |
| `--verbose` | Show verbose output of applied changes | `false` |

**Examples:**
```bash
# Preview pending migrations
atomic-cli --db_source "user:pass@tcp(localhost:3306)/atomic" db migrate

# Create database and apply migrations
atomic-cli --db_source "user:pass@tcp(localhost:3306)/atomic" db migrate --create --apply
```

### Import Command

Import data from a remote Passport instance into the local instance. Connects to a remote API, lists objects by type, and creates or updates them in the target instance specified by `-i`. Uses progress bars and spinners during fetching and importing, and prints a summary table at the end.

```bash
atomic-cli -i <target_instance> import [options]
```

**Options:**

| Option | Description | Default |
|------------------------|----------------------------------------------|---------|
| `--remote-profile` | Use a profile from `~/.atomic/credentials` as the source. Reads `host`, `access_token`, `client_id`, `client_secret`, and `instance_id` from the named profile. **Mutually exclusive** with `--remote-host` / `--remote-token` / `--remote-client-id` / `--remote-client-secret`. | |
| `--remote-host` | Remote Passport API host (e.g. `api.example.com`); mutually exclusive with `--remote-profile` | |
| `--remote-token` | Remote access token (mutually exclusive with client credentials and with `--remote-profile`) | |
| `--remote-client-id` | Remote client ID for client credentials auth (mutually exclusive with `--remote-profile`) | |
| `--remote-client-secret` | Remote client secret for client credentials auth (mutually exclusive with `--remote-profile`) | |
| `--types`, `-t` | Types to import (repeatable): `categories`, `plans`, `audiences`, `templates`, `assets`, `articles` | *required* |
| `--plan-types` | Plan types to import: `paid`, `free`, `all` | `all` |
| `--overwrite` | Overwrite existing items (matched by name) | `true` |
| `--dry-run` | Preview what would be imported without making changes | `false` |

Use the global `-v` / `--verbose` flag to show individual items being imported and detailed error messages.

When the import starts, the source and target are printed up front so you can sanity-check before any data moves:

```
importing
  source: api.staging.example.com (profile: staging)
  target: api.production.example.com — instance ankler.production (CZ6psMmMo4BBCGyE2NyR2)
```

**Import order and behavior:**

Types are imported in dependency order to ensure references resolve correctly:

1. **Categories** — matched by name. Created or updated in target.
2. **Plans** — fetched with prices and categories via preload. Plan categories are remapped from source to target by slug/name. Plan images are downloaded from remote URLs and created as local public assets. Prices are created for each plan; duplicate prices (same name on same plan) are silently skipped. The `--plan-types` flag filters by `paid`, `free`, or `all`.
3. **Audiences** — internal audiences are automatically skipped. Audience expression filters that reference `category_id.$in` UUIDs are remapped from source category UUIDs to target category UUIDs (matched by category name). Matched by name for overwrite.
4. **Templates** — uses the built-in `Overwrite` flag on `TemplateCreate`. Preserves slug, type, title, body, settings, defaults, metadata, and events.
5. **Assets** — created from remote URLs. The server downloads the content and determines size and mime type.
6. **Articles** — fetched in pages of 100 (paginated). Categories are remapped by ID. Verbose mode does not list individual articles due to potential volume.

**Summary table:**

After all types are processed, a summary table is printed:

```
Type              Found  Created  Updated  Skipped   Errors
-----------------------------------------------------------------
Categories           33       33        0        0        0
Plans                 9        9        0        0        0
Prices               10       10        0        0        0
Audiences            25       25        0        0        0
Templates            12       12        0        0        0
-----------------------------------------------------------------
import complete
```

**Examples:**

```bash
# Import categories and plans from staging
atomic-cli -i prod_inst import \
  --remote-host api.staging.example.com \
  --remote-client-id xxx --remote-client-secret yyy \
  --types categories,plans

# Import everything with verbose output, dry run
atomic-cli -v -i local_inst import \
  --remote-host api.source.com \
  --remote-token bearer_xxx \
  --types categories,plans,audiences,templates,articles \
  --dry-run

# Import only paid plans, skip existing
atomic-cli -i new_inst import \
  --remote-host api.source.com \
  --remote-token xxx \
  --types plans \
  --plan-types paid \
  --overwrite=false

# Full instance clone (all content types)
atomic-cli -v -i target_inst import \
  --remote-host api.source.com \
  --remote-client-id xxx --remote-client-secret yyy \
  --types categories,plans,audiences,templates,assets,articles

# Use a credentials profile for the source — host/token/client_id/client_secret
# are all read from ~/.atomic/credentials under the named profile
atomic-cli -i target_inst import \
  --remote-profile staging \
  --types categories,plans,audiences,templates
```

### Migrate Command

Migrate subscriber data from external platforms into Passport. The `migrate` command scans a source platform's Stripe account, maps subscriptions to Passport plans, calculates per-user discounts for grandfathered pricing, and outputs a CSV file compatible with `user import`.

```bash
atomic-cli migrate <platform> [options]
```

Currently supported platforms:

- **substack** - Migrate Substack subscribers via Stripe

Additional tools:

- **map** - Map and filter any third-party CSV to Passport user import format using a config file or inline column mappings
- **validate** - Validate a user import CSV and optionally deduplicate records

#### User Import Record CSV Format

All migrate subcommands output a CSV file with the following columns. This is the format expected by the Passport `user import` API.

| Column | Type | Required | Default | Description |
|---|---|---|---|---|
| `login` | string | Yes | — | The user's login identifier. Must be a valid email address. |
| `email` | string | No | same as `login` | The user's distribution email address. |
| `email_verified` | boolean | No | `false` | Whether the email address should be marked as verified. |
| `email_opt_in` | boolean | No | `true` | Whether the user has opted in to email communications. |
| `phone_number` | string | No | — | The user's phone number in E.164 format (e.g., `+15551234567`). |
| `phone_number_verified` | boolean | No | `false` | Whether the phone number should be marked as verified. |
| `phone_number_opt_in` | boolean | No | `false` | Whether the user has opted in to phone/SMS communications. |
| `name` | string | No | — | The user's display name. |
| `roles` | string | No | `member` | Pipe-delimited roles (e.g., `member\|admin`). |
| `stripe_customer_id` | string | No | — | An existing Stripe customer ID to link to the user's account. |
| `subscription_plan_id` | string | No | — | The plan ID to subscribe the user to. |
| `subscription_currency` | string | No | `usd` | The currency for the subscription. |
| `subscription_quantity` | integer | No | `1` | The quantity for the subscription. |
| `subscription_interval` | string | No | — | Billing interval: `month`, `year`, `once`. |
| `subscription_anchor_date` | date-time | No | today | Billing cycle anchor. Format: RFC 3339 (e.g. `2026-05-08T21:29:00Z`). |
| `subscription_end_at` | date-time | No | — | Subscription end date for subs that have already ended (terminal). Format: RFC 3339. |
| `subscription_cancel_at` | date-time | No | — | Future scheduled cancellation date. The subscription stays active until this date, then cancels. Format: RFC 3339. Mirrors Stripe `subscription.cancel_at`. |
| `subscription_cancel_at_period_end` | boolean | No | `false` | If true, the subscription will cancel automatically at the end of the current billing period. Mirrors Stripe `subscription.cancel_at_period_end`. |
| `subscription_prorate` | boolean | No | `false` | If true, prorate the period between creation and anchor date. |
| `subscription_payment_method` | string | No | — | Stripe payment method ID or test card token (e.g. `pm_card_visa`) for the subscription. |
| `metadata` | string | No | — | User metadata as pipe-delimited key=value pairs (e.g. `key1=val1\|key2=val2`). Supports nested values when type is `any`. |
| `stripe_customer_metadata` | string | No | — | Stripe customer metadata as pipe-delimited key=value pairs. Applied when a Stripe customer is created during import. |
| `discount_percentage` | float | No | — | Discount percentage to apply to the subscription. |
| `discount_term` | string | No | — | Discount term: `once`, `repeating`, `forever`. |
| `discount_duration_days` | integer | No | — | Discount duration in days. |
| `is_team_owner` | boolean | No | `false` | Marks the user as a team owner. Requires `subscription_quantity > 1`. |
| `team_key` | string | No | — | Groups users into teams. |
| `channel_opt_in` | string | No | — | Channels the user opts in to, pipe-delimited (e.g., `email\|sms`). Channels not listed are opted out. Overrides `email_opt_in` and `phone_number_opt_in`. Values: `email`, `sms`, `web`, `rss`, `podcast`. |
| `category_opt_out` | string | No | — | Categories the user opts out of, pipe-delimited (by name, slug, or ID). Listed categories are opted out across all channels. |
| `import_comment` | string | No | — | A comment stored in the user's metadata as `import:comment`. |
| `import_source` | string | No | — | Import source identifier stored in the user's metadata as `import:source`. |

Boolean columns accept: `true`, `false`, `1`, `0`. Multi-value columns use the pipe (`|`) delimiter.

All imported users automatically receive `import:date` in their metadata, set to the current UTC timestamp at the time the record is processed.

#### Common Options

`--stripe-key` (alias `--sk`) is now a **global flag** on `atomic-cli migrate`, shared by all subcommands. It can also be set via the `STRIPE_API_KEY` environment variable. It is **required** for `migrate substack` and for any `migrate map` config that uses `stripe.*` expr functions.

```bash
atomic-cli migrate --sk sk_live_xxx substack ...
atomic-cli migrate --sk sk_live_xxx map -c config.json -in source.csv
```

These options apply to all migrate subcommands:

| Option | Description | Default |
|------------------------|----------------------------------------------|---------|
| `--stripe-key`, `--sk` | Stripe API key (or `$STRIPE_API_KEY`); set on the parent `migrate` command | |
| `--dry-run` | Preview what would happen without creating plans | `false` |
| `--output`, `--out` | Output CSV file path. Each subcommand has its own default: `migrate substack` → `migrate_substack.csv`, `migrate map` → `migrate_map.csv`. When the file already exists and `--append=false`, the command prompts for confirmation before overwriting. | (per-subcommand) |
| `--subscription-prorate` | Set prorate flag on migrated subscriptions | `false` |
| `--email-domain-overwrite` | Rewrite all emails to use this domain (e.g. `passport.xyz`); mutually exclusive with `--email-template` | |
| `--email-template` | Generate emails from a template with function placeholders (see [Email Template Functions](#email-template-functions)); mutually exclusive with `--email-domain-overwrite` | |
| `--append` | Append to existing output CSV instead of overwriting; deduplicates on `login` (existing rows win) | `true` |
| `--source` | Import source identifier set on each record's `import_source` field | |
| `--limit` | Limit the number of records in each output CSV; 0 = no limit | `0` |
| `--skip` | Skip the first N records in each output CSV; 0 = no skip | `0` |

#### Email Template Functions

The `--email-template` flag generates email addresses from a template string. The following functions can be used inside `{{...}}` placeholders:

| Function | Description | Example Input | Example Output |
|---|---|---|---|
| `{{seq}}` | Sequential number (1, 2, 3, ...) | `inbox+{{seq}}@mailtrap.io` | `inbox+1@mailtrap.io` |
| `{{seq "user"}}` | Prefixed sequential number | `inbox+{{seq "user"}}@mailtrap.io` | `inbox+user1@mailtrap.io` |
| `{{hash}}` | Short hash (8 hex chars) of the original email | `inbox+{{hash}}@mailtrap.io` | `inbox+3f2a1b9c@mailtrap.io` |
| `{{hash "u"}}` | Prefixed hash | `inbox+{{hash "u"}}@mailtrap.io` | `inbox+u3f2a1b9c@mailtrap.io` |
| `{{sanitize}}` | Sanitized original email (`@`, `.`, `+`, `-` → `_`) | (for `bob+test@hot.com`) `inbox+{{sanitize}}@mailtrap.io` | `inbox+bob_test_hot_com@mailtrap.io` |

Functions can be combined in a single template. `{{seq}}` increments globally across all rewritten emails in the run.

**Mailtrap sandbox example:**

```bash
# Using the per-sandbox address format: https://docs.mailtrap.io/email-sandbox/setup/email-address-per-sandbox
atomic-cli migrate substack \
  -i inst_abc123 \
  --stripe-key sk_test_xxx \
  --email-template "sandbox-12ab34+{{seq "user"}}@inbox.mailtrap.io"
# produces: sandbox-12ab34+user1@inbox.mailtrap.io, sandbox-12ab34+user2@inbox.mailtrap.io, ...
```

#### migrate substack

Migrates Substack subscribers by scanning the Stripe account for prices tagged with Substack metadata, collecting active subscriptions across all prices (including inactive/grandfathered ones), and producing a Passport-compatible import CSV.

```bash
atomic-cli migrate substack [options]
```

**Substack-specific options:**

| Option | Description | Default |
|------------------------|----------------------------------------------|---------|
| `--subscriber-plan` | Existing Passport plan ID for regular subscribers | |
| `--founder-plan` | Existing Passport plan ID for founding members (implies `--founders`) | |
| `--founders` | Include founding member subscriptions in the migration | `false` |
| `--create-plans` | Auto-create Subscriber and Founder plans from Stripe data | `false` |
| `--legacy-pricing` | Calculate forever discounts for users on grandfathered prices (price difference between source and target plan) | `false` |
| `--apply-discounts` | Carry over existing Stripe subscription coupons/discounts to the import CSV | `true` |
| `--discount-threshold` | Minimum discount percentage to include (discounts below this are ignored) | `1` |
| `--discount-term` | Override the discount term for all applied discounts (`once`, `repeating`, `forever`); when not set, uses the coupon's original term | |
| `--omit-customer-id` | Omit `stripe_customer_id` from the output CSV (for sandbox testing) | `false` |
| `--omit-payment-methods` | Omit `subscription_payment_method` from the output CSV | `false` |
| `--migrate-test-cards` | Use Stripe test cards for `subscription_payment_method` based on currency (mutually exclusive with `--omit-payment-methods`) | `false` |
| `--shift-anchor-dates` | Shift billing cycle anchor dates forward by a duration (e.g. `24h`, `7d`, `30d`). By default shifts every subscription; pair with `--shift-anchor-window` to restrict which subscriptions are shifted. | |
| `--shift-anchor-window` | Only shift subscriptions whose next renewal falls within `now` + this duration (e.g. `24h`, `7d`). Requires `--shift-anchor-dates`. Subscriptions renewing outside the window keep their natural anchor, and subscriptions scheduled to cancel before their next renewal are skipped (no double-bill risk). Useful for creating a short reconciliation window during a Substack migration so imminent renewals are deferred while far-future renewals stay put. Every shifted record carries `atomic_migrate:anchor_shifted_from=<original-anchor>` in its `import_comment` column, and a compact monthly/yearly count summary is printed to stderr at the end of the run. | |
| `--diff` | Produce an incremental diff CSV containing only customers created after the latest `created_at` in the existing output (or last `-diff-NN.csv`). Writes to `<base>-diff-NN.csv` with auto-incrementing suffix (e.g. `-diff-01.csv`, `-diff-02.csv`). If no existing output is found, falls back to a full collection. Records in the diff are still sorted ascending by `created_at`. | `false` |

**How it works:**

1. **Price discovery** - Scans all Stripe prices for `metadata["substack"] = "yes"`. Classifies each as monthly, annual, or founding (via `metadata["founding"] = "yes"`). Active prices have no `metadata["inactive"]` key; inactive prices are included because subscribers may still be on them.

2. **Price report** - Displays a table of all discovered prices showing type, amount, currency, active status, and currency options. Shows how prices map to Passport plans.

3. **Plan resolution** - Resolves plans in one of three ways:
   - **Default** (no `--create-plans`, no `--subscriber-plan`): generates a `plans-<stripe_account_id>.jsonl` file describing the plans and prices that need to be created. Records are split into separate CSV files by plan type (subscribers and founders) without `subscription_plan_id`. Use the import-level `subscribe_plans` parameter at import time to auto-subscribe users to the correct plans.
   - With `--create-plans`: creates a hidden "Subscriber" plan with monthly/annual prices and a hidden "Founder" plan with an annual price, matching amounts and currency options from the active Stripe prices. Prompts for confirmation before creating (skipped with `--dry-run`).
   - With `--subscriber-plan` / `--founder-plan`: fetches the existing Passport plans and reads their active price amounts for discount calculation.

4. **Subscription collection** - Iterates every discovered Substack price (active and inactive) and lists all active Stripe subscriptions on each. For each subscriber, captures:
   - Customer ID, email, name
   - **`created_at`** sourced from the Stripe customer's `created` timestamp (UTC), so imported users preserve their original signup date
   - Subscription currency, quantity, billing cycle anchor
   - The Stripe price and subscription IDs (written as `migrate_stripe_price` and `migrate_stripe_subscription` in the CSV for audit purposes)
   - Cancellation state: if Stripe `subscription.cancel_at` is set (future scheduled cancel), it's recorded as `subscription_cancel_at`. If `subscription.cancel_at_period_end` is true, `subscription_cancel_at_period_end=true` is recorded. The billing cycle anchor is still computed (and advanced one interval if it would fall in the past).

   After collection, records are sorted ascending by `created_at` so the resulting CSV reflects the order users originally signed up. This is also the cutoff used by `--diff`.

5. **Discount handling** - Two types of discounts can be applied:
   - **Existing coupons** (`--apply-discounts`, default on): Stripe subscription discounts/coupons are carried over. The `--discount-threshold` filters out discounts below a minimum percentage (default 1%). The `--discount-term` can override the coupon's original term.
   - **Legacy pricing** (`--legacy-pricing`): Compares each subscriber's source price against the target Passport plan price. If the subscriber's rate is lower, a forever percentage discount is calculated to preserve their grandfathered price.
   - When both are enabled and a subscriber has an existing coupon AND a legacy price difference, the percentages are added together (capped at 100%) and the term is set to `forever`.

6. **CSV output** - The default output file is `migrate_substack.csv` (override with `--output`). In default mode (no plans), writes two CSVs: `migrate_substack-subscribers.csv` and `migrate_substack-founders.csv` (if founders exist), without `subscription_plan_id`. In plan mode, writes a single CSV with `subscription_plan_id` set. All CSVs include `migrate_stripe_price` and `migrate_stripe_subscription` audit columns. If the output file already exists and `--append=false`, the command prompts for confirmation before overwriting.

**Examples:**

```bash
# Generate plans JSONL and subscriber/founder CSVs (default behavior, no instance required)
atomic-cli migrate substack \
  --stripe-key sk_live_xxx
# outputs: plans-1A2B3C4D.jsonl, migrate_substack-subscribers.csv, migrate_substack-founders.csv

# Auto-create plans, preview with dry run
atomic-cli migrate substack \
  -i inst_abc123 \
  --stripe-key sk_live_xxx \
  --create-plans \
  --dry-run

# Auto-create plans with legacy pricing discounts
atomic-cli migrate substack \
  -i inst_abc123 \
  --stripe-key sk_live_xxx \
  --create-plans \
  --legacy-pricing \
  --out production_migrate.csv

# Use existing plans, carry over coupons with 5% threshold
atomic-cli migrate substack \
  -i inst_abc123 \
  --stripe-key sk_live_xxx \
  --subscriber-plan plan_abc123 \
  --founder-plan plan_def456 \
  --discount-threshold 5

# Use existing plans, strip all discounts
atomic-cli migrate substack \
  -i inst_abc123 \
  --stripe-key sk_live_xxx \
  --subscriber-plan plan_abc123 \
  --apply-discounts=false

# Rewrite emails for safe testing against a staging environment (no instance required)
atomic-cli migrate substack \
  --stripe-key sk_test_xxx \
  --email-domain-overwrite passport.xyz \
  --out test_migrate.csv
```

**Example `plans-1A2B3C4D.jsonl` output:**

```jsonl
{"name":"Subscriber","description":"Substack subscriber migration","type":"paid","active":true,"hidden":true,"prices":[{"name":"Monthly","currency":"usd","currency_options":{"eur":{"unit_amount":450},"gbp":{"unit_amount":400},"sek":{"unit_amount":5500}},"active":true,"amount":500,"type":"recurring","recurring":{"interval":"month","interval_count":1}},{"name":"Annual","currency":"usd","currency_options":{"eur":{"unit_amount":4500},"gbp":{"unit_amount":4000},"sek":{"unit_amount":55000}},"active":true,"amount":5000,"type":"recurring","recurring":{"interval":"year","interval_count":1}}]}
{"name":"Founder","description":"Substack founder migration","type":"paid","active":true,"hidden":true,"prices":[{"name":"Annual","currency":"usd","currency_options":{"eur":{"unit_amount":9000},"gbp":{"unit_amount":8000},"sek":{"unit_amount":100000}},"active":true,"amount":10000,"type":"recurring","recurring":{"interval":"year","interval_count":1}}]}
```

The `--email-domain-overwrite` and `--email-template` flags rewrite every email address in the output CSV so the file can be safely imported into a test environment without affecting real users. For example, with `--email-domain-overwrite passport.xyz`, `oli2p@hotmail.com` becomes `oli2p-hotmail.com@passport.xyz`. With `--email-template "sandbox+{{seq}}@inbox.mailtrap.io"`, emails become `sandbox+1@inbox.mailtrap.io`, `sandbox+2@inbox.mailtrap.io`, etc.

#### migrate map

Maps and filters any third-party CSV into the Passport `UserImportRecord` format using inline mappings or a JSON mapping file. This is useful for sources that export subscriber data as a CSV with non-standard column names (e.g., Substack's free subscriber export). Multiple target fields can map to the same source column. Rows can be filtered using an [expr](https://github.com/expr-lang/expr) expression.

```bash
atomic-cli migrate map [options]
```

**Map-specific options** (in addition to [common options](#common-options)):

| Option | Description | Default |
|------------------------|----------------------------------------------|---------|
| `--input`, `--in` | Input CSV file path | *required* |
| `--config`, `-c` | JSON mapping config file path (mutually exclusive with `--columns`) | |
| `--columns`, `--col` | Inline column mappings as `target=expression` pairs (repeatable, or semicolon-separated) | |
| `--filter` | Expression to filter rows (only matching rows are included) | |
| `--vars` | Define variables for use in expressions as `NAME=value` (repeatable) | |
| `--split-error-rows` | Route rows with non-fatal mapping errors (e.g. stripe customer not found) to a separate `<output>_errors.csv` sibling file instead of including them in the main output | `false` |
| `--map-errors` | Track soft mapping errors (stripe customer not found, etc.) in the `map_error` column and summary. Set to `false` when soft errors represent the desired outcome — e.g. using `stripe.customer_search` inside a `--filter` to select rows where the customer does NOT exist in Stripe | `true` |

Either `--config` or `--columns` is required.

**Inline columns (`--columns` / `--col`):**

Map fields directly on the command line. Each mapping is `target=expression` where `target` is a `UserImportRecord` field name and `expression` is an [expr](https://github.com/expr-lang/expr) expression. CSV column names are available as variables. A bare column name (e.g. `Email`) returns the column value directly. Use `true`/`false` for static boolean values.

```bash
# Simple column mapping
--col login=Email --col name=Name --col email_verified=true

# With expressions
--col 'login=trim(lower(Email))' --col 'name=trim(First_Name) + " " + trim(Last_Name)'

# Semicolon-separated
--col 'login=trim(lower(Email)); name=Name; email_verified=true'
```

**Custom functions:**

In addition to [expr built-in functions](https://expr-lang.org/docs/language-definition#built-in-functions), the following custom functions are available in both mapping expressions and filter expressions:

| Function | Description | Example |
|---|---|---|
| `splitTrim(s [, sep])` | Splits a string by `sep` (default: `,`), trims whitespace from each element, and removes empty entries. Returns an array. | `join(splitTrim(Sections), "\|")` → `"News\|Sports\|Opinion"` |
| `without(a, b)` | Returns elements in array `a` that are not in array `b` (set difference). | `without(splitTrim(ALL, ","), splitTrim(Sections))` → categories not in user's sections |
| `sprintf(format, args...)` | Formats a string using Go `fmt.Sprintf` syntax. | `sprintf("Substack subscriber type, %s", Type)` |
| `atoi(s)` | Parses a string into an integer; empty strings return `0`. | `atoi(Quantity) > 1` |
| `date(s [, layout [, location]])` | Parses a date/time string (overrides expr's builtin with a more flexible version). With no `layout`, auto-detects from common formats: RFC3339, `YYYY-MM-DD[ T]HH:MM[:SS[.fff]]`, `YYYY-MM-DD`, `MM/DD/YYYY[ HH:MM[:SS]]`, RFC1123/822/850, unix seconds. With an explicit `layout`, tries it first and falls back to auto-detect on mismatch. Returns `time.Time`. | `date(LastSeen)` or `date(LastSeen, "2006-01-02 15:04", "UTC")` |
| `since(unit, when)` | Whole `unit`s elapsed from `when` until now. `unit` ∈ `seconds`/`s`, `minutes`/`m`, `hours`/`h`, `days`/`d`, `months`/`M`, `years`/`y` (singular forms accepted). Short forms are case-sensitive so `M` (month) doesn't collide with `m` (minute). `when` is a `time.Time` or any RFC3339, `YYYY-MM-DD`, or unix-seconds string (column values qualify). Months/years use anniversary semantics. Negative when `when` is in the future. | `since("days", LastSeen) > 30` |
| `until(unit, when)` | Whole `unit`s from now until `when`; same units as `since`. Negative when `when` is in the past. | `until("d", TrialEnd) > 0` (trial still active) |
| `currencyForCountry(country [, fallback])` | Maps a country (Alpha-2, Alpha-3, or name; case-insensitive) to a lowercased ISO 4217 currency code. Returns the country's native currency only if it's in `atomic.LocalizedCurrencies` (`gbp, eur, cad, aud, brl, mxn, nzd, chf, dkk, nok, sek, pln`). Otherwise returns the optional `fallback` — which must itself be one of the localized currencies — or `usd` when no fallback is given. Unknown country values fall back the same way. | `currencyForCountry(Country, "eur")` → `gbp` for `"GB"`, `eur` for `"DE"`, `eur` (fallback) for `"US"`, `eur` for `"unknown"` |
| `shiftAnchorDate(date [, interval])` | Rolls a past `date` forward by whole intervals until it's in the future. Mirrors the anchor-date normalization the user-import job applies before sending to Stripe (Stripe rejects past anchor dates). `date` may be a column value, a string, or a `time.Time`. `interval` ∈ `year`/`y`, `month`/`M`, `week`/`w`, `day`/`d` (long forms case-insensitive; defaults to `month`). Future dates are returned unchanged; zero/empty dates return the zero time. | `shiftAnchorDate(Paid_upgrade_date, Interval)` |

**Variables (`--vars`):**

Define string variables for use in expressions. Useful for defining a master list to compare against per-row values.

```bash
--vars 'ALL_SECTIONS=News,Sports,Opinion,Tech' \
--col 'category_opt_out=join(without(splitTrim(ALL_SECTIONS), splitTrim(Sections)), "|")'
```

This computes the categories the user does NOT have by subtracting their `Sections` from the full list, and joins the result with pipes for `category_opt_out`.

**Filter expressions:**

The `--filter` flag accepts an [expr](https://github.com/expr-lang/expr) expression. CSV column names are available as variables (using their original header names). The expression must evaluate to a boolean. Only rows where the expression returns `true` are included in the output.

Examples:
- `'STRIPE_CUSTOMER_ID == "" && STRIPE_SUBSCRIPTION_ID == ""'` — only rows with no Stripe data (free users)
- `'STRIPE_CUSTOMER_ID != ""'` — only rows with a Stripe customer
- `'IS_GROUP_PARENT == "TRUE"'` — only group parent rows

**Config file format (`--config`):**

The config file is a JSON object with the following top-level keys:

| Key | Type | Description |
|---|---|---|
| `vars` | object | Variables available in all expressions — values can be strings or string arrays |
| `filter` | string | Global expr filter expression applied to all rows before output routing |
| `options` | object | Shared settings (see below) |
| `outputs` | array | Multiple output files with per-output filters (mutually exclusive with `--output`) |
| `columns` | object | **(required)** Column mappings — keys are target field names, values are expr expressions or static values |

**Options object:**

| Key | Type | Description |
|---|---|---|
| `append` | boolean | Append to existing output CSVs (same as `--append`) |
| `email_domain_overwrite` | string | Rewrite emails to this domain (same as `--email-domain-overwrite`) |
| `email_template` | string | Generate emails from template (same as `--email-template`) |
| `source` | string | Import source identifier (same as `--source`) |
| `limit` | integer | Limit per output file (same as `--limit`) |
| `skip` | integer | Skip first N records per output file (same as `--skip`) |
| `filter` | string | Global filter expression — same as the top-level `filter` key. Provided here for ergonomics when you put all your config under `options`. The top-level `filter` wins if both are set. |
| `map_errors` | boolean | Track soft mapping errors in the `map_error` column and summary (same as `--map-errors`). Default `true`. |
| `split_error_rows` | boolean | Route rows with soft mapping errors to a `<output>_errors.csv` sibling (same as `--split-error-rows`). Default `false`. No effect when `map_errors` is `false`. |

CLI flags override config file options when explicitly set.

**Outputs array:**

Each entry has `path` (required) and an optional `filter` expression. Rows are evaluated against each output's filter independently — a single row can match multiple outputs. When `outputs` is present, the `--output` CLI flag cannot be used.

Column values can be:

- **string** — an [expr](https://github.com/expr-lang/expr) expression; CSV column names and variables are available
- **bool/number** — a static value applied to every row
- **object `{ "filter": "<expr>", "value": "<expr or static>" }`** — conditional column. The `filter` is evaluated first; the `value` is only computed and applied when the filter is truthy. Useful for expensive lookups (like `stripe.customer_search`) that should only run for some rows.
- **array of `{filter, value}` objects** — a list of conditional alternatives. Each entry is evaluated in order; the **first** entry whose filter matches wins and its `value` is used. If no entry matches, the column is left empty. A filter of `"default"` (or an entry with no `filter`) always matches, so it can be placed at the end of the array as a fallback.

  ```json
  "subscription_plan_id": [
    { "filter": "Tier == \"vip\"",   "value": "\"plan_vip\"" },
    { "filter": "Tier == \"basic\"", "value": "\"plan_basic\"" },
    { "filter": "default",            "value": "\"plan_free\"" }
  ]
  ```

**Stripe expr functions** (require `--stripe-key` / `--sk` / `$STRIPE_API_KEY`):

- `stripe.customer_search(field, value)` — searches Stripe customers using its [search query language](https://stripe.com/docs/search#search-query-language). Returns the first matching customer's ID, or an empty string if not found. Common field values: `email`, `name`, `phone`, `metadata['key']`. Not-found rows are counted and printed at the end of the run; with `--verbose`, each missing customer is logged. Real Stripe errors (auth, network, rate limit) are fatal — see [Mapping errors](#mapping-errors-1) below.

  ```json
  "stripe_customer_id": {
    "filter": "Type != \"Free\"",
    "value": "stripe.customer_search(\"email\", Email)"
  }
  ```

  When any column expression references `stripe.*`, the CLI **fails fast** at startup if `--stripe-key` is not set, instead of erroring per-row.

**Filters and progress:**

Before processing rows, `migrate map` prints every filter currently in effect, e.g.:

```
filter (global): hasSuffix(Type, "Subscriber")
filter (output free-users.csv): Type == "Free"
filter (column stripe_customer_id): Type != "Free"
```

If the same filter expression text appears in multiple places (global / output / column), a `redundant filter` warning is logged so you can simplify your config.

The progress bar shows live counts as it scans the source CSV:

```
Mapping (mapped:5234 excluded:2317 ignored:0 errors:12)  18% |███████  | (7551/146577) [22s:6m48s]
```

| Counter | Meaning |
|---|---|
| **mapped** | rows that survived all filters and were routed to at least one output target |
| **excluded** | rows removed by the global filter |
| **ignored** | rows with no `login` value (unmappable) |
| **errors** | rows that picked up at least one non-fatal mapping error (e.g. a stripe customer not found). The error message is written to the row's `map_error` CSV column. |

The total `(N/M)` is the source row scan position; filters apply per-row inside the loop, so the bar always advances through the full source. Counts refresh every 100 rows. The bar's stripe-search warnings (when `--verbose`) are interleaved cleanly above the bar instead of overwriting it.

**Mapping errors:**

Output CSVs always include a `map_error` column. Rows that mapped cleanly leave it empty; rows that hit a soft error (like `stripe customer not found for email=foo@bar.com`) get the message written to that column so you can grep / triage later.

- **`--split-error-rows`** — when set, rows with `map_error` are routed to a separate `<output>_errors.csv` sibling file instead of mixing with the main output. With multi-output configs, each output target gets its own `_errors` sibling. The split file is written only when at least one row had an error.
- **`--map-errors=false`** — disables soft-error tracking entirely: the `map_error` column stays empty, the `errors:N` counter drops from the progress bar and summary, and the end-of-run `stripe.customer_search: N not found` line is suppressed. Use this when a soft error represents the desired outcome — for example, filtering for rows where a customer does NOT exist in Stripe:

  ```bash
  --filter 'hasSuffix(Type, "Subscriber") && stripe.customer_search("email", Email) == ""' \
  --map-errors=false
  ```

  Without `--map-errors=false`, every kept row would still carry a `stripe customer not found` message in its `map_error` column and be counted as an "error" in the summary — misleading framing when the absence is actually what you're selecting for. Combining `--map-errors=false` with `--split-error-rows` logs a warning and disables the split, since no row gets classified as errored.
- **Fatal stripe errors** — `stripe.customer_search` distinguishes "not found" (soft, captured in `map_error`) from real Stripe errors like authentication, network, or rate-limit failures. Real errors **abort the run immediately** so you don't end up with thousands of empty IDs from a misconfigured key.

Other behaviors:

- **Ctrl+C** — exits cleanly mid-scan; the row loop checks the cancellation context on each iteration.
- **Existing output files** — when `--append=false`, you'll be prompted to confirm overwrite **before** any rows are processed (including any `_errors` siblings when `--split-error-rows` is set), so you can bail without wasting any stripe lookups.

Supported target fields (matches all CSV columns on `atomic.UserImportRecord`): `created_at`, `login`, `email`, `email_verified`, `email_opt_in`, `phone_number`, `phone_number_verified`, `phone_number_opt_in`, `name`, `roles`, `metadata`, `stripe_customer_id`, `stripe_customer_metadata`, `subscription_plan_id`, `subscription_currency`, `subscription_quantity`, `subscription_interval`, `subscription_anchor_date`, `subscription_end_at`, `subscription_prorate`, `subscription_payment_method`, `discount_percentage`, `discount_term`, `discount_duration_days`, `is_team_owner`, `team_key`, `channel_opt_in`, `category_opt_out`, `import_comment`, `import_source`.

The output CSV also includes a `map_error` column (auto-populated by the mapper, not a target you'd set yourself) and audit columns `migrate_stripe_price` / `migrate_stripe_subscription` (only set by `migrate substack`).

The `created_at` field accepts RFC3339, `YYYY-MM-DD`, `YYYY-MM-DD HH:MM:SS`, or unix seconds — values are normalized to UTC. When omitted, the user is created with the timestamp at job runtime.

**Example config file with multiple outputs:**

```json
{
  "vars": {
    "ALL_SECTIONS": ["The Ankler", "Entertainment Strategy Guy", "The Wakeup", "Sports"]
  },
  "options": {
    "append": true,
    "email_template": "sandbox+{{sanitize}}@inbox.mailtrap.io"
  },
  "outputs": [
    { "path": "free-users.csv", "filter": "Type == \"Free\"" },
    { "path": "comp-users.csv", "filter": "Type == \"Comp\"" },
    { "path": "admin-users.csv", "filter": "Type == \"Author\"" }
  ],
  "columns": {
    "login": "trim(lower(Email))",
    "name": "Name",
    "category_opt_out": "join(without(ALL_SECTIONS, splitTrim(Sections)), \"|\")",
    "email_verified": true,
    "import_comment": "sprintf(\"Substack subscriber type %s\", Type)"
  }
}
```

**Example config file with single output:**

```json
{
  "vars": {
    "ALL_SECTIONS": ["The Ankler", "Sports"]
  },
  "filter": "Type != \"Comp\"",
  "columns": {
    "login": "trim(lower(Email))",
    "name": "Name",
    "category_opt_out": "join(without(ALL_SECTIONS, splitTrim(Sections)), \"|\")",
    "email_verified": true
  }
}
```



**Examples:**

```bash
# Inline mapping with filter
atomic-cli migrate map \
  --input ./substack-subscribers.csv \
  --col 'login=email; email=email; name=name; email_verified=false' \
  --filter 'STRIPE_CUSTOMER_ID == "" && STRIPE_SUBSCRIPTION_ID == ""' \
  --output ./free-users.csv

# Using a config file
atomic-cli migrate map \
  --input ./substack-subscribers.csv \
  -c ./substack-mapping.json \
  --output ./all-users.csv

# Append free users to an existing paid subscriber CSV (default: --append=true)
# Run substack migrate first, then map appends to the same file.
# Existing rows (paid subscribers) win on login conflict.
atomic-cli migrate substack \
  -i inst_abc123 \
  --stripe-key sk_test_xxx \
  --output ./merged-users.csv

atomic-cli migrate map \
  --input ./substack-free-subscribers.csv \
  --col 'login=email; email=email; name=name' \
  --filter 'STRIPE_CUSTOMER_ID == "" && STRIPE_SUBSCRIPTION_ID == ""' \
  --output ./merged-users.csv

# Map with email rewriting for test environment
atomic-cli migrate map \
  --input ./substack-subscribers.csv \
  -c ./substack-mapping.json \
  --email-domain-overwrite passport.xyz \
  --output ./free-users-test.csv
```

Rows without a `login` value after mapping are skipped. Both filtered and skipped counts are reported to stderr.

#### Global migrate post-processing

Every `migrate` subcommand (`map`, `substack`, `validate`, and anything added later) runs an automatic **validate + dedupe** pass against its written output(s) before exiting. The behavior is controlled by flags on the parent `migrate` command:

| Option | Description | Default |
|------------------------|----------------------------------------------|---------|
| `--validate` | Run per-record structural validation and uniqueness reporting on each output CSV | `true` |
| `--dedupe` | Drop or merge duplicate records in each output CSV | `true` |
| `--dedupe-columns` | Columns used to detect duplicates, repeatable; applied in order so earlier columns act as tie-breakers (valid: `login`, `email`, `phone_number`, `stripe_customer_id`) | `login` |
| `--merge` | When deduping, merge empty fields from duplicate rows into the first occurrence instead of dropping them | `true` |

For `migrate map` and `migrate substack` the pass runs in place — the same file written by the mapper is read back, deduped, and rewritten. No separate output file is produced.

For `migrate validate`, the pass runs against the positional `<input.csv>` and writes to `--output`, defaulting to `<input_basename>+deduped<ext>` (e.g., `migrate_map.csv` → `migrate_map+deduped.csv`). If `--output` resolves to the same file as the input, you will be prompted before overwriting.

Disable either phase with `--validate=false` or `--dedupe=false`. The two flags are independent — you can validate without deduping, or dedupe without emitting validation errors.

**Uniqueness checks** (used by both validation report and deduplication):

| Field | Description |
|---|---|
| `login` | Must be globally unique |
| `email` | Must be unique when present |
| `phone_number` | Must be unique when present |
| `stripe_customer_id` | Must be unique when present |

**Multi-column dedupe:** each column in `--dedupe-columns` is collapsed in order. After the `login` pass, surviving records feed into the `email` pass, and so on. This means the first column is the authoritative tie-breaker — two rows with the same `login` collapse before either can conflict on `email`.

**Merge semantics** (when `--merge=true`):

- First occurrence is retained; later duplicates are merged into it.
- Empty/nil fields on the first row get filled from the duplicate. The first row wins on any conflict.
- `roles`, `metadata`, and `stripe_customer_metadata` are unioned rather than overwritten.
- With `--merge=false`, later duplicates are dropped outright without merging.

#### migrate validate

Explicit entry point for the validate + dedupe pass — useful when you want to run it against a CSV that wasn't produced by a migrate subcommand.

```bash
atomic-cli migrate validate <input.csv> [options]
```

Accepts the parent migrate flags above (`--validate`, `--dedupe`, `--dedupe-columns`, `--merge`) plus the common migrate flags (`--output`, `--verbose`, etc.).

**Examples:**

```bash
# Validate only — report summary, no output file
atomic-cli migrate validate ./merged-users.csv --dedupe=false

# Default behavior: validate + dedupe by login → ./merged-users+deduped.csv
atomic-cli migrate validate ./merged-users.csv

# Dedupe by login AND stripe_customer_id (login wins as tie-breaker)
atomic-cli migrate validate ./merged-users.csv \
  --dedupe-columns login --dedupe-columns stripe_customer_id

# Drop duplicates without merging
atomic-cli migrate validate ./merged-users.csv --merge=false

# Deduplicate in place (prompts before overwriting)
atomic-cli migrate validate ./merged-users.csv \
  --output ./merged-users.csv
```

**Example output (default — no `--verbose`):**

```
loaded 1500 records from ./merged-users.csv

total rows: 1500
validation errors: 2
  email: 1
  login: 1
duplicate errors: 2
  login: 1
  stripe_customer_id: 1
deduplicated on login: 2 duplicates, 1 merged (3 fields filled), 1 dropped, 1498 remaining → ./merged-users+deduped.csv
```

**Example output (with `--verbose`):**

```
loaded 1500 records from ./merged-users.csv

  row 42 [bob@example.com] (validation): email: must be a valid email address.
  row 99 [] (validation): login: cannot be blank.
  row 315 [alice@example.com] login="alice@example.com": duplicate login (first seen at row 12)
  row 780 [] stripe_customer_id="cus_ABC123": duplicate stripe_customer_id (first seen at row 200)

total rows: 1500
validation errors: 2
  email: 1
  login: 1
duplicate errors: 2
  login: 1
  stripe_customer_id: 1

dedupe actions:
  row 315 → row 12: filled [name, phone_number, stripe_customer_id]
  row 780 → row 200: dropped (no fields to merge)
deduplicated on login: 2 duplicates, 1 merged (3 fields filled), 1 dropped, 1498 remaining → ./merged-users+deduped.csv
```

### Stripe Management

Manage Stripe data with the `stripe` command. All subcommands require a Stripe API key.

**Parent options:**

| Option | Alias | Description | Default |
|------------------------|-------|----------------------------------------------|---------|
| `--stripe-key` | `-k` | Stripe API key (or `$STRIPE_API_KEY`) | *required* |
| `--live-mode` | `--livemode` | Allow live stripe keys; without this flag only test keys are accepted | `false` |

#### Export

Export Stripe data to JSONL files for backup. Creates a `stripe-export-<account_id>` folder containing one `.jsonl` file per object type and a `manifest.json` with account info and record counts.

```bash
atomic-cli stripe export [options]
```

**Options:**

| Option | Alias | Description | Default |
|------------------------------|-------|----------------------------------------------|---------|
| `--output` | `-o` | Output directory (the export folder is created inside) | `.` |
| `--types` | `-t` | Object types to export (repeatable) | `all` |
| `--clean` | | Clear existing export data and start fresh | `false` |
| `--active-only` | | Only export active products, prices, and promotion codes | `false` |
| `--terminated-subscriptions` | | Include terminated subscriptions (canceled, unpaid, incomplete_expired) | `false` |
| `--past-due-subscriptions` | | Include past_due subscriptions in the export | `false` |
| `--email-domain-overwrite` | | Rewrite all customer email addresses to this domain; mutually exclusive with `--email-template` | |
| `--email-template` | | Generate customer email addresses from a template (see [Email Template Functions](#email-template-functions)); mutually exclusive with `--email-domain-overwrite` | |

When email rewriting is enabled, all email addresses on customer records are rewritten — including the top-level email, billing details on the default payment method, and any nested customer back-references. This ensures no real email addresses leak into test/sandbox environments.

**Supported types:** `products`, `prices`, `customers`, `subscriptions`, `coupons`, `promotion-codes`, `all`

**Expanded fields by type:**

| Type | Expansions |
|-------------------|----------------------------------------------|
| Prices | `currency_options`, `tiers` |
| Customers | `default_source`, `discount`, `invoice_settings.default_payment_method`, `tax` |
| Subscriptions | `default_payment_method`, `default_source`, `discount`, `discounts`, `items.data.price`, `items.data.discounts` |

Subscriptions are exported across statuses: active, trialing, and paused. With `--past-due-subscriptions`, past_due subscriptions are also included. With `--terminated-subscriptions`, canceled, unpaid, incomplete, and incomplete_expired subscriptions are also included.

**`--clean` confirmation:** Using `--clean` prompts for confirmation before deleting existing export data.

**Concurrency and rate limiting:** Customers and subscriptions are exported concurrently for performance, while smaller types (products, prices, coupons, promotion codes) are exported sequentially first. API requests are rate-limited to stay within Stripe's limits (40 req/s for live keys, 10 req/s for test keys) using a shared token-bucket limiter across all concurrent goroutines.

**Graceful shutdown:** The CLI handles interrupt signals (Ctrl+C, SIGTERM) globally. Exports check for cancellation between types and within the Stripe API iterator, so in-progress work is flushed cleanly before exit.

**Periodic flushing:** For customers and subscriptions, progress is saved to disk every 200 records. Both the JSONL file and manifest are flushed, so if the export is interrupted (Ctrl+C, crash, etc.), re-running the command continues from where it left off rather than re-exporting from scratch.

**Resume/sync behavior:** Resume tracking is per-object-type. On startup, the export prints a resume status summary:

```
resume status:
  customers           continuing from 2026-03-15T10:30:00Z (5234 records exported)
  subscriptions       incremental sync (12456 records)
  products            fresh export
```

Each type follows one of three strategies:

- **Fresh export** — no previous data exists (or `--clean` was used). Full export from the API.
- **Incremental sync** — previous export completed successfully. Only fetches records created since the last export (`created.gte`), then merges into existing files by object ID (last-write-wins).
- **Continue** — previous export was interrupted. Picks up where it left off using the oldest record's timestamp (`created.lt`), appending new records and skipping duplicates. If the JSONL file has a truncated last record (from an interrupted write), it is automatically repaired on resume.

Files are written atomically via temp file + rename for completed types, so interrupted exports never leave corrupt data. On resume, MD5 checksums are verified for completed types — tampered or corrupt files are re-exported from scratch. Use `--clean` to clear existing data and start fresh.

**manifest.json** includes:
- `version` — manifest format version (`"3"`)
- `created_at` — first export timestamp (RFC 3339)
- `updated_at` — most recent sync timestamp
- `account_id` — Stripe account ID (verified on resume; mismatches are rejected)
- `account_name` — dashboard display name
- `livemode` — whether the export used a live key
- `types` — list of exported object types
- `files` — map of type to `{filename, count, md5, exported_at, complete, oldest_created}`
  - `complete` — whether the export for this type finished successfully
  - `oldest_created` — Unix timestamp of the oldest record exported (used for resume)

**Examples:**

```bash
# Export everything (test key)
atomic-cli stripe export -k sk_test_xxx

# Export with a live key (must explicitly opt in)
atomic-cli stripe export -k sk_live_xxx --live-mode

# Export specific types to a custom directory
atomic-cli stripe export -k sk_live_xxx --live-mode -t products -t prices -o /backups

# Re-run to incrementally sync new records
atomic-cli stripe export -k sk_test_xxx

# Export only active products, prices, and promotion codes
atomic-cli stripe export -k sk_test_xxx --active-only

# Include terminated subscriptions
atomic-cli stripe export -k sk_test_xxx --terminated-subscriptions

# Clear existing data and start fresh
atomic-cli stripe export -k sk_test_xxx --clean

# Using environment variable
STRIPE_API_KEY=sk_live_xxx atomic-cli stripe export
```

#### Import

Import Stripe data from an export directory into a target Stripe account. Reads the `manifest.json` and JSONL files produced by `stripe export` and recreates objects in dependency order: products, prices, coupons, promotion codes, customers, then subscriptions.

Products are imported with their original IDs preserved. If a product already exists in the target account (e.g. after a `--clean` re-import), the import automatically falls back to updating the existing product instead of failing.

**Import metadata:**

All imported objects receive Stripe metadata fields for traceability back to the source account:

| Object | Metadata Key | Value |
|-----------------|--------------------------------------|----------------------------------------------|
| All | `atomic:import:time` | RFC 3339 timestamp of the import run |
| Products | `atomic:import:product_id` | Original product ID from the source account |
| Prices | `atomic:import:price_id` | Original price ID |
| Coupons | `atomic:import:coupon_id` | Original coupon ID |
| Promotion Codes | `atomic:import:promotion_code_id` | Original promotion code ID |
| Customers | `atomic:import:customer_id` | Original customer ID |
| Customers | `atomic:import:customer_email` | Original email (only when `--email-domain-overwrite` or `--email-template` is set) |
| Subscriptions | `atomic:import:subscription_id` | Original subscription ID |

```bash
atomic-cli stripe import --input <export-directory> [options]
```

**Options:**

| Option                          | Description                                                              | Default       |
|---------------------------------|--------------------------------------------------------------------------|---------------|
| `--input`, `-i`                 | Path to the export directory (containing manifest.json)                  | *required*    |
| `--types`, `-t`                 | Object types to import (repeatable, or "all")                            | `all`         |
| `--validate`                    | Validate export data before importing (referential integrity, required fields) | `true`   |
| `--dry-run`                     | Report what would be imported without making any changes                 | `false`       |
| `--email-domain-overwrite`      | Rewrite all customer email addresses with this domain                    |               |
| `--email-template`              | Generate customer email addresses from a template                        |               |
| `--application-fees`            | Retain application fees from exported subscriptions (requires Connect platform) | `true`  |
| `--application-fee-percent`     | Override application fee % for all subscriptions (requires Connect platform) |            |
| `--on-behalf-of`                | Connected account ID for subscriptions                                   |               |
| `--create-test-cards`           | Attach test payment methods to customers (test mode only)                | `true`        |
| `--default-test-card`           | Override the auto-detected test card for all customers                   | `pm_card_us`  |
| `--prorate-subscriptions`       | Prorate subscriptions on creation                                        | `false`       |
| `--drop-expired-trials`         | Shift expired trials forward with the same duration instead of converting to active | `true` |
| `--past-due-subscriptions`      | Import past_due subscriptions (attaches a declining test card to trigger past_due status) | `false` |
| `--limit`                       | Limit the number of new customers imported; subscriptions are limited to imported customers; 0 = no limit | `0` |
| `--abort-on-error`              | Stop the entire import on the first failure                              | `false`       |
| `--ignore-sandbox-email-warning`| Skip the email rewriting requirement when importing live data into test  | `false`       |
| `--workers`                     | Number of concurrent workers for customer and subscription imports       | 2× CPU count  |
| `--clean`                       | Clear import state and start a fresh import                              | `false`       |
| `--update-existing`             | Update previously imported objects whose source data has changed (by SHA-256) | `true`   |

**Import behavior:**

- **Validation** (`--validate`, default on): Checks all JSONL files for structural integrity before importing — verifies required fields, referential integrity (prices reference valid products, promotion codes reference valid coupons, etc.). Also verifies that all requested export types completed successfully (rejects incomplete exports). Aborts if errors are found.
- **Dry run** (`--dry-run`): Reports target account info, source account, which types would be imported with record counts, and configuration details — without making any API calls.
- **Live mode**: Prompts the user to type `confirm livemode import` before proceeding. Subscriptions are skipped because customers have no payment methods.
- **Sandbox email safety**: When importing live-mode export data into a test account, `--email-domain-overwrite` or `--email-template` is required to prevent Stripe from sending emails to real customers. Use `--ignore-sandbox-email-warning` to bypass this check (prompts for confirmation).
- **Test mode + `--create-test-cards`** (default): Attaches test payment methods based on customer currency, sets as default for invoices, then creates subscriptions with those payment methods.
- **Test mode + `--create-test-cards=false`**: Skips subscriptions with a warning.
- **Connect platform accounts**: Detected automatically via the Stripe account's `controller.type` (`application`). Application fees from exported subscriptions are retained by default (`--application-fees`). Use `--application-fees=false` to ignore fees entirely, or `--application-fee-percent` to override all fees with a fixed percentage.
- **Proration**: Disabled by default (`--prorate-subscriptions=false`). Enable to prorate subscription charges on creation.
- **Limit** (`--limit`): Import only N new customers and their subscriptions. Already-imported customers (from prior runs) are skipped and don't count against the limit. Subscriptions are only imported for customers present in the ID map, so subs for non-imported customers are skipped. Run again with `--limit` to import the next batch, or without `--limit` to import everything remaining.
- **Errors**: By default, failures on individual records are logged as warnings and the import continues. Use `--abort-on-error` to stop on the first failure.
- **Error propagation**: Errors in upstream types automatically abort dependent downstream types. Product errors abort price import; price errors abort subscription import; coupon errors abort promotion code import; customer errors abort subscription import. This prevents cascading failures.
- **ID map fallback**: When a referenced object (product, coupon, customer, price) is not found in the import ID map — e.g. after a `--clean` re-import — the import uses the original source ID as a fallback instead of skipping the record. This allows re-imports to succeed when objects already exist in the target account.
- **Rate limit retry**: Customer and subscription creates automatically retry on Stripe 429 (rate limit) errors with exponential backoff (1s, 2s, 4s, 8s, 16s) up to 5 attempts. Retries are silent — no warnings are logged unless all attempts are exhausted.
- **Billing dates**: All subscriptions are backdated to their original creation date (`backdate_start_date` = `sub.created`) and `billing_cycle_anchor` is set to the source's `current_period_end` so that period dates and next invoice match the export exactly. With `proration_behavior: none` (default), no charges are generated for the backdated period.
- **Subscription statuses**: Only `active` and `trialing` subscriptions are imported by default. With `--past-due-subscriptions`, past_due subscriptions are also imported — a declining test card (`pm_card_visa_chargeDeclined`) is attached to the customer and used as the subscription's payment method with `payment_behavior: allow_incomplete`, causing the first invoice to fail and Stripe to transition the subscription to `past_due`. Other statuses (`canceled`, `unpaid`, `paused`, `incomplete`, `incomplete_expired`) are skipped with counts logged at the end.
- **Trials**: Active trials with a future `trial_end` are preserved. Expired trials (status is `trialing` but `trial_end` is in the past) are shifted forward by default (`--drop-expired-trials`): a new trial is created with the same duration as the original, starting from now. Set `--drop-expired-trials=false` to convert them to active subscriptions instead. Both shifted and converted trial counts are logged.
- **Cancellation**: Subscriptions with `cancel_at_period_end` preserve that flag. Subscriptions with a future `cancel_at` preserve the cancellation date. Subscriptions with `cancel_at` in the past are skipped.
- **Concurrency**: Customer and subscription imports use multiple concurrent workers (default: 2× CPU count, configurable via `--workers`). API requests are rate-limited to stay within Stripe's limits (10 req/s test, 40 req/s live). Imports run sequentially in dependency order (products → prices → coupons → promotion codes → customers → subscriptions), but within each type the individual record creates are parallelized.
- **Import state**: Persisted in the export directory alongside `manifest.json`. Consists of two parts:
  - `import-state.json` — lightweight metadata: per-type completion status, source MD5 checksums, record counts, and error counts.
  - `<type>.map.db` files — [bbolt](https://github.com/etcd-io/bbolt) key-value databases storing old ID → new ID mappings and SHA-256 hashes for each type. These are memory-mapped, so lookups are fast without loading entire maps into memory. This keeps import state efficient even for large datasets (tens of thousands of customers/subscriptions). On interrupt, all open databases are synced before exit to prevent data loss.
- **Smart skip**: Types whose source JSONL file hasn't changed (MD5 match) since the last completed import are skipped entirely. This makes re-running import after a successful run nearly instant.
- **Graceful shutdown**: The CLI handles interrupt signals (Ctrl+C, SIGTERM) globally. On interrupt, the import stops accepting new records, waits for in-flight API calls to complete, syncs all bbolt ID map databases, and exits cleanly. This ensures no data is lost on interruption.
- **Resume**: If an import is interrupted, re-running the command continues from where it left off. Already-created objects are skipped via the persisted bbolt ID maps. For customers and subscriptions, the database is synced every 200 records.
- **Progress**: Each import type shows a progress bar with record count and throughput (rec/s).
- **Change detection**: Each imported record's SHA-256 hash is stored alongside its ID mapping. On re-import, records whose hash hasn't changed are skipped automatically — no unnecessary API calls. With `--update-existing` (default), records that have changed are updated via the Stripe Update API: products and customers are fully updated, prices and coupons update metadata/active status (immutable fields like amount are unchanged), and subscriptions are always skipped (too complex to diff safely). With `--update-existing=false`, changed records are skipped entirely (only new records are created).
- **`--clean`**: Prompts for confirmation, then clears `import-state.json` and all `.map.db` files, forcing a full re-import. Objects that already exist in the target account are handled gracefully — products fall back to update on `resource_already_exists`, and cross-references (prices→products, subscriptions→customers/prices, etc.) fall back to original IDs when not found in the import map. Note: `stripe export --clean` also clears the import state automatically.

**Test card mapping (currency → payment method):**

All test cards are non-3D-Secure Visa cards from [Stripe's testing documentation](https://docs.stripe.com/testing?testing-method=payment-methods#visa).

| Currency | Test Card      | Country       |
|----------|----------------|---------------|
| USD      | `pm_card_us`   | United States |
| GBP      | `pm_card_gb`   | United Kingdom |
| EUR      | `pm_card_de`   | Germany       |
| CAD      | `pm_card_ca`   | Canada        |
| AUD      | `pm_card_au`   | Australia     |
| JPY      | `pm_card_jp`   | Japan         |
| SGD      | `pm_card_sg`   | Singapore     |
| HKD      | `pm_card_hk`   | Hong Kong     |
| NZD      | `pm_card_nz`   | New Zealand   |
| CHF      | `pm_card_ch`   | Switzerland   |
| BRL      | `pm_card_br`   | Brazil        |
| MXN      | `pm_card_mx`   | Mexico        |
| INR      | `pm_card_in`   | India         |
| SEK      | `pm_card_se`   | Sweden        |
| NOK      | `pm_card_no`   | Norway        |
| DKK      | `pm_card_dk`   | Denmark       |
| PLN      | `pm_card_pl`   | Poland        |
| CZK      | `pm_card_cz`   | Czech Republic |
| RON      | `pm_card_ro`   | Romania       |
| BGN      | `pm_card_bg`   | Bulgaria      |
| HUF      | `pm_card_hu`   | Hungary       |
| THB      | `pm_card_th`   | Thailand      |
| MYR      | `pm_card_my`   | Malaysia      |

Use `--default-test-card` to override all currency lookups with a specific test card.

**Examples:**

```bash
# Dry run — see what would be imported
atomic-cli stripe import -k sk_test_xxx --input stripe-export-1234 --dry-run

# Import everything into a test account
atomic-cli stripe import -k sk_test_xxx --input stripe-export-1234

# Import with email rewriting for sandbox
atomic-cli stripe import -k sk_test_xxx --input stripe-export-1234 \
  --email-template "sandbox+{{seq "user"}}@inbox.mailtrap.io"

# Import with Connect application fees
atomic-cli stripe import -k sk_test_xxx --input stripe-export-1234 \
  --application-fee-percent 10

# Import without subscriptions (just products, prices, customers)
atomic-cli stripe import -k sk_test_xxx --input stripe-export-1234 \
  --create-test-cards=false

# Import with proration enabled
atomic-cli stripe import -k sk_test_xxx --input stripe-export-1234 \
  --prorate-subscriptions

# Import including past_due subscriptions
atomic-cli stripe import -k sk_test_xxx --input stripe-export-1234 \
  --past-due-subscriptions

# Import just 10 customers and their subscriptions for testing
atomic-cli stripe import -k sk_test_xxx --input stripe-export-1234 --limit 10

# Skip validation (if you know the data is clean)
atomic-cli stripe import -k sk_test_xxx --input stripe-export-1234 --validate=false

# Import into live account (requires confirmation prompt)
atomic-cli stripe import -k sk_live_xxx --live-mode --input stripe-export-1234
```

#### Connect

Connect a Stripe account to your platform via Stripe Connect OAuth. This is essential for creating sandbox environments with production-like data — you connect a test Stripe account to your platform's test Connect account, then use the returned secret key with `stripe export` and a future `stripe import` to replicate production subscriptions, customers, products, and pricing in a fully functional sandbox.

**Why this matters:** When preparing for migrations or testing billing changes, you need a sandbox that mirrors production as closely as possible. Simply cloning data isn't enough — Stripe subscriptions, payment methods, and billing relationships must be structurally correct within Stripe itself. By connecting a test account via Connect and importing exported production data into it, you get a working sandbox where subscriptions actually bill, webhooks fire, and the full payment flow behaves like production.

```bash
atomic-cli stripe connect --client-id <stripe_connect_client_id> [options]
```

**Options:**

| Option | Alias | Description | Default |
|------------------------|-------|----------------------------------------------|---------|
| `--client-id` | | Stripe Connect client ID (or `$STRIPE_CLIENT_ID`) | *required* |
| `--output` | `-o` | Directory to save the credentials file | `.` |
| `--ngrok` | | Use ngrok to create a public tunnel for the OAuth callback | `false` |
| `--ngrok-authtoken` | | ngrok auth token (overrides config file and `$NGROK_AUTHTOKEN`) | |
| `--ngrok-config` | | Path to ngrok config file | `~/.ngrok2/ngrok.yml` |

**How it works:**

1. Starts a listener — either an ngrok tunnel (with `--ngrok`) or a local port (default, you handle proxying)
2. Reminds you to add the callback URI to your Stripe Dashboard under Connect > Settings > Redirects
3. Prints the Stripe Connect authorize URL to open in your browser
4. You log in to the target Stripe account and authorize the connection
5. The CLI receives the OAuth callback, exchanges the authorization code for access tokens
6. Fetches the connected account details and displays the credentials
7. Saves credentials to `stripe-connect-<account_id>.json` (permissions `0600`)

The `--stripe-key` from the parent command is your platform's secret key. The returned `secret_key` in the output is an access token that lets your platform make API calls on behalf of the connected account.

**Typical sandbox workflow:**

```bash
# 1. Export production data (live mode)
atomic-cli stripe export -k sk_live_xxx --live-mode

# 2. Connect a test account to your platform's test Connect account
atomic-cli stripe connect -k sk_test_platform_xxx --client-id ca_xxx --ngrok

# 3. Use the returned secret_key to import data into the connected test account
#    (stripe import command — coming soon)
#    The imported subscriptions, products, and prices will be fully functional
#    in the connected test account, mirroring your production structure.
```

**Output:** Credentials are printed in the configured `--out-format` (table, json, json-pretty) and saved as JSON:

| Field | Description |
|-------------------|----------------------------------------------|
| `account_id` | The connected Stripe account ID |
| `account_name` | Dashboard display name |
| `livemode` | Whether this is a live or test connection |
| `publishable_key` | Publishable key for client-side usage |
| `secret_key` | Access token — use this as the API key for the connected account |
| `refresh_token` | For refreshing the token later |
| `scope` | Permissions granted (`read_write`) |

**Examples:**

```bash
# Connect a test account with ngrok (reads authtoken from ~/.ngrok2/ngrok.yml)
atomic-cli stripe connect -k sk_test_xxx --client-id ca_xxx --ngrok

# Connect a live account with ngrok
atomic-cli stripe connect -k sk_live_xxx --live-mode --client-id ca_xxx --ngrok

# Without ngrok (listen on random local port, you handle proxying)
atomic-cli stripe connect -k sk_test_xxx --client-id ca_xxx

# Explicit ngrok authtoken
atomic-cli stripe connect -k sk_test_xxx --client-id ca_xxx --ngrok-authtoken xxx

# Save credentials to a specific directory
atomic-cli stripe connect -k sk_test_xxx --client-id ca_xxx --ngrok -o /credentials

# Using environment variables
STRIPE_API_KEY=sk_test_xxx STRIPE_CLIENT_ID=ca_xxx \
  atomic-cli stripe connect --ngrok
```

#### Webhook

Listen for Stripe webhook events in real time with an interactive terminal UI. Events are logged to a JSONL file and displayed in a live table with navigation, pause, and JSON detail viewing.

```bash
atomic-cli stripe webhook [options]
```

**Options:**

| Option | Alias | Description | Default |
|---------------------|-------|----------------------------------------------|---------|
| `--output` | `-o` | Directory for the events JSONL file | `.` |
| `--events` | `-e` | Event types to listen for (repeatable) | `atomic.StripeEvents` |
| `--display-events` | | Number of recent events to display in the table | `20` |
| `--log-only` | | Log events without the interactive UI | `false` |
| `--view-only` | | Browse existing events file without starting a listener | `false` |
| `--connect` | | Receive events from connected accounts (requires a platform key) | `false` |
| `--ngrok` | | Use ngrok to create a public tunnel | `false` |
| `--ngrok-authtoken` | | ngrok auth token (overrides config and `$NGROK_AUTHTOKEN`) | |
| `--ngrok-config` | | Path to ngrok config file | `~/.ngrok2/ngrok.yml` |

**Modes:**

- **Default (TUI + listener)**: Starts a webhook listener and displays events in an interactive side-by-side view — event table on the left, YAML detail on the right.
- **`--log-only`**: Starts the webhook listener but skips the TUI. Prints only the webhook URL and log file path (one per line), then silently appends events to the JSONL file. Useful for CI, scripts, or background processes. Press Ctrl+C to stop.
- **`--view-only`**: Opens the interactive TUI to browse an existing events JSONL file without starting a listener or registering a webhook. Useful for reviewing events after the fact.

**Behavior:**

- **With `--ngrok`**: Creates an ngrok tunnel, registers a Stripe webhook endpoint automatically with the tunnel URL, and starts listening. The webhook endpoint is cleaned up on exit.
- **With `--connect`**: Sets `connect: true` on the webhook endpoint so it receives events from connected accounts. Requires a **platform account key** (not a connected account key). The endpoint will appear under the platform account's dashboard.
- **Without `--ngrok`**: Listens on a random local port and prints instructions for how to proxy the local URL and register it in the Stripe Dashboard manually.
- **Event logging**: All received events are appended to `events-<account_id>.jsonl` (without the `acct_` prefix). Delete the file to start fresh.
- **Default events**: When `--events` is not specified, listens for the standard `atomic.StripeEvents` set: subscription lifecycle, payment methods, payment intents, invoices, charges, and credit notes.

**Interactive TUI:**

The TUI displays a side-by-side layout: an event table on the left (timestamp, event type, and optionally customer/subscription IDs on wide terminals) and a scrollable YAML detail view on the right showing the full event for the selected row.

| Key | Action |
|------------|----------------------------------------------|
| `↑` / `↓` | Navigate up/down in the event table |
| `Tab` | Switch focus between table and detail panel |
| `p` | Pause/unpause live updates |
| `c` | Show/hide connection info popup |
| `q` | Quit |

When paused, new events are still logged to the JSONL file but the table display freezes so you can inspect events without them scrolling away.

**Examples:**

```bash
# Listen with ngrok (auto-registers webhook endpoint)
atomic-cli stripe webhook -k sk_test_xxx --ngrok

# Listen for events from connected accounts (use platform key)
atomic-cli stripe webhook -k sk_test_PLATFORM_KEY --ngrok --connect

# Log-only mode (no TUI, just print events to stderr)
atomic-cli stripe webhook -k sk_test_xxx --ngrok --log-only

# Browse existing events file
atomic-cli stripe webhook -k sk_test_xxx --view-only

# Listen with specific events
atomic-cli stripe webhook -k sk_test_xxx --ngrok -e customer.subscription.created -e invoice.payment_succeeded

# Show more events in the table
atomic-cli stripe webhook -k sk_test_xxx --ngrok --display-events 50

# Without ngrok (manual proxy setup)
atomic-cli stripe webhook -k sk_test_xxx
```

#### Repair

Recreate missing Stripe objects (products, prices, coupons) from Passport data. This is useful after importing plans, prices, and credits from a remote Passport instance — the Passport records exist but the corresponding Stripe objects do not. The command checks each item against Stripe, creates any missing objects, and updates the Passport records with the new Stripe IDs.

**Test mode only** — only works with `sk_test_` or `rk_test_` keys.

```bash
atomic-cli stripe repair [options]
```

**Options:**

| Option | Alias | Description | Default |
|-------------|-------|------------------------------------------------------|---------|
| `--types` | `-t` | Types to repair: `plans`, `prices`, `credits`, `all` | `all` |
| `--dry-run` | | Preview what would be repaired without making changes | `false` |

**What gets repaired:**

| Type | Passport Field | Stripe Object | Notes |
|---------|----------------------|----------------|-------|
| Plans | `stripe_product` | Product | Created with ID `atomic_{plan_uuid}`. Only paid plans. |
| Prices | `stripe_price` | Price | Includes tiered/volume pricing and currency options. Requires the plan's Stripe product to exist. |
| Credits | `stripe_coupon` | Coupon | Aggregate coupons (`owner_id` is null) and volume discount credits. |

For each item, the command:
1. Checks if the existing Stripe ID (if any) resolves to a real Stripe object
2. If missing, creates a new Stripe object with the Passport data
3. Updates the Passport record with the new Stripe ID

**Examples:**

```bash
# Preview what would be repaired
atomic-cli stripe repair -k sk_test_xxx -i inst_abc --dry-run --verbose

# Repair everything
atomic-cli stripe repair -k sk_test_xxx -i inst_abc --verbose

# Repair only prices
atomic-cli stripe repair -k sk_test_xxx -i inst_abc -t prices

# Repair only credits (coupons)
atomic-cli stripe repair -k sk_test_xxx -i inst_abc -t credits --verbose
```

#### Customer

`stripe customer` (aliases: `customers`, `cust`) groups commands that operate on individual Stripe customers.

##### Cleanup

Delete disconnected Stripe customers that were created in error: customers with no associated Passport user, only atomic-imported subscriptions, and no payment methods anywhere on the customer or its subscriptions. Use this to clean up orphaned Stripe records left behind by aborted or partial imports.

```bash
atomic-cli -i <instance_id> stripe customer cleanup [options] <input.csv>
```

The CSV must include a column with Stripe customer IDs. By default the column is named `id`; use `--stripe_customer_id_col` to point at a different column. Other columns are ignored, so the same CSV can carry email/name/etc.

**Options:**

| Option                       | Description                                                                                  | Default |
|------------------------------|----------------------------------------------------------------------------------------------|---------|
| `--stripe_customer_id_col`   | Name of the CSV column containing the Stripe customer id                                     | `id`    |
| `--dry-run`                  | Preview what would be deleted without making changes (every check still runs; only the delete API call is skipped) | `false` |
| `--skip`                     | Skip the first N customer ids in the input CSV; `0` = no skip                                | `0`     |
| `--limit`                    | Limit the number of customer ids processed (applied after `--skip`); `0` = no limit          | `0`     |

`--instance_id` (the global atomic-cli flag) is required so the Passport user lookup is scoped to the right instance.

**Eligibility — a customer is deleted only when ALL of the following hold:**

1. No Passport user references the customer (`UserList` with `stripe_customer=<id>` returns nothing).
2. The customer has no `default_source`.
3. The customer has no `invoice_settings.default_payment_method`.
4. Every non-canceled / non-incomplete-expired subscription on the customer:
   - has `metadata["atomic:import"] = "true"`, AND
   - has no `default_payment_method`, AND
   - has no `default_source`.
5. At least one such atomic-imported subscription exists (a customer with no qualifying subs is skipped, never deleted).

If any check fails, the customer is **skipped** (with the reason printed in `--verbose` mode).

**Outcomes per row:** `deleted` (or `would-delete` under `--dry-run`), `skipped`, `not found` (Stripe returned 404 for the customer), `errors`. The progress bar shows running counts in its description, e.g.:

```
Cleaning up customers [would-delete=14 skipped=2 not-found=0 errors=0]   1% | ... | (16/1079)
```

A final summary line is always printed:

```
customers: 14 deleted, 2 skipped, 0 not found, 0 errors
```

With `--verbose`, every row prints its outcome (and skip reason) above the live progress bar.

**Examples:**

```bash
# Preview using a CSV whose id column is named "id" (the default)
atomic-cli -i inst_abc stripe customer cleanup -k sk_test_xxx --dry-run active_no_payment.csv

# Verbose preview to inspect why each customer would be deleted or skipped
atomic-cli -i inst_abc -v stripe customer cleanup -k sk_test_xxx --dry-run active_no_payment.csv

# Use a CSV whose id lives in a different column
atomic-cli -i inst_abc stripe customer cleanup -k sk_test_xxx \
  --stripe_customer_id_col=stripe_customer_id customers.csv

# Live mode (real deletes against a live Stripe account)
atomic-cli -i inst_abc stripe customer cleanup -k sk_live_xxx --live-mode active_no_payment.csv
```

#### Invoice

```
atomic-cli stripe invoice [list|get] [options]
```

`stripe invoice list` walks `stripe.invoices.list` and emits a row per match. Defaults to `--status=open` so the typical use case — "find unpaid invoices, including those tied to canceled subscriptions" — works with no flags. The `--subscription` filter still works for canceled subs (Stripe keeps the link).

| Flag | Description | Default |
|---|---|---|
| `--status <s>` | Stripe invoice status (`draft`, `open`, `paid`, `void`, `uncollectible`). | `open` |
| `--past-due` | Only invoices whose `due_date` is in the past. Forces `--status=open`. Note: `due_date` is null on `charge_automatically` invoices, so use `--collection-disabled` / `--failed` for those. | `false` |
| `--failed` | Only invoices whose latest payment attempt actually failed (`attempted=true`, `attempt_count >= 1`, plus a real failure code on the `payment_intent.last_payment_error` or `charge.failure_code`). Implies `--attempts 1`. | `false` |
| `--collection-disabled` | Only invoices with no `next_payment_attempt` scheduled (Stripe gave up retrying). | `false` |
| `--attempts <N>` | Keep only invoices whose `attempt_count >= N`. | `0` |
| `--customer <id>` | Filter to a single customer. | |
| `--subscription <id>` | Filter to a single subscription (works for canceled subs too). | |
| `--collection-method <m>` | `charge_automatically` or `send_invoice`. | |
| `--created '>= now-30d'` | Server-side range filter on `invoice.created`. Repeatable to set both bounds. Same expression grammar as `migrate substack --created`. | |
| `--due '< 2025-01-01'` | Server-side range filter on `invoice.due_date` (excludes invoices with no due_date). | |
| `--created-before <T>` / `--created-after <T>` | Shorthand for `--created '< T'` / `--created '>= T'`. | |
| `--due-before <T>` / `--due-after <T>` | Same shorthand for `--due`. | |
| `--limit <N>` | Stop after N matching invoices (client-side). `0` = no limit. | `0` |
| `--out <path>` | Write rows to a file. Format picked from extension: `.csv`, `.json`, `.jsonl`/`.ndjson`. | _(stdout)_ |

Time arguments accept RFC3339, `YYYY-MM-DD`, unix seconds, or `now+/-<duration>` (`now-30d`, `now+1h`).

Output columns include the request fields plus collection metadata: `attempted`, `attempt_count`, `next_payment_attempt`, `failure_code`, `failure_decline_code`, `failure_message`. The `failure_*` fields prefer `PaymentIntent.LastPaymentError` (modern flow) and fall back to `Charge.FailureCode` / `Charge.FailureMessage` (legacy invoices).

A live spinner on stderr shows scanned/kept counts during iteration; `-v` logs each kept invoice's id/status/amount/failure to stderr too. Both go to stderr so they don't pollute `-o jsonl` output.

```bash
# every unpaid invoice (incl. those on canceled subs)
atomic-cli -i inst stripe invoice list -k sk_xxx

# invoices stripe has given up on, written to CSV
atomic-cli -i inst stripe invoice list -k sk_xxx --failed -O failed.csv

# overdue invoices for one customer in the last 90 days
atomic-cli -i inst stripe invoice list -k sk_xxx --past-due \
  --customer cus_X --created-after now-90d

# filter to a known sub even if it's canceled
atomic-cli -i inst stripe invoice list -k sk_xxx --subscription sub_X
```

`stripe invoice get <invoice_id>` fetches one invoice and prints the full Stripe object as pretty JSON (subscription + customer expanded). The output bypasses the table renderer because the object is too nested to flatten cleanly.

### Session Diagnostics

Two subcommands under `atomic-cli session` for inspecting browser/auth state — useful when triaging customer reports of "the site is broken" or "I can't log in":

#### session decode

Reads a HAR file (Chrome DevTools → Network → "Save all as HAR") and produces a Markdown report with client info, the atomic session cookie decoded, a per-request summary classified by surface (oauth / api / app / other), and a per-request detail block with bodies and diagnostic hints.

```bash
atomic-cli -i my-instance session decode browser-trace.har > report.md
```

| Flag | Description | Default |
|---|---|---|
| `--cookie-name <name>` | Atomic session cookie name. Auto-detected from the instance when `-i` is set, else `_atomic_session`. | `_atomic_session` |
| `--host <host>` | Filter requests to this host. Auto-detected from the cookie's domain or the global `--host` when not set. | _(auto)_ |
| `--all` | Disable the host filter so traffic to other hosts (CDNs, third-party widgets, telemetry) is included too. | `false` |
| `--max-body <n>` | Max bytes of request/response body to include per entry. | `600` |
| `--markdown` | Render as Markdown. Pass `--markdown=false` for the plain-text format. | `true` |
| `--out <path>` | Write the report to a file instead of stdout. | _(stdout)_ |

Report sections:

- **HAR file** — version, creator, browser metadata.
- **Client** — most-common User-Agent (with a count if multiple are seen), Accept-Language, Referer, Origin, server IPs, time range, hosts touched.
- **Session cookie: <name>** — Set-Cookie attributes (domain, path, secure, expires) and a JWT decode of the value when JWT-shaped. For gorilla/sessions cookies (atomic's default) it surfaces the envelope; use `session cookie` for the full decode.
- **Request summary** — one row per request with columns `# | time | host | type | endpoint | status | backend method`. Type values:
  - `oauth` — `/oauth/*`, `/.well-known/*`, JWKS, OIDC discovery
  - `api` — atomic REST surface (`/api/<v>/...`)
  - `app` — `/member`, `/admin`, `/auth/*`, `/login`, `/logout` (HTML / app shell)
  - `other` — third-party assets, telemetry
  The **backend method** column maps `oauth` calls to `oauth.Authorize` / `oauth.Token` / etc., and `api` calls to `atomic.<Resource><Verb>` derived from path + HTTP method (e.g. `GET /api/1.0.0/instances/abc` → `atomic.InstanceGet`, `POST /api/1.0.0/users` → `atomic.UserCreate`).
- **Request detail** — drills into every entry in the summary. Per request: heading shows `METHOD /path → backend.Method`, then a meta table (time, host, type, oauth/atomic method, status, duration), an optional query-parameter table, request body (pretty JSON when applicable), response body (pretty JSON when applicable), and a one-line hint for known failure modes.
- **Summary** — request counts by status class (`2xx`, `3xx`, `4xx`, `5xx`, `0` for no-response).
- **Diagnosis** — plain-language hints derived from the counts (server error, no response / CORS, client error, no issues visible).

#### session cookie

Decodes an atomic session cookie value (gorilla/sessions format). When `-i` is set the instance's `session_key` is used automatically to derive both the hash and block keys, so the inner `Session.Values` map is fully decoded:

```bash
atomic-cli -i my-instance session cookie '<cookie-value>'
echo '<cookie-value>' | atomic-cli -i my-instance session cookie
```

Output (when keys verify):

```json
{
  "format": "gorilla/sessions",
  "cookie_name": "_atomic_session",
  "timestamp": 1777496240,
  "timestamp_human": "2026-04-29T20:57:20Z",
  "key_source": "instance CZg... session_key",
  "mac_verified": true,
  "values": {
    "audience": "passport.example.com",
    "client_id": "KSgqXAh...",
    "subject": "user_abc",
    "scope": ["openid", "profile", "..."],
    "domain": "passport.example.com",
    "created_at": 1777496240,
    "created_at_human": "2026-04-29T20:57:20Z",
    "expires_at": 1809053840,
    "expires_at_human": "2027-04-30T02:57:20Z"
  },
  "user": {
    "id": "Ca3...",
    "login": "rob@modelrocket.io",
    "subject": "9b8e...uuid",
    "name": "Rob Rodriguez",
    "email": "rob@modelrocket.io",
    "roles": ["admin", "member"]
  },
  "application": {
    "id": "Cb1...",
    "name": "Passport Web",
    "client_id": "KSgqXAh...",
    "description": "Customer-facing web app",
    "permissions": ["openid", "profile", "..."],
    "allowed_grants": ["authorization_code", "refresh_token"]
  }
}
```

When `-i` is set the cli uses the loaded backend client to look up:

- **`user`** — the user behind the session (resolved from the `subject` claim, falling back to `login`). Surfaces the user's id, login, subject, name, email, and roles.
- **`application`** — the OAuth client (atomic Application) that issued the cookie, looked up by `client_id`. Surfaces the app's id, name, client_id, description, permissions, and allowed grant types.

Both lookups are best-effort — failures are silent so the rest of the report still renders.

| Flag | Description |
|---|---|
| `--session-key <k>` | Raw session key (sha512 → 32 + 32). Defaults to the instance's `session_key` when `-i` is set, falling back to `atomic.DefaultSessionKey`. |
| `--hash-key <k>` | Explicit HMAC key (base64 / hex / raw bytes). Overrides the derivation. |
| `--block-key <k>` | Explicit AES-CTR key (same accepted forms). Overrides the derivation. |
| `--name <name>` | Cookie name used for MAC verification. Defaults to the instance's `session_cookie` when `-i` is set, else `_atomic_session`. |
| `--session` | Include the **Session values** block in the report. |
| `--user` | Include the **User** block (resolved from the session's `subject` / `login`). |
| `--application` | Include the **Application** block (resolved from the session's `client_id`). |

**Section selection:** when none of `--session` / `--user` / `--application` are passed, the report includes all three (the default). Pass any combination to narrow the output — e.g. `--user` alone returns only the cookie envelope plus the user block. The cookie envelope is always shown since it carries the metadata that identifies the cookie itself.

```bash
# default — envelope + values + user + application
atomic-cli -i my-instance session cookie '<value>'

# just envelope + user
atomic-cli -i my-instance session cookie '<value>' --user

# envelope + user + application (no raw session values)
atomic-cli -i my-instance session cookie '<value>' --user --application
```

**Output formats:** the default is bordered terminal tables (one section per `Cookie envelope` / `Session values` / `User` / `Application`). Use the global `-o json` / `-o json-pretty` for the raw object — useful when piping into `jq`.

Tolerated input forms: bare cookie value, `name=value` (the `name=` is stripped), URL-encoded values. JWT-shaped values are decoded as JWT (header + claims printed) instead of as a gorilla envelope.

When the MAC doesn't verify, the gob decode is skipped (wrong key → garbage bytes); the report includes a `values_skipped` note explaining why so you can spot key mismatches up-front.

### Cluster Status

A live, top-style view of an atomic cluster. Polls the server's `/.well-known/ping?status=true` endpoint and renders a continuously-updating screen with one row per node and (optionally) one row per queue. Refreshes every 60 seconds by default — the same cadence as the server's heartbeat. Press **q** or **ctrl+c** to exit.

```bash
atomic-cli -p prod status
atomic-cli -p prod status --nodes api,scheduler
atomic-cli -p prod status --queues=false
```

| Flag | Description | Default |
|---|---|---|
| `--nodes <filter>` | Comma-separated services (`api`, `scheduler`, `event`, `message`, `work`) or `all`. Maps to the server's `?nodes=` query parameter. | `all` |
| `--queues` | Render the queues table below the nodes table. | `true` |
| `--interval <duration>` | Polling cadence. **Minimum is 60s** (the server's heartbeat interval); smaller values are silently clamped. | `60s` |

**Keys while running:**

- `q` / `ctrl+c` / `esc` — exit.
- `r` — refresh now (resets the countdown).

**Layout:**

The TUI runs in alt-screen mode so it doesn't trash your scrollback. The header line shows the host, node filter, last-refresh timestamp, and a "next refresh in N s" countdown that ticks every second. State columns are color-coded: green `OK`, yellow `WARN`, red `ERROR`.

- **Nodes table** — one row per node returned by the filter. Columns: `ID | HOSTNAME | IP | SERVICES | STATE | UPTIME | LAST HB | BUILD`.
- **Queues table** — one row per dispatcher per node. Columns: `NODE | KIND | NAME | TYPE | STATE | W | IN-PROG | TOTAL | RATE | ERR% | AVG | LAST DISP | LAST HB | LAST ERROR`. `KIND` is `event`, `scheduler`, `msg`, or `work`. `W` = active worker count.

A transient HTTP failure shows as a red banner above the tables; the previous data stays on screen so a single missed poll doesn't blank the view. Auth, when needed, is taken from the global `--access_token` (or the `PASSPORT_ACCESS_TOKEN` env var) and sent as a `Bearer` header.

### MCP Server

`atomic-cli mcp` runs the CLI as a [Model Context Protocol](https://modelcontextprotocol.io/) server, exposing every CLI subcommand as a tool that an MCP-aware host (Claude Desktop, Claude Code, etc.) can call. Each tool dispatch fork-execs a fresh `atomic-cli` subprocess, so no state leaks between calls.

```bash
# Read-only mode (the default), bound to a specific instance
atomic-cli -p prod -i <instance> mcp

# Allow write/destructive tools too — the host should still confirm each call
atomic-cli -p prod -i <instance> mcp --allow-write

# HTTP transport (for remote clients or sharing across processes)
atomic-cli -p prod -i <instance> mcp --transport http --listen 127.0.0.1:8765
```

| Flag | Description | Default |
|---|---|---|
| `--transport` | `stdio` or `http`. Stdio is what Claude Desktop / Claude Code use locally. | `stdio` |
| `--listen <addr>` | Bind address for the HTTP transport. | `127.0.0.1:8765` |
| `--allow-write` | Register mutating tools (create / update / delete / cancel / import / migrate / …). Off by default. | `false` |
| `--tool-prefix <s>` | Prefix added to every tool name (useful when you wire multiple instances into the same host). | (empty) |

Auth and the bound instance come from the global flags / credentials profile / env vars used to launch `atomic-cli mcp`. They're captured at server startup and forwarded to every spawned subprocess. **Use `--client_id` / `--client_secret`** for long-lived sessions: `WithClientCredentials` auto-refreshes tokens, while a static `--access_token` will eventually expire.

#### Tool naming and read-only classification

Each leaf command becomes a tool whose name is the underscore-joined command path: `audience list` → `audience_list`, `stripe customer cleanup` → `stripe_customer_cleanup`. (Underscores rather than dots because Claude Desktop's frontend rejects `.` in tool names — the spec allows it but Desktop's stricter validator does not.) Tools are auto-classified:

- **Read-only** (`readOnlyHint: true`) — leaf verb matches `list|get|search|show|describe|tail|wait|status|view|inspect|count`. Always registered.
- **Destructive** (`destructiveHint: true`) — leaf verb matches `delete|cancel|drop|purge|reset|destroy|remove`. Only registered with `--allow-write`.
- **Other writes** (create / update / import / migrate / restart / …) — registered with `--allow-write`, but not flagged destructive.

Override per command via `cli.Command.Metadata`: `"mcp:readOnly"`, `"mcp:destructive"`, or `"mcp:skip"` (boolean). The `status` TUI and the `mcp` command itself are always skipped.

#### Wiring `atomic-cli mcp` to Claude Desktop

Claude Desktop reads its MCP server list from a JSON config file:

- **macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows:** `%APPDATA%\Claude\claude_desktop_config.json`

Add an entry under `mcpServers` (create the file if it doesn't exist):

```json
{
  "mcpServers": {
    "atomic": {
      "command": "/usr/local/bin/atomic-cli",
      "args": ["-p", "prod", "-i", "<your-instance-id-or-name>", "mcp"]
    }
  }
}
```

Use the absolute path to the binary — Claude Desktop doesn't inherit your shell's `$PATH`. Restart Claude Desktop after editing the file; the `atomic` tools should appear in the tool picker. Add `"--allow-write"` to `args` if you want write tools available (Claude will still prompt before each mutating call).

To pass auth explicitly instead of relying on a credentials profile:

```json
{
  "mcpServers": {
    "atomic": {
      "command": "/usr/local/bin/atomic-cli",
      "args": [
        "-i", "<your-instance>",
        "--client_id", "...",
        "--client_secret", "...",
        "--host", "api.example.com",
        "mcp"
      ]
    }
  }
}
```

You can also lift secrets out of `args` into an `env` block and reference them with the `PASSPORT_*` env vars the CLI already honors:

```json
{
  "mcpServers": {
    "atomic": {
      "command": "/usr/local/bin/atomic-cli",
      "args": ["-i", "<your-instance>", "mcp"],
      "env": {
        "PASSPORT_CLIENT_ID": "...",
        "PASSPORT_CLIENT_SECRET": "...",
        "PASSPORT_API_HOST": "api.example.com"
      }
    }
  }
}
```

#### Wiring to Claude Code

```bash
claude mcp add atomic -- /usr/local/bin/atomic-cli -p prod -i <instance> mcp
```

For HTTP transport (e.g. shared across multiple Claude Code sessions):

```bash
atomic-cli -p prod -i <instance> mcp --transport http --listen 127.0.0.1:8765 &
claude mcp add --transport http atomic http://127.0.0.1:8765
```

#### Multiple instances / profiles

Each `claude mcp add <name>` call registers a separate server, so you can stack as many as you want — one per instance, environment, or profile:

```bash
claude mcp add atomic-ankler-dev  -- /usr/local/bin/atomic-cli -p ankler_dev  -i <instance> mcp
claude mcp add atomic-ankler-prod -- /usr/local/bin/atomic-cli -p ankler_prod -i <instance> mcp
claude mcp add atomic-stratechery -- /usr/local/bin/atomic-cli -p prod -i stratechery mcp
```

The same pattern applies in Claude Desktop — add multiple keys under `mcpServers`:

```json
{
  "mcpServers": {
    "atomic-ankler-dev": {
      "command": "/usr/local/bin/atomic-cli",
      "args": ["-p", "ankler_dev", "-i", "<instance>", "mcp"]
    },
    "atomic-ankler-prod": {
      "command": "/usr/local/bin/atomic-cli",
      "args": ["-p", "ankler_prod", "-i", "<instance>", "mcp"]
    }
  }
}
```

Both hosts namespace tools by server name, so `audience_list` from `atomic-ankler-dev` and `atomic-ankler-prod` don't collide — they show up as distinct tools and the model picks the right one based on the question. Each server is its own subprocess, started lazily on first tool call and held open for the session (≈ 30 MB resident per idle server). `--tool-prefix` is generally not needed given that namespacing.

To switch a single server's instance, restart it with a different `-i`. Mid-session instance switching isn't supported today.

#### Example queries

Once wired up, the host can answer questions by composing read-only tool calls. For instance:

- "When did the last `distribution:publish` job run?" → `job_list` with `{ "type": "distribution:publish", "status": "success", "order_by": "completed_at desc", "limit": 1 }`.
- "How big is the `<name>` audience?" → `audience_list` to find the ID, then `audience_get` to read `member_count`.

#### Notes & limitations

- **Instance is bound at server start.** To switch instances, restart with a different `-i`.
- **File-input commands** (`audience import <file>`, `job get --logs`, etc.) work, but the file path must be reachable from the process running the MCP server.
- **`--out-format` is forced to `json`** for tool dispatches; the dispatcher attempts to parse stdout as JSON for structured content and falls back to a text block for non-JSON output (e.g. progress lines from import commands).
- **Subprocess errors** (non-zero exit, panic, network failure) are returned as `isError: true` MCP results with the child's stderr included — the server itself stays alive across failed calls.
- **Secrets are redacted** in the server's own log line; `--client_id`, `--client_secret`, and `--access_token` are forwarded to subprocess calls but never echoed at full value to stderr.

## Output Formats

The CLI supports multiple output formats controlled by the `--out-format` option:

### Table Format (Default)
Displays results in a formatted table with borders and headers.

```bash
atomic-cli instance list --out-format table
```

### JSON Format
Outputs raw JSON data.

```bash
atomic-cli instance list --out-format json
```

### Pretty JSON Format
Outputs formatted, indented JSON for readability.

```bash
atomic-cli instance list --out-format json-pretty
```

### JSON Lines / NDJSON
Outputs one compact JSON object per line — pipes cleanly to `jq -c`, `gron`, or row-streaming tools without an array wrapper. `jsonl` and `ndjson` are accepted as aliases.

```bash
atomic-cli stripe invoice list --failed -o jsonl > failed.jsonl
atomic-cli stripe invoice list --past-due -o jsonl | jq -c 'select(.amount_due | tonumber > 1000)'
```

## Field Selection

Use the `--fields` option to specify which fields to display in table output:

```bash
atomic-cli instance list --fields "id,name,created_at,parent_id"
```

## File Input

Many commands support reading input from JSON files:

```bash
# Create instance from file
atomic-cli instance create --file instance-config.json

# Create application from file
atomic-cli application create --file app-config.json

# Create user from file
atomic-cli user create --file user-config.json

# Create or update option from file (full input payload)
atomic-cli option create --file option-input.json
```

## Examples

### Complete Workflow

```bash
# 1. Create an instance
INSTANCE_ID=$(atomic-cli instance create my-app \
  --title "My Application" \
  --domains "app.example.com" \
  --out-format json | jq -r '.[0].id')

# 2. Create an application in that instance
APP_ID=$(atomic-cli application create \
  --name "My Web App" \
  --instance_id $INSTANCE_ID \
  --out-format json | jq -r '.[0].id')

# 3. Create a user (login must be a valid email)
USER_ID=$(atomic-cli user create john.doe@example.com \
  --email "john.doe@example.com" \
  --instance_id $INSTANCE_ID \
  --out-format json | jq -r '.[0].id')

# 4. List all resources
echo "Instances:"
atomic-cli instance list

echo "Applications:"
atomic-cli application list --instance_id $INSTANCE_ID

echo "Users:"
atomic-cli user list --instance_id $INSTANCE_ID
```

### Custom Fields

Display specific fields in table format:

```bash
atomic-cli user list \
  --fields "id,login,email,created_at,roles" \
  --instance_id inst_1234567890abcdef
```

## Error Handling

The CLI provides clear error messages and exits with appropriate status codes:

- `0` - Success
- `-1` - Error occurred

## Version

Check the CLI version:

```bash
atomic-cli --version
```

## License

This project is licensed under the GNU General Public License v3.0. See the LICENSE file for details.




