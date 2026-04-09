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
  - [Access Token Management](#access-token-management)
  - [Partner Management](#partner-management)
  - [Asset Management](#asset-management)
  - [Job Management](#job-management)
  - [Option Management](#option-management)
  - [Database Management](#database-management)
  - [Migrate Command](#migrate-command)
  - [Stripe Management](#stripe-management)
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

- `ATOMIC_ACCESS_TOKEN` - Your access token for authentication
- `ATOMIC_CLIENT_ID` - Your client ID for OAuth2 client credentials flow
- `ATOMIC_CLIENT_SECRET` - Your client secret for OAuth2 client credentials flow
- `ATOMIC_API_HOST` - The Atomic API host (defaults to the client default)
- `ATOMIC_DB_SOURCE` - Used for direct connection to the atomic db rather than API

### Credentials file (TOML or YAML)

You can also provide credentials in a config file. By default the CLI looks for `~/.atomic/credentials` and supports either TOML or YAML.

- Default path: `~/.atomic/credentials`
- Override path: use `--credentials` (alias `-c`)
- Supported keys under the `default` section: `access_token`, `client_id`, `client_secret`, `host`
- Precedence: flags > environment variables > credentials file

TOML example (`~/.atomic/credentials`):

```toml
[default]
access_token = "at_XXXXXXXXXXXXXXXX"
# Alternatively use client credentials:
# client_id = "your-client-id"
# client_secret = "your-client-secret"
host = "https://api.atomic.example.com"
```

YAML example (`~/.atomic/credentials`):

```yaml
default:
  access_token: "at_XXXXXXXXXXXXXXXX"
  # Alternatively use client credentials:
  # client_id: "your-client-id"
  # client_secret: "your-client-secret"
  host: "https://api.atomic.example.com"
```

Usage:

```bash
# Uses default path
atomic-cli instance list

# Specify a custom credentials file
atomic-cli --credentials /path/to/credentials instance list
```

### Authentication

The CLI supports two authentication methods:

1. **Access Token**: Use `--access-token` flag or `ATOMIC_ACCESS_TOKEN` environment variable
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
| `--existing_user_behavior` | Behavior for existing users: `skip`, `merge` (update and process subscriptions), `recreate` (delete and re-create) | `merge` |
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
| `--default_discount_percentage` | Default discount percentage for subscriptions | |
| `--default_discount_term` | Default discount term: `once`, `repeating`, `forever` | `forever` |
| `--default_discount_duration_days` | Default discount duration in days | |
| `--default_subscription_prorate` | Prorate subscriptions by default | `false` |
| `--default_subscription_anchor_date` | Default subscription anchor date (RFC3339, e.g. `2026-05-08T21:29:00Z`) | |
| `--create_teams` | Enable team import processing | `false` |
| `--team_limit_behavior` | Team seat limit behavior: `drop_admin`, `drop_user`, `expand_subscription` | `drop_admin` |

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

Before calling the API, the CLI validates the input CSV locally — checking per-record structural validity and uniqueness on `login`, `email`, `phone_number`, and `stripe_customer_id`. If validation fails, the import is aborted with a summary. Run `migrate verify --verbose` for detailed per-row error reporting.

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
| `--partner_id` | Partner ID to associate with the token | |
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

### Partner Management

Manage partners with the `partner` (or `partners`) command.

#### Create Partner

```bash
atomic-cli partner create <name> [options]
```

**Options:**
- `--name` - Set the partner name
- `--description` - Set the partner description
- `--support_contact` - Set the partner support contact
- `--metadata` - Set partner metadata from a JSON file
- `--roles` - Set the partner roles (default: `admin`)
- `--permissions` - Set the partner permissions
- `--file` - Read partner input from a JSON file

**Example:**
```bash
atomic-cli partner create "My Partner" \
  --description "Integration partner" \
  --support_contact "support@partner.com"
```

#### Get Partner

```bash
atomic-cli partner get <partner_id> [options]
```

**Options:**
- `--credentials` / `-c` - Include credentials (default: true)
- `--tokens` / `-t` - Include tokens (default: true)

#### Update Partner

```bash
atomic-cli partner update <partner_id> [options]
```

**Options:** Same as create.

#### List Partners

```bash
atomic-cli partner list
```

#### Delete Partner

```bash
atomic-cli partner delete <partner_id>
```

#### Partner Credentials

Manage partner credentials with `partner credential` (or `credentials`, `creds`).

Requires `--partner_id` on the parent command.

```bash
# Create a credential
atomic-cli partner credential create --partner_id <id> [options]

# Get a credential
atomic-cli partner credential get <client_id> --partner_id <id>

# Revoke a credential
atomic-cli partner credential revoke <client_id> --partner_id <id>
```

**Create options:**
- `--permissions` - Set credential permissions
- `--roles` - Set credential roles
- `--instance_id` - Scope to an instance
- `--expires_at` - Set expiration timestamp

#### Partner Tokens

Manage partner tokens with `partner token`.

Requires `--partner_id` on the parent command.

```bash
# Create a token
atomic-cli partner token create --partner_id <id> [options]

# Get a token
atomic-cli partner token get <token_id> --partner_id <id>

# Revoke a token
atomic-cli partner token revoke <token_id> --partner_id <id>
```

**Create options:**
- `--instance_id` - Scope to an instance
- `--expires_at` - Set expiration timestamp
- `--permissions` - Set token permissions
- `--roles` - Set token roles

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
- `--force` - Force update even if protected (requires partner role)
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
- `--force` - Force delete even if protected (requires partner role)

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

### Migrate Command

Migrate subscriber data from external platforms into Passport. The `migrate` command scans a source platform's Stripe account, maps subscriptions to Passport plans, calculates per-user discounts for grandfathered pricing, and outputs a CSV file compatible with `user import`.

```bash
atomic-cli migrate <platform> [options]
```

Currently supported platforms:

- **substack** - Migrate Substack subscribers via Stripe

Additional tools:

- **map** - Map and filter any third-party CSV to Passport user import format using a config file or inline column mappings
- **verify** - Validate a user import CSV and optionally deduplicate records

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
| `billing_email` | string | No | same as `email` | Billing email address. |
| `billing_phone_number` | string | No | same as `phone_number` | Billing phone number in E.164 format. |
| `name` | string | No | — | The user's display name. |
| `roles` | string | No | `member` | Pipe-delimited roles (e.g., `member\|admin`). |
| `stripe_customer_id` | string | No | — | An existing Stripe customer ID to link to the user's account. |
| `subscription_plan_id` | string | No | — | The plan ID to subscribe the user to. |
| `subscription_currency` | string | No | `usd` | The currency for the subscription. |
| `subscription_quantity` | integer | No | `1` | The quantity for the subscription. |
| `subscription_interval` | string | No | — | Billing interval: `month`, `year`, `once`. |
| `subscription_anchor_date` | date-time | No | today | Billing cycle anchor. Format: RFC 3339 (e.g. `2026-05-08T21:29:00Z`). |
| `subscription_end_at` | date-time | No | — | Subscription end date. Format: RFC 3339. |
| `subscription_prorate` | boolean | No | `false` | If true, prorate the period between creation and anchor date. |
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

These options apply to all migrate subcommands:

| Option | Description | Default |
|------------------------|----------------------------------------------|---------|
| `--stripe-key` | Stripe API key for the source account (or `$STRIPE_API_KEY`) | *required* |
| `--dry-run` | Preview what would happen without creating plans | `false` |
| `--output`, `--out` | Output CSV file path (automatically suffixed with `-<stripe_account_id>` for substack) | `migrate_users.csv` |
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
| `--founder-plan` | Existing Passport plan ID for founding members | |
| `--create-plans` | Auto-create Subscriber and Founder plans from Stripe data | `false` |
| `--apply-discounts` | Calculate per-user forever discounts for price differences | `true` |

**How it works:**

1. **Price discovery** - Scans all Stripe prices for `metadata["substack"] = "yes"`. Classifies each as monthly, annual, or founding (via `metadata["founding"] = "yes"`). Active prices have no `metadata["inactive"]` key; inactive prices are included because subscribers may still be on them.

2. **Price report** - Displays a table of all discovered prices showing type, amount, currency, active status, and currency options. Shows how prices map to Passport plans.

3. **Plan resolution** - Resolves plans in one of three ways:
   - **Default** (no `--create-plans`, no `--subscriber-plan`): generates a `plans-<stripe_account_id>.jsonl` file describing the plans and prices that need to be created. Records are split into separate CSV files by plan type (subscribers and founders) without `subscription_plan_id`. Use the import-level `subscribe_plans` parameter at import time to auto-subscribe users to the correct plans.
   - With `--create-plans`: creates a hidden "Subscriber" plan with monthly/annual prices and a hidden "Founder" plan with an annual price, matching amounts and currency options from the active Stripe prices. Prompts for confirmation before creating (skipped with `--dry-run`).
   - With `--subscriber-plan` / `--founder-plan`: fetches the existing Passport plans and reads their active price amounts for discount calculation.

4. **Subscription collection** - Iterates every discovered Substack price (active and inactive) and lists all active Stripe subscriptions on each. For each subscriber, captures:
   - Customer ID, email, name
   - Subscription currency, quantity, billing cycle anchor
   - The Stripe price and subscription IDs (written as `migrate_stripe_price` and `migrate_stripe_subscription` in the CSV for audit purposes)
   - Cancellation handling: if `cancel_at` or `cancel_at_period_end` is set, the subscription end date is recorded and the billing anchor is omitted. Otherwise, the billing cycle anchor is advanced by one interval if it falls in the past.

5. **Discount calculation** - When `--apply-discounts` is enabled, compares each subscriber's price (in their subscription currency) against the corresponding Passport plan price at the same interval and currency. If the subscriber's rate is lower, a forever percentage discount is calculated so they keep their grandfathered price. If their rate is equal to or higher than the current price, no discount is applied.

6. **CSV output** - In default mode (no plans), writes two CSVs: `migrate_users-<id>-subscribers.csv` and `migrate_users-<id>-founders.csv` (if founders exist), without `subscription_plan_id`. In plan mode, writes a single CSV (suffixed with `-<stripe_account_id>`) with `subscription_plan_id` set. All CSVs include `migrate_stripe_price` and `migrate_stripe_subscription` audit columns.

**Examples:**

```bash
# Generate plans JSONL and subscriber/founder CSVs (default behavior, no instance required)
atomic-cli migrate substack \
  --stripe-key sk_live_xxx
# outputs: plans-1A2B3C4D.jsonl, migrate_users-1A2B3C4D-subscribers.csv, migrate_users-1A2B3C4D-founders.csv

# Auto-create plans, preview with dry run
atomic-cli migrate substack \
  -i inst_abc123 \
  --stripe-key sk_live_xxx \
  --create-plans \
  --dry-run

# Auto-create plans and apply discounts
atomic-cli migrate substack \
  -i inst_abc123 \
  --stripe-key sk_live_xxx \
  --create-plans \
  --out production_migrate.csv

# Use existing plans, skip discount calculation
atomic-cli migrate substack \
  -i inst_abc123 \
  --stripe-key sk_live_xxx \
  --subscriber-plan plan_abc123 \
  --founder-plan plan_def456 \
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

CLI flags override config file options when explicitly set.

**Outputs array:**

Each entry has `path` (required) and an optional `filter` expression. Rows are evaluated against each output's filter independently — a single row can match multiple outputs. When `outputs` is present, the `--output` CLI flag cannot be used.

Column values can be:

- **string** — an [expr](https://github.com/expr-lang/expr) expression; CSV column names and variables are available
- **bool/number** — a static value applied to every row

Supported target fields: `login`, `email`, `email_verified`, `email_opt_in`, `phone_number`, `phone_number_verified`, `phone_number_opt_in`, `billing_email`, `billing_phone_number`, `name`, `roles`, `stripe_customer_id`, `channel_opt_in`, `category_opt_out`, `import_comment`, `import_source`.

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

#### migrate verify

Validates a user import CSV by running per-record validation (`UserImportRecord.Validate()`) and checking uniqueness constraints. Optionally deduplicates the file. Uses the global `--output` flag for the deduplicated output path.

```bash
atomic-cli migrate verify [options]
```

**Verify-specific options** (in addition to [common options](#common-options)):

| Option | Description | Default |
|------------------------|----------------------------------------------|---------|
| `--input`, `--in` | Input CSV file path to verify | *required* |
| `--dedupe` | Deduplicate on the specified field; first occurrence wins | |
| `--verbose`, `-v` | Print each duplicate row with the colliding field and value | `false` |

When `--dedupe` is set, the deduplicated CSV is written to `--output`. If `--output` resolves to the same file as `--input`, you will be prompted before overwriting.

Valid `--dedupe` fields: `login`, `email`, `phone_number`, `stripe_customer_id`.

**Uniqueness checks:**

The following fields are checked for duplicates across all rows:

| Field | Description |
|---|---|
| `login` | Must be globally unique |
| `email` | Must be unique when present |
| `phone_number` | Must be unique when present |
| `stripe_customer_id` | Must be unique when present |

`billing_email` is **not** checked for uniqueness.

When `--dedupe` is not set, duplicates are reported as errors and the command exits with a non-zero status. When `--dedupe` is set, the first occurrence of each duplicate value is kept and later occurrences are removed.

**Examples:**

```bash
# Validate only — report summary
atomic-cli migrate verify \
  --input ./merged-users.csv

# Validate with verbose duplicate details
atomic-cli migrate verify \
  --input ./merged-users.csv \
  --verbose

# Deduplicate on login, writing to a separate file
atomic-cli migrate verify \
  --input ./merged-users.csv \
  --dedupe login \
  --output ./merged-users-clean.csv

# Deduplicate in place (prompts before overwriting)
atomic-cli migrate verify \
  --input ./merged-users.csv \
  --dedupe login \
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
```

### Stripe Management

Manage Stripe data with the `stripe` command. All subcommands require a Stripe API key.

**Parent options:**

| Option | Alias | Description | Default |
|------------------------|-------|----------------------------------------------|---------|
| `--stripe-key` | `-k` | Stripe API key (or `$STRIPE_API_KEY`) | *required* |
| `--live-mode` | | Allow live stripe keys; without this flag only test keys are accepted | `false` |

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




