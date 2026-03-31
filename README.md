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

Bulk-import users from a CSV file. The import is processed as a background job and supports subscriptions, Stripe customer linking, discounts, and more.

```bash
atomic-cli user import <file> [options]
```

**Options:**
- `--mime_type` - MIME type of the import file (default: `text/csv`)
- `--source` - Import source format: `atomic`, `ghost`, `substack`, etc. (default: `atomic`)
- `--trial_plan_id` - Plan ID for trial subscriptions
- `--trial_price_id` - Price ID for trial subscriptions
- `--trial_end_at` - Trial end date
- `--trial_existing_users` - Apply trial to existing users
- `--user_email_verified` - Mark imported user emails as verified
- `--source_params` - Path to a JSON file with source-specific parameters
- `--import_audience_id` - Audience ID to add imported users to
- `--import_audience_behavior` - Audience behavior: `add_all_users`, `add_new_users`, `add_existing_users`
- `--suppress_parent_triggers` - Suppress parent instance triggers during import

**Example:**
```bash
atomic-cli user import migrate_users.csv \
  -i inst_abc123 \
  --source atomic \
  --user_email_verified
```

##### CSV Format

The import CSV uses the `UserImportRecord` format. All fields except `login` are optional:

| Column | Description | Default |
|------------------------|----------------------------------------------|---------|
| `login` | User login (must be a valid email address) | *required* |
| `email` | Distribution email address | login |
| `email_verified` | Mark email as verified | `false` |
| `email_opt_in` | Mark email as opted in | `true` |
| `name` | Display name | |
| `roles` | Pipe-delimited roles (e.g. `member\|admin`) | `member` |
| `phone_number` | Phone number (E.164 format) | |
| `phone_number_verified` | Mark phone as verified | `false` |
| `billing_email` | Billing email address | email |
| `billing_phone_number` | Billing phone number | phone_number |
| `stripe_customer_id` | Stripe customer ID to link | |
| `subscription_plan_id` | Passport plan ID to subscribe to | |
| `subscription_currency` | Subscription currency (ISO 4217) | `usd` |
| `subscription_quantity` | Subscription seat quantity | `1` |
| `subscription_interval` | Billing interval: `month` or `year` | |
| `subscription_anchor_date` | Billing anchor date (`YYYYMMDD`) | today |
| `subscription_end_at` | Subscription cancellation date (RFC 3339) | |
| `subscription_prorate` | Prorate the subscription | `false` |
| `discount_percentage` | Coupon discount percentage (0-100) | |
| `discount_term` | Discount duration: `forever`, `once`, `repeating` | |
| `is_team_owner` | Mark user as team owner; requires subscription with quantity > 1 | `false` |
| `team_key` | Arbitrary key to group users into teams (e.g. `team-1`) | |
| `team_limit_behavior` | What to do when team seats are exceeded (see below) | `drop_admin` |

**Team imports:** When `create_teams` is enabled on the import job (default `true`), records with a `team_key` are grouped. The team owner (`is_team_owner=true`) must have a subscription with `subscription_quantity > 1`. Team members (same `team_key`, `is_team_owner` not set) do not get their own subscription — instead they receive an entitlement to the team owner's subscription, consuming one seat. Records are automatically sorted so team owners are processed before their members. The owner occupies 1 seat; each team member consumes 1 additional seat.

**Team limit behavior** (`team_limit_behavior` column, default `drop_admin`): controls what happens when the number of team members exceeds the subscription quantity:

| Behavior | Description |
|------------------------|----------------------------------------------|
| `drop_admin` | The first user over the limit causes the admin/owner's own entitlement to be dropped, freeing one seat for the member. Subsequent users over the limit are dropped (same as `drop_user`). |
| `drop_user` | Users over the seat limit are skipped entirely — no entitlement is created. |
| `expand_subscription` | The subscription quantity is automatically increased to accommodate all team members. |

All team capacity events (drops, expansions, failures) are logged in the job report under the "Team Entitlements" section.

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

- **convert** - Convert any third-party CSV to Passport user import format using a JSON mapping file
- **verify** - Validate a user import CSV and optionally deduplicate records

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
   - **Default** (no `--create-plans`, no `--subscriber-plan`): generates a `plans-<stripe_account_id>.jsonl` file describing the plans and prices that need to be created. Records are split into separate CSV files by plan type (subscribers and founders), with `is_subscriber=true` and no `subscription_plan_id`. The import-level `subscriber_plan_id` parameter is used at import time to resolve the actual plan.
   - With `--create-plans`: creates a hidden "Subscriber" plan with monthly/annual prices and a hidden "Founder" plan with an annual price, matching amounts and currency options from the active Stripe prices. Prompts for confirmation before creating (skipped with `--dry-run`).
   - With `--subscriber-plan` / `--founder-plan`: fetches the existing Passport plans and reads their active price amounts for discount calculation.

4. **Subscription collection** - Iterates every discovered Substack price (active and inactive) and lists all active Stripe subscriptions on each. For each subscriber, captures:
   - Customer ID, email, name
   - Subscription currency, quantity, billing cycle anchor
   - The Stripe price and subscription IDs (written as `migrate_stripe_price` and `migrate_stripe_subscription` in the CSV for audit purposes)
   - Cancellation handling: if `cancel_at` or `cancel_at_period_end` is set, the subscription end date is recorded and the billing anchor is omitted. Otherwise, the billing cycle anchor is advanced by one interval if it falls in the past.

5. **Discount calculation** - When `--apply-discounts` is enabled, compares each subscriber's price (in their subscription currency) against the corresponding Passport plan price at the same interval and currency. If the subscriber's rate is lower, a forever percentage discount is calculated so they keep their grandfathered price. If their rate is equal to or higher than the current price, no discount is applied.

6. **CSV output** - In default mode (no plans), writes two CSVs: `migrate_users-<id>-subscribers.csv` and `migrate_users-<id>-founders.csv` (if founders exist), with `is_subscriber=true` and no `subscription_plan_id`. In plan mode, writes a single CSV (suffixed with `-<stripe_account_id>`) with `subscription_plan_id` set. All CSVs include `migrate_stripe_price` and `migrate_stripe_subscription` audit columns.

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

#### migrate convert

Converts any third-party CSV into the Passport `UserImportRecord` format using a JSON mapping file. This is useful for sources that export subscriber data as a CSV with non-standard column names (e.g., Substack's free subscriber export). Multiple target fields can map to the same source column.

```bash
atomic-cli migrate convert [options]
```

**Convert-specific options** (in addition to [common options](#common-options)):

| Option | Description | Default |
|------------------------|----------------------------------------------|---------|
| `--input`, `--in` | Input CSV file path | *required* |
| `--mapping`, `-m` | JSON mapping file path | *required* |

**Mapping file format:**

The mapping file is a JSON object where keys are `UserImportRecord` field names (using their `csv` tag names) and values are either:

- **string** — the source CSV column name to read from
- **bool/number** — a static value applied to every row

Multiple target fields can reference the same source column. For example, `login` and `email` can both map to the source `email` column.

Supported target fields: `login`, `email`, `email_verified`, `email_opt_in`, `phone_number`, `phone_number_verified`, `phone_number_opt_in`, `billing_email`, `billing_phone_number`, `name`, `roles`, `stripe_customer_id`.

**Example mapping file (`substack-mapping.json`):**

```json
{
  "login": "email",
  "email": "email",
  "name": "name",
  "email_verified": false
}
```

This maps the source CSV's `email` column to both `login` and `email` in the output, the `name` column to `name`, and sets `email_verified` to `false` for every row.

**Examples:**

```bash
# Convert a Substack free subscriber export
atomic-cli migrate convert \
  --input ./substack-subscribers.csv \
  --mapping ./substack-mapping.json \
  --output ./merged-users.csv

# Append free users to an existing paid subscriber CSV (default: --append=true)
# Run substack migrate first, then convert appends to the same file.
# Existing rows (paid subscribers) win on login conflict.
atomic-cli migrate substack \
  -i inst_abc123 \
  --stripe-key sk_test_xxx \
  --output ./merged-users.csv

atomic-cli migrate convert \
  --input ./substack-free-subscribers.csv \
  --mapping ./substack-mapping.json \
  --output ./merged-users.csv

# Overwrite instead of appending
atomic-cli migrate convert \
  --input ./substack-subscribers.csv \
  --mapping ./substack-mapping.json \
  --output ./free-users-only.csv \
  --append=false

# Convert with email rewriting for test environment
atomic-cli migrate convert \
  --input ./substack-subscribers.csv \
  --mapping ./substack-mapping.json \
  --email-domain-overwrite passport.xyz \
  --output ./free-users-test.csv
```

Rows without a `login` value after mapping are skipped and the count is reported to stderr.

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
|------------------------|-------|----------------------------------------------|---------|
| `--output` | `-o` | Output directory (the export folder is created inside) | `.` |
| `--types` | `-t` | Object types to export (repeatable) | `all` |
| `--clean` | | Clear existing export data and start fresh | `false` |
| `--active` | | Only export active objects (products, prices, promotion codes, active subscriptions) | `false` |
| `--email-domain-overwrite` | | Rewrite all customer emails to this domain; mutually exclusive with `--email-template` | |
| `--email-template` | | Generate customer emails from a template (see [Email Template Functions](#email-template-functions)); mutually exclusive with `--email-domain-overwrite` | |

**Supported types:** `products`, `prices`, `customers`, `subscriptions`, `coupons`, `promotion-codes`, `all`

**Expanded fields by type:**

| Type | Expansions |
|-------------------|----------------------------------------------|
| Prices | `currency_options`, `tiers` |
| Customers | `default_source`, `invoice_settings.default_payment_method`, `tax` |
| Subscriptions | `default_payment_method`, `default_source`, `discount`, `discounts`, `items.data.price`, `items.data.discounts` |

Subscriptions are exported across all statuses: active, past_due, trialing, canceled, unpaid, and paused. With `--active`, only active subscriptions are exported.

**Resume/sync behavior:** Running export again on the same account performs an incremental sync — only objects created since the last export are fetched from Stripe (using `created.gte` from the manifest `updated_at`), then merged into existing files by object ID (last-write-wins). Files are written atomically via temp file + rename, so interrupted exports never leave corrupt data. On resume, MD5 checksums are verified — tampered or corrupt files are re-exported from scratch. Use `--clean` to clear existing data and start fresh.

**manifest.json** includes:
- `version` — manifest format version (`"2"`)
- `created_at` — first export timestamp (RFC 3339)
- `updated_at` — most recent sync timestamp
- `account_id` — Stripe account ID (verified on resume; mismatches are rejected)
- `account_name` — dashboard display name
- `livemode` — whether the export used a live key
- `types` — list of exported object types
- `files` — map of type to `{filename, count, md5, exported_at}`

**Examples:**

```bash
# Export everything (test key)
atomic-cli stripe export -k sk_test_xxx

# Export with a test key (default, no extra flag needed)
atomic-cli stripe export -k sk_test_xxx

# Export with a live key (must explicitly opt in)
atomic-cli stripe export -k sk_live_xxx --live-mode

# Export specific types to a custom directory
atomic-cli stripe export -k sk_live_xxx --live-mode -t products -t prices -o /backups

# Re-run to incrementally sync new records
atomic-cli stripe export -k sk_test_xxx

# Export only active objects
atomic-cli stripe export -k sk_test_xxx --active

# Clear existing data and start fresh
atomic-cli stripe export -k sk_test_xxx --clean

# Using environment variable
STRIPE_API_KEY=sk_live_xxx atomic-cli stripe export
```

#### Import

Import Stripe data from an export directory into a target Stripe account. Reads the `manifest.json` and JSONL files produced by `stripe export` and recreates objects in dependency order: products, prices, coupons, promotion codes, customers, then subscriptions.

Products are imported with their original IDs preserved. All imported objects receive `atomic:import_time` and `atomic:import_id` metadata fields for traceability.

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
| `--email-domain-overwrite`      | Rewrite customer emails with this domain                                 |               |
| `--email-template`              | Generate customer emails from a template                                 |               |
| `--application-fees`            | Retain application fees from exported subscriptions (requires Connect platform) | `true`  |
| `--application-fee-percent`     | Override application fee % for all subscriptions (requires Connect platform) |            |
| `--on-behalf-of`                | Connected account ID for subscriptions                                   |               |
| `--create-test-cards`           | Attach test payment methods to customers (test mode only)                | `true`        |
| `--default-test-card`           | Override the auto-detected test card for all customers                   | `pm_card_us`  |
| `--retain-billing-anchor`       | Preserve billing_cycle_anchor from exported subscriptions                | `true`        |
| `--prorate-subscriptions`       | Prorate subscriptions on creation                                        | `false`       |
| `--abort-on-error`              | Stop the entire import on the first failure                              | `false`       |

**Import behavior:**

- **Validation** (`--validate`, default on): Checks all JSONL files for structural integrity before importing — verifies required fields, referential integrity (prices reference valid products, promotion codes reference valid coupons, etc.). Aborts if errors are found.
- **Dry run** (`--dry-run`): Reports target account info, source account, which types would be imported with record counts, and configuration details — without making any API calls.
- **Live mode**: Prompts the user to type `confirm livemode import` before proceeding. Subscriptions are skipped because customers have no payment methods.
- **Test mode + `--create-test-cards`** (default): Attaches test payment methods based on customer currency, sets as default for invoices, then creates subscriptions with those payment methods.
- **Test mode + `--create-test-cards=false`**: Skips subscriptions with a warning.
- **Connect platform accounts**: Detected automatically via the Stripe account's `controller.type` (`application`). Application fees from exported subscriptions are retained by default (`--application-fees`). Use `--application-fees=false` to ignore fees entirely, or `--application-fee-percent` to override all fees with a fixed percentage.
- **Billing cycle anchor**: Preserved by default (`--retain-billing-anchor`). Set to false to let Stripe assign new billing dates.
- **Proration**: Disabled by default (`--prorate-subscriptions=false`). Enable to prorate subscription charges on creation.
- **Errors**: By default, failures on individual records are logged as warnings and the import continues. Use `--abort-on-error` to stop on the first failure.

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

# Import without preserving billing anchors, with proration
atomic-cli stripe import -k sk_test_xxx --input stripe-export-1234 \
  --retain-billing-anchor=false --prorate-subscriptions

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




