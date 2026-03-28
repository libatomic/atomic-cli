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
|--------|-------|-------------|---------|
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
|--------|-------------|---------|
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

### Access Token Management

Manage access tokens with the `access-token` (or `token`) command.

#### Create Access Token

```bash
atomic-cli access-token create [options]
```

**Options:**

| Option | Description | Default |
|--------|-------------|---------|
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
|--------|-------------|---------|
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
|--------|-------|-------------|---------|
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
|--------|-------|-------------|---------|
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
|--------|-------------|---------|
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

#### Common Options

These options apply to all migrate subcommands:

| Option | Description | Default |
|--------|-------------|---------|
| `--stripe-key` | Stripe API key for the source account (or `$STRIPE_API_KEY`) | *required* |
| `--dry-run` | Preview what would happen without creating plans | `false` |
| `--output`, `--out` | Output CSV file path | `migrate_users.csv` |
| `--subscription-prorate` | Set prorate flag on migrated subscriptions | `false` |
| `--email-domain-overwrite` | Rewrite all emails to this domain (for testing) | |

#### migrate substack

Migrates Substack subscribers by scanning the Stripe account for prices tagged with Substack metadata, collecting active subscriptions across all prices (including inactive/grandfathered ones), and producing a Passport-compatible import CSV.

```bash
atomic-cli migrate substack [options]
```

**Substack-specific options:**

| Option | Description | Default |
|--------|-------------|---------|
| `--subscriber-plan` | Existing Passport plan ID for regular subscribers | |
| `--founder-plan` | Existing Passport plan ID for founding members | |
| `--create-plans` | Auto-create Subscriber and Founder plans from Stripe data | `true` |
| `--apply-discounts` | Calculate per-user forever discounts for price differences | `true` |

**How it works:**

1. **Price discovery** - Scans all Stripe prices for `metadata["substack"] = "yes"`. Classifies each as monthly, annual, or founding (via `metadata["founding"] = "yes"`). Active prices have no `metadata["inactive"]` key; inactive prices are included because subscribers may still be on them.

2. **Price report** - Displays a table of all discovered prices showing type, amount, currency, active status, and currency options. Shows how prices map to Passport plans.

3. **Plan resolution** - Either creates new Passport plans or fetches existing ones:
   - With `--create-plans` (default): creates a hidden "Subscriber" plan with monthly/annual prices and a hidden "Founder" plan with an annual price, matching amounts and currency options from the active Stripe prices. Prompts for confirmation before creating (skipped with `--dry-run`).
   - With `--subscriber-plan` / `--founder-plan`: fetches the existing Passport plans and reads their active price amounts for discount calculation.

4. **Subscription collection** - Iterates every discovered Substack price (active and inactive) and lists all active Stripe subscriptions on each. For each subscriber, captures:
   - Customer ID, email, name
   - Subscription currency, quantity, billing cycle anchor
   - The Stripe price and subscription IDs (written as `migrate_stripe_price` and `migrate_stripe_subscription` in the CSV for audit purposes)
   - Cancellation handling: if `cancel_at` or `cancel_at_period_end` is set, the subscription end date is recorded and the billing anchor is omitted. Otherwise, the billing cycle anchor is advanced by one interval if it falls in the past.

5. **Discount calculation** - When `--apply-discounts` is enabled, compares each subscriber's price (in their subscription currency) against the corresponding Passport plan price at the same interval and currency. If the subscriber's rate is lower, a forever percentage discount is calculated so they keep their grandfathered price. If their rate is equal to or higher than the current price, no discount is applied.

6. **CSV output** - Writes the final CSV with all standard `UserImportRecord` fields plus `migrate_stripe_price` and `migrate_stripe_subscription` columns.

**Examples:**

```bash
# Auto-create plans, preview with dry run
atomic-cli migrate substack \
  -i inst_abc123 \
  --stripe-key sk_live_xxx \
  --dry-run

# Auto-create plans and apply discounts (defaults)
atomic-cli migrate substack \
  -i inst_abc123 \
  --stripe-key sk_live_xxx \
  --out production_migrate.csv

# Use existing plans, skip discount calculation
atomic-cli migrate substack \
  -i inst_abc123 \
  --stripe-key sk_live_xxx \
  --subscriber-plan plan_abc123 \
  --founder-plan plan_def456 \
  --apply-discounts=false

# Rewrite emails for safe testing against a staging environment
atomic-cli migrate substack \
  -i inst_abc123 \
  --stripe-key sk_test_xxx \
  --email-domain-overwrite passport.xyz \
  --out test_migrate.csv
```

The `--email-domain-overwrite` flag rewrites every email address in the output CSV so the file can be safely imported into a test environment without affecting real users. For example, `oli2p@hotmail.com` becomes `oli2p-hotmail.com@passport.xyz`.

### Stripe Management

Manage Stripe data with the `stripe` command. All subcommands require a Stripe API key.

**Parent options:**

| Option | Alias | Description | Default |
|--------|-------|-------------|---------|
| `--stripe-key` | `-k` | Stripe API key (or `$STRIPE_API_KEY`) | *required* |
| `--live-mode` | | Allow live stripe keys; without this flag only test keys are accepted | `false` |

#### Export

Export Stripe data to JSONL files for backup. Creates a `stripe-export-<account_id>` folder containing one `.jsonl` file per object type and a `manifest.json` with account info and record counts.

```bash
atomic-cli stripe export [options]
```

**Options:**

| Option | Alias | Description | Default |
|--------|-------|-------------|---------|
| `--output` | `-o` | Output directory (the export folder is created inside) | `.` |
| `--types` | `-t` | Object types to export (repeatable) | `all` |
| `--clean` | | Clear existing export data and start fresh | `false` |
| `--active` | | Only export active objects (products, prices, promotion codes, active subscriptions) | `false` |

**Supported types:** `products`, `prices`, `customers`, `subscriptions`, `coupons`, `promotion-codes`, `all`

**Expanded fields by type:**

| Type | Expansions |
|------|-----------|
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

#### Connect

Connect a Stripe account via OAuth using Stripe Connect. Starts a temporary ngrok tunnel to receive the OAuth callback, then displays the resulting credentials.

```bash
atomic-cli stripe connect --client-id <stripe_connect_client_id> [options]
```

**Options:**

| Option | Description | Default |
|--------|-------------|---------|
| `--client-id` | Stripe Connect client ID (or `$STRIPE_CLIENT_ID`) | *required* |
| `--ngrok` | Use ngrok to create a public tunnel for the OAuth callback | `false` |
| `--ngrok-authtoken` | ngrok auth token (overrides config file and `$NGROK_AUTHTOKEN`) | |
| `--ngrok-config` | Path to ngrok config file | `~/.ngrok2/ngrok.yml` |

**How it works:**

1. Starts a listener — either an ngrok tunnel (with `--ngrok`) or a local port (default, you proxy it yourself)
2. Prints a Stripe Connect authorize URL for the user to open in their browser
3. Waits for the user to authorize the connection on Stripe
4. Exchanges the authorization code for access tokens
5. Fetches the connected account details
6. Displays the credentials (account ID, publishable key, secret key, etc.)

The `--stripe-key` from the parent command is used as the platform's secret key for the OAuth token exchange. Use `--live-mode` on the parent to connect live accounts.

**Examples:**

```bash
# Connect a test account with ngrok (reads authtoken from ~/.ngrok2/ngrok.yml)
atomic-cli stripe connect -k sk_test_xxx --client-id ca_xxx --ngrok

# Connect a live account with ngrok
atomic-cli stripe connect -k sk_live_xxx --live-mode --client-id ca_xxx --ngrok

# Without ngrok (listen on random local port, you proxy it)
atomic-cli stripe connect -k sk_test_xxx --client-id ca_xxx

# Explicit ngrok authtoken
atomic-cli stripe connect -k sk_test_xxx --client-id ca_xxx --ngrok-authtoken xxx

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




