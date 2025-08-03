# atomic-cli

A command-line interface for managing Atomic instances, applications, and users.

## Overview

The `atomic-cli` is a powerful command-line tool for interacting with the Atomic platform. It provides comprehensive management capabilities for instances, applications, and users through an intuitive CLI interface.

## Installation

### Prerequisites

- Go 1.24.1 or later
- Access to an Atomic API endpoint

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
| `--silent` | `-s` | Do not print any output | false |
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
atomic-cli user create
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

# 3. Create a user
USER_ID=$(atomic-cli user create john.doe \
  --email "john@example.com" \
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

### Silent Mode

Use `--silent` to suppress output (useful in scripts):

```bash
atomic-cli instance create my-instance --silent
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




