---
name: atomic-cli-identity
description: >
  Use with root atomic-cli for Passport users and logins, bulk user import
  from CSV, user search by email / role / audience / Stripe account, session
  cookie and HAR diagnostics, and access token creation or revocation.
---

# atomic-cli-identity

Load `../atomic-cli/SKILL.md` first; it owns invocation, safety, and
discovery rules. Run `atomic-cli help describe user -o json` before composing
flags.

## First route

| Intent | Command |
|---|---|
| Find a user by email | `user list --login <email>` |
| Users with a role / in an audience | `user list --roles <role>` / `user list --audience <id>` |
| Full user with subscriptions and entitlements | `user get <user_id> --expand` |
| Look up by Stripe customer | `user get --stripe_customer <cus_id>` |
| Create a user | `user create <login> [--file user.json]` |
| Change profile, roles, metadata, preferences | `user update <user_id> …` |
| Bulk import subscribers | `user import <file.csv> [--config import.json] --dry_run` first |
| Watch an import job | `job get <job_id> --wait --logs` |
| Inspect a browser session | `session decode <file.har>` or `session cookie <value>` |
| Mint or revoke an API token | `access-token create …` / `access-token revoke <token_id>` |

## User import

- `user import` runs as a background job; it returns a job ID. Pass `--wait`
  to block, or follow with `job get <id> --wait`.
- Always run with `--dry_run` first and show the user the summary before the
  real run.
- Import behaviours (`--existing_user_behavior`, `--subscribe_behavior`,
  `--trial_behavior`, `--discount_behavior`, team flags) change money and
  access; set them only as the user specifies. Describe the command to see
  accepted values.
- The CSV format and defaults are documented in the atomic-cli README under
  "User Import Record CSV Format". `migrate validate` checks a CSV before import.

## Safety notes

- `user delete` with `--delete_stripe_account` or `--admin_delete_override`
  is irreversible; confirm both the user ID and the flags.
- `access-token create` returns a secret once. Hand it to the user; never
  store or echo it elsewhere.
- `session cookie` needs the instance session key; ask the user for it rather
  than reading it from any file.
