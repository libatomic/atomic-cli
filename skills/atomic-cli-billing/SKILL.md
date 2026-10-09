---
name: atomic-cli-billing
description: >
  Use with root atomic-cli for plans, prices, subscriptions, credits and
  invites, instance options, and Stripe operations: export, import, repair,
  invoices, customer cleanup, Connect onboarding and webhook capture.
---

# atomic-cli-billing

Load `../atomic-cli/SKILL.md` first. Billing commands move money and
entitlements; describe before running and confirm every write.

## First route

| Intent | Command |
|---|---|
| Plans and their prices | `plan list --expand` / `plan get <plan_id> --expand` |
| Prices for one plan | `price list --plan_id <plan_id>` |
| Who is subscribed to a plan | `subscription list --plan_id <plan_id>` |
| A user's subscriptions | `subscription list --user_id <user_id>` |
| Subscribe a user | `plan subscribe <plan_id> --user_id <user_id> [--price_id …]` |
| Cancel a subscription | `subscription delete <sub_id>` (immediate by default; see `--immediate`) |
| Grant a discount or credit | `credit create <type> …` then `credit invite create` |
| Instance settings | `option list` / `option get <name>` / `option create <name> <value>` |
| Stripe invoices | `stripe invoice list --past-due` / `stripe invoice get <inv_id>` |
| Back up a Stripe account | `stripe export --output <dir>` |
| Load a backup into Stripe | `stripe import --input <dir> --dry-run` first |
| Recreate missing Stripe products / prices / coupons | `stripe repair --dry-run` first |

## Stripe

- Every `stripe` subcommand needs a key: `-k` / `--stripe-key` after `stripe`,
  or `stripe_key` in the credentials profile, or `STRIPE_API_KEY`. Test keys
  only unless the user passes `--live-mode` themselves.
- `stripe export` writes `stripe-export-<account>/` with one JSONL per type
  and a manifest. `stripe import` reads that directory and keeps ID maps so
  re-runs resume; `--clean` discards them.
- Importing real customers into a test account requires email rewriting
  (`--email-domain-overwrite` or `--email-template`). Do not pass
  `--ignore-sandbox-email-warning` unprompted.
- `stripe webhook` and `stripe connect` open tunnels and TUIs; they are for a
  human at a terminal, use `--log-only` when scripting.
- `stripe customer cleanup` deletes Stripe customers from a CSV. Dry-run,
  show the count, confirm.

## Safety notes

- `plan subscribe`, `subscription create`, `subscription update` with
  quantity or status changes, and `credit create` affect billing. Repeat the
  user, plan, price, and amount back before running.
- `option create --force` overwrites protected options; never add `--force`
  on your own.
