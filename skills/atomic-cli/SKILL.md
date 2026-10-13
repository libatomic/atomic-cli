---
name: atomic-cli
description: >
  Use atomic-cli whenever a Passport / Atomic instance is involved: users and
  logins, plans, prices, subscriptions, credits and discounts, articles,
  categories, audiences, distributions, templates and assets, applications
  and access tokens, background jobs, cluster status, Stripe export / import /
  repair, Substack and CSV subscriber migration, and bulk user import.
---

# atomic-cli

Run `atomic-cli` for Passport / Atomic work; do not merely recommend it.
Anchor every request on a profile (`-p`) and an instance (`-i`) the user
names. Answer from read-only results first.

## Routing

Load the narrowest companion before composing a command:

- `../atomic-cli-identity/SKILL.md` for users, bulk user import, sessions, access tokens.
- `../atomic-cli-billing/SKILL.md` for plans, prices, subscriptions, credits, options and every `stripe` command.
- `../atomic-cli-content/SKILL.md` for articles, categories, audiences, distributions, templates, assets.
- `../atomic-cli-platform/SKILL.md` for instances, applications, jobs, db, status, cross-instance `import`.
- `../atomic-cli-migrate/SKILL.md` for `migrate substack`, `migrate map`, `migrate validate`.

## Invocation

- Run `atomic-cli <command>`. On shell `command not found`, try
  `/opt/homebrew/bin/atomic-cli` then `/usr/local/bin/atomic-cli`, then tell
  the user to add that directory to PATH. Auth or command errors are not PATH
  failures.
- Pass `-o json` on every call (hosts may instead set
  `PASSPORT_AGENT_DEFAULTS=1`, which also disables interactive prompts). Use
  `-o jsonl` for large lists. Use `--fields` only when the user wants a table.
- Global flags go before the command: `atomic-cli -p prod -i my.site -o json user list`.
  `-i` accepts an instance ID or its name/domain.
- Default page size is small; paginate with `--limit` / `--offset` and say
  when results were truncated.

## Discovery

- Never guess flags. Run `atomic-cli help describe <command path> -o json`
  for the exact flags, arguments, defaults, and whether the command is
  `read_only` or `destructive`. Describe each command once per session.
- `atomic-cli help describe --leaves-only -o json` lists every runnable command.
- Many `create` / `update` commands accept `--file <json>` for full payloads;
  prefer it over long flag lists.

## Safety

- Read-only verbs (`list`, `get`, `status`, `decode`) need no confirmation.
- `create`, `update`, `import`, `subscribe`, `revoke`, `repair`, and anything
  under `migrate` or `stripe` mutate data: state the exact command and wait
  for the user's go-ahead unless they already asked for that change.
- `delete`, `cancel`, `remove`, `cleanup` are destructive: always confirm,
  and prefer `--dry-run` / `--dry_run` where the command offers it.
- Never pass `--yes`, `--force`, `--live-mode`, `--admin_delete_override`,
  `--ignore-sandbox-email-warning` or similar overrides unless the user asked.
- Stop after the first auth, permission, or validation error. Do not retry
  with different credentials or profiles.

## Auth and setup guard

Do not run `setup`, `skills install`, `doctor` repairs, or edit
`~/.atomic/credentials` unless the user explicitly asks for setup, auth, or
repair. On an auth failure, run `atomic-cli -p <profile> doctor --no-network -o json`,
report `problems`, and wait for direction. Never print credential values.

## Output

- Results are JSON arrays (or one object with `get`). Summarize; do not echo
  whole payloads. Quote IDs exactly as returned.
- Errors go to stderr with a non-zero exit. Report the message verbatim.
