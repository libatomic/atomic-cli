---
name: atomic-cli-migrate
description: >
  Use with root atomic-cli to migrate subscribers from Substack (via its
  Stripe account) or any third-party CSV into Passport user-import CSVs,
  including plan mapping, grandfathered discounts, anchor-date shifting,
  deduplication and validation before user import.
---

# atomic-cli-migrate

Load `../atomic-cli/SKILL.md` first. Migration is a pipeline that ends in
`user import`; each step writes files the next step reads.

## Pipeline

1. `migrate substack -k <stripe_key> --dry-run --output subs.csv …`
   or `migrate map --input source.csv --config map.json --output users.csv --dry-run`
2. `migrate validate users.csv --output users.clean.csv`
3. `user import users.clean.csv --dry_run` then the real import (see
   `../atomic-cli-identity/SKILL.md`).

## First route

| Intent | Command |
|---|---|
| Preview a Substack migration | `migrate substack --dry-run --limit 20` |
| Map plans and founders | add `--subscriber-plan <id> --founder-plan <id> --founders founders.csv` |
| Keep legacy prices as discounts | `--legacy-pricing --apply-discounts --discount-term forever` |
| Keep billing dates | `--shift-anchor-dates --shift-anchor-window <days>` |
| Diff against a previous run | `--diff previous.csv` |
| Map an arbitrary CSV | `migrate map --input f.csv --columns 'login=Email,name=Name' --filter '…'` |
| Dedupe / check a CSV | `migrate validate <input.csv> --output out.csv` |

## Notes

- `migrate substack` reads Stripe directly; it needs a key (`-k`, profile
  `stripe_key`, or `STRIPE_API_KEY`) and is read-only against Stripe, but it
  writes CSVs locally. It prompts before overwriting an existing output file;
  in agent mode that prompt fails, so choose a new `--output` name.
- `--email-domain-overwrite` / `--email-template` rewrite real emails for
  sandbox imports. Use them whenever the target instance is not production.
- `--create-plans` creates Passport plans and asks for confirmation; run it
  only when the user wants plans created, and only interactively.
- Describe the command for the full filter set (`--status`, `--created`,
  `--canceled-before`, `--current-period-end`, …); do not guess date formats,
  they are documented in the flag usage.
- Report row counts and the error-row file paths from each step before
  moving to the next.
