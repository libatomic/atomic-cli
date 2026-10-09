---
name: atomic-cli-platform
description: >
  Use with root atomic-cli for instances and child instances, OAuth
  applications, background jobs (list, wait, logs, cancel, restart),
  database migration, node and queue status, cross-instance data import,
  and CLI diagnostics via doctor.
---

# atomic-cli-platform

Load `../atomic-cli/SKILL.md` first.

## First route

| Intent | Command |
|---|---|
| Which instances exist | `instance list` / `instance list --is_parent` |
| Instance details | `instance get <instance-id>` |
| OAuth clients | `application list` / `application get <application-id>` |
| Running or failed jobs | `job list --status running` / `job list --status failed --limit 20` |
| Follow a job to completion | `job get <job_id> --wait --logs` |
| Export job logs | `job get <job_id> --logs --export <dir>` |
| Stop or retry | `job cancel <job_id>` / `job restart <job_id>` |
| Cluster health | `status --nodes --queues` (no `--top`; that is a TUI) |
| Copy categories / plans / audiences between instances | `import --remote-profile <p> --types categories,plans --dry-run` |
| Is the CLI set up correctly | `doctor --no-network -o json` (add network only when asked) |

## Notes

- `instance create`, `instance update --recreate_jobs`, and `instance delete`
  are instance-wide operations; confirm the instance name and flags.
- `application create` returns a client secret once; hand it to the user and
  do not persist it.
- `db migrate` needs `db_source` (direct database access) and is for
  operators; never run it from an agent session without explicit instruction.
- `import` pulls from another Passport instance using `--remote-*` flags or a
  second credentials profile via `--remote-profile`. Always dry-run first.
- `job create <type> --params '<json>'` starts arbitrary server jobs; only
  use types the user names.
- `status --top` and `stripe webhook` are interactive TUIs and refuse to run
  without a terminal.
