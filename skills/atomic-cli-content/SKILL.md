---
name: atomic-cli-content
description: >
  Use with root atomic-cli for articles, categories, audiences and audience
  membership counts, distributions (email / channel sends and schedules),
  templates and template events, and uploaded assets.
---

# atomic-cli-content

Load `../atomic-cli/SKILL.md` first. Run
`atomic-cli help describe <command> -o json` before composing flags.

## First route

| Intent | Command |
|---|---|
| Recent or filtered articles | `article list --status <s> --categories <id> --preload` |
| One article with body | `article get <article_id> --preload` |
| Create or edit an article | `article create [title] --body-file post.md …` / `article update <id> …` |
| Categories | `category list` / `category create <name>` / `category import <file> --dry-run` |
| Audiences and sizes | `audience list` (shows `member_count`) / `audience get <id>` |
| What was sent, to whom, when | `distribution list --audience_id <id> --channel email --with_audience` |
| Schedule or send | `distribution create [audience_id] --article_id … --scheduled_at … --file dist.json` |
| Email / notification templates | `template list` / `template get <id>` / `template create --file t.json` |
| Template triggers | `template event list <template_id>` / `template event add <template_id> …` |
| Files and images | `asset list --type image` / `asset get <id> --link` / `asset create <filename> …` |

## Notes

- `article`, `distribution`, and `template` create / update accept `--file`
  with the full JSON payload; prefer it for bodies, settings, and context.
- `distribution create` with a `scheduled_at` in the past or
  `--status active` sends immediately. Confirm the audience and timing.
- `template update --republish` and `template event update` change live
  notifications; confirm before running.
- Audiences are mostly derived; `audience delete` on an internal audience
  fails by design. `audience import` only loads non-internal audiences.
- Asset links from `asset get --link` are signed and may expire; do not
  cache them in notes.
