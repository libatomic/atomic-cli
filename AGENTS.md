# Agent instructions

## Pull requests

Do not open stacked pull requests. GitHub groups a branch that is based on another unmerged branch into a stack. A stack is painful to merge, rebase, or move onto another release.

- Branch off the release branch this change belongs to, and open the PR against that same branch.
- Feature work for a version uses `feature/vX.Y.Z`. Patch work uses `patch/vX.Y.Z`. Use a version branch only when it exists in this repo. This repo currently has no `feature/v2.2.0`; branch off `master` unless the change belongs on an existing `patch/vX.Y.Z` branch.
- Do not base your branch on another feature branch, and do not set the PR base to another open PR's head.
- If the change depends on an unmerged PR, say so in the description. Do not encode that dependency by basing the branch on the other PR.

## Recent learnings

- 2026-11-12: Stacked PRs could not be moved from one release branch to another without closing and reopening them. Branch from the release branch and mention unmerged dependencies in the description.
