/*
 * This file is part of the Passport Atomic Stack (https://github.com/libatomic/atomic).
 * Copyright (c) 2026 Passport, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

// Package skills embeds the agent skill directories shipped with atomic-cli.
// Each top-level directory is one skill (SKILL.md plus optional references)
// that `atomic-cli skills install` copies into the skills directories read
// by Claude Code, Codex, Cursor, Gemini CLI and other agents.
package skills

import (
	"embed"
	"io/fs"
	"sort"
)

const (
	// RootSkill is the routing skill every companion hangs off.
	RootSkill = "atomic-cli"
)

// FS holds every skill directory shipped with the binary. The patterns are
// directory names relative to this package; `all:` keeps dotfiles.
//
//go:embed all:atomic-cli all:atomic-cli-*
var FS embed.FS

// Names returns the top-level skill directory names in FS, sorted, with the
// root skill first.
func Names() ([]string, error) {
	entries, err := fs.ReadDir(FS, ".")
	if err != nil {
		return nil, err
	}

	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			names = append(names, e.Name())
		}
	}

	sort.Slice(names, func(i, j int) bool {
		if names[i] == RootSkill {
			return true
		}
		if names[j] == RootSkill {
			return false
		}
		return names[i] < names[j]
	})

	return names, nil
}
