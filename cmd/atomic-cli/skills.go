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

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/libatomic/atomic-cli/v2/skills"
	"github.com/urfave/cli/v3"
)

type (
	// agentTarget is one skills directory an agent host reads.
	agentTarget struct {
		// Name is the --agent value.
		Name string
		// Label is the human-readable host name.
		Label string
		// Covers lists other --agent values that resolve to this target.
		Covers []string
		// GlobalDir returns the per-user skills directory.
		GlobalDir func(home string) string
		// LocalDir is the project-relative skills directory.
		LocalDir string
	}

	// installManifest is written into every installed skill directory so
	// later runs can tell our installs from user-authored skills and detect
	// stale copies.
	installManifest struct {
		SkillName        string `json:"skillName"`
		Target           string `json:"target"`
		Agent            string `json:"agent"`
		InstallPath      string `json:"installPath"`
		BinaryPath       string `json:"binaryPath"`
		InstalledAt      string `json:"installedAt"`
		InstalledVersion string `json:"installedVersion"`
		BuildCommit      string `json:"buildCommit"`
		BuiltAt          string `json:"builtAt"`
	}

	// skillStatus describes one skill slot in one skills directory.
	skillStatus struct {
		Agent         string           `json:"agent"`
		SkillsDir     string           `json:"skillsDir"`
		Name          string           `json:"name"`
		Path          string           `json:"path"`
		Status        string           `json:"status"`
		Fresh         string           `json:"fresh"`
		Manifest      *installManifest `json:"manifest,omitempty"`
		RepairCommand string           `json:"repairCommand,omitempty"`
	}

	// installResult summarizes one skills install run.
	installResult struct {
		Installed []skillStatus `json:"installed"`
		Pruned    []string      `json:"pruned,omitempty"`
		Skipped   []string      `json:"skipped,omitempty"`
	}
)

const (
	manifestName = ".atomic-cli-install.json"

	skillStatusMissing   = "missing"
	skillStatusDirectory = "directory"
	skillStatusSymlink   = "symlink"
	skillStatusForeign   = "foreign"

	targetGlobal = "global"
	targetLocal  = "local"
)

var (
	agentTargets = []agentTarget{
		{
			Name:   "agents",
			Label:  "canonical (.agents/skills)",
			Covers: []string{"codex", "cursor", "gemini", "copilot", "windsurf"},
			GlobalDir: func(home string) string {
				return filepath.Join(home, ".agents", "skills")
			},
			LocalDir: filepath.Join(".agents", "skills"),
		},
		{
			Name:  "claude",
			Label: "Claude Code",
			GlobalDir: func(home string) string {
				return filepath.Join(home, ".claude", "skills")
			},
			LocalDir: filepath.Join(".claude", "skills"),
		},
	}

	// skillTargetFlags are shared by `skills install`, `skills uninstall`
	// and `setup`.
	skillTargetFlags = []cli.Flag{
		&cli.StringSliceFlag{
			Name:  "agent",
			Usage: "agent host to install for (agents|claude; codex, cursor, gemini, copilot resolve to agents). Repeatable. Default: all",
		},
		&cli.BoolFlag{
			Name:  "all-agents",
			Usage: "install for every known agent host (the default when --agent is not given)",
		},
		&cli.BoolFlag{
			Name:    "local",
			Aliases: []string{"l"},
			Usage:   "install into the current project (./.agents/skills, ./.claude/skills) instead of the home directory",
		},
		&cli.BoolFlag{
			Name:    "yes",
			Aliases: []string{"y"},
			Usage:   "do not prompt; also replaces symlinked skill directories",
		},
	}

	skillsCmd = &cli.Command{
		Name:     "skills",
		Usage:    "install the atomic-cli agent skills for Claude Code, Codex, Cursor, Gemini and other agents",
		Metadata: localMeta(),
		Commands: []*cli.Command{
			skillsInstallCmd,
			skillsUninstallCmd,
			skillsListCmd,
		},
	}

	skillsInstallCmd = &cli.Command{
		Name:  "install",
		Usage: "copy the embedded skills into the agent skills directories",
		Flags: append(append([]cli.Flag{}, skillTargetFlags...),
			&cli.BoolFlag{
				Name:  "no-prune",
				Usage: "keep atomic-cli skill directories from older versions that no longer ship",
			},
		),
		Action: func(ctx context.Context, cmd *cli.Command) error {
			res, err := skillsInstall(cmd)
			if err != nil {
				return err
			}
			return printSkillsInstall(cmd, res)
		},
	}

	skillsUninstallCmd = &cli.Command{
		Name:      "uninstall",
		Usage:     "remove installed atomic-cli skills (default: all)",
		ArgsUsage: "[skill-name]...",
		Flags:     skillTargetFlags,
		Action:    skillsUninstall,
	}

	skillsListCmd = &cli.Command{
		Name:    "list",
		Aliases: []string{"status"},
		Usage:   "show where atomic-cli skills are installed and whether they match this binary",
		Flags: []cli.Flag{
			&cli.BoolFlag{
				Name:    "local",
				Aliases: []string{"l"},
				Usage:   "include the current project's skills directories",
			},
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			statuses, err := skillStatuses(cmd.Bool("local"))
			if err != nil {
				return err
			}
			PrintResult(cmd, statuses, WithFields("agent", "name", "status", "fresh", "path"))
			return nil
		},
	}
)

// selectedTargets resolves --agent / --all-agents into targets.
func selectedTargets(cmd *cli.Command) ([]agentTarget, error) {
	wanted := cmd.StringSlice("agent")
	if len(wanted) == 0 || cmd.Bool("all-agents") {
		return agentTargets, nil
	}

	seen := map[string]bool{}
	var out []agentTarget
	for _, w := range wanted {
		w = strings.ToLower(strings.TrimSpace(w))
		t, ok := findTarget(w)
		if !ok {
			return nil, fmt.Errorf("unknown agent %q; known: %s", w, strings.Join(knownAgentNames(), ", "))
		}
		if !seen[t.Name] {
			seen[t.Name] = true
			out = append(out, t)
		}
	}
	return out, nil
}

func findTarget(name string) (agentTarget, bool) {
	for _, t := range agentTargets {
		if t.Name == name {
			return t, true
		}
		for _, c := range t.Covers {
			if c == name {
				return t, true
			}
		}
	}
	return agentTarget{}, false
}

func knownAgentNames() []string {
	var out []string
	for _, t := range agentTargets {
		out = append(out, t.Name)
		out = append(out, t.Covers...)
	}
	return out
}

// skillsDirFor returns the skills directory for a target, global or local.
func skillsDirFor(t agentTarget, local bool) (string, error) {
	if local {
		return filepath.Abs(t.LocalDir)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home directory: %w", err)
	}
	return t.GlobalDir(home), nil
}

// skillsInstall copies every embedded skill into the selected directories,
// writes a manifest per skill and prunes orphaned atomic-cli skills.
func skillsInstall(cmd *cli.Command) (*installResult, error) {
	targets, err := selectedTargets(cmd)
	if err != nil {
		return nil, err
	}

	names, err := skills.Names()
	if err != nil {
		return nil, fmt.Errorf("read embedded skills: %w", err)
	}

	local := cmd.Bool("local")
	target := targetGlobal
	if local {
		target = targetLocal
	}

	binary := currentBinaryPath()
	res := &installResult{}
	keep := map[string]bool{}
	for _, n := range names {
		keep[n] = true
	}

	for _, t := range targets {
		dir, err := skillsDirFor(t, local)
		if err != nil {
			return nil, err
		}
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fmt.Errorf("create %s: %w", dir, err)
		}

		for _, name := range names {
			dst := filepath.Join(dir, name)

			if fi, err := os.Lstat(dst); err == nil && fi.Mode()&os.ModeSymlink != 0 && !cmd.Bool("yes") {
				res.Skipped = append(res.Skipped, dst+" (symlink; pass --yes to replace)")
				continue
			}

			m := installManifest{
				SkillName:        name,
				Target:           target,
				Agent:            t.Name,
				InstallPath:      dst,
				BinaryPath:       binary,
				InstalledAt:      time.Now().UTC().Format(time.RFC3339),
				InstalledVersion: Version,
				BuildCommit:      Commit,
				BuiltAt:          Date,
			}
			if err := installSkill(dst, name, m); err != nil {
				return nil, err
			}
			res.Installed = append(res.Installed, statusFor(t, dir, name))
		}

		if !cmd.Bool("no-prune") {
			pruned, err := pruneOrphans(dir, keep)
			if err != nil {
				return nil, err
			}
			res.Pruned = append(res.Pruned, pruned...)
		}
	}

	return res, nil
}

func printSkillsInstall(cmd *cli.Command, res *installResult) error {
	switch cmd.String("out-format") {
	case "json", "json-pretty", "jsonl":
		enc := json.NewEncoder(os.Stdout)
		if cmd.String("out-format") == "json-pretty" {
			enc.SetIndent("", "  ")
		}
		return enc.Encode(res)
	}

	for _, s := range res.Installed {
		fmt.Printf("installed %-24s -> %s\n", s.Name, s.Path)
	}
	for _, p := range res.Pruned {
		fmt.Printf("pruned    %s\n", p)
	}
	for _, s := range res.Skipped {
		fmt.Printf("skipped   %s\n", s)
	}
	if len(res.Installed) > 0 {
		fmt.Println("restart your agent session to pick up the new skills; run `atomic-cli doctor` to verify")
	}
	return nil
}

// installSkill replaces dst with the embedded skill tree for name and
// writes the manifest last.
func installSkill(dst, name string, m installManifest) error {
	if err := os.RemoveAll(dst); err != nil {
		return fmt.Errorf("remove %s: %w", dst, err)
	}

	err := fs.WalkDir(skills.FS, name, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(name, p)
		if err != nil {
			return err
		}
		out := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(out, 0o755)
		}
		data, err := skills.FS.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(out, data, 0o644)
	})
	if err != nil {
		return fmt.Errorf("install %s: %w", name, err)
	}

	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dst, manifestName), append(data, '\n'), 0o644)
}

// pruneOrphans removes atomic-cli skill directories under dir that carry
// our manifest but are no longer shipped. Directories without a manifest
// are never touched.
func pruneOrphans(dir string, keep map[string]bool) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	var pruned []string
	for _, e := range entries {
		if !e.IsDir() || !strings.HasPrefix(e.Name(), skills.RootSkill) || keep[e.Name()] {
			continue
		}
		p := filepath.Join(dir, e.Name())
		if _, err := readManifest(p); err != nil {
			continue
		}
		if err := os.RemoveAll(p); err != nil {
			return pruned, fmt.Errorf("prune %s: %w", p, err)
		}
		pruned = append(pruned, p)
	}
	return pruned, nil
}

func skillsUninstall(ctx context.Context, cmd *cli.Command) error {
	targets, err := selectedTargets(cmd)
	if err != nil {
		return err
	}

	names := cmd.Args().Slice()
	if len(names) == 0 {
		names, err = skills.Names()
		if err != nil {
			return err
		}
	}

	if !cmd.Bool("yes") {
		ok, err := confirmAction(fmt.Sprintf("Remove %d skill(s) from %d location(s)?", len(names), len(targets)))
		if err != nil {
			return err
		}
		if !ok {
			return errors.New("aborted")
		}
	}

	for _, t := range targets {
		dir, err := skillsDirFor(t, cmd.Bool("local"))
		if err != nil {
			return err
		}
		for _, name := range names {
			p := filepath.Join(dir, name)
			if _, err := os.Lstat(p); errors.Is(err, os.ErrNotExist) {
				continue
			}
			if _, err := readManifest(p); err != nil {
				fmt.Fprintf(os.Stderr, "skipping %s: not installed by atomic-cli\n", p)
				continue
			}
			if err := os.RemoveAll(p); err != nil {
				return fmt.Errorf("remove %s: %w", p, err)
			}
			fmt.Printf("removed %s\n", p)
		}
	}
	return nil
}

func readManifest(dir string) (*installManifest, error) {
	data, err := os.ReadFile(filepath.Join(dir, manifestName))
	if err != nil {
		return nil, err
	}
	var m installManifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

// skillStatuses reports every shipped skill in every target directory.
func skillStatuses(includeLocal bool) ([]skillStatus, error) {
	names, err := skills.Names()
	if err != nil {
		return nil, err
	}

	var out []skillStatus
	for _, t := range agentTargets {
		dir, err := skillsDirFor(t, false)
		if err != nil {
			return nil, err
		}
		for _, n := range names {
			out = append(out, statusFor(t, dir, n))
		}
		if includeLocal {
			ldir, err := skillsDirFor(t, true)
			if err != nil {
				return nil, err
			}
			for _, n := range names {
				out = append(out, statusFor(t, ldir, n))
			}
		}
	}
	return out, nil
}

// statusFor inspects one skill slot.
func statusFor(t agentTarget, dir, name string) skillStatus {
	p := filepath.Join(dir, name)
	s := skillStatus{
		Agent:     t.Name,
		SkillsDir: dir,
		Name:      name,
		Path:      p,
		Status:    skillStatusMissing,
		Fresh:     "n/a",
	}

	repair := "atomic-cli skills install --agent " + t.Name
	if !strings.HasPrefix(dir, mustHome()) {
		repair += " --local"
	}

	fi, err := os.Lstat(p)
	if err != nil {
		s.RepairCommand = repair
		return s
	}

	if fi.Mode()&os.ModeSymlink != 0 {
		s.Status = skillStatusSymlink
	} else {
		s.Status = skillStatusDirectory
	}

	m, err := readManifest(p)
	if err != nil {
		s.Status = skillStatusForeign
		return s
	}
	s.Manifest = m

	switch {
	case Version == "dev":
		s.Fresh = "unknown"
	case m.InstalledVersion == Version && m.BuildCommit == Commit:
		s.Fresh = "yes"
	default:
		s.Fresh = "no"
		s.RepairCommand = repair
	}
	return s
}

func currentBinaryPath() string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		return resolved
	}
	return exe
}

func mustHome() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return string(filepath.Separator) + "\x00"
	}
	return home
}

// skillStatusesIn reports every shipped skill in one directory.
func skillStatusesIn(t agentTarget, dir string) ([]skillStatus, error) {
	names, err := skills.Names()
	if err != nil {
		return nil, err
	}
	out := make([]skillStatus, 0, len(names))
	for _, n := range names {
		out = append(out, statusFor(t, dir, n))
	}
	return out, nil
}
