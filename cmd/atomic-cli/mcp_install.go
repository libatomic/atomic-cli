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
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/urfave/cli/v3"
)

type (
	// mcpTarget is one agent host whose config can carry an MCP server entry.
	mcpTarget struct {
		// Name is the --target value.
		Name string
		// Label is the human-readable host name.
		Label string
		// Format is "json" (mcpServers map) or "toml" ([mcp_servers.<name>]).
		Format string
		// GlobalPath returns the per-user config file.
		GlobalPath func(home string) string
		// LocalPath is the project-relative config file, or "" when the host
		// has no project scope.
		LocalPath string
	}

	// mcpServerEntry is the stdio server definition written into configs.
	mcpServerEntry struct {
		Command string            `json:"command"`
		Args    []string          `json:"args"`
		Env     map[string]string `json:"env,omitempty"`
	}

	// mcpRegistration describes one target's state for status and doctor.
	mcpRegistration struct {
		Target        string   `json:"target"`
		Label         string   `json:"label"`
		Path          string   `json:"path"`
		Exists        bool     `json:"exists"`
		Registered    bool     `json:"registered"`
		Name          string   `json:"name,omitempty"`
		Command       string   `json:"command,omitempty"`
		Args          []string `json:"args,omitempty"`
		BinaryExists  bool     `json:"binaryExists"`
		BinaryCurrent bool     `json:"binaryCurrent"`
		Error         string   `json:"error,omitempty"`
		RepairCommand string   `json:"repairCommand,omitempty"`
	}
)

const (
	defaultMCPServerName = "atomic"
	mcpTargetDefault     = "claude-desktop"
)

var (
	mcpTargets = []mcpTarget{
		{
			Name:       "claude-desktop",
			Label:      "Claude Desktop",
			Format:     "json",
			GlobalPath: claudeDesktopConfigPath,
		},
		{
			Name:   "claude",
			Label:  "Claude Code",
			Format: "json",
			GlobalPath: func(home string) string {
				return filepath.Join(home, ".claude.json")
			},
			LocalPath: ".mcp.json",
		},
		{
			Name:   "cursor",
			Label:  "Cursor",
			Format: "json",
			GlobalPath: func(home string) string {
				return filepath.Join(home, ".cursor", "mcp.json")
			},
			LocalPath: filepath.Join(".cursor", "mcp.json"),
		},
		{
			Name:   "codex",
			Label:  "Codex",
			Format: "toml",
			GlobalPath: func(home string) string {
				return filepath.Join(home, ".codex", "config.toml")
			},
		},
	}

	mcpTargetFlags = []cli.Flag{
		&cli.StringSliceFlag{
			Name:  "target",
			Usage: "agent host config to write (claude-desktop|claude|cursor|codex). Repeatable. Default: claude-desktop",
		},
		&cli.BoolFlag{
			Name:  "all-targets",
			Usage: "write every known agent host config",
		},
		&cli.BoolFlag{
			Name:    "local",
			Aliases: []string{"l"},
			Usage:   "write the project-scoped config in the current directory (claude: .mcp.json, cursor: .cursor/mcp.json)",
		},
		&cli.StringFlag{
			Name:  "name",
			Usage: "server name inside the host config",
			Value: defaultMCPServerName,
		},
	}

	mcpInstallCmd = &cli.Command{
		Name:     "install",
		Usage:    "register `atomic-cli mcp` as a server in Claude Desktop and other agent host configs",
		Metadata: localMeta(),
		Flags: append(append([]cli.Flag{}, mcpTargetFlags...),
			&cli.BoolFlag{
				Name:  "allow-write",
				Usage: "register the server with --allow-write so mutating tools are available",
			},
			&cli.StringFlag{
				Name:  "binary",
				Usage: "absolute path to the atomic-cli binary to register (default: this executable, or atomic-cli on PATH if that resolves to the same file)",
			},
		),
		Action: mcpInstall,
	}

	mcpUninstallCmd = &cli.Command{
		Name:     "uninstall",
		Usage:    "remove the atomic-cli server entry from agent host configs",
		Metadata: localMeta(),
		Flags:    mcpTargetFlags,
		Action:   mcpUninstall,
	}

	mcpStatusCmd = &cli.Command{
		Name:     "status",
		Usage:    "show which agent host configs register atomic-cli as an MCP server",
		Metadata: readOnlyLocalMeta(),
		Flags: []cli.Flag{
			&cli.BoolFlag{
				Name:    "local",
				Aliases: []string{"l"},
				Usage:   "include project-scoped configs in the current directory",
			},
			&cli.StringFlag{
				Name:  "name",
				Usage: "server name to look for",
				Value: defaultMCPServerName,
			},
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			regs := mcpRegistrations(cmd.String("name"), cmd.Bool("local"))
			PrintResult(cmd, regs, WithFields("target", "path", "registered", "command", "binaryCurrent", "error"))
			return nil
		},
	}
)

func claudeDesktopConfigPath(home string) string {
	switch runtime.GOOS {
	case "darwin":
		return filepath.Join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json")
	case "windows":
		if appdata := os.Getenv("APPDATA"); appdata != "" {
			return filepath.Join(appdata, "Claude", "claude_desktop_config.json")
		}
		return filepath.Join(home, "AppData", "Roaming", "Claude", "claude_desktop_config.json")
	default:
		return filepath.Join(home, ".config", "Claude", "claude_desktop_config.json")
	}
}

func selectedMCPTargets(cmd *cli.Command) ([]mcpTarget, error) {
	if cmd.Bool("all-targets") {
		return mcpTargets, nil
	}
	wanted := cmd.StringSlice("target")
	if len(wanted) == 0 {
		wanted = []string{mcpTargetDefault}
	}

	seen := map[string]bool{}
	var out []mcpTarget
	for _, w := range wanted {
		w = strings.ToLower(strings.TrimSpace(w))
		t, ok := findMCPTarget(w)
		if !ok {
			return nil, fmt.Errorf("unknown target %q; known: %s", w, strings.Join(mcpTargetNames(), ", "))
		}
		if !seen[t.Name] {
			seen[t.Name] = true
			out = append(out, t)
		}
	}
	return out, nil
}

func findMCPTarget(name string) (mcpTarget, bool) {
	for _, t := range mcpTargets {
		if t.Name == name {
			return t, true
		}
	}
	return mcpTarget{}, false
}

func mcpTargetNames() []string {
	out := make([]string, 0, len(mcpTargets))
	for _, t := range mcpTargets {
		out = append(out, t.Name)
	}
	return out
}

// mcpConfigPathFor resolves the config file for a target.
func mcpConfigPathFor(t mcpTarget, local bool) (string, error) {
	if local {
		if t.LocalPath == "" {
			return "", fmt.Errorf("%s has no project-scoped config; omit --local", t.Label)
		}
		return filepath.Abs(t.LocalPath)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home directory: %w", err)
	}
	return t.GlobalPath(home), nil
}

// mcpEntryFor builds the server entry: the binary plus the root flags that
// select profile, credentials file, host and instance. Secrets are never
// written; they stay in the credentials file.
func mcpEntryFor(cmd *cli.Command, binary string) mcpServerEntry {
	args := []string{}
	if profile != "" && profile != DefaultProfile {
		args = append(args, "-p", profile)
	}
	if mainCmd.IsSet("credentials") {
		args = append(args, "-c", creds)
	}
	if mainCmd.IsSet("host") {
		args = append(args, "--host", mainCmd.String("host"))
	}
	if mainCmd.IsSet("instance_id") {
		args = append(args, "-i", mainCmd.String("instance_id"))
	}
	args = append(args, "mcp")
	if cmd.Bool("allow-write") {
		args = append(args, "--allow-write")
	}
	return mcpServerEntry{Command: binary, Args: args}
}

// registeredBinaryPath picks the path to write into host configs: an
// explicit --binary, else the PATH binary when it is this executable, else
// this executable.
func registeredBinaryPath(explicit string) (string, error) {
	if explicit != "" {
		if !filepath.IsAbs(explicit) {
			return "", fmt.Errorf("--binary must be an absolute path")
		}
		return explicit, nil
	}
	self := currentBinaryPath()
	if self == "" {
		return "", errors.New("could not resolve the running executable; pass --binary")
	}
	return self, nil
}

func mcpInstall(ctx context.Context, cmd *cli.Command) error {
	targets, err := selectedMCPTargets(cmd)
	if err != nil {
		return err
	}
	return mcpInstallTargets(cmd, targets)
}

// mcpInstallFor registers the server for the named targets. Used by setup,
// whose flag set lacks --target/--binary.
func mcpInstallFor(cmd *cli.Command, names []string) error {
	var targets []mcpTarget
	for _, n := range names {
		t, ok := findMCPTarget(strings.ToLower(strings.TrimSpace(n)))
		if !ok {
			return fmt.Errorf("unknown mcp host %q; known: %s", n, strings.Join(mcpTargetNames(), ", "))
		}
		targets = append(targets, t)
	}
	return mcpInstallTargets(cmd, targets)
}

func mcpInstallTargets(cmd *cli.Command, targets []mcpTarget) error {
	explicit := ""
	if cmd.IsSet("binary") {
		explicit = cmd.String("binary")
	}
	binary, err := registeredBinaryPath(explicit)
	if err != nil {
		return err
	}

	name := defaultMCPServerName
	if cmd.IsSet("name") {
		name = cmd.String("name")
	}
	entry := mcpEntryFor(cmd, binary)

	for _, t := range targets {
		path, err := mcpConfigPathFor(t, cmd.Bool("local"))
		if err != nil {
			return err
		}
		switch t.Format {
		case "json":
			err = writeJSONMCPEntry(path, name, entry)
		case "toml":
			err = writeTOMLMCPEntry(path, name, entry)
		}
		if err != nil {
			return fmt.Errorf("%s: %w", t.Label, err)
		}
		fmt.Printf("registered %-16s %s -> %s %s\n", t.Label, name, entry.Command, strings.Join(entry.Args, " "))

		if t.Name == "claude-desktop" && claudeDesktopRunning() {
			fmt.Fprintln(os.Stderr, "WARNING: Claude Desktop is running. It rewrites its config file from memory when it quits, which will discard this entry.")
			fmt.Fprintln(os.Stderr, "         Quit Claude Desktop fully, run `atomic-cli mcp install` again, then start it.")
		}
	}

	fmt.Println("restart the host application to load the server; run `atomic-cli mcp status` to verify")
	return nil
}

// claudeDesktopRunning reports whether the Claude Desktop app is running.
// Desktop persists its config from memory on quit, so edits made while it
// runs are lost; callers warn when that is about to happen.
func claudeDesktopRunning() bool {
	if runtime.GOOS != "darwin" {
		return false
	}
	// pgrep does not reliably see the app from a sandboxed shell; ps does.
	// Match the app binary exactly so Claude Code's lowercase `claude`
	// helper and other processes are not mistaken for Desktop.
	out, err := exec.Command("ps", "-axo", "comm").Output()
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasSuffix(strings.TrimSpace(line), "/Claude.app/Contents/MacOS/Claude") {
			return true
		}
	}
	return false
}

func mcpUninstall(ctx context.Context, cmd *cli.Command) error {
	targets, err := selectedMCPTargets(cmd)
	if err != nil {
		return err
	}
	name := cmd.String("name")

	for _, t := range targets {
		path, err := mcpConfigPathFor(t, cmd.Bool("local"))
		if err != nil {
			return err
		}
		var removed bool
		switch t.Format {
		case "json":
			removed, err = removeJSONMCPEntry(path, name)
		case "toml":
			removed, err = removeTOMLMCPEntry(path, name)
		}
		if err != nil {
			return fmt.Errorf("%s: %w", t.Label, err)
		}
		if removed {
			fmt.Printf("removed %s from %s\n", name, path)
		}
	}
	return nil
}

// mcpRegistrations inspects every target (global, plus local when asked).
func mcpRegistrations(name string, includeLocal bool) []mcpRegistration {
	var out []mcpRegistration
	for _, t := range mcpTargets {
		if p, err := mcpConfigPathFor(t, false); err == nil {
			out = append(out, inspectMCPRegistration(t, p, name, false))
		}
		if includeLocal && t.LocalPath != "" {
			if p, err := mcpConfigPathFor(t, true); err == nil {
				if _, err := os.Stat(p); err == nil {
					out = append(out, inspectMCPRegistration(t, p, name, true))
				}
			}
		}
	}
	return out
}

func inspectMCPRegistration(t mcpTarget, path, name string, local bool) mcpRegistration {
	r := mcpRegistration{Target: t.Name, Label: t.Label, Path: path, Name: name}

	repair := "atomic-cli mcp install --target " + t.Name
	if local {
		repair += " --local"
	}

	if _, err := os.Stat(path); err != nil {
		r.RepairCommand = repair
		return r
	}
	r.Exists = true

	var (
		entry *mcpServerEntry
		err   error
	)
	switch t.Format {
	case "json":
		entry, err = readJSONMCPEntry(path, name)
	case "toml":
		entry, err = readTOMLMCPEntry(path, name)
	}
	if err != nil {
		r.Error = err.Error()
		return r
	}
	if entry == nil {
		r.RepairCommand = repair
		return r
	}

	r.Registered = true
	r.Command = entry.Command
	r.Args = entry.Args
	if _, err := os.Stat(entry.Command); err == nil {
		r.BinaryExists = true
	}
	if resolved, err := filepath.EvalSymlinks(entry.Command); err == nil && resolved == currentBinaryPath() {
		r.BinaryCurrent = true
	}
	if !r.BinaryExists {
		r.Error = "registered binary does not exist"
		r.RepairCommand = repair
	}
	return r
}

// --- JSON hosts (mcpServers map) ---

func readJSONConfig(path string) (map[string]any, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return map[string]any{}, nil
	}
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(string(data)) == "" {
		return map[string]any{}, nil
	}
	var cfg map[string]any
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("%s is not valid JSON (%v); fix it by hand before atomic-cli will edit it", path, err)
	}
	if cfg == nil {
		cfg = map[string]any{}
	}
	return cfg, nil
}

func writeJSONConfig(path string, cfg map[string]any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	mode := os.FileMode(0o600)
	if fi, err := os.Stat(path); err == nil {
		mode = fi.Mode().Perm()
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".atomic-cli.tmp"
	if err := os.WriteFile(tmp, append(data, '\n'), mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func writeJSONMCPEntry(path, name string, entry mcpServerEntry) error {
	cfg, err := readJSONConfig(path)
	if err != nil {
		return err
	}
	servers, _ := cfg["mcpServers"].(map[string]any)
	if servers == nil {
		servers = map[string]any{}
	}
	raw := map[string]any{"command": entry.Command, "args": entry.Args}
	if len(entry.Env) > 0 {
		raw["env"] = entry.Env
	}
	servers[name] = raw
	cfg["mcpServers"] = servers
	return writeJSONConfig(path, cfg)
}

func removeJSONMCPEntry(path, name string) (bool, error) {
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	cfg, err := readJSONConfig(path)
	if err != nil {
		return false, err
	}
	servers, _ := cfg["mcpServers"].(map[string]any)
	if servers == nil {
		return false, nil
	}
	if _, ok := servers[name]; !ok {
		return false, nil
	}
	delete(servers, name)
	cfg["mcpServers"] = servers
	return true, writeJSONConfig(path, cfg)
}

func readJSONMCPEntry(path, name string) (*mcpServerEntry, error) {
	cfg, err := readJSONConfig(path)
	if err != nil {
		return nil, err
	}
	servers, _ := cfg["mcpServers"].(map[string]any)
	raw, ok := servers[name].(map[string]any)
	if !ok {
		return nil, nil
	}
	e := &mcpServerEntry{}
	e.Command, _ = raw["command"].(string)
	if args, ok := raw["args"].([]any); ok {
		for _, a := range args {
			if s, ok := a.(string); ok {
				e.Args = append(e.Args, s)
			}
		}
	}
	return e, nil
}

// --- TOML hosts (Codex: [mcp_servers.<name>]) ---
//
// Codex's config.toml is hand-edited and carries comments, so it is patched
// textually: the [mcp_servers.<name>] table (and its sub-tables) is replaced
// or appended, everything else is left byte-for-byte.

func tomlTableHeader(name string) string {
	return "[mcp_servers." + tomlKey(name) + "]"
}

// tomlKey quotes the server name when it is not a bare key.
func tomlKey(name string) string {
	for _, r := range name {
		if !(r == '-' || r == '_' || (r >= '0' && r <= '9') || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')) {
			return fmt.Sprintf("%q", name)
		}
	}
	return name
}

func tomlString(s string) string {
	return fmt.Sprintf("%q", s)
}

func renderTOMLMCPEntry(name string, entry mcpServerEntry) string {
	var b strings.Builder
	b.WriteString(tomlTableHeader(name) + "\n")
	b.WriteString("command = " + tomlString(entry.Command) + "\n")
	quoted := make([]string, 0, len(entry.Args))
	for _, a := range entry.Args {
		quoted = append(quoted, tomlString(a))
	}
	b.WriteString("args = [" + strings.Join(quoted, ", ") + "]\n")
	if len(entry.Env) > 0 {
		b.WriteString("\n" + tomlTableHeader(name) + ".env]\n")
	}
	return b.String()
}

// stripTOMLMCPEntry removes the named table and its sub-tables from text and
// reports whether anything was removed.
func stripTOMLMCPEntry(text, name string) (string, bool) {
	header := tomlTableHeader(name)
	subPrefix := strings.TrimSuffix(header, "]") + "."

	lines := strings.Split(text, "\n")
	var out []string
	skipping, removed := false, false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "[") {
			if trimmed == header || strings.HasPrefix(trimmed, subPrefix) {
				skipping, removed = true, true
				continue
			}
			skipping = false
		}
		if skipping {
			continue
		}
		out = append(out, line)
	}
	result := strings.Join(out, "\n")
	result = strings.TrimRight(result, "\n")
	if result != "" {
		result += "\n"
	}
	return result, removed
}

func writeTOMLMCPEntry(path, name string, entry mcpServerEntry) error {
	data, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	text, _ := stripTOMLMCPEntry(string(data), name)
	if text != "" {
		text += "\n"
	}
	text += renderTOMLMCPEntry(name, entry)

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	mode := os.FileMode(0o600)
	if fi, err := os.Stat(path); err == nil {
		mode = fi.Mode().Perm()
	}
	tmp := path + ".atomic-cli.tmp"
	if err := os.WriteFile(tmp, []byte(text), mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func removeTOMLMCPEntry(path, name string) (bool, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	text, removed := stripTOMLMCPEntry(string(data), name)
	if !removed {
		return false, nil
	}
	mode := os.FileMode(0o600)
	if fi, err := os.Stat(path); err == nil {
		mode = fi.Mode().Perm()
	}
	return true, os.WriteFile(path, []byte(text), mode)
}

func readTOMLMCPEntry(path, name string) (*mcpServerEntry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	header := tomlTableHeader(name)
	var (
		in    bool
		entry *mcpServerEntry
	)
	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "[") {
			in = trimmed == header
			if in {
				entry = &mcpServerEntry{}
			}
			continue
		}
		if !in || entry == nil {
			continue
		}
		k, v, ok := strings.Cut(trimmed, "=")
		if !ok {
			continue
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		switch k {
		case "command":
			entry.Command = strings.Trim(v, `"`)
		case "args":
			v = strings.TrimSuffix(strings.TrimPrefix(v, "["), "]")
			for _, a := range strings.Split(v, ",") {
				a = strings.TrimSpace(a)
				if a != "" {
					entry.Args = append(entry.Args, strings.Trim(a, `"`))
				}
			}
		}
	}
	return entry, nil
}
