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
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestJSONMCPEntryRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "claude_desktop_config.json")

	// Pre-existing unrelated keys and another server must survive.
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	seed := `{"preferences":{"theme":"dark"},"mcpServers":{"other":{"command":"x","args":[]}}}`
	if err := os.WriteFile(path, []byte(seed), 0o644); err != nil {
		t.Fatal(err)
	}

	entry := mcpServerEntry{Command: "/usr/local/bin/atomic-cli", Args: []string{"-p", "prod", "mcp"}}
	if err := writeJSONMCPEntry(path, "atomic", entry); err != nil {
		t.Fatal(err)
	}

	got, err := readJSONMCPEntry(path, "atomic")
	if err != nil || got == nil {
		t.Fatalf("read: %v %v", got, err)
	}
	if got.Command != entry.Command || strings.Join(got.Args, " ") != "-p prod mcp" {
		t.Fatalf("round trip mismatch: %+v", got)
	}

	var cfg map[string]any
	data, _ := os.ReadFile(path)
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatal(err)
	}
	if _, ok := cfg["preferences"]; !ok {
		t.Fatal("unrelated key dropped")
	}
	if _, ok := cfg["mcpServers"].(map[string]any)["other"]; !ok {
		t.Fatal("other server dropped")
	}

	removed, err := removeJSONMCPEntry(path, "atomic")
	if err != nil || !removed {
		t.Fatalf("remove: %v %v", removed, err)
	}
	if got, _ := readJSONMCPEntry(path, "atomic"); got != nil {
		t.Fatal("entry still present after remove")
	}
	if removed, _ := removeJSONMCPEntry(path, "atomic"); removed {
		t.Fatal("second remove reported a removal")
	}
}

func TestJSONMCPEntryRefusesInvalidJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mcp.json")
	if err := os.WriteFile(path, []byte(`{"mcpServers": {"broken"{}}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	err := writeJSONMCPEntry(path, "atomic", mcpServerEntry{Command: "/x"})
	if err == nil || !strings.Contains(err.Error(), "not valid JSON") {
		t.Fatalf("expected invalid JSON error, got %v", err)
	}
	data, _ := os.ReadFile(path)
	if !strings.Contains(string(data), "broken") {
		t.Fatal("invalid file was overwritten")
	}
}

func TestTOMLMCPEntryPatching(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	seed := `model = "gpt"

[mcp_servers.node_repl]
args = []
command = "/bin/node_repl"

[mcp_servers.node_repl.env]
FOO = "bar"

[features]
js_repl = false
`
	if err := os.WriteFile(path, []byte(seed), 0o644); err != nil {
		t.Fatal(err)
	}

	entry := mcpServerEntry{Command: "/opt/homebrew/bin/atomic-cli", Args: []string{"mcp"}}
	if err := writeTOMLMCPEntry(path, "atomic", entry); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	text := string(data)
	for _, want := range []string{`model = "gpt"`, "[mcp_servers.node_repl.env]", `FOO = "bar"`, "[features]", "[mcp_servers.atomic]", `command = "/opt/homebrew/bin/atomic-cli"`, `args = ["mcp"]`} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %q in:\n%s", want, text)
		}
	}

	got, err := readTOMLMCPEntry(path, "atomic")
	if err != nil || got == nil || got.Command != entry.Command || len(got.Args) != 1 || got.Args[0] != "mcp" {
		t.Fatalf("read back: %+v %v", got, err)
	}

	// Re-install replaces rather than duplicates.
	entry.Args = []string{"-p", "prod", "mcp"}
	if err := writeTOMLMCPEntry(path, "atomic", entry); err != nil {
		t.Fatal(err)
	}
	data, _ = os.ReadFile(path)
	if strings.Count(string(data), "[mcp_servers.atomic]") != 1 {
		t.Fatalf("duplicate table:\n%s", data)
	}
	got, _ = readTOMLMCPEntry(path, "atomic")
	if strings.Join(got.Args, " ") != "-p prod mcp" {
		t.Fatalf("args not replaced: %v", got.Args)
	}

	removed, err := removeTOMLMCPEntry(path, "atomic")
	if err != nil || !removed {
		t.Fatalf("remove: %v %v", removed, err)
	}
	data, _ = os.ReadFile(path)
	if strings.Contains(string(data), "mcp_servers.atomic") || !strings.Contains(string(data), "[mcp_servers.node_repl.env]") {
		t.Fatalf("remove damaged file:\n%s", data)
	}
}

func TestSkillBodyStripsFrontmatter(t *testing.T) {
	body, err := skillBody("atomic-cli")
	if err != nil {
		t.Fatal(err)
	}
	if strings.HasPrefix(body, "---") || !strings.HasPrefix(body, "# atomic-cli") {
		t.Fatalf("frontmatter not stripped:\n%.80s", body)
	}
	if d := skillDescription("atomic-cli-billing"); !strings.Contains(d, "Stripe") || strings.Contains(d, "\n") {
		t.Fatalf("bad description: %q", d)
	}
}
