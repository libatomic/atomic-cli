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
	"bufio"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/mattn/go-isatty"
	"github.com/urfave/cli/v3"
)

const (
	// envAgentDefaults switches the CLI into agent mode: JSON output by
	// default and no interactive prompts. AI coding agents set it in the
	// environment they spawn the CLI from.
	envAgentDefaults = "PASSPORT_AGENT_DEFAULTS"

	// envAgentDefaultsAlt is accepted as an alias of envAgentDefaults.
	envAgentDefaultsAlt = "ATOMIC_AGENT_DEFAULTS"

	// envOutFormat is the env var backing the global --out-format flag.
	envOutFormat = "PASSPORT_OUT_FORMAT"

	// metaLocal marks a command (or command group) that runs entirely on the
	// local machine: no backend client is built and no instance is resolved.
	metaLocal = "local"
)

var (
	errNonInteractive = errors.New("confirmation required but no interactive terminal is attached; re-run interactively or pass --yes where supported")
)

// agentDefaults reports whether the caller asked for agent-friendly defaults.
func agentDefaults() bool {
	for _, k := range []string{envAgentDefaults, envAgentDefaultsAlt} {
		switch strings.ToLower(strings.TrimSpace(os.Getenv(k))) {
		case "1", "true", "yes", "on":
			return true
		}
	}
	return false
}

// applyAgentDefaults must run before flags are parsed. In agent mode it
// defaults --out-format to json unless the caller set it explicitly.
func applyAgentDefaults() {
	if !agentDefaults() {
		return
	}
	if os.Getenv(envOutFormat) == "" {
		os.Setenv(envOutFormat, "json")
	}
}

// interactive reports whether it is safe to prompt the user on the terminal.
func interactive() bool {
	if agentDefaults() {
		return false
	}
	return isTerminal(os.Stdin) && isTerminal(os.Stdout)
}

func isTerminal(f *os.File) bool {
	return isatty.IsTerminal(f.Fd()) || isatty.IsCygwinTerminal(f.Fd())
}

// localMeta returns the Metadata used by commands that never touch the
// backend. They are skipped by the MCP server as well.
func localMeta() map[string]any {
	return map[string]any{
		metaLocal:  true,
		"mcp:skip": true,
	}
}

// readOnlyLocalMeta is localMeta for commands that only inspect state.
func readOnlyLocalMeta() map[string]any {
	m := localMeta()
	m["mcp:readOnly"] = true
	return m
}

// resolveInvokedLineage returns the chain of commands the current arguments
// select, from the first subcommand down to the leaf. Before hooks run once
// at the leaf after every level has parsed its flags, so at hook time each
// command's Args().First() is the next subcommand name.
func resolveInvokedLineage(root *cli.Command) []*cli.Command {
	var lineage []*cli.Command
	c := root
	for c != nil {
		next := c.Command(c.Args().First())
		if next == nil {
			break
		}
		lineage = append(lineage, next)
		c = next
	}
	return lineage
}

// isLocalCommand reports whether the invoked command, or any group above
// it, is marked local via metaLocal.
func isLocalCommand(root *cli.Command) bool {
	for _, c := range resolveInvokedLineage(root) {
		if v, ok := c.Metadata[metaLocal]; ok {
			if b, _ := v.(bool); b {
				return true
			}
		}
	}
	return false
}

// confirmAction prompts for a yes/no answer on stderr. It fails with
// errNonInteractive when no terminal is attached or agent mode is on.
func confirmAction(title string) (bool, error) {
	answer, err := promptLine(fmt.Sprintf("%s [y/N]: ", title))
	if err != nil {
		return false, err
	}
	answer = strings.ToLower(answer)
	return answer == "y" || answer == "yes", nil
}

// promptLine prints the prompt on stderr and returns one trimmed line from
// stdin. It fails with errNonInteractive when no terminal is attached or
// agent mode is on.
func promptLine(prompt string) (string, error) {
	if !interactive() {
		return "", errNonInteractive
	}
	fmt.Fprint(os.Stderr, prompt)
	answer, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(answer), nil
}
