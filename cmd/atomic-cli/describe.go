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
	"fmt"
	"os"
	"strings"

	"github.com/urfave/cli/v3"
)

type (
	// commandDesc is the machine-readable description of one command node
	// emitted by `atomic-cli help describe`.
	commandDesc struct {
		Path        string        `json:"path"`
		Name        string        `json:"name"`
		Aliases     []string      `json:"aliases,omitempty"`
		Usage       string        `json:"usage,omitempty"`
		Description string        `json:"description,omitempty"`
		ArgsUsage   string        `json:"args_usage,omitempty"`
		Args        []argDesc     `json:"args,omitempty"`
		Flags       []flagDesc    `json:"flags,omitempty"`
		GlobalFlags []flagDesc    `json:"global_flags,omitempty"`
		ReadOnly    bool          `json:"read_only"`
		Destructive bool          `json:"destructive"`
		Local       bool          `json:"local"`
		Leaf        bool          `json:"leaf"`
		Commands    []commandDesc `json:"commands,omitempty"`
	}

	flagDesc struct {
		Name     string   `json:"name"`
		Aliases  []string `json:"aliases,omitempty"`
		Type     string   `json:"type"`
		Usage    string   `json:"usage,omitempty"`
		Default  any      `json:"default,omitempty"`
		Required bool     `json:"required,omitempty"`
		EnvVars  []string `json:"env_vars,omitempty"`
	}

	argDesc struct {
		Name     string `json:"name"`
		Required bool   `json:"required"`
		Variadic bool   `json:"variadic,omitempty"`
	}
)

var (
	// helpCmd replaces urfave/cli's built-in root `help` command so that
	// `help describe` can live under it. Defining a root command named
	// `help` suppresses the built-in without affecting -h or nested help.
	helpCmd = &cli.Command{
		Name:      "help",
		Aliases:   []string{"h"},
		Usage:     "show help for a command, or `help describe` for a machine-readable command tree",
		ArgsUsage: "[command]",
		HideHelp:  true,
		Metadata:  localMeta(),
		Commands: []*cli.Command{
			describeCmd,
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			if arg := cmd.Args().First(); arg != "" {
				return cli.ShowCommandHelp(ctx, cmd.Root(), arg)
			}
			return cli.ShowAppHelp(cmd.Root())
		},
	}

	describeCmd = &cli.Command{
		Name:      "describe",
		Usage:     "emit the command tree, flags and arguments as JSON (for agents and tooling)",
		ArgsUsage: "[command path...]",
		Metadata:  readOnlyLocalMeta(),
		Flags: []cli.Flag{
			&cli.BoolFlag{
				Name:  "leaves-only",
				Usage: "flatten the tree to runnable leaf commands",
			},
			&cli.IntFlag{
				Name:  "depth",
				Usage: "maximum nesting depth below the selected command (0 = unlimited)",
			},
		},
		Action: describeAction,
	}
)

func describeAction(ctx context.Context, cmd *cli.Command) error {
	root := cmd.Root()

	target := root
	path := []string{}
	for _, name := range cmd.Args().Slice() {
		next := target.Command(name)
		if next == nil {
			return fmt.Errorf("unknown command %q under %q", name, strings.Join(append([]string{root.Name}, path...), " "))
		}
		target = next
		path = append(path, next.Name)
	}

	desc := describeCommand(target, path, cmd.Int("depth"))
	if target == root {
		desc.Path = root.Name
		desc.Name = root.Name
		desc.GlobalFlags = describeFlags(root.Flags)
	} else {
		desc.GlobalFlags = describeFlags(root.Flags)
	}

	var out any = desc
	if cmd.Bool("leaves-only") {
		out = flattenLeaves(desc)
	}

	enc := json.NewEncoder(os.Stdout)
	if cmd.String("out-format") == "json-pretty" || cmd.String("out-format") == "table" {
		enc.SetIndent("", "  ")
	}
	return enc.Encode(out)
}

// describeCommand builds the description of c (located at path) and its
// visible descendants. depth limits recursion; 0 means unlimited.
func describeCommand(c *cli.Command, path []string, depth int) commandDesc {
	d := commandDesc{
		Path:        strings.Join(path, " "),
		Name:        c.Name,
		Aliases:     c.Aliases,
		Usage:       strings.TrimSpace(c.Usage),
		Description: strings.TrimSpace(c.Description),
		ArgsUsage:   c.ArgsUsage,
		Local:       hasBoolMeta(c, metaLocal),
		// urfave/cli installs a default help Action on the root command, so
		// only subcommands with an Action count as runnable leaves.
		Leaf: len(path) > 0 && c.Action != nil,
	}

	if len(path) > 0 {
		ann := annotationsFor(c, path)
		d.ReadOnly = ann.ReadOnlyHint
		d.Destructive = ann.DestructiveHint != nil && *ann.DestructiveHint
	}

	d.Flags = describeFlags(c.Flags)

	for _, m := range argTokenRE.FindAllStringSubmatch(c.ArgsUsage, -1) {
		d.Args = append(d.Args, argDesc{
			Name:     m[2],
			Required: m[1] == "<",
			Variadic: m[4] == "...",
		})
	}

	if depth == 1 {
		return d
	}
	next := depth
	if next > 0 {
		next--
	}

	for _, sub := range c.Commands {
		if sub.Hidden || sub.Name == "help" {
			continue
		}
		d.Commands = append(d.Commands, describeCommand(sub, append(append([]string{}, path...), sub.Name), next))
	}

	return d
}

func describeFlags(flags []cli.Flag) []flagDesc {
	out := make([]flagDesc, 0, len(flags))
	for _, f := range flags {
		names := f.Names()
		if len(names) == 0 || names[0] == "help" || names[0] == "version" {
			continue
		}

		fd := flagDesc{
			Name:  names[0],
			Usage: flagUsage(f),
			Type:  flagType(f),
		}
		if len(names) > 1 {
			fd.Aliases = names[1:]
		}
		if rf, ok := f.(cli.RequiredFlag); ok && rf.IsRequired() {
			fd.Required = true
		}
		if df, ok := f.(cli.DocGenerationFlag); ok {
			if v := df.GetDefaultText(); v != "" {
				fd.Default = v
			}
			fd.EnvVars = df.GetEnvVars()
		}
		out = append(out, fd)
	}
	return out
}

func flagType(f cli.Flag) string {
	s := flagSchema(f)
	if t, ok := s["type"].(string); ok {
		if t == "array" {
			return "array[string]"
		}
		return t
	}
	return "string"
}

func flattenLeaves(d commandDesc) []commandDesc {
	var out []commandDesc
	var walk func(n commandDesc)
	walk = func(n commandDesc) {
		if n.Leaf {
			leaf := n
			leaf.Commands = nil
			out = append(out, leaf)
			return
		}
		for _, c := range n.Commands {
			walk(c)
		}
	}
	walk(d)
	return out
}

func hasBoolMeta(c *cli.Command, key string) bool {
	if v, ok := c.Metadata[key]; ok {
		b, _ := v.(bool)
		return b
	}
	return false
}
