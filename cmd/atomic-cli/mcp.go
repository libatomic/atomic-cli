/*
 * This file is part of the Passport Atomic Stack (https://github.com/libatomic/atomic).
 * Copyright (c) 2026 Passport, LLC.
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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/apex/log"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/urfave/cli/v3"
)

var (
	mcpCmd = &cli.Command{
		Name:  "mcp",
		Usage: "run atomic-cli as an MCP server (exposes CLI commands as tools)",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  "transport",
				Usage: "transport: stdio or http",
				Value: "stdio",
			},
			&cli.StringFlag{
				Name:  "listen",
				Usage: "address to listen on for http transport",
				Value: "127.0.0.1:8765",
			},
			&cli.BoolFlag{
				Name:  "allow-write",
				Usage: "register mutating tools (defaults to read-only)",
				Value: false,
			},
			&cli.StringFlag{
				Name:  "tool-prefix",
				Usage: "prefix added to every tool name (e.g. \"atomic.\")",
			},
		},
		Action: runMCPServer,
	}

	// forwardedRootArgs is captured at server startup. Each tool dispatch
	// spawns a fresh `atomic-cli` subprocess and prepends these flags so the
	// subprocess shares auth/instance config with the parent server.
	forwardedRootArgs []string

	// selfExecutable is the absolute path to the running binary, resolved
	// once at server startup so subprocess spawns don't depend on $PATH.
	selfExecutable string

	readOnlyVerbs    = regexp.MustCompile(`^(list|get|search|show|describe|tail|wait|status|view|inspect|count)$`)
	destructiveVerbs = regexp.MustCompile(`^(delete|cancel|drop|purge|reset|destroy|remove)$`)

	// matches `<name>` and `[name]` tokens in ArgsUsage, with optional `...` for variadic.
	argTokenRE = regexp.MustCompile(`([\<\[])([a-zA-Z0-9_\-]+)([\>\]])(\.{3})?`)

	// tool names allowed by the MCP spec: [A-Za-z0-9_.\-]+ — convert anything else to `_`.
	toolNameSanitizer = regexp.MustCompile(`[^A-Za-z0-9_.\-]`)
)

func runMCPServer(ctx context.Context, cmd *cli.Command) error {
	prefix := cmd.String("tool-prefix")
	allowWrite := cmd.Bool("allow-write")

	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve own executable: %w", err)
	}
	selfExecutable = exe
	forwardedRootArgs = captureRootArgs(cmd)
	log.Infof("mcp: forwarding root flags %v to subprocess invocations", redactSecrets(forwardedRootArgs))

	impl := &mcp.Implementation{
		Name:    "atomic-cli",
		Title:   "Atomic CLI",
		Version: Version,
	}
	srv := mcp.NewServer(impl, nil)

	tools := buildTools(mainCmd, prefix, allowWrite)
	if len(tools) == 0 {
		return fmt.Errorf("no MCP tools to register")
	}
	for _, t := range tools {
		t := t
		srv.AddTool(t.tool, t.handler)
	}
	log.Infof("registered %d MCP tools (allow-write=%v)", len(tools), allowWrite)

	switch cmd.String("transport") {
	case "stdio", "":
		return srv.Run(ctx, &mcp.StdioTransport{})

	case "http":
		addr := cmd.String("listen")
		handler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return srv }, nil)
		httpSrv := &http.Server{
			Addr:              addr,
			Handler:           handler,
			ReadHeaderTimeout: 10 * time.Second,
		}

		errCh := make(chan error, 1)
		go func() {
			log.Infof("MCP HTTP server listening on %s", addr)
			errCh <- httpSrv.ListenAndServe()
		}()

		select {
		case err := <-errCh:
			if err != nil && err != http.ErrServerClosed {
				return err
			}
			return nil
		case <-ctx.Done():
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			return httpSrv.Shutdown(shutdownCtx)
		}

	default:
		return fmt.Errorf("unknown transport %q (want stdio or http)", cmd.String("transport"))
	}
}

type (
	toolBinding struct {
		tool    *mcp.Tool
		handler mcp.ToolHandler
	}

	positional struct {
		name     string
		variadic bool
	}
)

// buildTools walks every leaf command under root and synthesizes an MCP tool.
// allowWrite=false skips tools whose annotations are not read-only.
func buildTools(root *cli.Command, prefix string, allowWrite bool) []toolBinding {
	var out []toolBinding

	var walk func(c *cli.Command, path []string)
	walk = func(c *cli.Command, path []string) {
		if shouldSkip(c) {
			return
		}
		// A command with an Action is treated as a leaf even when urfave/cli
		// auto-injects a `help` subcommand. Pure command groups have no Action.
		if c.Action != nil {
			ann := annotationsFor(c, path)
			if !allowWrite && !ann.ReadOnlyHint {
				return
			}

			name := prefix + sanitizeToolName(strings.Join(path, "."))
			schema := schemaFor(c)

			desc := strings.TrimSpace(c.Usage)
			if c.ArgsUsage != "" {
				desc = strings.TrimSpace(desc + " — args: " + c.ArgsUsage)
			}
			if desc == "" {
				desc = "atomic-cli " + strings.Join(path, " ")
			}

			tool := &mcp.Tool{
				Name:        name,
				Description: desc,
				InputSchema: schema,
				Annotations: ann,
			}

			out = append(out, toolBinding{
				tool:    tool,
				handler: makeDispatcher(append([]string{}, path...), c),
			})
			return
		}
		for _, sub := range c.Commands {
			walk(sub, append(append([]string{}, path...), sub.Name))
		}
	}

	for _, sub := range root.Commands {
		walk(sub, []string{sub.Name})
	}
	return out
}

func shouldSkip(c *cli.Command) bool {
	if c.Hidden {
		return true
	}
	switch c.Name {
	case "mcp", "status":
		// `mcp` would self-recurse; `status` is an interactive bubbletea TUI
		// that takes over the terminal and is incompatible with stdio MCP.
		return true
	case "help", "h":
		return true
	}
	if v, ok := c.Metadata["mcp:skip"]; ok {
		if b, _ := v.(bool); b {
			return true
		}
	}
	return false
}

func annotationsFor(c *cli.Command, path []string) *mcp.ToolAnnotations {
	leaf := path[len(path)-1]
	ann := &mcp.ToolAnnotations{
		Title: strings.Join(path, " "),
	}

	switch {
	case readOnlyVerbs.MatchString(leaf):
		ann.ReadOnlyHint = true
	case destructiveVerbs.MatchString(leaf):
		t := true
		ann.DestructiveHint = &t
	}

	if v, ok := c.Metadata["mcp:readOnly"]; ok {
		if b, _ := v.(bool); b {
			ann.ReadOnlyHint = true
			ann.DestructiveHint = nil
		}
	}
	if v, ok := c.Metadata["mcp:destructive"]; ok {
		if b, _ := v.(bool); b {
			t := true
			ann.DestructiveHint = &t
			ann.ReadOnlyHint = false
		}
	}
	return ann
}

// schemaFor returns a JSON Schema (as map[string]any) covering the command's
// flags plus any `<positional>` / `[positional]` tokens parsed from ArgsUsage.
func schemaFor(c *cli.Command) map[string]any {
	props := map[string]any{}
	required := []string{}

	for _, f := range c.Flags {
		name := f.Names()[0]
		if name == "help" || name == "h" {
			continue
		}
		entry := flagSchema(f)
		if u := flagUsage(f); u != "" {
			entry["description"] = u
		}
		props[name] = entry
		if rf, ok := f.(cli.RequiredFlag); ok && rf.IsRequired() {
			required = append(required, name)
		}
	}

	for _, m := range argTokenRE.FindAllStringSubmatch(c.ArgsUsage, -1) {
		open, name, _, dots := m[1], m[2], m[3], m[4]
		entry := map[string]any{}
		if dots == "..." {
			entry["type"] = "array"
			entry["items"] = map[string]any{"type": "string"}
		} else {
			entry["type"] = "string"
		}
		entry["description"] = fmt.Sprintf("positional arg %q", name)
		props[name] = entry
		if open == "<" {
			required = append(required, name)
		}
	}

	schema := map[string]any{
		"type":       "object",
		"properties": props,
	}
	if len(required) > 0 {
		schema["required"] = required
	}
	return schema
}

func flagSchema(f cli.Flag) map[string]any {
	switch f.(type) {
	case *cli.BoolFlag:
		return map[string]any{"type": "boolean"}
	case *cli.IntFlag, *cli.Int64Flag, *cli.UintFlag, *cli.Uint64Flag:
		return map[string]any{"type": "integer"}
	case *cli.Float32Flag, *cli.Float64Flag:
		return map[string]any{"type": "number"}
	case *cli.StringSliceFlag, *cli.IntSliceFlag:
		return map[string]any{"type": "array", "items": map[string]any{"type": "string"}}
	case *cli.TimestampFlag:
		return map[string]any{"type": "string", "format": "date-time"}
	default:
		return map[string]any{"type": "string"}
	}
}

func flagUsage(f cli.Flag) string {
	type usager interface{ GetUsage() string }
	if u, ok := f.(usager); ok {
		return u.GetUsage()
	}
	return ""
}

func sanitizeToolName(s string) string {
	return toolNameSanitizer.ReplaceAllString(s, "_")
}

// captureRootArgs reads the root flag values the user passed when launching
// the MCP server (auth, host, instance, etc) and emits them in `--name=value`
// form. These get forwarded to every subprocess invocation so the spawned
// `atomic-cli` shares the same auth/instance config.
func captureRootArgs(mcpCmd *cli.Command) []string {
	var out []string
	skip := map[string]bool{"verbose": true, "help": true, "h": true}
	for _, f := range mainCmd.Flags {
		name := f.Names()[0]
		if skip[name] {
			continue
		}
		if !mainCmd.IsSet(name) {
			continue
		}
		switch f.(type) {
		case *cli.BoolFlag:
			if mainCmd.Bool(name) {
				out = append(out, "--"+name)
			}
		case *cli.StringSliceFlag:
			for _, v := range mainCmd.StringSlice(name) {
				out = append(out, "--"+name+"="+v)
			}
		default:
			out = append(out, "--"+name+"="+fmt.Sprint(mainCmd.Value(name)))
		}
	}
	return out
}

// redactSecrets returns a copy of args with credential values replaced by
// `***` so they don't end up in server logs.
func redactSecrets(args []string) []string {
	out := make([]string, len(args))
	for i, a := range args {
		eq := strings.IndexByte(a, '=')
		if eq < 0 {
			out[i] = a
			continue
		}
		name := strings.TrimLeft(a[:eq], "-")
		switch name {
		case "client_secret", "access_token", "client_id":
			out[i] = a[:eq] + "=***"
		default:
			out[i] = a
		}
	}
	return out
}

// makeDispatcher returns a ToolHandler that spawns a fresh `atomic-cli`
// subprocess for each call. Subprocesses inherit auth/instance via the
// forwardedRootArgs captured at MCP server startup.
func makeDispatcher(cmdPath []string, leaf *cli.Command) mcp.ToolHandler {
	// pre-index flags so we can look up types when building argv
	flagsByName := map[string]cli.Flag{}
	for _, f := range leaf.Flags {
		for _, n := range f.Names() {
			flagsByName[n] = f
		}
	}

	// pre-extract positional parameter names in the order they appear in ArgsUsage.
	var positionals []positional
	for _, m := range argTokenRE.FindAllStringSubmatch(leaf.ArgsUsage, -1) {
		positionals = append(positionals, positional{name: m[2], variadic: m[4] == "..."})
	}

	return func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var args map[string]json.RawMessage
		if len(req.Params.Arguments) > 0 {
			if err := json.Unmarshal(req.Params.Arguments, &args); err != nil {
				return errorResult(fmt.Errorf("decode arguments: %w", err)), nil
			}
		}

		// Build argv passed to the subprocess (program name omitted; exec.Command adds it).
		// Layout: <forwarded root flags> --out-format=json <command-path...> <derived flags> -- <positionals>
		argv := append([]string{}, forwardedRootArgs...)
		argv = append(argv, "--out-format=json")
		argv = append(argv, cmdPath...)

		// flags
		for k, v := range args {
			if _, isPos := findPositional(positionals, k); isPos {
				continue
			}
			f, ok := flagsByName[k]
			if !ok {
				// unknown -- ignore so the LLM can't smuggle root flags via tool args
				continue
			}
			pieces, err := flagToArgv(f, k, v)
			if err != nil {
				return errorResult(fmt.Errorf("flag %q: %w", k, err)), nil
			}
			argv = append(argv, pieces...)
		}

		// positionals (in declaration order)
		var posArgs []string
		for _, p := range positionals {
			raw, ok := args[p.name]
			if !ok {
				continue
			}
			if p.variadic {
				var ss []string
				if err := json.Unmarshal(raw, &ss); err != nil {
					// allow scalar string as a single-element slice
					var s string
					if err2 := json.Unmarshal(raw, &s); err2 != nil {
						return errorResult(fmt.Errorf("positional %q: %w", p.name, err)), nil
					}
					ss = []string{s}
				}
				posArgs = append(posArgs, ss...)
			} else {
				s, err := jsonScalarToString(raw)
				if err != nil {
					return errorResult(fmt.Errorf("positional %q: %w", p.name, err)), nil
				}
				posArgs = append(posArgs, s)
			}
		}
		if len(posArgs) > 0 {
			argv = append(argv, "--")
			argv = append(argv, posArgs...)
		}

		stdout, stderr, runErr := runSubprocess(ctx, argv)

		if runErr != nil {
			detail := strings.TrimSpace(string(stderr))
			if detail == "" {
				detail = runErr.Error()
			} else {
				detail = runErr.Error() + "\n" + detail
			}
			res := errorResult(fmt.Errorf("%s", detail))
			if len(stdout) > 0 {
				res.Content = append(res.Content, &mcp.TextContent{Text: string(stdout)})
			}
			return res, nil
		}

		res := &mcp.CallToolResult{}
		trimmed := strings.TrimSpace(string(stdout))
		if trimmed == "" {
			res.Content = []mcp.Content{&mcp.TextContent{Text: "(no output)"}}
			return res, nil
		}

		// Try to expose the result as structured content so the model can
		// reason over it; fall back to a text block if it isn't valid JSON
		// (e.g. progress lines from import commands).
		var parsed any
		if err := json.Unmarshal([]byte(trimmed), &parsed); err == nil {
			// MCP requires structuredContent to be a JSON object.
			if obj, ok := parsed.(map[string]any); ok {
				res.StructuredContent = obj
			} else {
				res.StructuredContent = map[string]any{"result": parsed}
			}
		}
		res.Content = []mcp.Content{&mcp.TextContent{Text: trimmed}}
		return res, nil
	}
}

func findPositional(ps []positional, name string) (int, bool) {
	for i, p := range ps {
		if p.name == name {
			return i, true
		}
	}
	return -1, false
}

func flagToArgv(f cli.Flag, name string, raw json.RawMessage) ([]string, error) {
	switch f.(type) {
	case *cli.BoolFlag:
		var b bool
		if err := json.Unmarshal(raw, &b); err != nil {
			return nil, err
		}
		if !b {
			return nil, nil
		}
		return []string{"--" + name}, nil

	case *cli.StringSliceFlag:
		var ss []string
		if err := json.Unmarshal(raw, &ss); err != nil {
			var s string
			if err2 := json.Unmarshal(raw, &s); err2 != nil {
				return nil, err
			}
			ss = []string{s}
		}
		out := make([]string, 0, len(ss))
		for _, v := range ss {
			out = append(out, "--"+name+"="+v)
		}
		return out, nil

	case *cli.IntSliceFlag:
		var ns []int64
		if err := json.Unmarshal(raw, &ns); err != nil {
			return nil, err
		}
		out := make([]string, 0, len(ns))
		for _, v := range ns {
			out = append(out, "--"+name+"="+strconv.FormatInt(v, 10))
		}
		return out, nil

	default:
		s, err := jsonScalarToString(raw)
		if err != nil {
			return nil, err
		}
		return []string{"--" + name + "=" + s}, nil
	}
}

func jsonScalarToString(raw json.RawMessage) (string, error) {
	v := strings.TrimSpace(string(raw))
	if len(v) == 0 {
		return "", nil
	}
	// strip JSON quotes from strings without further unmarshal alloc
	if v[0] == '"' {
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			return "", err
		}
		return s, nil
	}
	return v, nil
}

// runSubprocess spawns a fresh `atomic-cli` subprocess to execute one tool
// call. Each invocation gets a clean process state, so urfave/cli's mutable
// flag-parser internals can't leak between calls. stdout carries the
// machine-readable result; stderr is captured for error context only.
func runSubprocess(ctx context.Context, argv []string) (stdout, stderr []byte, err error) {
	cmdCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(cmdCtx, selfExecutable, argv...)
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	cmd.Env = os.Environ()

	runErr := cmd.Run()
	return outBuf.Bytes(), errBuf.Bytes(), runErr
}

func errorResult(err error) *mcp.CallToolResult {
	res := &mcp.CallToolResult{}
	res.SetError(err)
	return res
}
