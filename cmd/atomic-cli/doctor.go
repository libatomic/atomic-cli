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
	"sort"
	"strings"
	"time"

	client "github.com/libatomic/atomic-go/v2"
	"github.com/libatomic/atomic/v2/pkg/atomic"
	"github.com/libatomic/atomic/v2/pkg/ptr"
	"github.com/urfave/cli/v3"
)

type (
	doctorReport struct {
		Build        doctorBuild        `json:"build"`
		Install      doctorInstall      `json:"install"`
		Credentials  doctorCredentials  `json:"credentials"`
		Connectivity doctorConnectivity `json:"connectivity"`
		Skills       doctorSkills       `json:"skills"`
		Problems     []string           `json:"problems"`
	}

	doctorBuild struct {
		Version string `json:"version"`
		Commit  string `json:"commit"`
		BuiltAt string `json:"builtAt"`
	}

	doctorInstall struct {
		Executable string   `json:"executable"`
		OnPath     string   `json:"onPath,omitempty"`
		Candidates []string `json:"candidates,omitempty"`
		Conflict   bool     `json:"conflict"`
	}

	doctorCredentials struct {
		Path         string        `json:"path"`
		Exists       bool          `json:"exists"`
		Valid        bool          `json:"valid"`
		ParseErrors  []string      `json:"parseErrors,omitempty"`
		EnvVars      []string      `json:"envVars"`
		AgentMode    bool          `json:"agentMode"`
		Profile      string        `json:"profile"`
		ProfileFound bool          `json:"profileFound"`
		Profiles     []profileInfo `json:"profiles"`
	}

	// profileInfo never carries secret values, only which fields are set.
	profileInfo struct {
		Name           string   `json:"name"`
		Host           string   `json:"host,omitempty"`
		Fields         []string `json:"fields"`
		HasClientCreds bool     `json:"hasClientCreds"`
		HasToken       bool     `json:"hasToken"`
		HasInstance    bool     `json:"hasInstance"`
	}

	doctorConnectivity struct {
		Attempted bool   `json:"attempted"`
		OK        bool   `json:"ok"`
		Host      string `json:"host,omitempty"`
		Auth      string `json:"auth,omitempty"`
		Instance  string `json:"instance,omitempty"`
		Message   string `json:"message"`
	}

	doctorSkills struct {
		CanonicalDir string            `json:"canonicalDir"`
		Agents       []agentSkillsInfo `json:"agents"`
	}

	agentSkillsInfo struct {
		Agent         string        `json:"agent"`
		Label         string        `json:"label"`
		Covers        []string      `json:"covers,omitempty"`
		SkillsDir     string        `json:"skillsDir"`
		Installed     int           `json:"installed"`
		Expected      int           `json:"expected"`
		Stale         []string      `json:"stale,omitempty"`
		Skills        []skillStatus `json:"skills"`
		RepairCommand string        `json:"repairCommand,omitempty"`
	}
)

var (
	doctorEnvVars = []string{
		"PASSPORT_API_HOST",
		"PASSPORT_ACCESS_TOKEN",
		"PASSPORT_CLIENT_ID",
		"PASSPORT_CLIENT_SECRET",
		"PASSPORT_INSTANCE_ID",
		"PASSPORT_DB_SOURCE",
		"PASSPORT_OUT_FORMAT",
		envAgentDefaults,
		envAgentDefaultsAlt,
	}

	doctorCmd = &cli.Command{
		Name:     "doctor",
		Usage:    "diagnose the install, credentials, API connectivity and agent skills",
		Metadata: readOnlyLocalMeta(),
		Flags: []cli.Flag{
			&cli.BoolFlag{
				Name:  "no-network",
				Usage: "skip the API connectivity check",
			},
			&cli.DurationFlag{
				Name:  "timeout",
				Usage: "connectivity check timeout",
				Value: 10 * time.Second,
			},
			&cli.BoolFlag{
				Name:    "local",
				Aliases: []string{"l"},
				Usage:   "also report the current project's skills directories",
			},
		},
		Action: doctorAction,
	}
)

func doctorAction(ctx context.Context, cmd *cli.Command) error {
	rep := buildDoctorReport(ctx, cmd)

	switch cmd.String("out-format") {
	case "json", "json-pretty", "jsonl":
		enc := json.NewEncoder(os.Stdout)
		if cmd.String("out-format") == "json-pretty" {
			enc.SetIndent("", "  ")
		}
		return enc.Encode(rep)
	}

	printDoctorReport(rep)
	return nil
}

func buildDoctorReport(ctx context.Context, cmd *cli.Command) *doctorReport {
	rep := &doctorReport{
		Build:    doctorBuild{Version: Version, Commit: Commit, BuiltAt: Date},
		Problems: []string{},
	}

	rep.Install = doctorInstallInfo()
	rep.Credentials = doctorCredentialsInfo(cmd)
	if !rep.Credentials.Exists && len(rep.Credentials.EnvVars) == 0 {
		rep.Problems = append(rep.Problems, fmt.Sprintf("no credentials: create %s with a [%s] profile or export PASSPORT_CLIENT_ID / PASSPORT_CLIENT_SECRET", rep.Credentials.Path, rep.Credentials.Profile))
	} else if rep.Credentials.Exists && !rep.Credentials.Valid {
		rep.Problems = append(rep.Problems, fmt.Sprintf("credentials file %s could not be parsed; expected TOML with one [profile] section per environment", rep.Credentials.Path))
	} else if rep.Credentials.Exists && !rep.Credentials.ProfileFound && !hasAnyEnv("PASSPORT_CLIENT_ID", "PASSPORT_ACCESS_TOKEN") {
		rep.Problems = append(rep.Problems, fmt.Sprintf("profile %q not found in %s; known profiles: %s", rep.Credentials.Profile, rep.Credentials.Path, strings.Join(profileNames(rep.Credentials.Profiles), ", ")))
	}

	rep.Connectivity = doctorConnectivityInfo(ctx, cmd)
	if rep.Connectivity.Attempted && !rep.Connectivity.OK {
		rep.Problems = append(rep.Problems, "API connectivity failed: "+rep.Connectivity.Message)
	}

	rep.Skills = doctorSkillsInfo(cmd.Bool("local"))
	for _, a := range rep.Skills.Agents {
		if a.RepairCommand != "" {
			rep.Problems = append(rep.Problems, fmt.Sprintf("%s skills: %d/%d installed, %d stale; run `%s`", a.Label, a.Installed, a.Expected, len(a.Stale), a.RepairCommand))
		}
	}

	return rep
}

func doctorInstallInfo() doctorInstall {
	info := doctorInstall{Executable: currentBinaryPath()}

	if p, err := exec.LookPath("atomic-cli"); err == nil {
		if r, err := filepath.EvalSymlinks(p); err == nil {
			p = r
		}
		info.OnPath = p
	}

	home, _ := os.UserHomeDir()
	dirs := []string{"/opt/homebrew/bin", "/usr/local/bin", filepath.Join(home, "go", "bin"), filepath.Join(home, ".local", "bin")}
	if gp := os.Getenv("GOPATH"); gp != "" {
		dirs = append(dirs, filepath.Join(gp, "bin"))
	}
	seen := map[string]bool{}
	for _, d := range dirs {
		p := filepath.Join(d, "atomic-cli")
		if _, err := os.Stat(p); err != nil {
			continue
		}
		if r, err := filepath.EvalSymlinks(p); err == nil {
			p = r
		}
		if !seen[p] {
			seen[p] = true
			info.Candidates = append(info.Candidates, p)
		}
	}
	info.Conflict = len(info.Candidates) > 1
	return info
}

func doctorCredentialsInfo(cmd *cli.Command) doctorCredentials {
	info := doctorCredentials{
		Path:      creds,
		Profile:   profile,
		EnvVars:   []string{},
		Profiles:  []profileInfo{},
		AgentMode: agentDefaults(),
	}

	for _, k := range doctorEnvVars {
		if os.Getenv(k) != "" {
			info.EnvVars = append(info.EnvVars, k)
		}
	}

	if _, err := os.Stat(creds); err == nil {
		info.Exists = true
	}

	cf := loadCredentials(creds)
	info.Valid = cf.loaded
	info.ParseErrors = cf.parseErrors

	names := cf.Profiles()
	sort.Strings(names)
	for _, n := range names {
		fields := make([]string, 0, len(cf.profiles[n]))
		for k := range cf.profiles[n] {
			fields = append(fields, k)
		}
		sort.Strings(fields)

		host, _ := cf.Lookup(n, "host")
		_, hasID := cf.Lookup(n, "client_id")
		_, hasSecret := cf.Lookup(n, "client_secret")
		_, hasToken := cf.Lookup(n, "access_token")
		_, hasInst := cf.Lookup(n, "instance_id")

		info.Profiles = append(info.Profiles, profileInfo{
			Name:           n,
			Host:           host,
			Fields:         fields,
			HasClientCreds: hasID && hasSecret,
			HasToken:       hasToken,
			HasInstance:    hasInst,
		})
		if n == profile {
			info.ProfileFound = true
		}
	}

	return info
}

// doctorConnectivityInfo builds the API client the same way the root Before
// hook does and performs the same instance lookup, under a timeout.
func doctorConnectivityInfo(ctx context.Context, cmd *cli.Command) doctorConnectivity {
	info := doctorConnectivity{Host: cmd.String("host")}

	if cmd.Bool("no-network") {
		info.Message = "skipped (--no-network)"
		return info
	}
	if cmd.IsSet("db_source") && cmd.String("db_source") != "" {
		info.Message = "skipped (direct database access configured via db_source)"
		return info
	}

	opts := []client.ApiOption{client.WithHost(cmd.String("host"))}
	switch {
	case cmd.IsSet("client_id") && cmd.IsSet("client_secret"):
		opts = append(opts, client.WithClientCredentials(cmd.String("client_id"), cmd.String("client_secret")))
		info.Auth = "client_credentials"
	case cmd.IsSet("access_token"):
		opts = append(opts, client.WithToken(cmd.String("access_token")))
		info.Auth = "access_token"
	default:
		info.Message = "skipped: no client_id/client_secret or access_token resolved for profile " + profile
		return info
	}

	info.Attempted = true
	api := client.New(opts...)

	tctx, cancel := context.WithTimeout(ctx, cmd.Duration("timeout"))
	defer cancel()

	lookup := cmd.String("instance_id")
	explicit := cmd.IsSet("instance_id")
	if !explicit {
		lookup = cmd.String("host")
	}

	if id, err := atomic.ParseID(lookup); err == nil {
		in, err := api.InstanceGet(tctx, &atomic.InstanceGetInput{InstanceID: &id})
		if err != nil {
			info.Message = "instance lookup failed: " + err.Error()
			return info
		}
		info.OK = true
		info.Instance = in.Name
		info.Message = "authenticated; instance resolved"
		return info
	}

	insts, err := api.InstanceList(tctx, &atomic.InstanceListInput{Name: ptr.String(lookup)})
	if err != nil {
		info.Message = "instance list failed: " + err.Error()
		return info
	}
	info.OK = true
	if len(insts) > 0 {
		info.Instance = insts[0].Name
		info.Message = "authenticated; instance resolved"
	} else if explicit {
		info.OK = false
		info.Message = fmt.Sprintf("authenticated, but instance %q was not found", lookup)
	} else {
		info.Message = "authenticated; no instance matched the host (pass -i to bind one)"
	}
	return info
}

func doctorSkillsInfo(includeLocal bool) doctorSkills {
	out := doctorSkills{}
	if d, err := skillsDirFor(agentTargets[0], false); err == nil {
		out.CanonicalDir = d
	}

	add := func(t agentTarget, local bool) {
		dir, err := skillsDirFor(t, local)
		if err != nil {
			return
		}
		if local {
			if _, err := os.Stat(dir); errors.Is(err, os.ErrNotExist) {
				return
			}
		}
		statuses, err := skillStatusesIn(t, dir)
		if err != nil {
			return
		}

		a := agentSkillsInfo{
			Agent:     t.Name,
			Label:     t.Label,
			Covers:    t.Covers,
			SkillsDir: dir,
			Expected:  len(statuses),
			Skills:    statuses,
		}
		for _, s := range statuses {
			if s.Status == skillStatusDirectory || s.Status == skillStatusSymlink {
				a.Installed++
			}
			if s.Fresh == "no" {
				a.Stale = append(a.Stale, s.Name)
			}
			if s.RepairCommand != "" && a.RepairCommand == "" {
				a.RepairCommand = s.RepairCommand
			}
		}
		out.Agents = append(out.Agents, a)
	}

	for _, t := range agentTargets {
		add(t, false)
		if includeLocal {
			add(t, true)
		}
	}
	return out
}

func printDoctorReport(rep *doctorReport) {
	mark := func(ok bool) string {
		if ok {
			return "OK  "
		}
		return "WARN"
	}

	fmt.Printf("%s build        %s (%s) built %s\n", mark(true), rep.Build.Version, rep.Build.Commit, rep.Build.BuiltAt)

	fmt.Printf("%s binary       %s\n", mark(!rep.Install.Conflict), rep.Install.Executable)
	if rep.Install.OnPath != "" && rep.Install.OnPath != rep.Install.Executable {
		fmt.Printf("     on PATH      %s\n", rep.Install.OnPath)
	}
	if rep.Install.Conflict {
		fmt.Printf("     multiple installs: %s\n", strings.Join(rep.Install.Candidates, ", "))
	}

	c := rep.Credentials
	fmt.Printf("%s credentials  %s (exists=%v valid=%v profile=%s found=%v)\n", mark(c.Exists && c.Valid && c.ProfileFound || len(c.EnvVars) > 0), c.Path, c.Exists, c.Valid, c.Profile, c.ProfileFound)
	for _, p := range c.Profiles {
		fmt.Printf("     [%s] host=%s client_creds=%v token=%v instance=%v\n", p.Name, p.Host, p.HasClientCreds, p.HasToken, p.HasInstance)
	}
	if len(c.EnvVars) > 0 {
		fmt.Printf("     env: %s\n", strings.Join(c.EnvVars, ", "))
	}
	if c.AgentMode {
		fmt.Printf("     agent mode on (%s): json output, no prompts\n", envAgentDefaults)
	}

	n := rep.Connectivity
	fmt.Printf("%s connectivity %s", mark(!n.Attempted || n.OK), n.Message)
	if n.Instance != "" {
		fmt.Printf(" (instance %s)", n.Instance)
	}
	fmt.Println()

	for _, a := range rep.Skills.Agents {
		fmt.Printf("%s skills       %-26s %d/%d installed", mark(a.RepairCommand == ""), a.Label, a.Installed, a.Expected)
		if len(a.Stale) > 0 {
			fmt.Printf(", stale: %s", strings.Join(a.Stale, ", "))
		}
		fmt.Printf("  %s\n", a.SkillsDir)
	}

	if len(rep.Problems) == 0 {
		fmt.Println("\nno problems found")
		return
	}
	fmt.Println("\nproblems:")
	for _, p := range rep.Problems {
		fmt.Printf("  - %s\n", p)
	}
}

func hasAnyEnv(keys ...string) bool {
	for _, k := range keys {
		if os.Getenv(k) != "" {
			return true
		}
	}
	return false
}

func profileNames(ps []profileInfo) []string {
	out := make([]string, 0, len(ps))
	for _, p := range ps {
		out = append(out, p.Name)
	}
	return out
}
