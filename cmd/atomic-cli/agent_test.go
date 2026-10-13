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
	"testing"

	"github.com/urfave/cli/v3"
)

// TestIsLocalCommand pins the urfave/cli v3 behaviour the root Before hook
// relies on: at hook time the lineage of the invoked command is resolvable
// from Args().First() at each level.
func TestIsLocalCommand(t *testing.T) {
	cases := []struct {
		args  []string
		local bool
	}{
		{[]string{"t", "skills", "list"}, true},
		{[]string{"t", "doctor"}, true},
		{[]string{"t", "-p", "prod", "skills", "install", "--local"}, true},
		{[]string{"t", "remote", "list"}, false},
		{[]string{"t", "-p", "prod", "remote", "list"}, false},
	}

	for _, tc := range cases {
		var got *bool

		noop := func(context.Context, *cli.Command) error { return nil }
		root := &cli.Command{
			Name:  "t",
			Flags: []cli.Flag{&cli.StringFlag{Name: "p"}},
			Commands: []*cli.Command{
				{Name: "skills", Metadata: localMeta(), Commands: []*cli.Command{
					{Name: "list", Action: noop},
					{Name: "install", Flags: []cli.Flag{&cli.BoolFlag{Name: "local"}}, Action: noop},
				}},
				{Name: "doctor", Metadata: localMeta(), Action: noop},
				{Name: "remote", Commands: []*cli.Command{{Name: "list", Action: noop}}},
			},
		}
		root.Before = func(ctx context.Context, cmd *cli.Command) (context.Context, error) {
			v := isLocalCommand(cmd)
			got = &v
			return ctx, nil
		}

		if err := root.Run(context.Background(), tc.args); err != nil {
			t.Fatalf("%v: run: %v", tc.args, err)
		}
		if got == nil {
			t.Fatalf("%v: Before did not run", tc.args)
		}
		if *got != tc.local {
			t.Errorf("%v: isLocalCommand = %v, want %v", tc.args, *got, tc.local)
		}
	}
}

func TestAgentDefaults(t *testing.T) {
	t.Setenv(envAgentDefaults, "")
	t.Setenv(envAgentDefaultsAlt, "")
	if agentDefaults() {
		t.Fatal("expected agent defaults off")
	}
	t.Setenv(envAgentDefaults, "1")
	if !agentDefaults() {
		t.Fatal("expected agent defaults on")
	}
	if interactive() {
		t.Fatal("agent mode must never be interactive")
	}
	if _, err := promptLine("x"); err != errNonInteractive {
		t.Fatalf("promptLine err = %v, want errNonInteractive", err)
	}
}
