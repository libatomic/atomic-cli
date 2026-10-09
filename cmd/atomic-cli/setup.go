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
	"fmt"
	"os"
	"time"

	"github.com/urfave/cli/v3"
)

var (
	setupCmd = &cli.Command{
		Name:     "setup",
		Usage:    "install the agent skills, check credentials and run doctor in one step",
		Metadata: localMeta(),
		Flags: append(append([]cli.Flag{}, skillTargetFlags...),
			&cli.BoolFlag{
				Name:  "no-prune",
				Usage: "keep atomic-cli skill directories from older versions that no longer ship",
			},
			&cli.BoolFlag{
				Name:  "no-network",
				Usage: "skip the API connectivity check",
			},
			&cli.DurationFlag{
				Name:  "timeout",
				Usage: "connectivity check timeout",
				Value: 10 * time.Second,
			},
		),
		Action: setupAction,
	}
)

func setupAction(ctx context.Context, cmd *cli.Command) error {
	res, err := skillsInstall(cmd)
	if err != nil {
		return fmt.Errorf("install skills: %w", err)
	}
	if err := printSkillsInstall(cmd, res); err != nil {
		return err
	}

	if _, err := os.Stat(creds); err != nil {
		fmt.Fprintf(os.Stderr, "\nno credentials file at %s; create one like:\n\n", creds)
		fmt.Fprintf(os.Stderr, "  [%s]\n  host = \"api.example.com\"\n  client_id = \"...\"\n  client_secret = \"...\"\n  instance_id = \"...\"\n\n", profile)
	}

	fmt.Println()
	return doctorAction(ctx, cmd)
}
