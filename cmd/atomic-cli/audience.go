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

	"github.com/libatomic/atomic/pkg/atomic"
	"github.com/urfave/cli/v3"
)

var (
	audienceCmd = &cli.Command{
		Name:    "audience",
		Aliases: []string{"audiences"},
		Usage:   "manage audiences",
		Commands: []*cli.Command{
			{
				Name:   "list",
				Usage:  "list audiences",
				Action: audienceList,
				Flags: []cli.Flag{
					&cli.BoolFlag{
						Name:  "internal",
						Usage: "filter by internal audiences",
					},
					&cli.BoolFlag{
						Name:  "static",
						Usage: "filter by static audiences",
					},
					&cli.IntFlag{
						Name:  "limit",
						Usage: "limit the number of audiences",
					},
					&cli.IntFlag{
						Name:  "offset",
						Usage: "offset the number of audiences",
					},
				},
			},
			{
				Name:      "get",
				Usage:     "get an audience",
				ArgsUsage: "<audience_id>",
				Action:    audienceGet,
			},
			{
				Name:      "delete",
				Usage:     "delete an audience",
				ArgsUsage: "<audience_id>",
				Action:    audienceDelete,
			},
			{
				Name:      "import",
				Usage:     "import non-internal audiences from a JSON file",
				ArgsUsage: "<file>",
				Action:    audienceImport,
				Flags: []cli.Flag{
					&cli.BoolFlag{
						Name:  "dry-run",
						Usage: "preview what would be created without making changes",
					},
				},
			},
		},
	}
)

func audienceList(ctx context.Context, cmd *cli.Command) error {
	var input atomic.AudienceListInput

	if err := BindFlagsFromContext(cmd, &input); err != nil {
		return err
	}

	input.InstanceID = inst.UUID

	if cmd.IsSet("internal") {
		v := cmd.Bool("internal")
		input.Internal = &v
	}

	if cmd.IsSet("static") {
		v := cmd.Bool("static")
		input.Static = &v
	}

	auds, err := backend.AudienceList(ctx, &input)
	if err != nil {
		return err
	}

	PrintResult(cmd, auds,
		WithFields("id", "name", "internal", "static", "member_count"),
	)

	return nil
}

func audienceGet(ctx context.Context, cmd *cli.Command) error {
	if cmd.NArg() < 1 {
		return fmt.Errorf("audience ID is required")
	}

	audID, err := atomic.ParseID(cmd.Args().First())
	if err != nil {
		return fmt.Errorf("failed to parse audience ID: %w", err)
	}

	instID := inst.UUID
	aud, err := backend.AudienceGet(ctx, &atomic.AudienceGetInput{
		InstanceID: &instID,
		AudienceID: &audID,
	})
	if err != nil {
		return err
	}

	PrintResult(cmd, []*atomic.Audience{aud},
		WithSingleValue(true),
		WithFields("id", "name", "internal", "static", "member_count", "created_at"),
	)

	return nil
}

func audienceDelete(ctx context.Context, cmd *cli.Command) error {
	if cmd.NArg() < 1 {
		return fmt.Errorf("audience ID is required")
	}

	audID, err := atomic.ParseID(cmd.Args().First())
	if err != nil {
		return fmt.Errorf("failed to parse audience ID: %w", err)
	}

	if err := backend.AudienceDelete(ctx, &atomic.AudienceDeleteInput{
		InstanceID: inst.UUID,
		AudienceID: audID,
	}); err != nil {
		return err
	}

	fmt.Println("Audience deleted")

	return nil
}

func audienceImport(ctx context.Context, cmd *cli.Command) error {
	if cmd.NArg() < 1 {
		return fmt.Errorf("JSON file is required")
	}

	dryRun := cmd.Bool("dry-run")

	content, err := os.ReadFile(cmd.Args().First())
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	var audiences []atomic.Audience
	if err := json.Unmarshal(content, &audiences); err != nil {
		return fmt.Errorf("failed to parse JSON: %w", err)
	}

	fmt.Fprintf(os.Stderr, "parsed %d audiences\n", len(audiences))

	var created, skipped int
	for _, aud := range audiences {
		if aud.Internal {
			fmt.Fprintf(os.Stderr, "skipping internal audience: %s\n", aud.Name)
			skipped++
			continue
		}

		if dryRun {
			fmt.Fprintf(os.Stderr, "[DRY RUN] would create: %s\n", aud.Name)
			created++
			continue
		}

		input := &atomic.AudienceCreateInput{
			InstanceID: inst.UUID,
			Name:       aud.Name,
			Metadata:   aud.Metadata,
		}

		if aud.Expr.Source != "" {
			input.Expr = &aud.Expr
		}

		if aud.Static {
			input.Static = &aud.Static
		}

		result, err := backend.AudienceCreate(ctx, input)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to create %q: %s\n", aud.Name, err)
			continue
		}

		fmt.Fprintf(os.Stderr, "created: %s -> %s\n", result.Name, result.UUID)
		created++
	}

	fmt.Fprintf(os.Stderr, "%d created, %d skipped (internal) of %d total\n", created, skipped, len(audiences))

	return nil
}
