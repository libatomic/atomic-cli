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
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/libatomic/atomic/pkg/atomic"
	"github.com/libatomic/atomic/pkg/ptr"
	"github.com/urfave/cli/v3"
)

var (
	instCommonFlags = []cli.Flag{
		&cli.BoolFlag{
			Name:  "file",
			Usage: "read the instance parameters from a `FILE`",
			Value: true,
		},
		&cli.StringFlag{
			Name:  "title",
			Usage: "set the instance display title",
		},
		&cli.StringFlag{
			Name:  "description",
			Usage: "set the instance description",
		},
		&cli.StringFlag{
			Name:  "session_key",
			Usage: "set the session key",
		},
		&cli.StringFlag{
			Name:  "session_cookie",
			Usage: "set the session cookie",
		},
		&cli.Int64Flag{
			Name:  "session_lifetime",
			Usage: "set the session lifetime in milliseconds",
			Value: 3600,
		},
		&cli.StringFlag{
			Name:  "metadata",
			Usage: "source `FILE` to set the metadata for the instance",
		},
		&cli.StringSliceFlag{
			Name:  "origins",
			Usage: "set the origins for the instance (comma separated)",
		},
		&cli.StringSliceFlag{
			Name:  "domains",
			Usage: "set the domains for the instance (comma separated)",
		},
	}

	instCreateFlags = append(instCommonFlags, &cli.StringFlag{
		Name:  "parent_id",
		Usage: "set the parent instance id",
	})

	instUpdateFlags = append(instCommonFlags, &cli.BoolFlag{
		Name:  "recreate_jobs",
		Usage: "recreate the instance jobs",
	})

	instCmd = &cli.Command{
		Name:    "instance",
		Aliases: []string{"inst"},
		Usage:   "instance management",
		Commands: []*cli.Command{
			{
				Name:      "create",
				Usage:     "create a new instance",
				ArgsUsage: "create <name>",
				Action:    instCreate,
				Flags:     instCreateFlags,
			},
			{
				Name:      "get",
				Usage:     "get an instance",
				Action:    instGet,
				ArgsUsage: "get <instance-id>",
			},
			{
				Name:      "update",
				Usage:     "update an instance",
				Action:    instUpdate,
				ArgsUsage: "update <instance-id>",
				Flags:     instUpdateFlags,
			},
			{
				Name:      "delete",
				Usage:     "delete an instance",
				Action:    instDelete,
				ArgsUsage: "delete <instance-id>",
			},
			{
				Name:      "list",
				Usage:     "list instances",
				Action:    instList,
				ArgsUsage: "list",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:  "name",
						Usage: "return only instances with the given name (regex)",
					},
					&cli.BoolFlag{
						Name:  "is_parent",
						Usage: "return only parent instances",
					},
					&cli.BoolFlag{
						Name:  "has_parent",
						Usage: "return only instances that have a parent",
					},
				},
			},
		},
	}
)

func instCreate(ctx context.Context, cmd *cli.Command) error {
	var input atomic.InstanceCreateInput

	if cmd.IsSet("file") && cmd.Bool("file") {
		content, err := os.ReadFile(cmd.Args().First())
		if err != nil {
			return fmt.Errorf("failed to read instance create input file: %w", err)
		}

		if err := json.Unmarshal(content, &input); err != nil {
			return fmt.Errorf("failed to unmarshal instance create input: %w", err)
		}
	} else if cmd.Args().First() != "" {
		input.Name = cmd.Args().First()
	}

	if err := BindFlagsFromContext(cmd, &input, "metadata"); err != nil {
		return err
	}

	if cmd.IsSet("metadata") {
		fd, err := os.Open(cmd.String("metadata"))
		if err != nil {
			return fmt.Errorf("failed to open metadata file: %w", err)
		}
		defer fd.Close()

		input.Metadata = atomic.Metadata{}

		if err := json.NewDecoder(fd).Decode(&input.Metadata); err != nil {
			return fmt.Errorf("failed to decode metadata: %w", err)
		}
	}

	inst, err := backend.InstanceCreate(ctx, &input)
	if err != nil {
		return err
	}

	PrintResult(cmd, []*atomic.Instance{inst}, WithFields("id", "name", "title", "created_at", "parent_id"))

	return nil
}

func instUpdate(ctx context.Context, cmd *cli.Command) error {
	var input atomic.InstanceUpdateInput

	if cmd.IsSet("file") && cmd.Bool("file") {
		content, err := os.ReadFile(cmd.Args().First())
		if err != nil {
			return fmt.Errorf("failed to read instance update input file: %w", err)
		}

		if err := json.Unmarshal(content, &input); err != nil {
			return fmt.Errorf("failed to unmarshal instance update input: %w", err)
		}
	} else if id, err := atomic.ParseID(cmd.Args().First()); err != nil {
		return fmt.Errorf("failed to parse instance id: %w", err)
	} else {
		input.InstanceID = id
	}

	if err := BindFlagsFromContext(cmd, &input, "metadata"); err != nil {
		return err
	}

	if cmd.IsSet("metadata") {
		fd, err := os.Open(cmd.String("metadata"))
		if err != nil {
			return fmt.Errorf("failed to open metadata file: %w", err)
		}
		defer fd.Close()

		input.Metadata = atomic.Metadata{}

		if err := json.NewDecoder(fd).Decode(&input.Metadata); err != nil {
			return fmt.Errorf("failed to decode metadata: %w", err)
		}
	}

	inst, err := backend.InstanceUpdate(ctx, &input)
	if err != nil {
		return err
	}

	PrintResult(cmd, []*atomic.Instance{inst}, WithFields("id", "name", "title", "created_at", "parent_id"))

	return nil
}

func instGet(ctx context.Context, cmd *cli.Command) error {
	var input atomic.InstanceGetInput

	id, err := atomic.ParseID(cmd.Args().First())
	if err != nil {
		return fmt.Errorf("failed to parse instance id: %w", err)
	}

	input.InstanceID = &id

	inst, err := backend.InstanceGet(ctx, &input)
	if err != nil {
		return err
	}

	PrintResult(cmd, []*atomic.Instance{inst}, WithFields("id", "name", "title", "created_at", "parent_id"))

	return nil
}

func instDelete(ctx context.Context, cmd *cli.Command) error {
	var input atomic.InstanceDeleteInput

	id, err := atomic.ParseID(cmd.Args().First())
	if err != nil {
		return fmt.Errorf("failed to parse instance id: %w", err)
	}

	input.InstanceID = id

	if err := backend.InstanceDelete(ctx, &input); err != nil {
		return err
	}

	return nil
}

func instList(ctx context.Context, cmd *cli.Command) error {
	var input atomic.InstanceListInput

	if cmd.IsSet("is_parent") {
		isParent := cmd.Bool("is-parent")
		input.IsParent = &isParent
	}

	if cmd.IsSet("has_parent") {
		hasParent := cmd.Bool("has-parent")
		input.HasParent = &hasParent
	}

	if cmd.IsSet("name") {
		input.Name = ptr.String(cmd.String("name"))
	}

	insts, err := backend.InstanceList(ctx, &input)
	if err != nil {
		return err
	}

	PrintResult(cmd, insts, WithFields("id", "name", "title", "created_at", "parent_id"))

	return nil
}
