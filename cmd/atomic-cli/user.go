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
	"github.com/urfave/cli/v3"
)

var (
	userUpdateFlags = []cli.Flag{
		&cli.BoolFlag{
			Name:  "file",
			Usage: "set the user input from a JSON file",
		},
		&cli.StringFlag{
			Name:  "login",
			Usage: "set the user login",
		},
		&cli.StringFlag{
			Name:  "password",
			Usage: "set the user password",
		},
		&cli.StringFlag{
			Name:  "email",
			Usage: "set the user email",
		},
		&cli.StringFlag{
			Name:  "profile",
			Usage: "set the user profile from a JSON file",
		},
		&cli.StringSliceFlag{
			Name:  "roles",
			Usage: "set the user roles from a JSON file",
			Value: []string{"user"},
		},
		&cli.StringFlag{
			Name:  "metadata",
			Usage: "set the user metadata from a JSON file",
		},
		&cli.StringFlag{
			Name:  "stripe_account",
			Usage: "set the user stripe account",
		},
		&cli.BoolFlag{
			Name:  "suppress_events",
			Usage: "suppress user events",
		},
		&cli.BoolFlag{
			Name:  "subscribe_default_plans",
			Usage: "subscribe to default plans",
		},
		&cli.StringFlag{
			Name:  "preferences",
			Usage: "set the user preferences from a JSON file",
		},
	}

	userCreateFlags = append(userUpdateFlags, []cli.Flag{
		&cli.BoolFlag{
			Name:  "create_only",
			Usage: "create the user only",
		},
		&cli.BoolFlag{
			Name:  "suppress_validation",
			Usage: "suppress user validation",
		},
		&cli.BoolFlag{
			Name:  "suppress_parent_triggers",
			Usage: "suppress parent triggers",
		},
		&cli.BoolFlag{
			Name:  "rebuild_audiences",
			Usage: "rebuild the user audiences",
		},
	}...)

	userCmd = &cli.Command{
		Name:    "user",
		Aliases: []string{"users"},
		Usage:   "manage users",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "instance_id",
				Usage:   "set the instance",
				Aliases: []string{"i", "instance"},
			},
		},
		Commands: []*cli.Command{
			{
				Name:      "create",
				Usage:     "create a user",
				Flags:     userCreateFlags,
				ArgsUsage: "create <login>",
				Action:    userCreate,
			},
			{
				Name:      "update",
				Usage:     "update a user",
				Flags:     userUpdateFlags,
				ArgsUsage: "update <user_id>",
			},
			{
				Name:      "get",
				Usage:     "get a user",
				ArgsUsage: "get <user_id>",
			},
			{
				Name:      "list",
				Usage:     "list users",
				ArgsUsage: "list",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:  "audience",
						Usage: "list by audience",
					},
					&cli.StringSliceFlag{
						Name:  "roles",
						Usage: "list by role",
					},
					&cli.StringFlag{
						Name:  "status",
						Usage: "list by status",
					},
					&cli.StringFlag{
						Name:  "login",
						Usage: "list by login",
					},
					&cli.StringFlag{
						Name:  "stripe_account",
						Usage: "list by stripe account",
					},
					&cli.IntFlag{
						Name:  "limit",
						Usage: "limit the number of users",
					},
					&cli.IntFlag{
						Name:  "offset",
						Usage: "offset the number of users",
					},
					&cli.StringSliceFlag{
						Name:  "expand",
						Usage: "expand the user",
					},
				},
				Action: userList,
			},
			{
				Name:      "delete",
				Usage:     "delete a user",
				ArgsUsage: "delete <user_id>",
			},
		},
	}
)

func userCreate(ctx context.Context, cmd *cli.Command) error {
	var input atomic.UserCreateInput

	if cmd.IsSet("file") && cmd.Bool("file") {
		content, err := os.ReadFile(cmd.Args().First())
		if err != nil {
			return fmt.Errorf("failed to read user create input file: %w", err)
		}

		if err := json.Unmarshal(content, &input); err != nil {
			return fmt.Errorf("failed to unmarshal user create input: %w", err)
		}
	} else if cmd.Args().First() != "" {
		input.Login = cmd.Args().First()
	}

	if err := BindFlagsFromContext(cmd, &input, "profile", "metadata", "preferences"); err != nil {
		return err
	}

	if cmd.IsSet("profile") {
		content, err := os.ReadFile(cmd.Args().First())
		if err != nil {
			return fmt.Errorf("failed to read user create input file: %w", err)
		}

		if err := json.Unmarshal(content, &input.Profile); err != nil {
			return fmt.Errorf("failed to unmarshal user create input: %w", err)
		}
	}

	if cmd.IsSet("metadata") {
		content, err := os.ReadFile(cmd.Args().First())
		if err != nil {
			return fmt.Errorf("failed to read user create input file: %w", err)
		}

		if err := json.Unmarshal(content, &input.Metadata); err != nil {
			return fmt.Errorf("failed to unmarshal user create input: %w", err)
		}
	}

	if cmd.IsSet("preferences") {
		content, err := os.ReadFile(cmd.Args().First())
		if err != nil {
			return fmt.Errorf("failed to read user create input file: %w", err)
		}

		if err := json.Unmarshal(content, &input.Preferences); err != nil {
			return fmt.Errorf("failed to unmarshal user create input: %w", err)
		}
	}

	user, err := backend.UserCreate(ctx, &input)
	if err != nil {
		return err
	}

	PrintResult(cmd, []*atomic.User{user}, WithFields("id", "login", "created_at", "updated_at", "roles", "instance_id"))

	return nil
}

func userList(ctx context.Context, cmd *cli.Command) error {
	var input atomic.UserListInput

	if err := BindFlagsFromContext(cmd, &input); err != nil {
		return err
	}

	if !cmd.IsSet("expand") {
		input.Expand = atomic.ExpandFields{"roles", "permissions", "stripe_account"}
	}

	users, err := backend.UserList(ctx, &input)
	if err != nil {
		return err
	}

	PrintResult(cmd, users, WithFields("id", "login", "created_at", "roles", "instance_id", "stripe_account.stripe_customer"))

	return nil
}
