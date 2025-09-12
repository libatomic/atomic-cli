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
	appCommonFlags = []cli.Flag{
		&cli.StringFlag{
			Name:  "name",
			Usage: "set the application name",
		},
		&cli.StringFlag{
			Name:  "description",
			Usage: "set the application description",
		},
		&cli.StringFlag{
			Name:  "type",
			Usage: "set the application type",
			Value: "web",
		},
		&cli.Int64Flag{
			Name:  "token_lifetime",
			Usage: "set the token lifetime",
			Value: 3600,
		},
		&cli.Int64Flag{
			Name:  "refresh_token_lifetime",
			Usage: "set the refresh token lifetime",
			Value: 3600,
		},
		&cli.StringSliceFlag{
			Name:  "allowed_redirects",
			Usage: "set the allowed redirects",
		},
		&cli.StringSliceFlag{
			Name:  "allowed_grants",
			Usage: "set the allowed grants",
		},
		&cli.StringSliceFlag{
			Name:  "permissions",
			Usage: "set the permissions",
		},
		&cli.StringFlag{
			Name:  "metadata",
			Usage: "source `FILE` to set the metadata for the application",
		},
		&cli.StringFlag{
			Name:  "session_domain",
			Usage: "set the session domain",
		},
		&cli.Int64Flag{
			Name:  "session_lifetime",
			Usage: "set the session lifetime",
		},
	}

	appCmd = &cli.Command{
		Name:    "application",
		Aliases: []string{"app"},
		Usage:   "manage applications",
		Commands: []*cli.Command{
			{
				Name:   "create",
				Usage:  "create an application",
				Action: appCreate,
				Flags:  appCommonFlags,
			},
			{
				Name:      "update",
				Usage:     "update an application",
				Action:    appUpdate,
				ArgsUsage: "update <application-id>",
				Flags:     appCommonFlags,
			},
			{
				Name:      "get",
				Usage:     "get an application",
				Action:    appGet,
				ArgsUsage: "get <application-id>",
			},
			{
				Name:      "delete",
				Usage:     "delete an application",
				Action:    appDelete,
				ArgsUsage: "delete <application-id>",
			},
			{
				Name:   "list",
				Usage:  "list applications",
				Action: appList,
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:  "name",
						Usage: "filter applications by name",
					},
				},
			},
		},
	}
)

func appCreate(ctx context.Context, cmd *cli.Command) error {
	if inst == nil {
		return fmt.Errorf("instance is required for application commands. Use --instance flag or set ATOMIC_INSTANCE_ID environment variable")
	}

	var input atomic.ApplicationCreateInput

	if cmd.IsSet("file") && cmd.Bool("file") {
		content, err := os.ReadFile(cmd.Args().First())
		if err != nil {
			return fmt.Errorf("failed to read application create input file: %w", err)
		}

		if err := json.Unmarshal(content, &input); err != nil {
			return fmt.Errorf("failed to unmarshal application create input: %w", err)
		}
	} else if cmd.Args().First() != "" {
		input.Name = cmd.Args().First()
	}

	if err := BindFlagsFromContext(cmd, &input, "metadata"); err != nil {
		return err
	}

	input.InstanceID = inst.UUID

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

	app, err := backend.ApplicationCreate(ctx, &input)
	if err != nil {
		return err
	}

	PrintResult(cmd, []*atomic.Application{app}, WithFields("id", "name", "type", "instance_id", "created_at", "client_id", "client_secret"))

	return nil
}

func appUpdate(ctx context.Context, cmd *cli.Command) error {
	if inst == nil {
		return fmt.Errorf("instance is required for application commands. Use --instance flag or set ATOMIC_INSTANCE_ID environment variable")
	}

	var input atomic.ApplicationUpdateInput

	if cmd.IsSet("file") && cmd.Bool("file") {
		content, err := os.ReadFile(cmd.Args().First())
		if err != nil {
			return fmt.Errorf("failed to read application create input file: %w", err)
		}

		if err := json.Unmarshal(content, &input); err != nil {
			return fmt.Errorf("failed to unmarshal application create input: %w", err)
		}
	}

	if cmd.Args().First() != "" {
		id, err := atomic.ParseID(cmd.Args().First())
		if err != nil {
			return fmt.Errorf("failed to parse application id: %w", err)
		}
		input.ApplicationID = id
	}

	if !input.ApplicationID.Valid() {
		return fmt.Errorf("application id is required")
	}

	if err := BindFlagsFromContext(cmd, &input, "metadata"); err != nil {
		return err
	}

	input.InstanceID = inst.UUID

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

	app, err := backend.ApplicationUpdate(ctx, &input)
	if err != nil {
		return err
	}

	PrintResult(cmd, []*atomic.Application{app}, WithFields("id", "name", "type", "instance_id", "created_at", "client_id", "client_secret"))

	return nil
}

func appGet(ctx context.Context, cmd *cli.Command) error {
	if inst == nil {
		return fmt.Errorf("instance is required for application commands. Use --instance flag or set ATOMIC_INSTANCE_ID environment variable")
	}

	var input atomic.ApplicationGetInput

	id, err := atomic.ParseID(cmd.Args().First())
	if err != nil {
		return fmt.Errorf("failed to parse application id: %w", err)
	}

	input.ApplicationID = &id
	input.InstanceID = &inst.UUID

	app, err := backend.ApplicationGet(ctx, &input)
	if err != nil {
		return err
	}

	PrintResult(cmd, []*atomic.Application{app}, WithFields("id", "name", "type", "instance_id", "created_at", "client_id", "client_secret"))

	return nil
}

func appList(ctx context.Context, cmd *cli.Command) error {
	if inst == nil {
		return fmt.Errorf("instance is required for application commands. Use --instance flag or set ATOMIC_INSTANCE_ID environment variable")
	}

	var input atomic.ApplicationListInput
	input.InstanceID = inst.UUID

	if cmd.IsSet("name") {
		input.Name = ptr.String(cmd.String("name"))
	}

	apps, err := backend.ApplicationList(ctx, &input)
	if err != nil {
		return err
	}

	PrintResult(cmd, apps, WithFields("id", "name", "type", "instance_id", "created_at", "client_id", "client_secret"))

	return nil
}

func appDelete(ctx context.Context, cmd *cli.Command) error {
	if inst == nil {
		return fmt.Errorf("instance is required for application commands. Use --instance flag or set ATOMIC_INSTANCE_ID environment variable")
	}

	var input atomic.ApplicationDeleteInput

	id, err := atomic.ParseID(cmd.Args().First())
	if err != nil {
		return fmt.Errorf("failed to parse application id: %w", err)
	}

	input.ApplicationID = id
	input.InstanceID = inst.UUID

	if err := backend.ApplicationDelete(ctx, &input); err != nil {
		return err
	}

	return nil
}
