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

	"github.com/libatomic/atomic/pkg/atomic"
	"github.com/urfave/cli/v3"
)

var (
	secretCmd = &cli.Command{
		Name:    "secret",
		Aliases: []string{"secrets"},
		Usage:   "manage instance secrets",
		Commands: []*cli.Command{
			secretListCmd,
			secretSetCmd,
			secretDeleteCmd,
		},
	}

	secretListCmd = &cli.Command{
		Name:   "list",
		Usage:  "list secret names (values are never returned)",
		Action: secretList,
	}

	secretSetCmd = &cli.Command{
		Name:      "set",
		Usage:     "set a secret",
		ArgsUsage: "<name> <value>",
		Action:    secretSet,
	}

	secretDeleteCmd = &cli.Command{
		Name:      "delete",
		Aliases:   []string{"rm"},
		Usage:     "delete a secret",
		ArgsUsage: "<name>",
		Action:    secretDeleteAction,
	}
)

func secretList(ctx context.Context, cmd *cli.Command) error {
	if inst == nil {
		return cli.Exit("instance is required", 1)
	}

	secrets, err := backend.SecretList(ctx, &atomic.SecretListInput{
		InstanceID: inst.UUID,
	})
	if err != nil {
		return err
	}

	if len(secrets) == 0 {
		return cli.Exit("no secrets found", 1)
	}

	PrintResult(cmd, secrets,
		WithFields("name", "created_at", "updated_at"),
		WithVirtualField("created_at", func(v any) string {
			s := v.(atomic.Secret)
			return s.CreatedAt.Format(time.RFC3339)
		}),
		WithVirtualField("updated_at", func(v any) string {
			s := v.(atomic.Secret)
			if s.UpdatedAt == nil {
				return ""
			}
			return s.UpdatedAt.Format(time.RFC3339)
		}),
	)

	return nil
}

func secretSet(ctx context.Context, cmd *cli.Command) error {
	if inst == nil {
		return cli.Exit("instance is required", 1)
	}

	if cmd.Args().Len() < 2 {
		return cli.Exit("name and value are required", 1)
	}

	secret, err := backend.SecretSet(ctx, &atomic.SecretSetInput{
		InstanceID: inst.UUID,
		Name:       cmd.Args().First(),
		Value:      cmd.Args().Get(1),
	})
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "secret %s set\n", secret.Name)

	return nil
}

func secretDeleteAction(ctx context.Context, cmd *cli.Command) error {
	if inst == nil {
		return cli.Exit("instance is required", 1)
	}

	if cmd.Args().Len() == 0 {
		return cli.Exit("secret name is required", 1)
	}

	if err := backend.SecretDelete(ctx, &atomic.SecretDeleteInput{
		InstanceID: inst.UUID,
		Name:       cmd.Args().First(),
	}); err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "secret %s deleted\n", cmd.Args().First())

	return nil
}
