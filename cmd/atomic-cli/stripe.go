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
	"fmt"
	"strings"

	"github.com/stripe/stripe-go/v79"
	"github.com/stripe/stripe-go/v79/account"
	"github.com/urfave/cli/v3"
)

var (
	stripeCmd = &cli.Command{
		Name:  "stripe",
		Usage: "stripe management",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     "stripe-key",
				Aliases:  []string{"k"},
				Usage:    "stripe api key",
				Sources:  cli.NewValueSourceChain(cli.EnvVar("STRIPE_API_KEY")),
				Required: true,
			},
			&cli.BoolFlag{
				Name:  "live-mode",
				Usage: "allow live stripe keys; without this flag only test keys (sk_test_) are accepted",
			},
		},
		Before: func(_ context.Context, cmd *cli.Command) (context.Context, error) {
			key := cmd.String("stripe-key")

			if !cmd.Bool("live-mode") && !strings.HasPrefix(key, "sk_test_") && !strings.HasPrefix(key, "rk_test_") {
				return nil, fmt.Errorf("live key detected; pass --live-mode to use live keys, got %s...", key[:12])
			}

			stripe.Key = key

			acct, err := account.Get()
			if err != nil {
				return nil, fmt.Errorf("failed to authenticate with stripe: %w", err)
			}

			root := cmd.Root()
			if root.Metadata == nil {
				root.Metadata = make(map[string]any)
			}
			root.Metadata["stripe_account"] = acct

			return nil, nil
		},
		Commands: []*cli.Command{
			stripeExportCmd,
		},
	}
)
