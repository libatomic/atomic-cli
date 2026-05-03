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
	priceUpdateFlags = []cli.Flag{
		&cli.StringFlag{
			Name:  "name",
			Usage: "price name",
		},
		&cli.BoolFlag{
			Name:  "active",
			Usage: "set the price as active",
		},
		&cli.BoolFlag{
			Name:  "hidden",
			Usage: "set the price as hidden",
		},
		&cli.IntFlag{
			Name:  "amount",
			Usage: "price amount in cents",
		},
		&cli.StringFlag{
			Name:  "metadata",
			Usage: "set price metadata from a JSON file",
		},
	}

	priceCreateFlags = append(priceUpdateFlags, []cli.Flag{
		&cli.BoolFlag{
			Name:  "file",
			Usage: "read price parameters from a JSON file",
		},
		&cli.StringFlag{
			Name:     "plan_id",
			Usage:    "plan ID this price belongs to",
			Required: true,
		},
		&cli.StringFlag{
			Name:  "currency",
			Usage: "price currency (e.g. usd)",
			Value: "usd",
		},
		&cli.StringFlag{
			Name:  "type",
			Usage: "price type: one_time, recurring",
			Value: "recurring",
		},
		&cli.StringFlag{
			Name:  "interval",
			Usage: "recurring interval: month, year",
		},
		&cli.IntFlag{
			Name:  "frequency",
			Usage: "recurring frequency",
			Value: 1,
		},
		&cli.BoolFlag{
			Name:  "metered",
			Usage: "metered price",
		},
		&cli.StringFlag{
			Name:  "stripe_price",
			Usage: "Stripe price ID",
		},
	}...)

	priceCmd = &cli.Command{
		Name:    "price",
		Aliases: []string{"prices"},
		Usage:   "manage prices",
		Commands: []*cli.Command{
			{
				Name:      "create",
				Usage:     "create a price",
				Flags:     priceCreateFlags,
				ArgsUsage: "<name>",
				Action:    priceCreate,
			},
			{
				Name:      "update",
				Usage:     "update a price",
				Flags:     priceUpdateFlags,
				ArgsUsage: "<price_id>",
				Action:    priceUpdate,
			},
			{
				Name:      "get",
				Usage:     "get a price",
				ArgsUsage: "<price_id>",
				Flags: []cli.Flag{
					&cli.StringSliceFlag{
						Name:  "expand",
						Usage: "expand fields (plan)",
					},
				},
				Action: priceGet,
			},
			{
				Name:   "list",
				Usage:  "list prices",
				Action: priceList,
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:  "plan_id",
						Usage: "filter by plan ID",
					},
					&cli.IntFlag{
						Name:  "limit",
						Usage: "limit the number of prices",
					},
					&cli.IntFlag{
						Name:  "offset",
						Usage: "offset the number of prices",
					},
				},
			},
			{
				Name:      "delete",
				Usage:     "delete a price",
				ArgsUsage: "<price_id>",
				Action:    priceDelete,
			},
		},
	}
)

func priceCreate(ctx context.Context, cmd *cli.Command) error {
	var input atomic.PriceCreateInput

	if cmd.IsSet("file") && cmd.Bool("file") {
		content, err := os.ReadFile(cmd.Args().First())
		if err != nil {
			return fmt.Errorf("failed to read price create input file: %w", err)
		}

		if err := json.Unmarshal(content, &input); err != nil {
			return fmt.Errorf("failed to unmarshal price create input: %w", err)
		}
	} else if cmd.Args().First() != "" {
		input.Name = cmd.Args().First()
	}

	if err := BindFlagsFromContext(cmd, &input, "file", "metadata", "interval", "frequency"); err != nil {
		return err
	}

	if cmd.IsSet("metadata") {
		content, err := os.ReadFile(cmd.String("metadata"))
		if err != nil {
			return fmt.Errorf("failed to read metadata file: %w", err)
		}

		if err := json.Unmarshal(content, &input.Metadata); err != nil {
			return fmt.Errorf("failed to unmarshal metadata: %w", err)
		}
	}

	if cmd.IsSet("interval") || cmd.IsSet("frequency") {
		input.Recurring = &atomic.PriceRecurring{
			Interval:  cmd.String("interval"),
			Frequency: int64(cmd.Int("frequency")),
		}
	}

	instID := inst.UUID
	input.InstanceID = &instID

	price, err := backend.PriceCreate(ctx, &input)
	if err != nil {
		return err
	}

	PrintResult(cmd, []*atomic.Price{price},
		WithSingleValue(true),
		WithFields("id", "name", "plan_id", "type", "amount", "currency", "recurring_interval", "recurring_frequency", "active", "created_at"),
	)

	return nil
}

func priceUpdate(ctx context.Context, cmd *cli.Command) error {
	if cmd.NArg() < 1 {
		return fmt.Errorf("price ID is required")
	}

	priceID, err := atomic.ParseID(cmd.Args().First())
	if err != nil {
		return fmt.Errorf("failed to parse price ID: %w", err)
	}

	var input atomic.PriceUpdateInput

	if err := BindFlagsFromContext(cmd, &input, "metadata"); err != nil {
		return err
	}

	input.InstanceID = inst.UUID
	input.PriceID = priceID

	if cmd.IsSet("metadata") {
		content, err := os.ReadFile(cmd.String("metadata"))
		if err != nil {
			return fmt.Errorf("failed to read metadata file: %w", err)
		}

		if err := json.Unmarshal(content, &input.Metadata); err != nil {
			return fmt.Errorf("failed to unmarshal metadata: %w", err)
		}
	}

	if cmd.IsSet("amount") {
		amt := int64(cmd.Int("amount"))
		input.Amount = &amt
	}

	price, err := backend.PriceUpdate(ctx, &input)
	if err != nil {
		return err
	}

	PrintResult(cmd, []*atomic.Price{price},
		WithSingleValue(true),
		WithFields("id", "name", "plan_id", "type", "amount", "currency", "recurring_interval", "recurring_frequency", "active", "updated_at"),
	)

	return nil
}

func priceGet(ctx context.Context, cmd *cli.Command) error {
	if cmd.NArg() < 1 {
		return fmt.Errorf("price ID is required")
	}

	priceID, err := atomic.ParseID(cmd.Args().First())
	if err != nil {
		return fmt.Errorf("failed to parse price ID: %w", err)
	}

	input := &atomic.PriceGetInput{
		InstanceID: inst.UUID,
		PriceID:    &priceID,
	}

	if expand := cmd.StringSlice("expand"); len(expand) > 0 {
		input.Expand = expand
	}

	price, err := backend.PriceGet(ctx, input)
	if err != nil {
		return err
	}

	PrintResult(cmd, []*atomic.Price{price},
		WithSingleValue(true),
		WithFields("id", "name", "plan_id", "type", "amount", "currency", "recurring_interval", "recurring_frequency", "active", "stripe_price", "created_at"),
	)

	return nil
}

func priceList(ctx context.Context, cmd *cli.Command) error {
	var input atomic.PriceListInput

	if err := BindFlagsFromContext(cmd, &input); err != nil {
		return err
	}

	input.InstanceID = inst.UUID

	if cmd.IsSet("plan_id") {
		planID, err := atomic.ParseID(cmd.String("plan_id"))
		if err != nil {
			return fmt.Errorf("failed to parse plan ID: %w", err)
		}
		input.PlanID = &planID
	}

	prices, err := backend.PriceList(ctx, &input)
	if err != nil {
		return err
	}

	PrintResult(cmd, prices,
		WithFields("id", "name", "plan_id", "type", "amount", "currency", "recurring_interval", "recurring_frequency", "active", "stripe_price"),
	)

	return nil
}

func priceDelete(ctx context.Context, cmd *cli.Command) error {
	if cmd.NArg() < 1 {
		return fmt.Errorf("price ID is required")
	}

	priceID, err := atomic.ParseID(cmd.Args().First())
	if err != nil {
		return fmt.Errorf("failed to parse price ID: %w", err)
	}

	if err := backend.PriceDelete(ctx, &atomic.PriceDeleteInput{
		InstanceID: inst.UUID,
		PriceID:    priceID,
	}); err != nil {
		return err
	}

	fmt.Println("Price deleted")

	return nil
}
