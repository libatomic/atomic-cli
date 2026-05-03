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
	"github.com/libatomic/atomic/pkg/ptr"
	"github.com/urfave/cli/v3"
)

var (
	planUpdateFlags = []cli.Flag{
		&cli.StringFlag{
			Name:  "name",
			Usage: "plan name",
		},
		&cli.StringFlag{
			Name:  "description",
			Usage: "plan description",
		},
		&cli.BoolFlag{
			Name:  "active",
			Usage: "set the plan as active",
		},
		&cli.BoolFlag{
			Name:  "hidden",
			Usage: "set the plan as hidden",
		},
		&cli.BoolFlag{
			Name:  "default",
			Usage: "set the plan as the default plan",
		},
		&cli.StringFlag{
			Name:  "password",
			Usage: "set the plan password",
		},
		&cli.StringFlag{
			Name:  "image",
			Usage: "set the plan image URL",
		},
		&cli.StringFlag{
			Name:  "metadata",
			Usage: "set plan metadata from a JSON file",
		},
	}

	planCreateFlags = append(planUpdateFlags, []cli.Flag{
		&cli.BoolFlag{
			Name:  "file",
			Usage: "read plan parameters from a JSON file",
		},
		&cli.StringFlag{
			Name:  "type",
			Usage: "plan type: free, paid, enterprise",
		},
		&cli.StringFlag{
			Name:  "stripe_product",
			Usage: "Stripe product ID",
		},
	}...)

	planCmd = &cli.Command{
		Name:    "plan",
		Aliases: []string{"plans"},
		Usage:   "manage plans",
		Commands: []*cli.Command{
			{
				Name:      "create",
				Usage:     "create a plan",
				Flags:     planCreateFlags,
				ArgsUsage: "<name>",
				Action:    planCreate,
			},
			{
				Name:      "update",
				Usage:     "update a plan",
				Flags:     planUpdateFlags,
				ArgsUsage: "<plan_id>",
				Action:    planUpdate,
			},
			{
				Name:      "get",
				Usage:     "get a plan",
				ArgsUsage: "<plan_id>",
				Flags: []cli.Flag{
					&cli.StringSliceFlag{
						Name:  "expand",
						Usage: "expand fields (prices, categories, audiences)",
					},
				},
				Action: planGet,
			},
			{
				Name:   "list",
				Usage:  "list plans",
				Action: planList,
				Flags: []cli.Flag{
					&cli.StringSliceFlag{
						Name:  "type",
						Usage: "filter by plan type (free, paid, enterprise)",
					},
					&cli.BoolFlag{
						Name:  "hidden",
						Usage: "include hidden plans",
					},
					&cli.BoolFlag{
						Name:  "inactive",
						Usage: "include inactive plans",
					},
					&cli.IntFlag{
						Name:  "limit",
						Usage: "limit the number of plans",
					},
					&cli.IntFlag{
						Name:  "offset",
						Usage: "offset the number of plans",
					},
					&cli.StringSliceFlag{
						Name:  "expand",
						Usage: "expand fields (prices, categories, audiences)",
					},
				},
			},
			{
				Name:      "delete",
				Usage:     "delete a plan",
				ArgsUsage: "<plan_id>",
				Action:    planDelete,
			},
			{
				Name:      "subscribe",
				Usage:     "subscribe a user to a plan",
				ArgsUsage: "<plan_id>",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:     "user_id",
						Usage:    "user ID to subscribe",
						Required: true,
					},
					&cli.StringFlag{
						Name:  "price_id",
						Usage: "specific price ID",
					},
					&cli.StringFlag{
						Name:  "interval",
						Usage: "subscription interval: month, year",
					},
					&cli.StringFlag{
						Name:  "currency",
						Usage: "subscription currency",
					},
					&cli.IntFlag{
						Name:  "quantity",
						Usage: "subscription quantity",
						Value: 1,
					},
					&cli.BoolFlag{
						Name:  "no_prorate",
						Usage: "do not prorate the subscription",
					},
					&cli.BoolFlag{
						Name:  "no_entitlement",
						Usage: "do not create entitlements",
					},
					&cli.BoolFlag{
						Name:  "trial",
						Usage: "start the subscription with a trial",
					},
					&cli.StringFlag{
						Name:  "password",
						Usage: "plan password",
					},
					&cli.StringSliceFlag{
						Name:  "expand",
						Usage: "expand fields",
					},
				},
				Action: planSubscribe,
			},
			{
				Name:      "import",
				Usage:     "import plans with prices from a JSON file",
				ArgsUsage: "<file>",
				Action:    planImport,
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

func planCreate(ctx context.Context, cmd *cli.Command) error {
	var input atomic.PlanCreateInput

	if cmd.IsSet("file") && cmd.Bool("file") {
		content, err := os.ReadFile(cmd.Args().First())
		if err != nil {
			return fmt.Errorf("failed to read plan create input file: %w", err)
		}

		if err := json.Unmarshal(content, &input); err != nil {
			return fmt.Errorf("failed to unmarshal plan create input: %w", err)
		}
	} else if cmd.Args().First() != "" {
		input.Name = cmd.Args().First()
	}

	if err := BindFlagsFromContext(cmd, &input, "file", "metadata"); err != nil {
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

	input.InstanceID = inst.UUID

	plan, err := backend.PlanCreate(ctx, &input)
	if err != nil {
		return err
	}

	PrintResult(cmd, []*atomic.Plan{plan},
		WithSingleValue(true),
		WithFields("id", "name", "type", "active", "hidden", "default", "created_at"),
	)

	return nil
}

func planUpdate(ctx context.Context, cmd *cli.Command) error {
	if cmd.NArg() < 1 {
		return fmt.Errorf("plan ID is required")
	}

	planID, err := atomic.ParseID(cmd.Args().First())
	if err != nil {
		return fmt.Errorf("failed to parse plan ID: %w", err)
	}

	var input atomic.PlanUpdateInput

	if err := BindFlagsFromContext(cmd, &input, "metadata"); err != nil {
		return err
	}

	input.InstanceID = inst.UUID
	input.PlanID = planID

	if cmd.IsSet("metadata") {
		content, err := os.ReadFile(cmd.String("metadata"))
		if err != nil {
			return fmt.Errorf("failed to read metadata file: %w", err)
		}

		if err := json.Unmarshal(content, &input.Metadata); err != nil {
			return fmt.Errorf("failed to unmarshal metadata: %w", err)
		}
	}

	plan, err := backend.PlanUpdate(ctx, &input)
	if err != nil {
		return err
	}

	PrintResult(cmd, []*atomic.Plan{plan},
		WithSingleValue(true),
		WithFields("id", "name", "type", "active", "hidden", "default", "updated_at"),
	)

	return nil
}

func planGet(ctx context.Context, cmd *cli.Command) error {
	if cmd.NArg() < 1 {
		return fmt.Errorf("plan ID is required")
	}

	planID, err := atomic.ParseID(cmd.Args().First())
	if err != nil {
		return fmt.Errorf("failed to parse plan ID: %w", err)
	}

	input := &atomic.PlanGetInput{
		InstanceID: inst.UUID,
		PlanID:     &planID,
	}

	if expand := cmd.StringSlice("expand"); len(expand) > 0 {
		input.Expand = expand
	}

	plan, err := backend.PlanGet(ctx, input)
	if err != nil {
		return err
	}

	PrintResult(cmd, []*atomic.Plan{plan},
		WithSingleValue(true),
		WithFields("id", "name", "type", "active", "hidden", "default", "stripe_product", "created_at"),
	)

	return nil
}

func planList(ctx context.Context, cmd *cli.Command) error {
	var input atomic.PlanListInput

	if err := BindFlagsFromContext(cmd, &input); err != nil {
		return err
	}

	input.InstanceID = inst.UUID

	if types := cmd.StringSlice("type"); len(types) > 0 {
		for _, t := range types {
			input.Type = append(input.Type, atomic.PlanType(t))
		}
	}

	if cmd.IsSet("hidden") {
		input.Hidden = ptr.Bool(cmd.Bool("hidden"))
	}

	if cmd.IsSet("inactive") {
		input.Inactive = ptr.Bool(cmd.Bool("inactive"))
	}

	if expand := cmd.StringSlice("expand"); len(expand) > 0 {
		input.Expand = expand
	}

	plans, err := backend.PlanList(ctx, &input)
	if err != nil {
		return err
	}

	PrintResult(cmd, plans,
		WithFields("id", "name", "type", "active", "hidden", "default", "stripe_product", "created_at"),
	)

	return nil
}

func planDelete(ctx context.Context, cmd *cli.Command) error {
	if cmd.NArg() < 1 {
		return fmt.Errorf("plan ID is required")
	}

	planID, err := atomic.ParseID(cmd.Args().First())
	if err != nil {
		return fmt.Errorf("failed to parse plan ID: %w", err)
	}

	if err := backend.PlanDelete(ctx, &atomic.PlanDeleteInput{
		InstanceID: inst.UUID,
		PlanID:     planID,
	}); err != nil {
		return err
	}

	fmt.Println("Plan deleted")

	return nil
}

func planSubscribe(ctx context.Context, cmd *cli.Command) error {
	if cmd.NArg() < 1 {
		return fmt.Errorf("plan ID is required")
	}

	planID, err := atomic.ParseID(cmd.Args().First())
	if err != nil {
		return fmt.Errorf("failed to parse plan ID: %w", err)
	}

	userID, err := atomic.ParseID(cmd.String("user_id"))
	if err != nil {
		return fmt.Errorf("failed to parse user ID: %w", err)
	}

	input := &atomic.PlanSubscribeInput{
		InstanceID: inst.UUID,
		PlanID:     &planID,
		UserID:     &userID,
	}

	if cmd.IsSet("price_id") {
		priceID, err := atomic.ParseID(cmd.String("price_id"))
		if err != nil {
			return fmt.Errorf("failed to parse price ID: %w", err)
		}
		input.PriceID = &priceID
	}

	if cmd.IsSet("interval") {
		interval := atomic.SubscriptionInterval(cmd.String("interval"))
		input.Interval = &interval
	}

	if cmd.IsSet("currency") {
		currency := cmd.String("currency")
		input.Currency = &currency
	}

	if cmd.IsSet("quantity") {
		qty := uint64(cmd.Int("quantity"))
		input.Quantity = &qty
	}

	if cmd.IsSet("no_prorate") {
		input.NoProrate = ptr.Bool(cmd.Bool("no_prorate"))
	}

	if cmd.IsSet("no_entitlement") {
		input.NoEntitlement = ptr.Bool(cmd.Bool("no_entitlement"))
	}

	if cmd.IsSet("trial") {
		input.Trial = ptr.Bool(cmd.Bool("trial"))
	}

	if cmd.IsSet("password") {
		password := cmd.String("password")
		input.Password = &password
	}

	if expand := cmd.StringSlice("expand"); len(expand) > 0 {
		input.Expand = expand
	}

	sub, err := backend.PlanSubscribe(ctx, input)
	if err != nil {
		return err
	}

	PrintResult(cmd, []*atomic.Subscription{sub},
		WithSingleValue(true),
		WithFields("id", "user_id", "plan_id", "price_id", "status", "recurring_interval", "quantity", "created_at"),
	)

	return nil
}

func planImport(ctx context.Context, cmd *cli.Command) error {
	if cmd.NArg() < 1 {
		return fmt.Errorf("JSON file is required")
	}

	dryRun := cmd.Bool("dry-run")

	content, err := os.ReadFile(cmd.Args().First())
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	var plans []atomic.Plan
	if err := json.Unmarshal(content, &plans); err != nil {
		return fmt.Errorf("failed to parse JSON: %w", err)
	}

	fmt.Fprintf(os.Stderr, "parsed %d plans\n", len(plans))

	var planCount, priceCount int
	for _, plan := range plans {
		if dryRun {
			fmt.Fprintf(os.Stderr, "[DRY RUN] would create plan: %s (%s)\n", plan.Name, plan.Type)
			for _, price := range plan.Prices {
				fmt.Fprintf(os.Stderr, "  would create price: %s %d %s (%s/%d)\n",
					price.Name, ptr.Value(price.FlatAmount, 0), price.Currency,
					ptr.Value(price.RecurringInterval, ""), ptr.Value(price.RecurringFrequency, 0))
			}
			planCount++
			priceCount += len(plan.Prices)
			continue
		}

		createInput := &atomic.PlanCreateInput{
			InstanceID:  inst.UUID,
			Name:        plan.Name,
			Description: plan.Description,
			Type:        plan.Type,
			Active:      &plan.Active,
			Hidden:      &plan.Hidden,
			Default:     &plan.Default,
			Image:       plan.Image,
			Metadata:    plan.Metadata,
			Categories:  plan.Categories,
		}

		newPlan, err := backend.PlanCreate(ctx, createInput)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to create plan %q: %s\n", plan.Name, err)
			continue
		}

		fmt.Fprintf(os.Stderr, "created plan: %s -> %s\n", newPlan.Name, newPlan.UUID)
		planCount++

		for _, price := range plan.Prices {
			priceInput := &atomic.PriceCreateInput{
				InstanceID: &inst.UUID,
				PlanID:     newPlan.UUID,
				Name:       price.Name,
				Currency:   price.Currency,
				Active:     &price.Active,
				Hidden:     &price.Hidden,
				Amount:     price.FlatAmount,
				Type:       price.RecurringType,
				Metered:    price.Metered,
			}

			if price.CurrencyOptions != nil {
				priceInput.CurrencyOptions = price.CurrencyOptions
			}

			if price.RecurringInterval != nil {
				priceInput.Recurring = &atomic.PriceRecurring{
					Interval:  string(*price.RecurringInterval),
					Frequency: int64(ptr.Value(price.RecurringFrequency, 1)),
				}
			}

			if price.TrialSettings != nil {
				priceInput.TrialSettings = price.TrialSettings
			}

			newPrice, err := backend.PriceCreate(ctx, priceInput)
			if err != nil {
				fmt.Fprintf(os.Stderr, "  failed to create price %q: %s\n", price.Name, err)
				continue
			}

			fmt.Fprintf(os.Stderr, "  created price: %s -> %s\n", newPrice.Name, newPrice.UUID)
			priceCount++
		}
	}

	fmt.Fprintf(os.Stderr, "%d plans, %d prices created\n", planCount, priceCount)

	return nil
}
