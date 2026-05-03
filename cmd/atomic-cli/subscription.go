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
	"time"

	"github.com/libatomic/atomic/pkg/atomic"
	"github.com/libatomic/atomic/pkg/ptr"
	"github.com/urfave/cli/v3"
)

var (
	subscriptionCmd = &cli.Command{
		Name:    "subscription",
		Aliases: []string{"subscriptions", "sub", "subs"},
		Usage:   "manage subscriptions",
		Commands: []*cli.Command{
			{
				Name:   "list",
				Usage:  "list subscriptions",
				Action: subscriptionList,
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "user_id", Usage: "filter by user id"},
					&cli.StringFlag{Name: "plan_id", Usage: "filter by plan id"},
					&cli.StringFlag{Name: "price_id", Usage: "filter by price id"},
					&cli.IntFlag{Name: "limit", Usage: "limit"},
					&cli.IntFlag{Name: "offset", Usage: "offset"},
					&cli.BoolFlag{Name: "preload", Usage: "preload related entities"},
				},
			},
			{
				Name:      "get",
				Usage:     "get a subscription",
				ArgsUsage: "<subscription_id>",
				Action:    subscriptionGet,
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "user_id", Usage: "look up by user id"},
					&cli.StringFlag{Name: "stripe_subscription", Usage: "look up by stripe subscription id"},
				},
			},
			{
				Name:      "create",
				Usage:     "create a subscription",
				ArgsUsage: "<user_id>",
				Action:    subscriptionCreate,
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "status", Usage: "status"},
					&cli.StringFlag{Name: "stripe_subscription", Usage: "stripe subscription id"},
					&cli.StringFlag{Name: "stripe_item", Usage: "stripe item id"},
					&cli.StringFlag{Name: "credit_id", Usage: "credit id"},
					&cli.StringFlag{Name: "price_id", Usage: "price id"},
					&cli.StringFlag{Name: "begins_at", Usage: "RFC3339 begin timestamp"},
					&cli.StringFlag{Name: "ends_at", Usage: "RFC3339 end timestamp"},
					&cli.StringFlag{Name: "cancel_at", Usage: "RFC3339 cancel timestamp"},
					&cli.StringFlag{Name: "trial_ends_at", Usage: "RFC3339 trial end timestamp"},
					&cli.IntFlag{Name: "quantity", Usage: "quantity"},
					&cli.IntFlag{Name: "max_quantity", Usage: "max quantity"},
					&cli.BoolFlag{Name: "auto_renew", Usage: "auto renew"},
					&cli.BoolFlag{Name: "no_entitlement", Usage: "skip entitlement creation"},
					&cli.StringFlag{Name: "metadata", Usage: "read metadata from a JSON `FILE`"},
					&cli.StringFlag{Name: "file", Usage: "read full input from JSON `FILE`"},
				},
			},
			{
				Name:      "update",
				Usage:     "update a subscription",
				ArgsUsage: "<subscription_id>",
				Action:    subscriptionUpdate,
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "status", Usage: "status"},
					&cli.StringFlag{Name: "stripe_subscription", Usage: "stripe subscription id"},
					&cli.StringFlag{Name: "stripe_item", Usage: "stripe item id"},
					&cli.StringFlag{Name: "credit_id", Usage: "credit id"},
					&cli.StringFlag{Name: "begins_at", Usage: "RFC3339 begin timestamp"},
					&cli.StringFlag{Name: "ends_at", Usage: "RFC3339 end timestamp"},
					&cli.StringFlag{Name: "trial_ends_at", Usage: "RFC3339 trial end timestamp"},
					&cli.BoolFlag{Name: "canceled", Usage: "mark canceled"},
					&cli.IntFlag{Name: "quantity", Usage: "quantity"},
					&cli.Int64Flag{Name: "increment_qty", Usage: "increment quantity by N"},
					&cli.IntFlag{Name: "max_quantity", Usage: "max quantity"},
					&cli.BoolFlag{Name: "auto_renew", Usage: "auto renew"},
					&cli.BoolFlag{Name: "skip_stripe_update", Usage: "do not push update to stripe"},
					&cli.BoolFlag{Name: "update_entitlement", Usage: "update entitlements"},
					&cli.BoolFlag{Name: "no_entitlement", Usage: "no entitlement"},
					&cli.StringFlag{Name: "metadata", Usage: "read metadata from a JSON `FILE`"},
					&cli.StringFlag{Name: "file", Usage: "read full input from JSON `FILE`"},
				},
			},
			{
				Name:      "delete",
				Usage:     "cancel/delete a subscription",
				ArgsUsage: "<subscription_id>",
				Action:    subscriptionDelete,
				Flags: []cli.Flag{
					&cli.BoolFlag{Name: "immediate", Usage: "cancel immediately"},
					&cli.BoolFlag{Name: "ignore_stripe", Usage: "do not propagate to stripe"},
					&cli.BoolFlag{Name: "skip_stripe_delete", Usage: "skip stripe deletion"},
				},
			},
		},
	}
)

func subscriptionList(ctx context.Context, cmd *cli.Command) error {
	var input atomic.SubscriptionListInput

	if err := BindFlagsFromContext(cmd, &input, "user_id", "plan_id", "price_id", "preload"); err != nil {
		return err
	}

	input.InstanceID = inst.UUID

	if cmd.IsSet("user_id") {
		id, err := atomic.ParseID(cmd.String("user_id"))
		if err != nil {
			return fmt.Errorf("failed to parse user_id: %w", err)
		}
		input.UserID = &id
	}
	if cmd.IsSet("plan_id") {
		id, err := atomic.ParseID(cmd.String("plan_id"))
		if err != nil {
			return fmt.Errorf("failed to parse plan_id: %w", err)
		}
		input.PlanID = &id
	}
	if cmd.IsSet("price_id") {
		id, err := atomic.ParseID(cmd.String("price_id"))
		if err != nil {
			return fmt.Errorf("failed to parse price_id: %w", err)
		}
		input.PriceID = &id
	}
	if cmd.IsSet("preload") {
		v := cmd.Bool("preload")
		input.Preload = &v
	}

	subs, err := backend.SubscriptionList(ctx, &input)
	if err != nil {
		return err
	}

	PrintResult(cmd, subs,
		WithFields("id", "user_id", "status", "begins_at", "ends_at", "auto_renew", "created_at"),
	)
	return nil
}

func subscriptionGet(ctx context.Context, cmd *cli.Command) error {
	input := &atomic.SubscriptionGetInput{
		InstanceID: inst.UUID,
	}

	if cmd.NArg() >= 1 {
		id, err := atomic.ParseID(cmd.Args().First())
		if err != nil {
			return fmt.Errorf("failed to parse subscription id: %w", err)
		}
		input.SubscriptionID = &id
	}
	if cmd.IsSet("user_id") {
		id, err := atomic.ParseID(cmd.String("user_id"))
		if err != nil {
			return fmt.Errorf("failed to parse user_id: %w", err)
		}
		input.UserID = &id
	}
	if cmd.IsSet("stripe_subscription") {
		input.StripeSubscription = ptr.String(cmd.String("stripe_subscription"))
	}

	if input.SubscriptionID == nil && input.UserID == nil && input.StripeSubscription == nil {
		return fmt.Errorf("provide a subscription id, --user_id, or --stripe_subscription")
	}

	sub, err := backend.SubscriptionGet(ctx, input)
	if err != nil {
		return err
	}

	PrintResult(cmd, []*atomic.Subscription{sub},
		WithSingleValue(true),
		WithFields("id", "user_id", "status", "begins_at", "ends_at", "trial_ends_at", "auto_renew", "quantity", "created_at"),
	)
	return nil
}

func subscriptionCreate(ctx context.Context, cmd *cli.Command) error {
	var input atomic.SubscriptionCreateInput

	if cmd.IsSet("file") {
		if err := readJSONFile(cmd.String("file"), &input); err != nil {
			return err
		}
	} else {
		if cmd.NArg() < 1 {
			return fmt.Errorf("user_id is required")
		}
		uid, err := atomic.ParseID(cmd.Args().First())
		if err != nil {
			return fmt.Errorf("failed to parse user_id: %w", err)
		}
		input.UserID = uid

		if cmd.IsSet("status") {
			s := atomic.SubscriptionStatus(cmd.String("status"))
			input.Status = &s
		}
		if cmd.IsSet("stripe_subscription") {
			input.StripeSubscription = ptr.String(cmd.String("stripe_subscription"))
		}
		if cmd.IsSet("stripe_item") {
			input.StripeItem = ptr.String(cmd.String("stripe_item"))
		}
		if cmd.IsSet("credit_id") {
			id, err := atomic.ParseID(cmd.String("credit_id"))
			if err != nil {
				return fmt.Errorf("failed to parse credit_id: %w", err)
			}
			input.CreditID = &id
		}
		if cmd.IsSet("price_id") {
			id, err := atomic.ParseID(cmd.String("price_id"))
			if err != nil {
				return fmt.Errorf("failed to parse price_id: %w", err)
			}
			input.PriceID = &id
		}
		if err := setTimePtr(cmd, "begins_at", &input.BeginsAt); err != nil {
			return err
		}
		if err := setTimePtr(cmd, "ends_at", &input.EndsAt); err != nil {
			return err
		}
		if err := setTimePtr(cmd, "cancel_at", &input.CancelAt); err != nil {
			return err
		}
		if err := setTimePtr(cmd, "trial_ends_at", &input.TrialEndsAt); err != nil {
			return err
		}
		if cmd.IsSet("quantity") {
			v := uint64(cmd.Int("quantity"))
			input.Quantity = &v
		}
		if cmd.IsSet("max_quantity") {
			v := uint64(cmd.Int("max_quantity"))
			input.MaxQuantity = &v
		}
		if cmd.IsSet("auto_renew") {
			v := cmd.Bool("auto_renew")
			input.AutoRenew = &v
		}
		if cmd.IsSet("no_entitlement") {
			v := cmd.Bool("no_entitlement")
			input.NoEntitlement = &v
		}
		if cmd.IsSet("metadata") {
			md, err := readMetadataFile(cmd.String("metadata"))
			if err != nil {
				return err
			}
			input.Metadata = md
		}
	}

	input.InstanceID = inst.UUID

	sub, err := backend.SubscriptionCreate(ctx, &input)
	if err != nil {
		return err
	}

	PrintResult(cmd, []*atomic.Subscription{sub},
		WithSingleValue(true),
		WithFields("id", "user_id", "status", "begins_at", "ends_at", "auto_renew", "created_at"),
	)
	return nil
}

func subscriptionUpdate(ctx context.Context, cmd *cli.Command) error {
	if cmd.NArg() < 1 {
		return fmt.Errorf("subscription id is required")
	}

	id, err := atomic.ParseID(cmd.Args().First())
	if err != nil {
		return fmt.Errorf("failed to parse subscription id: %w", err)
	}

	var input atomic.SubscriptionUpdateInput

	if cmd.IsSet("file") {
		if err := readJSONFile(cmd.String("file"), &input); err != nil {
			return err
		}
	} else {
		if cmd.IsSet("status") {
			s := atomic.SubscriptionStatus(cmd.String("status"))
			input.Status = &s
		}
		if cmd.IsSet("stripe_subscription") {
			input.StripeSubscription = ptr.String(cmd.String("stripe_subscription"))
		}
		if cmd.IsSet("stripe_item") {
			input.StripeItem = ptr.String(cmd.String("stripe_item"))
		}
		if cmd.IsSet("credit_id") {
			cid, err := atomic.ParseID(cmd.String("credit_id"))
			if err != nil {
				return fmt.Errorf("failed to parse credit_id: %w", err)
			}
			input.CreditID = &cid
		}
		if err := setTimePtr(cmd, "begins_at", &input.BeginsAt); err != nil {
			return err
		}
		if err := setTimePtr(cmd, "ends_at", &input.EndsAt); err != nil {
			return err
		}
		if err := setTimePtr(cmd, "trial_ends_at", &input.TrialEndsAt); err != nil {
			return err
		}
		if cmd.IsSet("canceled") {
			v := cmd.Bool("canceled")
			input.Canceled = &v
		}
		if cmd.IsSet("quantity") {
			v := uint64(cmd.Int("quantity"))
			input.Quantity = &v
		}
		if cmd.IsSet("increment_qty") {
			v := cmd.Int64("increment_qty")
			input.IncrementQuantity = &v
		}
		if cmd.IsSet("max_quantity") {
			v := uint64(cmd.Int("max_quantity"))
			input.MaxQuantity = &v
		}
		if cmd.IsSet("auto_renew") {
			v := cmd.Bool("auto_renew")
			input.AutoRenew = &v
		}
		if cmd.IsSet("skip_stripe_update") {
			v := cmd.Bool("skip_stripe_update")
			input.UpdateProvider = &v
		}
		if cmd.IsSet("update_entitlement") {
			v := cmd.Bool("update_entitlement")
			input.UpdateEntitlements = &v
		}
		if cmd.IsSet("no_entitlement") {
			v := cmd.Bool("no_entitlement")
			input.NoEntitlement = &v
		}
		if cmd.IsSet("metadata") {
			md, err := readMetadataFile(cmd.String("metadata"))
			if err != nil {
				return err
			}
			input.Metadata = md
		}
	}

	input.InstanceID = inst.UUID
	input.SubscriptionID = &id

	sub, err := backend.SubscriptionUpdate(ctx, &input)
	if err != nil {
		return err
	}

	PrintResult(cmd, []*atomic.Subscription{sub},
		WithSingleValue(true),
		WithFields("id", "user_id", "status", "begins_at", "ends_at", "auto_renew", "updated_at"),
	)
	return nil
}

func subscriptionDelete(ctx context.Context, cmd *cli.Command) error {
	if cmd.NArg() < 1 {
		return fmt.Errorf("subscription id is required")
	}

	id, err := atomic.ParseID(cmd.Args().First())
	if err != nil {
		return fmt.Errorf("failed to parse subscription id: %w", err)
	}

	input := &atomic.SubscriptionDeleteInput{
		InstanceID:     inst.UUID,
		SubscriptionID: &id,
		PreserveStripe: cmd.Bool("ignore_stripe"),
	}

	if cmd.IsSet("immediate") {
		v := cmd.Bool("immediate")
		input.CancelImmediately = &v
	}
	if cmd.IsSet("skip_stripe_delete") {
		input.SkipStripeCancel = cmd.Bool("skip_stripe_delete")
	}

	if err := backend.SubscriptionDelete(ctx, input); err != nil {
		return err
	}

	fmt.Println("Subscription canceled")
	return nil
}

func setTimePtr(cmd *cli.Command, name string, dst **time.Time) error {
	if !cmd.IsSet(name) {
		return nil
	}
	t, err := time.Parse(time.RFC3339, cmd.String(name))
	if err != nil {
		return fmt.Errorf("failed to parse %s: %w", name, err)
	}
	*dst = &t
	return nil
}
