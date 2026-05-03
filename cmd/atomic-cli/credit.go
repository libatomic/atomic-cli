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

	"github.com/libatomic/atomic/pkg/atomic"
	"github.com/libatomic/atomic/pkg/ptr"
	"github.com/urfave/cli/v3"
)

var (
	creditCmd = &cli.Command{
		Name:    "credit",
		Aliases: []string{"credits"},
		Usage:   "manage credits",
		Commands: []*cli.Command{
			{
				Name:   "list",
				Usage:  "list credits",
				Action: creditList,
				Flags: []cli.Flag{
					&cli.IntFlag{Name: "limit", Usage: "limit"},
					&cli.IntFlag{Name: "offset", Usage: "offset"},
					&cli.StringFlag{Name: "type", Usage: "filter by credit type"},
					&cli.StringFlag{Name: "owner_id", Usage: "filter by owner id"},
					&cli.StringFlag{Name: "owner_email", Usage: "filter by owner email"},
					&cli.StringFlag{Name: "passcode", Usage: "filter by passcode"},
					&cli.StringFlag{Name: "subscription_id", Usage: "filter by subscription id"},
					&cli.StringFlag{Name: "invite_code", Usage: "filter by invite code"},
					&cli.BoolFlag{Name: "aggregate", Usage: "aggregate by owner"},
				},
			},
			{
				Name:      "get",
				Usage:     "get a credit",
				ArgsUsage: "<credit_id>",
				Action:    creditGet,
			},
			{
				Name:      "create",
				Usage:     "create a credit",
				ArgsUsage: "[type]",
				Action:    creditCreate,
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "name", Usage: "name"},
					&cli.StringFlag{Name: "description", Usage: "description"},
					&cli.StringFlag{Name: "owner_id", Usage: "owner user id"},
					&cli.StringFlag{Name: "owner_email", Usage: "owner email"},
					&cli.StringFlag{Name: "plan_id", Usage: "plan id"},
					&cli.Int64Flag{Name: "amount", Usage: "amount in cents"},
					&cli.Float64Flag{Name: "percent_off", Usage: "percent off"},
					&cli.StringFlag{Name: "interval", Usage: "subscription interval"},
					&cli.IntFlag{Name: "quantity", Usage: "credit quantity"},
					&cli.Int64Flag{Name: "duration", Usage: "duration"},
					&cli.StringFlag{Name: "term", Usage: "credit term (once|repeating|forever)"},
					&cli.StringFlag{Name: "status", Usage: "credit status"},
					&cli.StringFlag{Name: "stripe_payment_intent", Usage: "stripe payment intent"},
					&cli.StringFlag{Name: "stripe_coupon", Usage: "stripe coupon"},
					&cli.StringFlag{Name: "subscription_id", Usage: "subscription id"},
					&cli.StringFlag{Name: "entitlement_id", Usage: "entitlement id"},
					&cli.StringFlag{Name: "metadata", Usage: "read metadata from a JSON `FILE`"},
					&cli.StringFlag{Name: "file", Usage: "read full input from JSON `FILE`"},
				},
			},
			{
				Name:      "update",
				Usage:     "update a credit",
				ArgsUsage: "<credit_id>",
				Action:    creditUpdate,
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "status", Usage: "status"},
					&cli.Int64Flag{Name: "amount", Usage: "amount in cents"},
					&cli.Float64Flag{Name: "percent_off", Usage: "percent off"},
					&cli.Int64Flag{Name: "duration", Usage: "duration"},
					&cli.StringFlag{Name: "stripe_coupon", Usage: "stripe coupon"},
					&cli.StringFlag{Name: "metadata", Usage: "read metadata from a JSON `FILE`"},
					&cli.StringFlag{Name: "file", Usage: "read full input from JSON `FILE`"},
				},
			},
		},
	}
)

func creditList(ctx context.Context, cmd *cli.Command) error {
	var input atomic.CreditListInput

	if err := BindFlagsFromContext(cmd, &input, "type", "owner_id", "subscription_id", "aggregate"); err != nil {
		return err
	}

	input.InstanceID = inst.UUID

	if cmd.IsSet("type") {
		t := atomic.CreditType(cmd.String("type"))
		input.Type = &t
	}
	if cmd.IsSet("owner_id") {
		id, err := atomic.ParseID(cmd.String("owner_id"))
		if err != nil {
			return fmt.Errorf("failed to parse owner_id: %w", err)
		}
		input.OwnerID = &id
	}
	if cmd.IsSet("subscription_id") {
		id, err := atomic.ParseID(cmd.String("subscription_id"))
		if err != nil {
			return fmt.Errorf("failed to parse subscription_id: %w", err)
		}
		input.SubscriptionID = &id
	}
	if cmd.IsSet("aggregate") {
		v := cmd.Bool("aggregate")
		input.Aggregate = &v
	}

	credits, err := backend.CreditList(ctx, &input)
	if err != nil {
		return err
	}

	PrintResult(cmd, credits,
		WithFields("id", "name", "type", "status", "owner_id", "amount", "percent_off", "created_at"),
	)
	return nil
}

func creditGet(ctx context.Context, cmd *cli.Command) error {
	if cmd.NArg() < 1 {
		return fmt.Errorf("credit id is required")
	}

	id, err := atomic.ParseID(cmd.Args().First())
	if err != nil {
		return fmt.Errorf("failed to parse credit id: %w", err)
	}

	credit, err := backend.CreditGet(ctx, &atomic.CreditGetInput{
		InstanceID: inst.UUID,
		CreditID:   &id,
	})
	if err != nil {
		return err
	}

	PrintResult(cmd, []*atomic.Credit{credit},
		WithSingleValue(true),
		WithFields("id", "name", "type", "status", "owner_id", "amount", "percent_off", "passcode", "created_at"),
	)
	return nil
}

func creditCreate(ctx context.Context, cmd *cli.Command) error {
	var input atomic.CreditCreateInput

	if cmd.IsSet("file") {
		if err := readJSONFile(cmd.String("file"), &input); err != nil {
			return err
		}
	} else {
		if cmd.NArg() >= 1 {
			input.Type = atomic.CreditType(cmd.Args().First())
		}
		if cmd.IsSet("name") {
			input.Name = ptr.String(cmd.String("name"))
		}
		if cmd.IsSet("description") {
			input.Description = ptr.String(cmd.String("description"))
		}
		if cmd.IsSet("owner_id") {
			id, err := atomic.ParseID(cmd.String("owner_id"))
			if err != nil {
				return fmt.Errorf("failed to parse owner_id: %w", err)
			}
			input.OwnerID = &id
		}
		if cmd.IsSet("plan_id") {
			id, err := atomic.ParseID(cmd.String("plan_id"))
			if err != nil {
				return fmt.Errorf("failed to parse plan_id: %w", err)
			}
			input.PlanID = &id
		}
		if cmd.IsSet("subscription_id") {
			id, err := atomic.ParseID(cmd.String("subscription_id"))
			if err != nil {
				return fmt.Errorf("failed to parse subscription_id: %w", err)
			}
			input.SubscriptionID = &id
		}
		if cmd.IsSet("entitlement_id") {
			id, err := atomic.ParseID(cmd.String("entitlement_id"))
			if err != nil {
				return fmt.Errorf("failed to parse entitlement_id: %w", err)
			}
			input.EntitlementID = &id
		}
		if cmd.IsSet("amount") {
			v := cmd.Int64("amount")
			input.Amount = &v
		}
		if cmd.IsSet("percent_off") {
			v := cmd.Float64("percent_off")
			input.PercentOff = &v
		}
		if cmd.IsSet("interval") {
			ivl := atomic.SubscriptionInterval(cmd.String("interval"))
			input.Interval = &ivl
		}
		if cmd.IsSet("quantity") {
			v := cmd.Int("quantity")
			input.Quantity = &v
		}
		if cmd.IsSet("duration") {
			v := cmd.Int64("duration")
			input.Duration = &v
		}
		if cmd.IsSet("term") {
			t := atomic.CreditTerm(cmd.String("term"))
			input.Term = &t
		}
		if cmd.IsSet("status") {
			s := atomic.CreditStatus(cmd.String("status"))
			input.Status = &s
		}
		if cmd.IsSet("stripe_payment_intent") {
			input.PaymentIntent = ptr.String(cmd.String("stripe_payment_intent"))
		}
		if cmd.IsSet("stripe_coupon") {
			input.StripeCoupon = ptr.String(cmd.String("stripe_coupon"))
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

	credit, err := backend.CreditCreate(ctx, &input)
	if err != nil {
		return err
	}

	PrintResult(cmd, []*atomic.Credit{credit},
		WithSingleValue(true),
		WithFields("id", "name", "type", "status", "owner_id", "amount", "passcode", "created_at"),
	)
	return nil
}

func creditUpdate(ctx context.Context, cmd *cli.Command) error {
	if cmd.NArg() < 1 {
		return fmt.Errorf("credit id is required")
	}

	id, err := atomic.ParseID(cmd.Args().First())
	if err != nil {
		return fmt.Errorf("failed to parse credit id: %w", err)
	}

	var input atomic.CreditUpdateInput

	if cmd.IsSet("file") {
		if err := readJSONFile(cmd.String("file"), &input); err != nil {
			return err
		}
	} else {
		if cmd.IsSet("status") {
			s := atomic.CreditStatus(cmd.String("status"))
			input.Status = &s
		}
		if cmd.IsSet("amount") {
			v := cmd.Int64("amount")
			input.Amount = &v
		}
		if cmd.IsSet("percent_off") {
			v := cmd.Float64("percent_off")
			input.PercentOff = &v
		}
		if cmd.IsSet("duration") {
			v := cmd.Int64("duration")
			input.Duration = &v
		}
		if cmd.IsSet("stripe_coupon") {
			input.StripeCoupon = ptr.String(cmd.String("stripe_coupon"))
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
	input.CreditID = id

	credit, err := backend.CreditUpdate(ctx, &input)
	if err != nil {
		return err
	}

	PrintResult(cmd, []*atomic.Credit{credit},
		WithSingleValue(true),
		WithFields("id", "name", "type", "status", "amount", "updated_at"),
	)
	return nil
}
