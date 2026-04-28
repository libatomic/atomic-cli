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
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/libatomic/atomic/pkg/atomic"
	"github.com/libatomic/atomic/pkg/ptr"
	"github.com/stripe/stripe-go/v79"
	stripeclient "github.com/stripe/stripe-go/v79/client"
	"github.com/urfave/cli/v3"
)

const (
	atomicImportMetadataKey   = "atomic:import"
	atomicImportMetadataValue = "true"
)

var (
	stripeCustomerCmd = &cli.Command{
		Name:    "customer",
		Aliases: []string{"customers", "cust"},
		Usage:   "stripe customer management",
		Commands: []*cli.Command{
			stripeCustomerCleanupCmd,
		},
	}

	stripeCustomerCleanupCmd = &cli.Command{
		Name: "cleanup",
		Usage: "delete disconnected stripe customers that were created in error: " +
			"no associated passport user, only atomic-imported subscriptions, " +
			"and no payment methods anywhere on the customer or its subscriptions",
		Description: "Reads a CSV of stripe customer ids and deletes the ones that are " +
			"clearly invalid orphans: no passport user references the customer, every " +
			"non-canceled subscription was created by atomic import (metadata " +
			"\"atomic:import\"=\"true\") and has no default_payment_method or " +
			"default_source, and the customer itself has no default_source and no " +
			"invoice_settings.default_payment_method. Customers that fail any of " +
			"these checks are skipped. Use --dry-run to preview without deleting.",
		ArgsUsage: "<input.csv>",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  "stripe_customer_id_col",
				Usage: "name of the CSV column containing the stripe customer id",
				Value: "id",
			},
			&cli.BoolFlag{
				Name:  "dry-run",
				Usage: "preview what would be deleted without making changes",
			},
			&cli.IntFlag{
				Name:  "limit",
				Usage: "limit the number of customer ids processed; 0 = no limit",
				Value: 0,
			},
			&cli.IntFlag{
				Name:  "skip",
				Usage: "skip the first N customer ids in the input CSV; 0 = no skip",
				Value: 0,
			},
		},
		Action: stripeCustomerCleanupAction,
	}
)

func stripeCustomerCleanupAction(ctx context.Context, cmd *cli.Command) error {
	if cmd.NArg() < 1 {
		return fmt.Errorf("input CSV path is required")
	}

	if inst == nil {
		return fmt.Errorf("--instance_id is required")
	}

	inputPath := cmd.Args().First()
	idCol := strings.ToLower(strings.TrimSpace(cmd.String("stripe_customer_id_col")))
	dryRun := cmd.Bool("dry-run")
	verbose := mainCmd.Bool("verbose")
	skip := int(cmd.Int("skip"))
	limit := int(cmd.Int("limit"))

	sc := stripeclient.New(cmd.String("stripe-key"), nil)

	f, err := os.Open(inputPath)
	if err != nil {
		return fmt.Errorf("failed to open input file: %w", err)
	}
	defer f.Close()

	reader := csv.NewReader(f)
	reader.FieldsPerRecord = -1

	headers, err := reader.Read()
	if err != nil {
		return fmt.Errorf("failed to read CSV header: %w", err)
	}

	idIdx := -1
	for i, h := range headers {
		if strings.ToLower(strings.TrimSpace(h)) == idCol {
			idIdx = i
			break
		}
	}
	if idIdx < 0 {
		return fmt.Errorf("column %q not found in CSV header", idCol)
	}

	var ids []string
	for {
		row, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("failed to read CSV row: %w", err)
		}
		if idIdx >= len(row) {
			continue
		}
		id := strings.TrimSpace(row[idIdx])
		if id == "" {
			continue
		}
		ids = append(ids, id)
	}

	if dryRun {
		fmt.Fprintf(os.Stderr, "[DRY RUN] previewing stripe customer cleanup\n")
	}
	totalLoaded := len(ids)
	fmt.Fprintf(os.Stderr, "loaded %d customer ids from %s\n", totalLoaded, inputPath)

	if skip > 0 {
		if skip >= len(ids) {
			fmt.Fprintf(os.Stderr, "--skip=%d >= %d ids; nothing to do\n", skip, totalLoaded)
			return nil
		}
		ids = ids[skip:]
		fmt.Fprintf(os.Stderr, "skipping first %d ids (--skip)\n", skip)
	}
	if limit > 0 && limit < len(ids) {
		ids = ids[:limit]
		fmt.Fprintf(os.Stderr, "processing %d ids (--limit)\n", limit)
	}

	deleted, skipped, notFound, errCount := 0, 0, 0, 0

	deletedLabel := "deleted"
	if dryRun {
		deletedLabel = "would-delete"
	}

	bar := newMigrateProgress(len(ids), "Cleaning up customers")
	updateDescription := func() {
		bar.Describe(fmt.Sprintf(
			"Cleaning up customers [%s=%d skipped=%d not-found=%d errors=%d]",
			deletedLabel, deleted, skipped, notFound, errCount,
		))
	}
	updateDescription()
	logf := func(format string, args ...any) {
		if !verbose {
			return
		}
		_ = bar.Clear()
		fmt.Fprintf(os.Stderr, format+"\n", args...)
	}
	for _, id := range ids {
		if ctx.Err() != nil {
			bar.Finish()
			return ctx.Err()
		}
		bar.Add(1)

		users, err := backend.UserList(ctx, &atomic.UserListInput{
			InstanceID:     &inst.UUID,
			StripeCustomer: ptr.String(id),
			Limit:          ptr.Uint64(1),
		})
		if err != nil {
			errCount++
			logf("  error looking up passport user for %s: %s", id, err)
			updateDescription()
			continue
		}
		if len(users) > 0 {
			skipped++
			logf("  skip %s: passport user %s exists", id, users[0].UUID)
			updateDescription()
			continue
		}

		ok, reason, err := customerIsCleanable(sc, id)
		if err != nil {
			if isStripeNotFound(err) {
				notFound++
				logf("  not found %s", id)
				updateDescription()
				continue
			}
			errCount++
			logf("  error checking %s: %s", id, err)
			updateDescription()
			continue
		}

		if !ok {
			skipped++
			logf("  skip %s: %s", id, reason)
			updateDescription()
			continue
		}

		if dryRun {
			deleted++
			logf("  would delete stripe customer %s", id)
			updateDescription()
			continue
		}

		if _, err := sc.Customers.Del(id, nil); err != nil {
			if isStripeNotFound(err) {
				notFound++
				logf("  not found %s", id)
				updateDescription()
				continue
			}
			errCount++
			logf("  error deleting stripe customer %s: %s", id, err)
			updateDescription()
			continue
		}

		deleted++
		logf("  deleted stripe customer %s", id)
		updateDescription()
	}
	bar.Finish()

	verb := "deleted"
	if dryRun {
		verb = "would be deleted"
	}
	fmt.Fprintf(os.Stderr, "customers: %d %s, %d skipped, %d not found, %d errors\n", deleted, verb, skipped, notFound, errCount)

	return nil
}

// customerIsCleanable returns true when the customer is safe to delete:
// the customer has at least one valid (active or trialing) subscription, every
// such subscription is an atomic import (metadata[atomic:import]=true) with no
// default_payment_method, and the customer itself has no default_source and no
// invoice_settings.default_payment_method.
func customerIsCleanable(sc *stripeclient.API, id string) (bool, string, error) {
	custParams := &stripe.CustomerParams{}
	custParams.AddExpand("default_source")
	custParams.AddExpand("invoice_settings.default_payment_method")

	cust, err := sc.Customers.Get(id, custParams)
	if err != nil {
		return false, "", err
	}

	if cust.Deleted {
		return false, "customer already deleted", nil
	}

	if cust.DefaultSource != nil {
		return false, "customer has default_source", nil
	}

	if cust.InvoiceSettings != nil && cust.InvoiceSettings.DefaultPaymentMethod != nil {
		return false, "customer has invoice_settings.default_payment_method", nil
	}

	listParams := &stripe.SubscriptionListParams{
		Customer: stripe.String(id),
	}
	listParams.Status = stripe.String("all")
	listParams.AddExpand("data.default_payment_method")

	validCount := 0
	iter := sc.Subscriptions.List(listParams)
	for iter.Next() {
		sub := iter.Subscription()

		switch sub.Status {
		case stripe.SubscriptionStatusCanceled,
			stripe.SubscriptionStatusIncompleteExpired:
			continue
		}

		if sub.Metadata[atomicImportMetadataKey] != atomicImportMetadataValue {
			return false, fmt.Sprintf("subscription %s missing atomic:import metadata", sub.ID), nil
		}

		if sub.DefaultPaymentMethod != nil {
			return false, fmt.Sprintf("subscription %s has default_payment_method", sub.ID), nil
		}

		if sub.DefaultSource != nil {
			return false, fmt.Sprintf("subscription %s has default_source", sub.ID), nil
		}

		validCount++
	}
	if err := iter.Err(); err != nil {
		return false, "", fmt.Errorf("listing subscriptions: %w", err)
	}

	if validCount == 0 {
		return false, "no valid atomic:import subscription", nil
	}

	return true, "", nil
}

func isStripeNotFound(err error) bool {
	var serr *stripe.Error
	if errors.As(err, &serr) {
		return serr.HTTPStatusCode == 404 || serr.Code == stripe.ErrorCodeResourceMissing
	}
	return false
}
