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

	"github.com/apex/log"
	"github.com/libatomic/atomic/pkg/atomic"
	"github.com/stripe/stripe-go/v79"
	stripeclient "github.com/stripe/stripe-go/v79/client"
	"github.com/urfave/cli/v3"
)

type (
	substackPrice struct {
		StripePrice *stripe.Price
		PriceType   string // "monthly", "annual", "founding"
		Active      bool
	}
)

var (
	migrateSubstackFlags = append(
		migrateCommonFlags,
		&cli.StringFlag{
			Name:  "subscriber-plan",
			Usage: "Passport plan ID for regular subscribers (mutually exclusive with --create-plans)",
		},
		&cli.StringFlag{
			Name:  "founder-plan",
			Usage: "Passport plan ID for founding members",
		},
		&cli.BoolFlag{
			Name:  "create-plans",
			Usage: "auto-create Subscriber and Founder plans in Passport from Stripe data",
			Value: true,
		},
		&cli.BoolFlag{
			Name:  "apply-discounts",
			Usage: "calculate and apply per-user forever discounts for price differences",
			Value: true,
		},
	)

	migrateSubstackCmd = &cli.Command{
		Name:   "substack",
		Usage:  "migrate users from Substack via Stripe",
		Flags:  migrateSubstackFlags,
		Action: migrateSubstackAction,
	}
)

func migrateSubstackAction(ctx context.Context, cmd *cli.Command) error {
	dryRun, output, err := validateMigrateFlags(cmd)
	if err != nil {
		return err
	}

	subscriberPlan := cmd.String("subscriber-plan")
	founderPlan := cmd.String("founder-plan")
	createPlans := cmd.Bool("create-plans")
	applyDiscounts := cmd.Bool("apply-discounts")

	if subscriberPlan != "" && createPlans {
		return fmt.Errorf("--subscriber-plan and --create-plans are mutually exclusive")
	}

	if subscriberPlan == "" && !createPlans {
		return fmt.Errorf("either --subscriber-plan or --create-plans must be set")
	}

	sc := initStripeClient(cmd.String("stripe-key"))

	// Pass 1: Discover all Substack prices
	result, err := runSpinner("Scanning Stripe for Substack prices...", func() (any, error) {
		return discoverSubstackPrices(sc)
	})
	if err != nil {
		return fmt.Errorf("failed to discover Substack prices: %w", err)
	}

	allPrices := result.([]*substackPrice)

	if len(allPrices) == 0 {
		return fmt.Errorf("no Substack prices found in Stripe (looking for metadata substack=yes)")
	}

	// Separate active prices and check for founding
	var activePriceInfos []*sourcePriceInfo
	var hasFoundingPrice bool
	for _, p := range allPrices {
		if p.Active {
			activePriceInfos = append(activePriceInfos, &sourcePriceInfo{
				StripePrice: p.StripePrice,
				PriceType:   p.PriceType,
			})
			if p.PriceType == "founding" {
				hasFoundingPrice = true
			}
		}
	}

	// Pass 2: Display price mapping report
	displaySubstackPriceReport(allPrices)

	// Check founding plan requirement
	if hasFoundingPrice && founderPlan == "" && !createPlans {
		return fmt.Errorf("founding member price found in Stripe but --founder-plan not set; use --founder-plan or --create-plans")
	}

	// Pass 3: Resolve or create Passport plans
	var mapping *passportPlanMapping

	if createPlans {
		mapping, err = handleCreatePlans(ctx, activePriceInfos, dryRun)
		if err != nil {
			return err
		}
	} else {
		mapping, err = handleExistingPlans(ctx, subscriberPlan, founderPlan)
		if err != nil {
			return err
		}
	}

	// Pass 4: Collect active subscriptions
	result, err = runProgress("Collecting active subscriptions...", func(send func(progressTickMsg)) (any, error) {
		return collectSubstackSubscriptions(sc, allPrices, mapping, send)
	})
	if err != nil {
		return fmt.Errorf("failed to collect subscriptions: %w", err)
	}

	records := result.([]*migrationRecord)

	if len(records) == 0 {
		log.Warn("no active subscriptions found")
	}

	// Pass 5: Calculate per-user discounts
	if applyDiscounts {
		calculatePerUserDiscounts(records, mapping)
	}

	// Pass 6: Write CSV
	_, err = runSpinner(fmt.Sprintf("Writing %d records to %s...", len(records), output), func() (any, error) {
		return nil, writeImportCSV(records, output, dryRun)
	})
	if err != nil {
		return fmt.Errorf("failed to write CSV: %w", err)
	}

	if dryRun {
		fmt.Printf("[DRY RUN] wrote %d records to %s\n", len(records), output)
	} else {
		fmt.Printf("Wrote %d records to %s\n", len(records), output)
	}

	return nil
}

func discoverSubstackPrices(sc *stripeclient.API) ([]*substackPrice, error) {
	var prices []*substackPrice

	params := &stripe.PriceListParams{}
	params.AddExpand("data.product")
	params.AddExpand("data.currency_options")

	iter := sc.Prices.List(params)
	for iter.Next() {
		p := iter.Price()

		if p.Metadata["substack"] != "yes" {
			continue
		}

		sp := &substackPrice{
			StripePrice: p,
			Active:      p.Active && p.Metadata["inactive"] == "",
			PriceType:   classifySubstackPrice(p),
		}

		prices = append(prices, sp)
	}

	if err := iter.Err(); err != nil {
		return nil, err
	}

	return prices, nil
}

func classifySubstackPrice(p *stripe.Price) string {
	if p.Recurring == nil {
		return "unknown"
	}

	if p.Metadata["founding"] == "yes" && p.Recurring.Interval == stripe.PriceRecurringIntervalYear {
		return "founding"
	}

	switch p.Recurring.Interval {
	case stripe.PriceRecurringIntervalMonth:
		return "monthly"
	case stripe.PriceRecurringIntervalYear:
		return "annual"
	default:
		return "unknown"
	}
}

func displaySubstackPriceReport(prices []*substackPrice) {
	fmt.Println()
	fmt.Println("Discovered Substack Prices:")
	fmt.Println(strings.Repeat("-", 100))
	fmt.Printf("%-20s %-30s %-10s %-10s %-12s %-10s\n", "Type", "Price ID", "Amount", "Currency", "Active", "Founding")
	fmt.Println(strings.Repeat("-", 100))

	for _, p := range prices {
		active := "yes"
		if !p.Active {
			active = "no"
		}
		founding := "no"
		if p.StripePrice.Metadata["founding"] == "yes" {
			founding = "yes"
		}

		fmt.Printf("%-20s %-30s %-10d %-10s %-12s %-10s\n",
			p.PriceType,
			p.StripePrice.ID,
			p.StripePrice.UnitAmount,
			string(p.StripePrice.Currency),
			active,
			founding,
		)

		if len(p.StripePrice.CurrencyOptions) > 0 {
			for cur, opt := range p.StripePrice.CurrencyOptions {
				fmt.Printf("  └─ %-18s %-28s %-10d %-10s\n", "", cur, opt.UnitAmount, cur)
			}
		}
	}

	fmt.Println(strings.Repeat("-", 100))
	fmt.Println()

	fmt.Println("Price Mapping:")
	for _, p := range prices {
		if !p.Active {
			continue
		}
		switch p.PriceType {
		case "monthly":
			fmt.Printf("  Monthly  (%d %s) → Subscriber plan (monthly price)\n", p.StripePrice.UnitAmount, p.StripePrice.Currency)
		case "annual":
			fmt.Printf("  Annual   (%d %s) → Subscriber plan (annual price)\n", p.StripePrice.UnitAmount, p.StripePrice.Currency)
		case "founding":
			fmt.Printf("  Founding (%d %s) → Founder plan (annual price)\n", p.StripePrice.UnitAmount, p.StripePrice.Currency)
		}
	}
	fmt.Println()
}

func collectSubstackSubscriptions(sc *stripeclient.API, prices []*substackPrice, mapping *passportPlanMapping, send func(progressTickMsg)) ([]*migrationRecord, error) {
	var records []*migrationRecord
	seen := make(map[string]bool)

	for i, sp := range prices {
		planID, interval := mapSubstackPriceToPassportPlan(sp, mapping)
		if planID == "" {
			continue
		}

		send(progressTickMsg{
			current: i,
			total:   len(prices),
			status:  fmt.Sprintf("Scanning price %s...", sp.StripePrice.ID),
		})

		params := &stripe.SubscriptionListParams{}
		params.Filters.AddFilter("price", "", sp.StripePrice.ID)
		params.Filters.AddFilter("status", "", "active")
		params.AddExpand("data.customer")

		iter := sc.Subscriptions.List(params)
		for iter.Next() {
			sub := iter.Subscription()

			if sub.Customer == nil {
				continue
			}

			if seen[sub.Customer.ID] {
				continue
			}
			seen[sub.Customer.ID] = true

			email := sub.Customer.Email
			if email == "" {
				log.Warnf("skipping customer %s: no email address", sub.Customer.ID)
				continue
			}

			currency := string(sub.Currency)
			userAmount := getUserAmount(sp.StripePrice, currency)

			records = append(records, &migrationRecord{
				CustomerID:     sub.Customer.ID,
				Email:          email,
				Name:           sub.Customer.Name,
				PlanID:         planID,
				Interval:       interval,
				Currency:       currency,
				UserAmount:     userAmount,
				PassportAmount: getPassportAmount(mapping, sp.PriceType, currency),
			})
		}

		if err := iter.Err(); err != nil {
			return nil, fmt.Errorf("failed to list subscriptions for price %s: %w", sp.StripePrice.ID, err)
		}
	}

	return records, nil
}

func mapSubstackPriceToPassportPlan(sp *substackPrice, mapping *passportPlanMapping) (string, atomic.SubscriptionInterval) {
	switch sp.PriceType {
	case "monthly":
		return mapping.SubscriberPlanID, atomic.SubscriptionIntervalMonth
	case "annual":
		return mapping.SubscriberPlanID, atomic.SubscriptionIntervalYear
	case "founding":
		if mapping.FounderPlanID != "" {
			return mapping.FounderPlanID, atomic.SubscriptionIntervalYear
		}
		return mapping.SubscriberPlanID, atomic.SubscriptionIntervalYear
	default:
		return "", ""
	}
}
