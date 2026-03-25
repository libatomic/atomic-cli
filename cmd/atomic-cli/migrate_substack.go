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
	"math"
	"strings"
	"time"

	"github.com/apex/log"
	"github.com/libatomic/atomic/pkg/atomic"
	"github.com/libatomic/atomic/pkg/ptr"
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

	passportPlanMapping struct {
		SubscriberPlanID string
		FounderPlanID    string
		MonthlyPriceID   string
		AnnualPriceID    string
		FounderPriceID   string
		// priceAmounts maps "planID:interval:currency" -> amount in cents
		// used to look up the active Passport price for discount calculation
		priceAmounts map[string]int64
	}

	sourcePriceInfo struct {
		StripePrice *stripe.Price
		PriceType   string // "monthly", "annual", "founding"
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

func newPassportPlanMapping() *passportPlanMapping {
	return &passportPlanMapping{
		priceAmounts: make(map[string]int64),
	}
}

func priceAmountKey(planID string, interval atomic.SubscriptionInterval, currency string) string {
	return planID + ":" + string(interval) + ":" + currency
}

func (m *passportPlanMapping) setAmount(planID string, interval atomic.SubscriptionInterval, sp *stripe.Price) {
	m.priceAmounts[priceAmountKey(planID, interval, string(sp.Currency))] = sp.UnitAmount
	for cur, opt := range sp.CurrencyOptions {
		m.priceAmounts[priceAmountKey(planID, interval, cur)] = opt.UnitAmount
	}
}

func (m *passportPlanMapping) getAmount(planID string, interval atomic.SubscriptionInterval, currency string) (int64, bool) {
	amt, ok := m.priceAmounts[priceAmountKey(planID, interval, currency)]
	return amt, ok
}

func migrateSubstackAction(ctx context.Context, cmd *cli.Command) error {
	dryRun, output, prorate, emailDomain, err := validateMigrateFlags(cmd)
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
	// Founding prices are included even if inactive, since there may be
	// active subscriptions on them that need a Passport plan to migrate to.
	var activePriceInfos []*sourcePriceInfo
	var hasFoundingPrice bool
	for _, p := range allPrices {
		if p.PriceType == "founding" {
			hasFoundingPrice = true
			activePriceInfos = append(activePriceInfos, &sourcePriceInfo{
				StripePrice: p.StripePrice,
				PriceType:   p.PriceType,
			})
		} else if p.Active {
			activePriceInfos = append(activePriceInfos, &sourcePriceInfo{
				StripePrice: p.StripePrice,
				PriceType:   p.PriceType,
			})
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
		return nil, writeImportCSV(records, output, dryRun, prorate, emailDomain)
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

func handleCreatePlans(ctx context.Context, activePrices []*sourcePriceInfo, dryRun bool) (*passportPlanMapping, error) {
	mapping := newPassportPlanMapping()

	var monthlyPrice, annualPrice, founderPrice *sourcePriceInfo
	for _, p := range activePrices {
		switch p.PriceType {
		case "monthly":
			monthlyPrice = p
		case "annual":
			annualPrice = p
		case "founding":
			founderPrice = p
		}
	}

	fmt.Println("\nPlans to create:")
	fmt.Println()

	if monthlyPrice != nil || annualPrice != nil {
		fmt.Println("  Subscriber plan (paid):")
		if monthlyPrice != nil {
			fmt.Printf("    Monthly: %d %s\n", monthlyPrice.StripePrice.UnitAmount, monthlyPrice.StripePrice.Currency)
			printStripeCurrencyOptions(monthlyPrice.StripePrice)
		}
		if annualPrice != nil {
			fmt.Printf("    Annual:  %d %s\n", annualPrice.StripePrice.UnitAmount, annualPrice.StripePrice.Currency)
			printStripeCurrencyOptions(annualPrice.StripePrice)
		}
	}

	if founderPrice != nil {
		fmt.Println("  Founder plan (paid):")
		fmt.Printf("    Annual:  %d %s\n", founderPrice.StripePrice.UnitAmount, founderPrice.StripePrice.Currency)
		printStripeCurrencyOptions(founderPrice.StripePrice)
	}

	fmt.Println()

	if dryRun {
		fmt.Println("[DRY RUN] skipping plan creation")

		mapping.SubscriberPlanID = "DRY_RUN_SUBSCRIBER_PLAN"
		mapping.FounderPlanID = "DRY_RUN_FOUNDER_PLAN"

		if monthlyPrice != nil {
			mapping.setAmount(mapping.SubscriberPlanID, atomic.SubscriptionIntervalMonth, monthlyPrice.StripePrice)
		}
		if annualPrice != nil {
			mapping.setAmount(mapping.SubscriberPlanID, atomic.SubscriptionIntervalYear, annualPrice.StripePrice)
		}
		if founderPrice != nil {
			mapping.setAmount(mapping.FounderPlanID, atomic.SubscriptionIntervalYear, founderPrice.StripePrice)
		}

		return mapping, nil
	}

	confirmed, err := confirmAction("Create these plans?")
	if err != nil {
		return nil, err
	}
	if !confirmed {
		return nil, fmt.Errorf("plan creation canceled by user")
	}

	// Create plans with spinner
	result, err := runSpinner("Creating plans...", func() (any, error) {
		// Create Subscriber plan
		if monthlyPrice != nil || annualPrice != nil {
			subscriberPlan, err := backend.PlanCreate(ctx, &atomic.PlanCreateInput{
				InstanceID:  inst.UUID,
				Name:        "Subscriber",
				Description: ptr.String("Substack subscriber migration"),
				Type:        atomic.PlanTypePaid,
				Active:      ptr.Bool(true),
				Hidden:      ptr.Bool(true),
			})
			if err != nil {
				return nil, fmt.Errorf("failed to create Subscriber plan: %w", err)
			}

			mapping.SubscriberPlanID = string(subscriberPlan.UUID)

			if monthlyPrice != nil {
				price, err := createPassportPrice(ctx, subscriberPlan.UUID, "Monthly", monthlyPrice.StripePrice, "month")
				if err != nil {
					return nil, err
				}
				mapping.MonthlyPriceID = string(price.UUID)
				mapping.setAmount(mapping.SubscriberPlanID, atomic.SubscriptionIntervalMonth, monthlyPrice.StripePrice)
			}

			if annualPrice != nil {
				price, err := createPassportPrice(ctx, subscriberPlan.UUID, "Annual", annualPrice.StripePrice, "year")
				if err != nil {
					return nil, err
				}
				mapping.AnnualPriceID = string(price.UUID)
				mapping.setAmount(mapping.SubscriberPlanID, atomic.SubscriptionIntervalYear, annualPrice.StripePrice)
			}
		}

		// Create Founder plan
		if founderPrice != nil {
			founderPlan, err := backend.PlanCreate(ctx, &atomic.PlanCreateInput{
				InstanceID:  inst.UUID,
				Name:        "Founder",
				Description: ptr.String("Substack founder migration"),
				Type:        atomic.PlanTypePaid,
				Active:      ptr.Bool(true),
				Hidden:      ptr.Bool(true),
			})
			if err != nil {
				return nil, fmt.Errorf("failed to create Founder plan: %w", err)
			}

			mapping.FounderPlanID = string(founderPlan.UUID)

			price, err := createPassportPrice(ctx, founderPlan.UUID, "Annual", founderPrice.StripePrice, "year")
			if err != nil {
				return nil, err
			}
			mapping.FounderPriceID = string(price.UUID)
			mapping.setAmount(mapping.FounderPlanID, atomic.SubscriptionIntervalYear, founderPrice.StripePrice)
		}

		return mapping, nil
	})

	if err != nil {
		return nil, err
	}

	return result.(*passportPlanMapping), nil
}

func createPassportPrice(ctx context.Context, planID atomic.ID, name string, sp *stripe.Price, interval string) (*atomic.Price, error) {
	currency := string(sp.Currency)

	currencyOpts := make(atomic.CurrencyOptions)
	for cur, opt := range sp.CurrencyOptions {
		currencyOpts[cur] = atomic.CurrencyOption{
			UnitAmount: &opt.UnitAmount,
		}
	}

	instID := inst.UUID
	price, err := backend.PriceCreate(ctx, &atomic.PriceCreateInput{
		InstanceID:      &instID,
		PlanID:          planID,
		Name:            name,
		Currency:        currency,
		CurrencyOptions: currencyOpts,
		Active:          ptr.Bool(true),
		Amount:          &sp.UnitAmount,
		Type:            atomic.PriceTypeRecurring,
		Recurring: &atomic.PriceRecurring{
			Interval:  interval,
			Frequency: 1,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create %s price: %w", name, err)
	}

	return price, nil
}

func handleExistingPlans(ctx context.Context, subscriberPlanStr, founderPlanStr string) (*passportPlanMapping, error) {
	result, err := runSpinner("Fetching Passport plans...", func() (any, error) {
		mapping := newPassportPlanMapping()

		subscriberPlanID, err := atomic.ParseID(subscriberPlanStr)
		if err != nil {
			return nil, fmt.Errorf("invalid subscriber plan ID: %w", err)
		}

		plan, err := backend.PlanGet(ctx, &atomic.PlanGetInput{
			InstanceID: inst.UUID,
			PlanID:     &subscriberPlanID,
			Expand:     atomic.ExpandFields{"prices"},
		})
		if err != nil {
			return nil, fmt.Errorf("failed to get subscriber plan: %w", err)
		}

		mapping.SubscriberPlanID = string(plan.UUID)

		for _, price := range plan.Prices {
			if !price.Active || price.RecurringType != atomic.PriceTypeRecurring || price.RecurringInterval == nil {
				continue
			}
			switch *price.RecurringInterval {
			case atomic.SubscriptionIntervalMonth:
				mapping.MonthlyPriceID = string(price.UUID)
				setPriceAmountsFromPassport(mapping, mapping.SubscriberPlanID, atomic.SubscriptionIntervalMonth, price)
			case atomic.SubscriptionIntervalYear:
				mapping.AnnualPriceID = string(price.UUID)
				setPriceAmountsFromPassport(mapping, mapping.SubscriberPlanID, atomic.SubscriptionIntervalYear, price)
			}
		}

		if founderPlanStr != "" {
			founderPlanID, err := atomic.ParseID(founderPlanStr)
			if err != nil {
				return nil, fmt.Errorf("invalid founder plan ID: %w", err)
			}

			founderPlan, err := backend.PlanGet(ctx, &atomic.PlanGetInput{
				InstanceID: inst.UUID,
				PlanID:     &founderPlanID,
				Expand:     atomic.ExpandFields{"prices"},
			})
			if err != nil {
				return nil, fmt.Errorf("failed to get founder plan: %w", err)
			}

			mapping.FounderPlanID = string(founderPlan.UUID)

			for _, price := range founderPlan.Prices {
				if !price.Active || price.RecurringType != atomic.PriceTypeRecurring || price.RecurringInterval == nil {
					continue
				}
				if *price.RecurringInterval == atomic.SubscriptionIntervalYear {
					mapping.FounderPriceID = string(price.UUID)
					setPriceAmountsFromPassport(mapping, mapping.FounderPlanID, atomic.SubscriptionIntervalYear, price)
				}
			}
		}

		return mapping, nil
	})

	if err != nil {
		return nil, err
	}

	return result.(*passportPlanMapping), nil
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

			quantity := 1
			if sub.Items != nil {
				for _, item := range sub.Items.Data {
					if item.Price != nil && item.Price.ID == sp.StripePrice.ID && item.Quantity > 0 {
						quantity = int(item.Quantity)
						break
					}
				}
			}

			rec := &migrationRecord{
				CustomerID:   sub.Customer.ID,
				Email:        email,
				Name:         sub.Customer.Name,
				PlanID:        planID,
				Interval:      interval,
				Currency:      currency,
				Quantity:      quantity,
				UserAmount:    userAmount,
				StripePriceID: sp.StripePrice.ID,
				StripeSubID:   sub.ID,
			}

			if sub.CancelAt > 0 {
				cancelAt := time.Unix(sub.CancelAt, 0).UTC()
				rec.EndAt = &cancelAt
			} else if sub.CancelAtPeriodEnd && sub.CurrentPeriodEnd > 0 {
				cancelAt := time.Unix(sub.CurrentPeriodEnd, 0).UTC()
				rec.EndAt = &cancelAt
			} else if sub.BillingCycleAnchor > 0 {
				anchor := time.Unix(sub.BillingCycleAnchor, 0).UTC()

				// if the anchor is in the past, advance by +1 interval
				if anchor.Before(time.Now().UTC()) {
					switch interval {
					case atomic.SubscriptionIntervalMonth:
						anchor = anchor.AddDate(0, 1, 0)
					case atomic.SubscriptionIntervalYear:
						anchor = anchor.AddDate(1, 0, 0)
					}
				}

				rec.AnchorDate = &anchor
			}

			records = append(records, rec)
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

func calculatePerUserDiscounts(records []*migrationRecord, mapping *passportPlanMapping) {
	for _, rec := range records {
		passportAmount, ok := mapping.getAmount(rec.PlanID, rec.Interval, rec.Currency)
		if !ok || passportAmount <= 0 {
			log.Warnf("no Passport price found for plan %s interval %s currency %s (%s); skipping discount",
				rec.PlanID, rec.Interval, rec.Currency, rec.Email)
			continue
		}

		if rec.UserAmount <= 0 {
			log.Warnf("no user amount in %s for %s; skipping discount", rec.Currency, rec.Email)
			continue
		}

		if rec.UserAmount >= passportAmount {
			continue
		}

		pct := math.Round((1.0-float64(rec.UserAmount)/float64(passportAmount))*10000) / 100
		term := atomic.CreditTermForever
		rec.DiscountPct = &pct
		rec.DiscountTerm = &term
	}
}

func getUserAmount(p *stripe.Price, currency string) int64 {
	if string(p.Currency) == currency {
		return p.UnitAmount
	}

	if opt, ok := p.CurrencyOptions[currency]; ok {
		return opt.UnitAmount
	}

	return 0
}

func setPriceAmountsFromPassport(mapping *passportPlanMapping, planID string, interval atomic.SubscriptionInterval, price *atomic.Price) {
	if price.FlatAmount != nil {
		mapping.priceAmounts[priceAmountKey(planID, interval, price.Currency)] = *price.FlatAmount
	}
	for cur, opt := range price.CurrencyOptions {
		if opt.UnitAmount != nil {
			mapping.priceAmounts[priceAmountKey(planID, interval, cur)] = *opt.UnitAmount
		}
	}
}

func printStripeCurrencyOptions(sp *stripe.Price) {
	for cur, opt := range sp.CurrencyOptions {
		fmt.Printf("      └─ %s: %d\n", cur, opt.UnitAmount)
	}
}
