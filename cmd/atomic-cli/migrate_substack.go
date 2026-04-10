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
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/apex/log"
	"github.com/libatomic/atomic/pkg/atomic"
	"github.com/libatomic/atomic/pkg/ptr"
	"github.com/schollz/progressbar/v3"
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

	// planJSONL is the JSONL output format for plans that need to be created
	planJSONL struct {
		Name        string          `json:"name"`
		Description string          `json:"description"`
		Type        atomic.PlanType `json:"type"`
		Active      bool            `json:"active"`
		Hidden      bool            `json:"hidden"`
		Prices      []priceJSONL    `json:"prices"`
	}

	priceJSONL struct {
		Name            string                 `json:"name"`
		Currency        string                 `json:"currency"`
		CurrencyOptions atomic.CurrencyOptions `json:"currency_options,omitempty"`
		Active          bool                   `json:"active"`
		Amount          int64                  `json:"amount"`
		Type            atomic.PriceType       `json:"type"`
		Recurring       *atomic.PriceRecurring `json:"recurring"`
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
			Usage: "Passport plan ID for founding members (requires --founders)",
		},
		&cli.BoolFlag{
			Name:  "founders",
			Usage: "include founding member subscriptions in the migration",
			Value: false,
		},
		&cli.BoolFlag{
			Name:  "create-plans",
			Usage: "auto-create Subscriber and Founder plans in Passport from Stripe data",
			Value: false,
		},
		&cli.BoolFlag{
			Name:  "legacy-pricing",
			Usage: "calculate forever discounts for users on grandfathered prices (price difference between source and target plan)",
			Value: false,
		},
		&cli.BoolFlag{
			Name:  "apply-discounts",
			Usage: "carry over existing Stripe subscription coupons/discounts to the import CSV",
			Value: true,
		},
		&cli.Float64Flag{
			Name:  "discount-threshold",
			Usage: "minimum discount percentage to include (discounts below this are ignored)",
			Value: 1,
		},
		&cli.StringFlag{
			Name:  "discount-term",
			Usage: "override the discount term for all applied discounts (once, repeating, forever); when not set, uses the coupon's original term",
		},
		&cli.BoolFlag{
			Name:  "omit-customer-id",
			Usage: "omit stripe_customer_id from the output CSV (for sandbox testing with a different Stripe account)",
			Value: false,
		},
		&cli.BoolFlag{
			Name:  "omit-payment-methods",
			Usage: "omit subscription_payment_method from the output CSV",
			Value: false,
		},
		&cli.BoolFlag{
			Name:  "migrate-test-cards",
			Usage: "use Stripe test cards for subscription_payment_method based on currency (mutually exclusive with --omit-payment-methods)",
			Value: false,
		},
		&cli.StringFlag{
			Name:  "shift-anchor-dates",
			Usage: "shift all billing cycle anchor dates forward by a duration (e.g. 24h, 7d, 30d) for testing",
		},
		&cli.IntFlag{
			Name:  "estimated-total",
			Usage: "estimated total subscriptions (enables a progress bar instead of a spinner)",
		},
		&cli.BoolFlag{
			Name:  "diff",
			Usage: "produce an incremental diff CSV containing only subscribers created after the latest created_at in the existing output (or last -diff-NN.csv); writes to <base>-diff-NN.csv with auto-incrementing suffix",
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
	subscriberPlan := cmd.String("subscriber-plan")
	createPlans := cmd.Bool("create-plans")

	// instance is only required when creating plans or using existing plans
	requireInstance := createPlans || subscriberPlan != ""

	dryRun, output, prorate, rewriter, appendMode, _, limit, _, err := validateMigrateFlags(cmd, requireInstance)
	if err != nil {
		return err
	}

	founderPlan := cmd.String("founder-plan")
	founders := cmd.Bool("founders")
	legacyPricing := cmd.Bool("legacy-pricing")
	applyDiscounts := cmd.Bool("apply-discounts")
	discountThreshold := cmd.Float64("discount-threshold")
	discountTermOverride := cmd.String("discount-term")
	omitCustomerID := cmd.Bool("omit-customer-id")
	omitPaymentMethods := cmd.Bool("omit-payment-methods")
	migrateTestCard := cmd.Bool("migrate-test-cards")
	shiftAnchorStr := cmd.String("shift-anchor-dates")
	verbose := mainCmd.Bool("verbose")

	if subscriberPlan != "" && createPlans {
		return fmt.Errorf("--subscriber-plan and --create-plans are mutually exclusive")
	}

	if omitPaymentMethods && migrateTestCard {
		return fmt.Errorf("--omit-payment-methods and --migrate-test-cards are mutually exclusive")
	}

	var shiftAnchor time.Duration
	if shiftAnchorStr != "" {
		var err error
		shiftAnchor, err = parseDuration(shiftAnchorStr)
		if err != nil {
			return fmt.Errorf("invalid --shift-anchor-dates value %q: %w", shiftAnchorStr, err)
		}
	}

	if founderPlan != "" {
		founders = true
	}

	sc, err := initStripeClient(cmd.String("stripe-key"))
	if err != nil {
		return fmt.Errorf("failed to initialize Stripe client: %w", err)
	}

	// retrieve the stripe account to suffix output files
	acct, err := sc.Accounts.Get()
	if err != nil {
		return fmt.Errorf("failed to retrieve Stripe account: %w", err)
	}

	stripeAccountSuffix := strings.TrimPrefix(acct.ID, "acct_")

	// suffix the output file with the stripe account id
	ext := filepath.Ext(output)
	base := strings.TrimSuffix(output, ext)
	output = fmt.Sprintf("%s-%s%s", base, stripeAccountSuffix, ext)

	// Pass 1: Discover all Substack prices
	bar := newMigrateSpinner("Scanning Stripe for Substack prices")
	allPrices, err := discoverSubstackPrices(sc, bar)
	bar.Finish()
	if err != nil {
		return fmt.Errorf("failed to discover Substack prices: %w", err)
	}

	fmt.Fprintf(os.Stderr, "found %d Substack prices\n", len(allPrices))

	if len(allPrices) == 0 {
		return fmt.Errorf("no Substack prices found in Stripe (looking for metadata substack=yes)")
	}

	// Separate active prices; skip founding prices unless --founders is set
	var activePriceInfos []*sourcePriceInfo
	var hasFoundingPrice bool
	for _, p := range allPrices {
		if p.PriceType == "founding" {
			hasFoundingPrice = true
			if founders {
				activePriceInfos = append(activePriceInfos, &sourcePriceInfo{
					StripePrice: p.StripePrice,
					PriceType:   p.PriceType,
				})
			}
		} else if p.Active {
			activePriceInfos = append(activePriceInfos, &sourcePriceInfo{
				StripePrice: p.StripePrice,
				PriceType:   p.PriceType,
			})
		}
	}

	// Pass 2: Display price mapping report
	if verbose {
		displaySubstackPriceReport(allPrices)
	}

	// Check founding plan requirement (only when --founders is enabled)
	if founders && hasFoundingPrice && founderPlan == "" && !createPlans && subscriberPlan != "" {
		return fmt.Errorf("founding member price found in Stripe but --founder-plan not set; use --founder-plan or --create-plans")
	}

	// Pass 3: Resolve or create Passport plans
	var mapping *passportPlanMapping

	if createPlans {
		mapping, err = handleCreatePlans(ctx, activePriceInfos, dryRun)
		if err != nil {
			return err
		}
	} else if subscriberPlan != "" {
		mapping, err = handleExistingPlans(ctx, subscriberPlan, founderPlan)
		if err != nil {
			return err
		}
	} else {
		// no plans specified and create-plans is false: generate the plans JSONL and use placeholder mapping
		mapping, err = handleGeneratePlansJSONL(activePriceInfos, stripeAccountSuffix)
		if err != nil {
			return err
		}
	}

	// Diff mode: resolve the cutoff timestamp from the latest existing CSV
	// (or last -diff-NN.csv) and pick the next diff filename
	diffMode := cmd.Bool("diff")
	var diffSince *time.Time
	if diffMode {
		sourcePath, nextOutput, err := resolveDiffPaths(output)
		if err != nil {
			return fmt.Errorf("diff: failed to resolve paths: %w", err)
		}
		if sourcePath != "" {
			cutoff, err := readMaxCreatedAt(sourcePath)
			if err != nil {
				return fmt.Errorf("diff: failed to read %s: %w", sourcePath, err)
			}
			if cutoff != nil {
				diffSince = cutoff
				fmt.Fprintf(os.Stderr, "diff mode: starting from created_at > %s (source: %s)\n",
					cutoff.UTC().Format(time.RFC3339), sourcePath)
			}
		} else {
			fmt.Fprintf(os.Stderr, "diff mode: no existing output found, doing a full collection\n")
		}
		output = nextOutput
		// diff files are always written fresh (no append)
		appendMode = false
		fmt.Fprintf(os.Stderr, "diff mode: writing to %s\n", output)
	}

	// Pass 4: Collect active subscriptions
	estimatedTotal := int(cmd.Int("estimated-total"))
	if estimatedTotal > 0 {
		bar = newMigrateProgress(estimatedTotal, "Collecting subscriptions")
	} else {
		bar = newMigrateSpinner("Collecting subscriptions")
	}
	records, err := collectSubstackSubscriptions(ctx, sc, allPrices, mapping, founders, legacyPricing, limit, omitPaymentMethods, migrateTestCard, shiftAnchor, diffSince, bar)
	bar.Finish()
	if err != nil {
		return fmt.Errorf("failed to collect subscriptions: %w", err)
	}

	fmt.Fprintf(os.Stderr, "collected %d subscriptions\n", len(records))

	if len(records) == 0 {
		log.Warn("no active subscriptions found")
	}

	// Pass 5: Process discounts
	// Parse discount term override if provided
	var termOverride *atomic.CreditTerm
	if discountTermOverride != "" {
		t := atomic.CreditTerm(discountTermOverride)
		termOverride = &t
	}

	// Apply discount threshold filter and term override on existing Stripe coupons
	if applyDiscounts {
		for _, rec := range records {
			if rec.DiscountPct == nil {
				continue
			}
			// filter below threshold
			if *rec.DiscountPct < discountThreshold {
				rec.DiscountPct = nil
				rec.DiscountTerm = nil
				continue
			}
			// apply term override
			if termOverride != nil {
				rec.DiscountTerm = termOverride
			}
		}
	} else {
		// --apply-discounts=false: strip all existing coupon discounts
		for _, rec := range records {
			rec.DiscountPct = nil
			rec.DiscountTerm = nil
		}
	}

	// Legacy pricing: calculate price-difference discounts
	if legacyPricing {
		calculateLegacyPricingDiscounts(records, mapping)
	}

	// Pass 6: Write CSV(s)
	// When in JSONL mode (no plans created/specified), split into subscriber and founder files
	// with is_subscriber=true and no plan ID
	isJSONLMode := !createPlans && subscriberPlan == ""

	if isJSONLMode {
		var subscriberRecords, founderRecords []*migrationRecord

		for _, rec := range records {
			if rec.PlanID == "PENDING_FOUNDER_PLAN" {
				rec.PlanID = ""
				founderRecords = append(founderRecords, rec)
			} else {
				rec.PlanID = ""
				subscriberRecords = append(subscriberRecords, rec)
			}
		}

		ext := filepath.Ext(output)
		base := strings.TrimSuffix(output, ext)
		subscriberOutput := fmt.Sprintf("%s-subscribers%s", base, ext)
		founderOutput := fmt.Sprintf("%s-founders%s", base, ext)

		if err := writeImportCSV(subscriberRecords, subscriberOutput, dryRun, prorate, rewriter, appendMode, "substack-stripe", 0, 0, omitCustomerID); err != nil {
			return fmt.Errorf("failed to write subscriber CSV: %w", err)
		}
		fmt.Fprintf(os.Stderr, "wrote %d subscriber records to %s\n", len(subscriberRecords), subscriberOutput)

		if len(founderRecords) > 0 {
			if err := writeImportCSV(founderRecords, founderOutput, dryRun, prorate, rewriter, appendMode, "substack-stripe", 0, 0, omitCustomerID); err != nil {
				return fmt.Errorf("failed to write founder CSV: %w", err)
			}
			fmt.Fprintf(os.Stderr, "wrote %d founder records to %s\n", len(founderRecords), founderOutput)
		}
	} else {
		if err := writeImportCSV(records, output, dryRun, prorate, rewriter, appendMode, "substack-stripe", 0, 0, omitCustomerID); err != nil {
			return fmt.Errorf("failed to write CSV: %w", err)
		}

		if dryRun {
			fmt.Fprintf(os.Stderr, "[DRY RUN] wrote %d records to %s\n", len(records), output)
		} else {
			fmt.Fprintf(os.Stderr, "wrote %d records to %s\n", len(records), output)
		}
	}

	// Print export summary
	var monthly, yearly, once, withDiscount, withEndAt int
	for _, rec := range records {
		switch rec.Interval {
		case atomic.SubscriptionIntervalMonth:
			monthly++
		case atomic.SubscriptionIntervalYear:
			yearly++
		case atomic.SubscriptionIntervalOnce:
			once++
		}
		if rec.DiscountPct != nil && *rec.DiscountPct > 0 {
			withDiscount++
		}
		if rec.EndAt != nil {
			withEndAt++
		}
	}

	fmt.Fprintln(os.Stderr)
	fmt.Fprintf(os.Stderr, "Export Summary\n")
	fmt.Fprintf(os.Stderr, "%s\n", strings.Repeat("-", 35))
	fmt.Fprintf(os.Stderr, "%-20s %10d\n", "Total", len(records))
	fmt.Fprintf(os.Stderr, "%-20s %10d\n", "Monthly", monthly)
	fmt.Fprintf(os.Stderr, "%-20s %10d\n", "Yearly", yearly)
	if once > 0 {
		fmt.Fprintf(os.Stderr, "%-20s %10d\n", "One-time", once)
	}
	fmt.Fprintf(os.Stderr, "%-20s %10d\n", "With discount", withDiscount)
	if withEndAt > 0 {
		fmt.Fprintf(os.Stderr, "%-20s %10d\n", "Canceling", withEndAt)
	}
	fmt.Fprintf(os.Stderr, "%s\n", strings.Repeat("-", 35))

	return nil
}

func discoverSubstackPrices(sc *stripeclient.API, bar *progressbar.ProgressBar) ([]*substackPrice, error) {
	var prices []*substackPrice

	params := &stripe.PriceListParams{}
	params.AddExpand("data.product")
	params.AddExpand("data.currency_options")

	iter := sc.Prices.List(params)
	for iter.Next() {
		p := iter.Price()
		bar.Add(1)

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

	bar := newMigrateSpinner("Creating plans")

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
			bar.Finish()
			return nil, fmt.Errorf("failed to create Subscriber plan: %w", err)
		}

		mapping.SubscriberPlanID = string(subscriberPlan.UUID)
		bar.Add(1)

		if monthlyPrice != nil {
			price, err := createPassportPrice(ctx, subscriberPlan.UUID, "Monthly", monthlyPrice.StripePrice, "month")
			if err != nil {
				bar.Finish()
				return nil, err
			}
			mapping.MonthlyPriceID = string(price.UUID)
			mapping.setAmount(mapping.SubscriberPlanID, atomic.SubscriptionIntervalMonth, monthlyPrice.StripePrice)
			bar.Add(1)
		}

		if annualPrice != nil {
			price, err := createPassportPrice(ctx, subscriberPlan.UUID, "Annual", annualPrice.StripePrice, "year")
			if err != nil {
				bar.Finish()
				return nil, err
			}
			mapping.AnnualPriceID = string(price.UUID)
			mapping.setAmount(mapping.SubscriberPlanID, atomic.SubscriptionIntervalYear, annualPrice.StripePrice)
			bar.Add(1)
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
			bar.Finish()
			return nil, fmt.Errorf("failed to create Founder plan: %w", err)
		}

		mapping.FounderPlanID = string(founderPlan.UUID)
		bar.Add(1)

		price, err := createPassportPrice(ctx, founderPlan.UUID, "Annual", founderPrice.StripePrice, "year")
		if err != nil {
			bar.Finish()
			return nil, err
		}
		mapping.FounderPriceID = string(price.UUID)
		mapping.setAmount(mapping.FounderPlanID, atomic.SubscriptionIntervalYear, founderPrice.StripePrice)
		bar.Add(1)
	}

	bar.Finish()
	fmt.Fprintf(os.Stderr, "plans created\n")

	return mapping, nil
}

func handleGeneratePlansJSONL(activePrices []*sourcePriceInfo, stripeAccountSuffix string) (*passportPlanMapping, error) {
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

	var plans []planJSONL

	// Subscriber plan
	if monthlyPrice != nil || annualPrice != nil {
		plan := planJSONL{
			Name:        "Subscriber",
			Description: "Substack subscriber migration",
			Type:        atomic.PlanTypePaid,
			Active:      true,
			Hidden:      true,
		}

		mapping.SubscriberPlanID = "PENDING_SUBSCRIBER_PLAN"

		if monthlyPrice != nil {
			plan.Prices = append(plan.Prices, stripePriceToJSONL("Monthly", monthlyPrice.StripePrice, "month"))
			mapping.setAmount(mapping.SubscriberPlanID, atomic.SubscriptionIntervalMonth, monthlyPrice.StripePrice)
		}
		if annualPrice != nil {
			plan.Prices = append(plan.Prices, stripePriceToJSONL("Annual", annualPrice.StripePrice, "year"))
			mapping.setAmount(mapping.SubscriberPlanID, atomic.SubscriptionIntervalYear, annualPrice.StripePrice)
		}

		plans = append(plans, plan)
	}

	// Founder plan
	if founderPrice != nil {
		plan := planJSONL{
			Name:        "Founder",
			Description: "Substack founder migration",
			Type:        atomic.PlanTypePaid,
			Active:      true,
			Hidden:      true,
			Prices: []priceJSONL{
				stripePriceToJSONL("Annual", founderPrice.StripePrice, "year"),
			},
		}

		mapping.FounderPlanID = "PENDING_FOUNDER_PLAN"
		mapping.setAmount(mapping.FounderPlanID, atomic.SubscriptionIntervalYear, founderPrice.StripePrice)

		plans = append(plans, plan)
	}

	// Write JSONL
	plansFile := fmt.Sprintf("plans-%s.jsonl", stripeAccountSuffix)
	f, err := os.Create(plansFile)
	if err != nil {
		return nil, fmt.Errorf("failed to create plans file: %w", err)
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	for _, plan := range plans {
		if err := enc.Encode(plan); err != nil {
			return nil, fmt.Errorf("failed to write plan: %w", err)
		}
	}

	fmt.Fprintf(os.Stderr, "wrote %d plans to %s\n", len(plans), plansFile)

	return mapping, nil
}

func stripePriceToJSONL(name string, sp *stripe.Price, interval string) priceJSONL {
	currencyOpts := make(atomic.CurrencyOptions)
	for cur, opt := range sp.CurrencyOptions {
		currencyOpts[cur] = atomic.CurrencyOption{
			UnitAmount: &opt.UnitAmount,
		}
	}

	return priceJSONL{
		Name:            name,
		Currency:        string(sp.Currency),
		CurrencyOptions: currencyOpts,
		Active:          true,
		Amount:          sp.UnitAmount,
		Type:            atomic.PriceTypeRecurring,
		Recurring: &atomic.PriceRecurring{
			Interval:  interval,
			Frequency: 1,
		},
	}
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
	bar := newMigrateSpinner("Fetching Passport plans")

	mapping := newPassportPlanMapping()

	subscriberPlanID, err := atomic.ParseID(subscriberPlanStr)
	if err != nil {
		bar.Finish()
		return nil, fmt.Errorf("invalid subscriber plan ID: %w", err)
	}

	plan, err := backend.PlanGet(ctx, &atomic.PlanGetInput{
		InstanceID: inst.UUID,
		PlanID:     &subscriberPlanID,
		Expand:     atomic.ExpandFields{"prices"},
	})
	if err != nil {
		bar.Finish()
		return nil, fmt.Errorf("failed to get subscriber plan: %w", err)
	}

	mapping.SubscriberPlanID = string(plan.UUID)
	bar.Add(1)

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
			bar.Finish()
			return nil, fmt.Errorf("invalid founder plan ID: %w", err)
		}

		founderPlan, err := backend.PlanGet(ctx, &atomic.PlanGetInput{
			InstanceID: inst.UUID,
			PlanID:     &founderPlanID,
			Expand:     atomic.ExpandFields{"prices"},
		})
		if err != nil {
			bar.Finish()
			return nil, fmt.Errorf("failed to get founder plan: %w", err)
		}

		mapping.FounderPlanID = string(founderPlan.UUID)
		bar.Add(1)

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

	bar.Finish()
	fmt.Fprintf(os.Stderr, "plans loaded\n")

	return mapping, nil
}

func collectSubstackSubscriptions(ctx context.Context, sc *stripeclient.API, prices []*substackPrice, mapping *passportPlanMapping, founders bool, legacyPricing bool, limit int, omitPaymentMethods bool, migrateTestCard bool, shiftAnchor time.Duration, since *time.Time, bar *progressbar.ProgressBar) ([]*migrationRecord, error) {
	var records []*migrationRecord
	seen := make(map[string]bool)
	startTime := time.Now()
	var sinceUnix int64
	if since != nil {
		sinceUnix = since.Unix()
	}

	for _, sp := range prices {
		// check for cancellation
		if ctx.Err() != nil {
			return records, ctx.Err()
		}

		// skip founding prices when --founders is not set
		if sp.PriceType == "founding" && !founders {
			continue
		}

		planID, interval := mapSubstackPriceToPassportPlan(sp, mapping)
		if planID == "" {
			continue
		}

		bar.Describe(collectingSubsStatus(len(records), startTime))

		params := &stripe.SubscriptionListParams{}
		params.Filters.AddFilter("price", "", sp.StripePrice.ID)
		params.Filters.AddFilter("status", "", "active")
		params.AddExpand("data.customer")
		params.AddExpand("data.default_payment_method")
		params.AddExpand("data.discount")
		params.AddExpand("data.discount.coupon")

		iter := sc.Subscriptions.List(params)
		for iter.Next() {
			sub := iter.Subscription()

			if ctx.Err() != nil {
				return records, ctx.Err()
			}

			if sub.Customer == nil {
				continue
			}

			// diff mode: skip customers created at-or-before the cutoff
			if sinceUnix > 0 && sub.Customer.Created <= sinceUnix {
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
			var userAmount int64
			if legacyPricing {
				userAmount = getUserAmount(sp.StripePrice, currency)
			}

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
				CustomerID:    sub.Customer.ID,
				Email:         email,
				Name:          sub.Customer.Name,
				PlanID:        planID,
				Interval:      interval,
				Currency:      currency,
				Quantity:      quantity,
				UserAmount:    userAmount,
				StripePriceID: sp.StripePrice.ID,
				StripeSubID:   sub.ID,
			}

			// derive user created_at from the stripe customer's created date (UTC)
			if sub.Customer.Created > 0 {
				t := time.Unix(sub.Customer.Created, 0).UTC()
				rec.CreatedAt = &t
			}

			// capture payment method
			if !omitPaymentMethods {
				if migrateTestCard {
					rec.PaymentMethod = stripeTestCardForCurrency(currency)
				} else if sub.DefaultPaymentMethod != nil {
					rec.PaymentMethod = sub.DefaultPaymentMethod.ID
				}
			}

			// detect group/team subscriptions
			if sub.Metadata["is_group"] == "true" {
				rec.IsTeamOwner = true
				rec.TeamKey = sub.ID // use the subscription ID as the team key
			}

			// extract discount from subscription
			if sub.Discount != nil && sub.Discount.Coupon != nil {
				coupon := sub.Discount.Coupon
				if coupon.PercentOff > 0 {
					pct := coupon.PercentOff
					rec.DiscountPct = &pct

					switch coupon.Duration {
					case stripe.CouponDurationForever:
						term := atomic.CreditTermForever
						rec.DiscountTerm = &term
					case stripe.CouponDurationOnce:
						term := atomic.CreditTermOnce
						rec.DiscountTerm = &term
					case stripe.CouponDurationRepeating:
						term := atomic.CreditTermRepeating
						rec.DiscountTerm = &term
					}
				}
			}

			if sub.CancelAt > 0 {
				cancelAt := time.Unix(sub.CancelAt, 0).UTC()
				if shiftAnchor > 0 {
					cancelAt = cancelAt.Add(shiftAnchor)
				}
				rec.EndAt = &cancelAt
			} else if sub.CancelAtPeriodEnd && sub.CurrentPeriodEnd > 0 {
				cancelAt := time.Unix(sub.CurrentPeriodEnd, 0).UTC()
				if shiftAnchor > 0 {
					cancelAt = cancelAt.Add(shiftAnchor)
				}
				rec.EndAt = &cancelAt
			} else if sub.BillingCycleAnchor > 0 {
				anchor := time.Unix(sub.BillingCycleAnchor, 0).UTC()

				if anchor.Before(time.Now().UTC()) {
					switch interval {
					case atomic.SubscriptionIntervalMonth:
						anchor = anchor.AddDate(0, 1, 0)
					case atomic.SubscriptionIntervalYear:
						anchor = anchor.AddDate(1, 0, 0)
					}
				}

				if shiftAnchor > 0 {
					anchor = anchor.Add(shiftAnchor)
				}

				rec.AnchorDate = &anchor
			}

			records = append(records, rec)
			bar.Add(1)
			bar.Describe(collectingSubsStatus(len(records), startTime))

			if limit > 0 && len(records) >= limit {
				break
			}
		}

		if err := iter.Err(); err != nil {
			return nil, fmt.Errorf("failed to list subscriptions for price %s: %w", sp.StripePrice.ID, err)
		}

		if limit > 0 && len(records) >= limit {
			break
		}
	}

	// sort ascending by customer created_at; this is the natural order users
	// were created in stripe and matches the diff cutoff semantics
	sort.SliceStable(records, func(i, j int) bool {
		var ti, tj time.Time
		if records[i].CreatedAt != nil {
			ti = *records[i].CreatedAt
		}
		if records[j].CreatedAt != nil {
			tj = *records[j].CreatedAt
		}
		return ti.Before(tj)
	})

	return records, nil
}

// resolveDiffPaths returns the source path to read for the diff cutoff (the
// highest existing -diff-NN.csv, or the base file if none exist), and the
// next diff output path with an incremented suffix. The source path is empty
// if no existing file is found — the caller should treat that as a fresh run.
func resolveDiffPaths(basePath string) (sourcePath, nextOutput string, err error) {
	ext := filepath.Ext(basePath)
	base := strings.TrimSuffix(basePath, ext)

	// the base may have already been suffixed earlier in JSONL mode (-subscribers,
	// -founders); diff numbering applies to whatever the current output points to
	dir := filepath.Dir(base)
	stem := filepath.Base(base)

	entries, err := os.ReadDir(dir)
	if err != nil && !os.IsNotExist(err) {
		return "", "", err
	}

	maxNum := 0
	maxFile := ""
	prefix := stem + "-diff-"
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasPrefix(name, prefix) || !strings.HasSuffix(name, ext) {
			continue
		}
		mid := strings.TrimSuffix(strings.TrimPrefix(name, prefix), ext)
		n, err := strconv.Atoi(mid)
		if err != nil || n <= 0 {
			continue
		}
		if n > maxNum {
			maxNum = n
			maxFile = filepath.Join(dir, name)
		}
	}

	if maxNum > 0 {
		sourcePath = maxFile
	} else if _, err := os.Stat(basePath); err == nil {
		sourcePath = basePath
	}

	nextOutput = fmt.Sprintf("%s-diff-%02d%s", base, maxNum+1, ext)
	return sourcePath, nextOutput, nil
}

// readMaxCreatedAt scans an existing import CSV and returns the latest
// created_at timestamp found in any row, or nil if the column is missing or
// empty in every row.
func readMaxCreatedAt(path string) (*time.Time, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	r := csv.NewReader(f)
	r.FieldsPerRecord = -1

	header, err := r.Read()
	if err != nil {
		return nil, err
	}

	col := -1
	for i, h := range header {
		if strings.EqualFold(strings.TrimSpace(h), "created_at") {
			col = i
			break
		}
	}
	if col < 0 {
		return nil, nil
	}

	var maxTime *time.Time
	for {
		row, err := r.Read()
		if err != nil {
			break
		}
		if col >= len(row) {
			continue
		}
		val := strings.TrimSpace(row[col])
		if val == "" {
			continue
		}
		t, err := time.Parse(time.RFC3339, val)
		if err != nil {
			continue
		}
		t = t.UTC()
		if maxTime == nil || t.After(*maxTime) {
			tCopy := t
			maxTime = &tCopy
		}
	}

	return maxTime, nil
}

func collectingSubsStatus(count int, start time.Time) string {
	elapsed := time.Since(start).Seconds()
	if elapsed < 1 || count == 0 {
		return fmt.Sprintf("Collecting subscriptions (%d found)", count)
	}
	rate := float64(count) / elapsed
	return fmt.Sprintf("Collecting subscriptions (%d found, %.1f/s)", count, rate)
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

// calculateLegacyPricingDiscounts computes a forever discount based on the
// difference between the subscriber's source price and the target plan price.
// If the record already has a discount (from an existing Stripe coupon), the
// percentages are added together and the term is set to forever.
func calculateLegacyPricingDiscounts(records []*migrationRecord, mapping *passportPlanMapping) {
	for _, rec := range records {
		passportAmount, ok := mapping.getAmount(rec.PlanID, rec.Interval, rec.Currency)
		if !ok || passportAmount <= 0 {
			log.Warnf("no Passport price found for plan %s interval %s currency %s (%s); skipping legacy pricing",
				rec.PlanID, rec.Interval, rec.Currency, rec.Email)
			continue
		}

		if rec.UserAmount <= 0 {
			continue
		}

		if rec.UserAmount >= passportAmount {
			continue
		}

		legacyPct := math.Round((1.0-float64(rec.UserAmount)/float64(passportAmount))*10000) / 100
		term := atomic.CreditTermForever

		if rec.DiscountPct != nil {
			// combine with existing coupon discount
			combined := *rec.DiscountPct + legacyPct
			if combined > 100 {
				combined = 100
			}
			rec.DiscountPct = &combined
		} else {
			rec.DiscountPct = &legacyPct
		}
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

// parseDuration parses a duration string supporting Go duration syntax plus
// "d" suffix for days (e.g. "7d", "30d", "24h", "2h30m").
func parseDuration(s string) (time.Duration, error) {
	if strings.HasSuffix(s, "d") {
		days := strings.TrimSuffix(s, "d")
		n, err := fmt.Sscanf(days, "%d", new(int))
		if err != nil || n != 1 {
			return 0, fmt.Errorf("invalid day duration: %s", s)
		}
		var d int
		fmt.Sscanf(days, "%d", &d)
		return time.Duration(d) * 24 * time.Hour, nil
	}
	return time.ParseDuration(s)
}

// stripeTestCardForCurrency returns a Stripe test payment method token for the given currency.
// See https://docs.stripe.com/testing#international-cards
func stripeTestCardForCurrency(currency string) string {
	switch strings.ToLower(currency) {
	case "usd":
		return "pm_card_visa"
	case "gbp":
		return "pm_card_gb"
	case "eur":
		return "pm_card_de"
	case "cad":
		return "pm_card_ca"
	case "aud":
		return "pm_card_au"
	case "jpy":
		return "pm_card_jp"
	case "sgd":
		return "pm_card_sg"
	case "hkd":
		return "pm_card_hk"
	case "nzd":
		return "pm_card_nz"
	case "brl":
		return "pm_card_br"
	case "mxn":
		return "pm_card_mx"
	case "inr":
		return "pm_card_in"
	default:
		return "pm_card_visa"
	}
}

func printStripeCurrencyOptions(sp *stripe.Price) {
	for cur, opt := range sp.CurrencyOptions {
		fmt.Printf("      └─ %s: %d\n", cur, opt.UnitAmount)
	}
}
