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
	"os"
	"strings"

	"github.com/libatomic/atomic/pkg/atomic"
	"github.com/libatomic/atomic/pkg/ptr"
	"github.com/stripe/stripe-go/v79"
	stripeclient "github.com/stripe/stripe-go/v79/client"
	"github.com/urfave/cli/v3"
)

var (
	stripeRepairCmd = &cli.Command{
		Name:  "repair",
		Usage: "recreate missing Stripe objects (products, prices, coupons) from Passport data (test mode only)",
		Flags: []cli.Flag{
			&cli.StringSliceFlag{
				Name:    "types",
				Aliases: []string{"t"},
				Usage:   "types to repair: plans, prices, credits, all",
				Value:   []string{"all"},
			},
			&cli.BoolFlag{
				Name:  "dry-run",
				Usage: "preview what would be repaired without making changes",
			},
		},
		Action: stripeRepairAction,
	}
)

func stripeRepairAction(ctx context.Context, cmd *cli.Command) error {
	key := cmd.String("stripe-key")
	if !strings.HasPrefix(key, "sk_test_") && !strings.HasPrefix(key, "rk_test_") {
		return fmt.Errorf("stripe repair only works with test keys")
	}

	sc := stripeclient.New(key, nil)
	dryRun := cmd.Bool("dry-run")
	verbose := mainCmd.Bool("verbose")

	types := cmd.StringSlice("types")
	typeSet := make(map[string]bool)
	for _, t := range types {
		typeSet[strings.ToLower(t)] = true
	}
	all := typeSet["all"]

	if dryRun {
		fmt.Fprintf(os.Stderr, "[DRY RUN] previewing stripe repair\n\n")
	}

	// fetch all plans with prices
	bar := newMigrateSpinner("Fetching plans")
	plans, err := backend.PlanList(ctx, &atomic.PlanListInput{InstanceID: inst.UUID})
	bar.Finish()
	if err != nil {
		return fmt.Errorf("failed to list plans: %w", err)
	}

	bar = newMigrateSpinner("Loading plan details")
	var fullPlans []*atomic.Plan
	for _, p := range plans {
		full, err := backend.PlanGet(ctx, &atomic.PlanGetInput{
			InstanceID: inst.UUID,
			PlanID:     &p.UUID,
			Preload:    ptr.Bool(true),
		})
		if err != nil {
			fullPlans = append(fullPlans, p)
		} else {
			fullPlans = append(fullPlans, full)
		}
		bar.Add(1)
	}
	bar.Finish()

	fmt.Fprintf(os.Stderr, "loaded %d plans\n", len(fullPlans))

	// repair plans (Stripe products)
	if all || typeSet["plans"] {
		repaired, skipped, errors := 0, 0, 0

		bar = newMigrateProgress(len(fullPlans), "Repairing plans")
		for _, plan := range fullPlans {
			bar.Add(1)

			if plan.Type != atomic.PlanTypePaid {
				skipped++
				continue
			}

			if plan.StripeProduct != nil && *plan.StripeProduct != "" {
				// verify it exists in Stripe
				if _, err := sc.Products.Get(*plan.StripeProduct, nil); err == nil {
					skipped++
					continue
				}
			}

			if dryRun {
				if verbose {
					fmt.Fprintf(os.Stderr, "\n  would create product for plan %s (%s)\n", plan.Name, plan.UUID)
				}
				repaired++
				continue
			}

			prodID := "atomic_" + plan.UUID.String()
			prod, err := sc.Products.New(&stripe.ProductParams{
				ID:          ptr.String(prodID),
				Name:        ptr.String(plan.Name),
				Active:      ptr.Bool(plan.Active),
				Description: plan.Description,
			})
			if err != nil {
				// product might already exist with this ID
				if existingProd, getErr := sc.Products.Get(prodID, nil); getErr == nil {
					prod = existingProd
				} else {
					errors++
					if verbose {
						fmt.Fprintf(os.Stderr, "\n  error creating product for %s: %s\n", plan.Name, err)
					}
					continue
				}
			}

			// update plan with stripe product ID
			if _, err := backend.PlanUpdate(ctx, &atomic.PlanUpdateInput{
				InstanceID:    inst.UUID,
				PlanID:        plan.UUID,
				StripeProduct: &prod.ID,
			}); err != nil {
				errors++
				if verbose {
					fmt.Fprintf(os.Stderr, "\n  error updating plan %s: %s\n", plan.Name, err)
				}
				continue
			}

			plan.StripeProduct = &prod.ID
			repaired++

			if verbose {
				fmt.Fprintf(os.Stderr, "\n  created product %s for plan %s\n", prod.ID, plan.Name)
			}
		}
		bar.Finish()
		fmt.Fprintf(os.Stderr, "plans: %d repaired, %d skipped, %d errors\n", repaired, skipped, errors)
	}

	// repair prices (Stripe prices)
	if all || typeSet["prices"] {
		repaired, skipped, errors := 0, 0, 0

		var allPrices []*atomic.Price
		for _, plan := range fullPlans {
			for _, price := range plan.Prices {
				p := price
				p.Plan = plan
				allPrices = append(allPrices, p)
			}
		}

		bar = newMigrateProgress(len(allPrices), "Repairing prices")
		for _, price := range allPrices {
			bar.Add(1)

			if price.Plan == nil || price.Plan.Type != atomic.PlanTypePaid {
				skipped++
				continue
			}

			if price.StripePrice != "" {
				// verify it exists in Stripe
				if _, err := sc.Prices.Get(price.StripePrice, nil); err == nil {
					skipped++
					continue
				}
			}

			if price.Plan.StripeProduct == nil || *price.Plan.StripeProduct == "" {
				if verbose {
					fmt.Fprintf(os.Stderr, "\n  skipping price %s: plan %s has no stripe product\n", price.Name, price.Plan.Name)
				}
				skipped++
				continue
			}

			if dryRun {
				if verbose {
					fmt.Fprintf(os.Stderr, "\n  would create price for %s/%s\n", price.Plan.Name, price.Name)
				}
				repaired++
				continue
			}

			priceParams := &stripe.PriceParams{
				Product:  price.Plan.StripeProduct,
				Currency: ptr.String(price.Currency),
				Active:   ptr.Bool(price.Active),
				Metadata: map[string]string{
					"atomic_price_id": price.UUID.String(),
				},
			}

			if price.TierMode != nil {
				priceParams.BillingScheme = stripe.String("tiered")
				priceParams.TiersMode = stripe.String(string(*price.TierMode))
				for _, tier := range price.Tiers {
					t := &stripe.PriceTierParams{
						FlatAmount: tier.FlatAmount,
						UnitAmount: stripe.Int64(tier.UnitAmount),
					}
					if tier.UpTo > 0 {
						t.UpTo = stripe.Int64(tier.UpTo)
					} else {
						t.UpToInf = stripe.Bool(true)
					}
					priceParams.Tiers = append(priceParams.Tiers, t)
				}
			} else if price.FlatAmount != nil {
				priceParams.UnitAmount = price.FlatAmount
			}

			if price.RecurringInterval != nil {
				priceParams.Recurring = &stripe.PriceRecurringParams{
					Interval:      stripe.String(string(*price.RecurringInterval)),
					IntervalCount: stripe.Int64(int64(ptr.Value(price.RecurringFrequency, 1))),
				}
			}

			// handle currency options
			if price.CurrencyOptions != nil {
				priceParams.CurrencyOptions = make(map[string]*stripe.PriceCurrencyOptionsParams)
				for cur, opt := range price.CurrencyOptions {
					coParams := &stripe.PriceCurrencyOptionsParams{}
					if opt.UnitAmount != nil {
						coParams.UnitAmount = opt.UnitAmount
					}
					if opt.TaxBehavior != nil {
						coParams.TaxBehavior = opt.TaxBehavior
					}
					priceParams.CurrencyOptions[cur] = coParams
				}
			}

			newPrice, err := sc.Prices.New(priceParams)
			if err != nil {
				errors++
				if verbose {
					fmt.Fprintf(os.Stderr, "\n  error creating price for %s/%s: %s\n", price.Plan.Name, price.Name, err)
				}
				continue
			}

			// update price with stripe price ID
			if _, err := backend.PriceUpdate(ctx, &atomic.PriceUpdateInput{
				PriceID:     price.UUID,
				StripePrice: &newPrice.ID,
			}); err != nil {
				errors++
				if verbose {
					fmt.Fprintf(os.Stderr, "\n  error updating price %s: %s\n", price.Name, err)
				}
				continue
			}

			repaired++
			if verbose {
				fmt.Fprintf(os.Stderr, "\n  created price %s for %s/%s\n", newPrice.ID, price.Plan.Name, price.Name)
			}
		}
		bar.Finish()
		fmt.Fprintf(os.Stderr, "prices: %d repaired, %d skipped, %d errors\n", repaired, skipped, errors)
	}

	// repair credits (Stripe coupons for aggregate coupons and volume discounts)
	if all || typeSet["credits"] {
		repaired, skipped, errors := 0, 0, 0

		bar = newMigrateSpinner("Fetching credits")

		// aggregate coupons (owner_id IS NULL)
		couponType := atomic.CreditTypeCoupon
		coupons, err := backend.CreditList(ctx, &atomic.CreditListInput{
			InstanceID: inst.UUID,
			Type:       &couponType,
			Aggregate:  ptr.Bool(true),
		})
		if err != nil {
			bar.Finish()
			return fmt.Errorf("failed to list aggregate coupons: %w", err)
		}

		// volume discounts
		volumeType := atomic.CreditTypeVolumeDiscount
		volumes, err := backend.CreditList(ctx, &atomic.CreditListInput{
			InstanceID: inst.UUID,
			Type:       &volumeType,
		})
		if err != nil {
			bar.Finish()
			return fmt.Errorf("failed to list volume discounts: %w", err)
		}
		bar.Finish()

		allCredits := append(coupons, volumes...)
		fmt.Fprintf(os.Stderr, "found %d credits to check (%d coupons, %d volume discounts)\n", len(allCredits), len(coupons), len(volumes))

		bar = newMigrateProgress(len(allCredits), "Repairing credits")
		for _, credit := range allCredits {
			bar.Add(1)

			if credit.StripeCoupon != nil && *credit.StripeCoupon != "" {
				// verify it exists in Stripe
				if _, err := sc.Coupons.Get(*credit.StripeCoupon, nil); err == nil {
					skipped++
					continue
				}
			}

			if dryRun {
				name := ptr.Value(credit.Name, credit.UUID.String())
				if verbose {
					fmt.Fprintf(os.Stderr, "\n  would create coupon for credit %s (%s)\n", name, credit.Type)
				}
				repaired++
				continue
			}

			cpnParams := &stripe.CouponParams{
				Metadata: map[string]string{
					"atomic_credit_id": credit.UUID.String(),
				},
			}

			if credit.PercentOff != nil {
				cpnParams.PercentOff = credit.PercentOff
			} else if credit.Amount != nil {
				cpnParams.AmountOff = credit.Amount
				cpnParams.Currency = credit.Currency
			}

			if credit.Term != nil {
				switch *credit.Term {
				case atomic.CreditTermOnce:
					cpnParams.Duration = stripe.String("once")
				case atomic.CreditTermRepeating:
					cpnParams.Duration = stripe.String("repeating")
					if credit.Duration != nil {
						// duration is in seconds, Stripe wants months
						months := *credit.Duration / (30 * 24 * 60 * 60)
						if months < 1 {
							months = 1
						}
						cpnParams.DurationInMonths = stripe.Int64(months)
					}
				case atomic.CreditTermForever:
					cpnParams.Duration = stripe.String("forever")
				}
			} else {
				cpnParams.Duration = stripe.String("forever")
			}

			if credit.Name != nil {
				cpnParams.Name = credit.Name
			}

			cpn, err := sc.Coupons.New(cpnParams)
			if err != nil {
				errors++
				name := ptr.Value(credit.Name, credit.UUID.String())
				if verbose {
					fmt.Fprintf(os.Stderr, "\n  error creating coupon for %s: %s\n", name, err)
				}
				continue
			}

			// update credit with stripe coupon ID
			if _, err := backend.CreditUpdate(ctx, &atomic.CreditUpdateInput{
				InstanceID:   inst.UUID,
				CreditID:     credit.UUID,
				StripeCoupon: &cpn.ID,
			}); err != nil {
				errors++
				if verbose {
					fmt.Fprintf(os.Stderr, "\n  error updating credit %s: %s\n", credit.UUID, err)
				}
				continue
			}

			repaired++
			name := ptr.Value(credit.Name, credit.UUID.String())
			if verbose {
				fmt.Fprintf(os.Stderr, "\n  created coupon %s for credit %s (%s)\n", cpn.ID, name, credit.Type)
			}
		}
		bar.Finish()
		fmt.Fprintf(os.Stderr, "credits: %d repaired, %d skipped, %d errors\n", repaired, skipped, errors)
	}

	return nil
}
