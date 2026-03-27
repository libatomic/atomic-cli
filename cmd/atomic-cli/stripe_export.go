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
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/libatomic/atomic/pkg/util"
	"github.com/schollz/progressbar/v3"
	"github.com/stripe/stripe-go/v79"
	"github.com/stripe/stripe-go/v79/coupon"
	"github.com/stripe/stripe-go/v79/customer"
	"github.com/stripe/stripe-go/v79/price"
	"github.com/stripe/stripe-go/v79/product"
	"github.com/stripe/stripe-go/v79/promotioncode"
	"github.com/stripe/stripe-go/v79/subscription"
	"github.com/urfave/cli/v3"
)

type (
	exportManifest struct {
		Version     string                    `json:"version"`
		CreatedAt   string                    `json:"created_at"`
		AccountID   string                    `json:"account_id"`
		AccountName string                    `json:"account_name,omitempty"`
		Livemode    bool                      `json:"livemode"`
		Types       []string                  `json:"types"`
		Files       map[string]exportFileInfo `json:"files"`
	}

	exportFileInfo struct {
		Filename string `json:"filename"`
		Count    int    `json:"count"`
	}
)

var (
	stripeExportCmd = &cli.Command{
		Name:   "export",
		Usage:  "export stripe data to jsonl files for backup",
		Action: stripeExport,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "output",
				Aliases: []string{"o"},
				Usage:   "output directory (the export folder will be created inside this directory)",
				Value:   ".",
			},
			&cli.StringSliceFlag{
				Name:    "types",
				Aliases: []string{"t"},
				Usage:   "object types to export: products, prices, customers, subscriptions, coupons, promotion-codes, or all",
				Value:   []string{"all"},
			},
		},
	}
)

func stripeExport(_ context.Context, cmd *cli.Command) error {
	acct := cmd.Root().Metadata["stripe_account"].(*stripe.Account)

	types := cmd.StringSlice("types")
	exportAll := false
	typeSet := make(map[string]bool)
	for _, t := range types {
		if t == "all" {
			exportAll = true
			break
		}
		typeSet[t] = true
	}

	accountID := strings.TrimPrefix(acct.ID, "acct_")
	exportDir := filepath.Join(cmd.String("output"), fmt.Sprintf("stripe-export-%s", accountID))

	if err := os.MkdirAll(exportDir, 0755); err != nil {
		return fmt.Errorf("failed to create export directory: %w", err)
	}

	mode := "live"
	if !acct.ChargesEnabled || strings.HasPrefix(cmd.Root().String("stripe-key"), "sk_test_") {
		mode = "test"
	}

	fmt.Fprintf(os.Stderr, "exporting account %s (%s mode) to %s\n", acct.ID, mode, exportDir)

	manifest := exportManifest{
		Version:     "1",
		CreatedAt:   time.Now().UTC().Format(time.RFC3339),
		AccountID:   acct.ID,
		AccountName: acct.Settings.Dashboard.DisplayName,
		Livemode:    !strings.HasPrefix(cmd.Root().String("stripe-key"), "sk_test_"),
		Types:       []string{},
		Files:       make(map[string]exportFileInfo),
	}

	exportTypes := []struct {
		name string
		fn   func(string) (int, error)
		file string
	}{
		{"products", exportProducts, "products.jsonl"},
		{"prices", exportPrices, "prices.jsonl"},
		{"coupons", exportCoupons, "coupons.jsonl"},
		{"promotion-codes", exportPromotionCodes, "promotion_codes.jsonl"},
		{"customers", exportCustomers, "customers.jsonl"},
		{"subscriptions", exportSubscriptions, "subscriptions.jsonl"},
	}

	for _, et := range exportTypes {
		if !exportAll && !typeSet[et.name] {
			continue
		}

		count, err := et.fn(exportDir)
		if err != nil {
			return fmt.Errorf("failed to export %s: %w", et.name, err)
		}

		manifest.Types = append(manifest.Types, et.name)
		manifest.Files[et.name] = exportFileInfo{
			Filename: et.file,
			Count:    count,
		}
	}

	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal manifest: %w", err)
	}

	if err := os.WriteFile(filepath.Join(exportDir, "manifest.json"), manifestBytes, 0644); err != nil {
		return fmt.Errorf("failed to write manifest: %w", err)
	}

	fmt.Fprintf(os.Stderr, "export complete: %s\n", exportDir)

	return nil
}

func newExportSpinner(description string) *progressbar.ProgressBar {
	return progressbar.NewOptions(-1,
		progressbar.OptionSetDescription(description),
		progressbar.OptionSetWriter(os.Stderr),
		progressbar.OptionSpinnerType(14),
		progressbar.OptionShowCount(),
		progressbar.OptionClearOnFinish(),
	)
}

func exportProducts(dir string) (int, error) {
	w, err := util.NewJSONLFileWriter[stripe.Product](filepath.Join(dir, "products.jsonl"))
	if err != nil {
		return 0, err
	}
	defer w.Close()

	bar := newExportSpinner("Exporting products")

	params := &stripe.ProductListParams{}
	params.Limit = stripe.Int64(100)

	iter := product.List(params)
	for iter.Next() {
		if err := w.Write(*iter.Product()); err != nil {
			return w.Count(), err
		}
		bar.Add(1)
	}

	bar.Finish()

	if err := iter.Err(); err != nil {
		return w.Count(), fmt.Errorf("failed to list products: %w", err)
	}

	fmt.Fprintf(os.Stderr, "exported %d products\n", w.Count())
	return w.Count(), nil
}

func exportPrices(dir string) (int, error) {
	w, err := util.NewJSONLFileWriter[stripe.Price](filepath.Join(dir, "prices.jsonl"))
	if err != nil {
		return 0, err
	}
	defer w.Close()

	bar := newExportSpinner("Exporting prices")

	params := &stripe.PriceListParams{}
	params.Limit = stripe.Int64(100)
	params.AddExpand("data.currency_options")
	params.AddExpand("data.tiers")

	iter := price.List(params)
	for iter.Next() {
		if err := w.Write(*iter.Price()); err != nil {
			return w.Count(), err
		}
		bar.Add(1)
	}

	bar.Finish()

	if err := iter.Err(); err != nil {
		return w.Count(), fmt.Errorf("failed to list prices: %w", err)
	}

	fmt.Fprintf(os.Stderr, "exported %d prices\n", w.Count())
	return w.Count(), nil
}

func exportCoupons(dir string) (int, error) {
	w, err := util.NewJSONLFileWriter[stripe.Coupon](filepath.Join(dir, "coupons.jsonl"))
	if err != nil {
		return 0, err
	}
	defer w.Close()

	bar := newExportSpinner("Exporting coupons")

	params := &stripe.CouponListParams{}
	params.Limit = stripe.Int64(100)

	iter := coupon.List(params)
	for iter.Next() {
		if err := w.Write(*iter.Coupon()); err != nil {
			return w.Count(), err
		}
		bar.Add(1)
	}

	bar.Finish()

	if err := iter.Err(); err != nil {
		return w.Count(), fmt.Errorf("failed to list coupons: %w", err)
	}

	fmt.Fprintf(os.Stderr, "exported %d coupons\n", w.Count())
	return w.Count(), nil
}

func exportPromotionCodes(dir string) (int, error) {
	w, err := util.NewJSONLFileWriter[stripe.PromotionCode](filepath.Join(dir, "promotion_codes.jsonl"))
	if err != nil {
		return 0, err
	}
	defer w.Close()

	bar := newExportSpinner("Exporting promotion codes")

	params := &stripe.PromotionCodeListParams{}
	params.Limit = stripe.Int64(100)

	iter := promotioncode.List(params)
	for iter.Next() {
		if err := w.Write(*iter.PromotionCode()); err != nil {
			return w.Count(), err
		}
		bar.Add(1)
	}

	bar.Finish()

	if err := iter.Err(); err != nil {
		return w.Count(), fmt.Errorf("failed to list promotion codes: %w", err)
	}

	fmt.Fprintf(os.Stderr, "exported %d promotion codes\n", w.Count())
	return w.Count(), nil
}

func exportCustomers(dir string) (int, error) {
	w, err := util.NewJSONLFileWriter[stripe.Customer](filepath.Join(dir, "customers.jsonl"))
	if err != nil {
		return 0, err
	}
	defer w.Close()

	bar := newExportSpinner("Exporting customers")

	params := &stripe.CustomerListParams{}
	params.Limit = stripe.Int64(100)
	params.AddExpand("data.default_source")
	params.AddExpand("data.invoice_settings.default_payment_method")
	params.AddExpand("data.tax")

	iter := customer.List(params)
	for iter.Next() {
		if err := w.Write(*iter.Customer()); err != nil {
			return w.Count(), err
		}
		bar.Add(1)
	}

	bar.Finish()

	if err := iter.Err(); err != nil {
		return w.Count(), fmt.Errorf("failed to list customers: %w", err)
	}

	fmt.Fprintf(os.Stderr, "exported %d customers\n", w.Count())
	return w.Count(), nil
}

func exportSubscriptions(dir string) (int, error) {
	w, err := util.NewJSONLFileWriter[stripe.Subscription](filepath.Join(dir, "subscriptions.jsonl"))
	if err != nil {
		return 0, err
	}
	defer w.Close()

	bar := newExportSpinner("Exporting subscriptions")

	params := &stripe.SubscriptionListParams{}
	params.Limit = stripe.Int64(100)
	params.AddExpand("data.default_payment_method")
	params.AddExpand("data.default_source")
	params.AddExpand("data.discount")
	params.AddExpand("data.discounts")
	params.AddExpand("data.items.data.price")
	params.AddExpand("data.items.data.discounts")

	for _, status := range []string{"active", "past_due", "trialing", "canceled", "unpaid", "paused"} {
		params.Status = stripe.String(status)
		bar.Describe(fmt.Sprintf("Exporting subscriptions [%s]", status))

		iter := subscription.List(params)
		for iter.Next() {
			if err := w.Write(*iter.Subscription()); err != nil {
				return w.Count(), err
			}
			bar.Add(1)
		}

		if err := iter.Err(); err != nil {
			return w.Count(), fmt.Errorf("failed to list %s subscriptions: %w", status, err)
		}
	}

	bar.Finish()

	fmt.Fprintf(os.Stderr, "exported %d subscriptions\n", w.Count())
	return w.Count(), nil
}
