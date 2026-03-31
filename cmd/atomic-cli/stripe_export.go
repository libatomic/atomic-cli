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
	"errors"
	"fmt"
	"iter"
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

const (
	manifestVersion  = "2"
	manifestFilename = "manifest.json"
)

type (
	exportManifest struct {
		Version     string                    `json:"version"`
		CreatedAt   string                    `json:"created_at"`
		UpdatedAt   string                    `json:"updated_at"`
		AccountID   string                    `json:"account_id"`
		AccountName string                    `json:"account_name,omitempty"`
		Livemode    bool                      `json:"livemode"`
		Types       []string                  `json:"types"`
		Files       map[string]exportFileInfo `json:"files"`
		Options     *exportManifestOptions    `json:"options,omitempty"`
	}

	exportManifestOptions struct {
		ActiveOnly         bool   `json:"active_only,omitempty"`
		EmailDomainRewrite string `json:"email_domain_rewrite,omitempty"`
		EmailTemplate      string `json:"email_template,omitempty"`
	}

	exportFileInfo struct {
		Filename   string `json:"filename"`
		Count      int    `json:"count"`
		MD5        string `json:"md5"`
		ExportedAt string `json:"exported_at"`
	}

	exportOptions struct {
		createdGTE *int64
		activeOnly bool
		rewriter   *emailRewriter
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
			&cli.BoolFlag{
				Name:  "clean",
				Usage: "clear existing export data and start fresh",
			},
			&cli.BoolFlag{
				Name:  "active",
				Usage: "only export active objects (applies to products, prices, promotion codes; subscriptions use active status only)",
			},
			&cli.StringFlag{
				Name:  "email-domain-overwrite",
				Usage: "rewrite all customer email addresses to use this domain; mutually exclusive with --email-template",
			},
			&cli.StringFlag{
				Name:  "email-template",
				Usage: "generate customer email addresses from a template (see migrate --help for template functions); mutually exclusive with --email-domain-overwrite",
			},
		},
	}
)

func stripeExport(_ context.Context, cmd *cli.Command) error {
	acct := cmd.Root().Metadata["stripe_account"].(*stripe.Account)
	clean := cmd.Bool("clean")
	activeOnly := cmd.Bool("active")

	emailDomain := cmd.String("email-domain-overwrite")
	emailTemplate := cmd.String("email-template")
	if emailDomain != "" && emailTemplate != "" {
		return fmt.Errorf("--email-domain-overwrite and --email-template are mutually exclusive")
	}

	var rewriter *emailRewriter
	if emailDomain != "" {
		rewriter = &emailRewriter{domain: emailDomain}
	} else if emailTemplate != "" {
		rewriter = &emailRewriter{template: emailTemplate}
	}

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
	isTest := strings.HasPrefix(stripe.Key, "sk_test_")
	if isTest {
		mode = "test"
	}

	// load or initialize manifest
	manifest, err := loadManifest(exportDir)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("failed to load manifest: %w", err)
	}

	currentOpts := &exportManifestOptions{
		ActiveOnly:         activeOnly,
		EmailDomainRewrite: emailDomain,
		EmailTemplate:      emailTemplate,
	}

	opts := exportOptions{activeOnly: activeOnly, rewriter: rewriter}

	if clean || manifest == nil {
		if clean && manifest != nil {
			fmt.Fprintf(os.Stderr, "clearing existing export data\n")
			cleanExportDir(exportDir)
		}

		now := time.Now().UTC().Format(time.RFC3339)
		manifest = &exportManifest{
			Version:     manifestVersion,
			CreatedAt:   now,
			UpdatedAt:   now,
			AccountID:   acct.ID,
			AccountName: acct.Settings.Dashboard.DisplayName,
			Livemode:    !isTest,
			Types:       []string{},
			Files:       make(map[string]exportFileInfo),
			Options:     currentOpts,
		}
	} else {
		// verify account matches
		if manifest.AccountID != acct.ID {
			return fmt.Errorf("export directory belongs to account %s, current account is %s", manifest.AccountID, acct.ID)
		}

		// verify options match previous export
		if err := verifyExportOptions(manifest.Options, currentOpts); err != nil {
			return err
		}

		// verify file integrity
		verifyManifestFiles(exportDir, manifest)

		// use manifest updated_at as created.gte for incremental sync
		if manifest.UpdatedAt != "" {
			t, err := time.Parse(time.RFC3339, manifest.UpdatedAt)
			if err == nil {
				ts := t.Unix()
				opts.createdGTE = &ts
				fmt.Fprintf(os.Stderr, "incremental sync from %s\n", manifest.UpdatedAt)
			}
		}

		// update stored options
		manifest.Options = currentOpts
	}

	fmt.Fprintf(os.Stderr, "exporting account %s (%s mode) to %s\n", acct.ID, mode, exportDir)

	exportTypes := []struct {
		name string
		fn   func(string, exportOptions) (int, error)
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

		count, err := et.fn(exportDir, opts)
		if err != nil {
			return fmt.Errorf("failed to export %s: %w", et.name, err)
		}

		filePath := filepath.Join(exportDir, et.file)
		md5sum, err := util.FileMD5(filePath)
		if err != nil {
			return fmt.Errorf("failed to compute md5 for %s: %w", et.file, err)
		}

		if !containsString(manifest.Types, et.name) {
			manifest.Types = append(manifest.Types, et.name)
		}

		manifest.Files[et.name] = exportFileInfo{
			Filename:   et.file,
			Count:      count,
			MD5:        md5sum,
			ExportedAt: time.Now().UTC().Format(time.RFC3339),
		}
	}

	// post-pass: extract coupons from subscription discounts and merge into coupons.jsonl
	if (exportAll || typeSet["subscriptions"]) && (exportAll || typeSet["coupons"]) {
		extracted, err := extractSubscriptionCoupons(exportDir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: failed to extract subscription coupons: %v\n", err)
		} else if extracted > 0 {
			fmt.Fprintf(os.Stderr, "merged %d subscription-referenced coupons into coupons.jsonl\n", extracted)

			// refresh coupons manifest entry
			couponPath := filepath.Join(exportDir, "coupons.jsonl")
			if md5sum, err := util.FileMD5(couponPath); err == nil {
				reader, _ := util.NewJSONLFileReader[stripe.Coupon](couponPath)
				count := 0
				if reader != nil {
					for _, err := range reader.All() {
						if err != nil {
							break
						}
						count++
					}
					reader.Close()
				}
				manifest.Files["coupons"] = exportFileInfo{
					Filename:   "coupons.jsonl",
					Count:      count,
					MD5:        md5sum,
					ExportedAt: time.Now().UTC().Format(time.RFC3339),
				}
			}
		}
	}

	manifest.UpdatedAt = time.Now().UTC().Format(time.RFC3339)

	if err := writeManifestAtomic(exportDir, manifest); err != nil {
		return fmt.Errorf("failed to write manifest: %w", err)
	}

	fmt.Fprintf(os.Stderr, "export complete: %s\n", exportDir)

	return nil
}

// loadManifest reads and parses the manifest from the export directory.
// Returns os.ErrNotExist if the manifest file does not exist.
func loadManifest(dir string) (*exportManifest, error) {
	data, err := os.ReadFile(filepath.Join(dir, manifestFilename))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, os.ErrNotExist
		}
		return nil, err
	}

	var m exportManifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("corrupt manifest: %w", err)
	}

	return &m, nil
}

// verifyManifestFiles checks MD5 checksums for all files in the manifest.
// Files that fail verification are removed from the manifest so they get re-exported.
func verifyManifestFiles(dir string, m *exportManifest) {
	for typeName, info := range m.Files {
		filePath := filepath.Join(dir, info.Filename)

		if _, err := os.Stat(filePath); errors.Is(err, os.ErrNotExist) {
			fmt.Fprintf(os.Stderr, "warning: %s missing, will re-export\n", info.Filename)
			delete(m.Files, typeName)
			m.Types = removeString(m.Types, typeName)
			continue
		}

		if info.MD5 == "" {
			continue
		}

		actual, err := util.FileMD5(filePath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: failed to verify %s, will re-export: %v\n", info.Filename, err)
			delete(m.Files, typeName)
			m.Types = removeString(m.Types, typeName)
			continue
		}

		if actual != info.MD5 {
			fmt.Fprintf(os.Stderr, "warning: %s modified outside export tool (md5 mismatch), will re-export\n", info.Filename)
			os.Remove(filePath)
			delete(m.Files, typeName)
			m.Types = removeString(m.Types, typeName)
		}
	}
}

// verifyExportOptions checks that current export flags match the previous export.
// Returns an error if critical options have changed that would produce inconsistent data.
func verifyExportOptions(previous, current *exportManifestOptions) error {
	if previous == nil {
		return nil
	}

	var mismatches []string

	if previous.EmailDomainRewrite != current.EmailDomainRewrite {
		mismatches = append(mismatches, fmt.Sprintf("email-domain-overwrite changed: %q → %q", previous.EmailDomainRewrite, current.EmailDomainRewrite))
	}

	if previous.EmailTemplate != current.EmailTemplate {
		mismatches = append(mismatches, fmt.Sprintf("email-template changed: %q → %q", previous.EmailTemplate, current.EmailTemplate))
	}

	if previous.ActiveOnly != current.ActiveOnly {
		mismatches = append(mismatches, fmt.Sprintf("active changed: %v → %v", previous.ActiveOnly, current.ActiveOnly))
	}

	if len(mismatches) > 0 {
		msg := "export options have changed since last run:\n"
		for _, m := range mismatches {
			msg += fmt.Sprintf("  - %s\n", m)
		}
		msg += "use --clean to start a fresh export with the new options"
		return fmt.Errorf(msg)
	}

	return nil
}

// writeManifestAtomic writes the manifest to a temp file and renames it atomically.
func writeManifestAtomic(dir string, m *exportManifest) error {
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}

	data = append(data, '\n')

	tmpPath := filepath.Join(dir, manifestFilename+".tmp")
	if err := os.WriteFile(tmpPath, data, 0644); err != nil {
		return err
	}

	return os.Rename(tmpPath, filepath.Join(dir, manifestFilename))
}

// cleanExportDir removes all jsonl files, tmp files, and the manifest from the directory.
func cleanExportDir(dir string) {
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		name := e.Name()
		if strings.HasSuffix(name, ".jsonl") || strings.HasSuffix(name, ".tmp") || name == manifestFilename {
			os.Remove(filepath.Join(dir, name))
		}
	}
}

// stripeIterSeq adapts a stripe-go list iterator into an iter.Seq2[T, error].
func stripeIterSeq[T any, I interface {
	Next() bool
	Err() error
}](it I, extract func(I) *T, onEach func()) iter.Seq2[T, error] {
	return func(yield func(T, error) bool) {
		for it.Next() {
			v := extract(it)
			if onEach != nil {
				onEach()
			}
			if !yield(*v, nil) {
				return
			}
		}
		if err := it.Err(); err != nil {
			var zero T
			yield(zero, err)
		}
	}
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

func exportProducts(dir string, opts exportOptions) (int, error) {
	bar := newExportSpinner("Exporting products")

	params := &stripe.ProductListParams{}
	params.Limit = stripe.Int64(100)

	if opts.activeOnly {
		params.Active = stripe.Bool(true)
	}
	if opts.createdGTE != nil {
		params.CreatedRange = &stripe.RangeQueryParams{GreaterThanOrEqual: *opts.createdGTE}
	}

	seq := stripeIterSeq(product.List(params),
		func(i *product.Iter) *stripe.Product { return i.Product() },
		func() { bar.Add(1) },
	)

	path := filepath.Join(dir, "products.jsonl")
	count, err := util.JSONLMergeWrite(path,
		func(p stripe.Product) string { return p.ID },
		seq,
	)

	bar.Finish()
	if err != nil {
		return count, fmt.Errorf("failed to export products: %w", err)
	}

	fmt.Fprintf(os.Stderr, "exported %d products\n", count)
	return count, nil
}

func exportPrices(dir string, opts exportOptions) (int, error) {
	bar := newExportSpinner("Exporting prices")

	params := &stripe.PriceListParams{}
	params.Limit = stripe.Int64(100)
	params.AddExpand("data.currency_options")
	params.AddExpand("data.tiers")

	if opts.activeOnly {
		params.Active = stripe.Bool(true)
	}
	if opts.createdGTE != nil {
		params.CreatedRange = &stripe.RangeQueryParams{GreaterThanOrEqual: *opts.createdGTE}
	}

	seq := stripeIterSeq(price.List(params),
		func(i *price.Iter) *stripe.Price { return i.Price() },
		func() { bar.Add(1) },
	)

	path := filepath.Join(dir, "prices.jsonl")
	count, err := util.JSONLMergeWrite(path,
		func(p stripe.Price) string { return p.ID },
		seq,
	)

	bar.Finish()
	if err != nil {
		return count, fmt.Errorf("failed to export prices: %w", err)
	}

	fmt.Fprintf(os.Stderr, "exported %d prices\n", count)
	return count, nil
}

func exportCoupons(dir string, opts exportOptions) (int, error) {
	bar := newExportSpinner("Exporting coupons")

	params := &stripe.CouponListParams{}
	params.Limit = stripe.Int64(100)

	if opts.createdGTE != nil {
		params.CreatedRange = &stripe.RangeQueryParams{GreaterThanOrEqual: *opts.createdGTE}
	}

	seq := stripeIterSeq(coupon.List(params),
		func(i *coupon.Iter) *stripe.Coupon { return i.Coupon() },
		func() { bar.Add(1) },
	)

	path := filepath.Join(dir, "coupons.jsonl")
	count, err := util.JSONLMergeWrite(path,
		func(c stripe.Coupon) string { return c.ID },
		seq,
	)

	bar.Finish()
	if err != nil {
		return count, fmt.Errorf("failed to export coupons: %w", err)
	}

	fmt.Fprintf(os.Stderr, "exported %d coupons\n", count)
	return count, nil
}

func exportPromotionCodes(dir string, opts exportOptions) (int, error) {
	bar := newExportSpinner("Exporting promotion codes")

	params := &stripe.PromotionCodeListParams{}
	params.Limit = stripe.Int64(100)

	if opts.activeOnly {
		params.Active = stripe.Bool(true)
	}
	if opts.createdGTE != nil {
		params.CreatedRange = &stripe.RangeQueryParams{GreaterThanOrEqual: *opts.createdGTE}
	}

	seq := stripeIterSeq(promotioncode.List(params),
		func(i *promotioncode.Iter) *stripe.PromotionCode { return i.PromotionCode() },
		func() { bar.Add(1) },
	)

	path := filepath.Join(dir, "promotion_codes.jsonl")
	count, err := util.JSONLMergeWrite(path,
		func(pc stripe.PromotionCode) string { return pc.ID },
		seq,
	)

	bar.Finish()
	if err != nil {
		return count, fmt.Errorf("failed to export promotion codes: %w", err)
	}

	fmt.Fprintf(os.Stderr, "exported %d promotion codes\n", count)
	return count, nil
}

func exportCustomers(dir string, opts exportOptions) (int, error) {
	bar := newExportSpinner("Exporting customers")

	params := &stripe.CustomerListParams{}
	params.Limit = stripe.Int64(100)
	params.AddExpand("data.default_source")
	params.AddExpand("data.invoice_settings.default_payment_method")
	params.AddExpand("data.tax")

	if opts.createdGTE != nil {
		params.CreatedRange = &stripe.RangeQueryParams{GreaterThanOrEqual: *opts.createdGTE}
	}

	baseSeq := stripeIterSeq(customer.List(params),
		func(i *customer.Iter) *stripe.Customer { return i.Customer() },
		func() { bar.Add(1) },
	)

	// wrap the iterator to rewrite emails if a rewriter is configured
	seq := baseSeq
	if opts.rewriter != nil {
		seq = func(yield func(stripe.Customer, error) bool) {
			baseSeq(func(c stripe.Customer, err error) bool {
				if err == nil && c.Email != "" {
					c.Email = opts.rewriter.Rewrite(c.Email)
				}
				return yield(c, err)
			})
		}
	}

	path := filepath.Join(dir, "customers.jsonl")
	count, err := util.JSONLMergeWrite(path,
		func(c stripe.Customer) string { return c.ID },
		seq,
	)

	bar.Finish()
	if err != nil {
		return count, fmt.Errorf("failed to export customers: %w", err)
	}

	fmt.Fprintf(os.Stderr, "exported %d customers\n", count)
	return count, nil
}

func exportSubscriptions(dir string, opts exportOptions) (int, error) {
	bar := newExportSpinner("Exporting subscriptions")

	statuses := []string{"active", "past_due", "trialing", "canceled", "unpaid", "paused"}
	if opts.activeOnly {
		statuses = []string{"active"}
	}

	seq := func(yield func(stripe.Subscription, error) bool) {
		params := &stripe.SubscriptionListParams{}
		params.Limit = stripe.Int64(100)
		params.AddExpand("data.default_payment_method")
		params.AddExpand("data.default_source")
		params.AddExpand("data.discount")
		params.AddExpand("data.discounts")
		params.AddExpand("data.items.data.price")
		params.AddExpand("data.items.data.discounts")

		if opts.createdGTE != nil {
			params.CreatedRange = &stripe.RangeQueryParams{GreaterThanOrEqual: *opts.createdGTE}
		}

		for _, status := range statuses {
			params.Status = stripe.String(status)
			bar.Describe(fmt.Sprintf("Exporting subscriptions [%s]", status))

			it := subscription.List(params)
			for it.Next() {
				bar.Add(1)
				if !yield(*it.Subscription(), nil) {
					return
				}
			}

			if err := it.Err(); err != nil {
				var zero stripe.Subscription
				yield(zero, fmt.Errorf("failed to list %s subscriptions: %w", status, err))
				return
			}
		}
	}

	path := filepath.Join(dir, "subscriptions.jsonl")
	count, err := util.JSONLMergeWrite(path,
		func(s stripe.Subscription) string { return s.ID },
		seq,
	)

	bar.Finish()
	if err != nil {
		return count, fmt.Errorf("failed to export subscriptions: %w", err)
	}

	fmt.Fprintf(os.Stderr, "exported %d subscriptions\n", count)
	return count, nil
}

func containsString(s []string, v string) bool {
	for _, item := range s {
		if item == v {
			return true
		}
	}
	return false
}

func removeString(s []string, v string) []string {
	result := make([]string, 0, len(s))
	for _, item := range s {
		if item != v {
			result = append(result, item)
		}
	}
	return result
}

// extractSubscriptionCoupons reads subscriptions.jsonl, extracts coupons from
// discounts, and merges them into coupons.jsonl. Returns the number of new coupons added.
func extractSubscriptionCoupons(dir string) (int, error) {
	subReader, err := util.NewJSONLFileReader[stripe.Subscription](filepath.Join(dir, "subscriptions.jsonl"))
	if err != nil {
		return 0, err
	}
	defer subReader.Close()

	// collect coupons from subscription discounts
	coupons := make(map[string]stripe.Coupon)

	for sub, err := range subReader.All() {
		if err != nil {
			return 0, err
		}

		if sub.Discount != nil && sub.Discount.Coupon != nil {
			c := sub.Discount.Coupon
			if c.ID != "" {
				coupons[c.ID] = *c
			}
		}

		for _, d := range sub.Discounts {
			if d != nil && d.Coupon != nil && d.Coupon.ID != "" {
				coupons[d.Coupon.ID] = *d.Coupon
			}
		}
	}

	if len(coupons) == 0 {
		return 0, nil
	}

	// merge into coupons.jsonl using JSONLMergeWrite with an empty seq
	// (the coupons from subscriptions are merged via a seq)
	seq := func(yield func(stripe.Coupon, error) bool) {
		for _, c := range coupons {
			if !yield(c, nil) {
				return
			}
		}
	}

	couponPath := filepath.Join(dir, "coupons.jsonl")
	_, err = util.JSONLMergeWrite(couponPath,
		func(c stripe.Coupon) string { return c.ID },
		seq,
	)
	if err != nil {
		return 0, err
	}

	return len(coupons), nil
}
