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
	"sync"
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
	"golang.org/x/sync/errgroup"
	"golang.org/x/time/rate"
)

const (
	manifestVersion  = "3"
	manifestFilename = "manifest.json"

	// flushInterval is the number of records after which large-type exports
	// flush their file and manifest to disk for resume safety.
	flushInterval = 200
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
		ActiveOnly              bool   `json:"active_only,omitempty"`
		TerminatedSubscriptions bool   `json:"terminated_subscriptions,omitempty"`
		EmailDomainRewrite      string `json:"email_domain_rewrite,omitempty"`
		EmailTemplate           string `json:"email_template,omitempty"`
	}

	exportFileInfo struct {
		Filename      string `json:"filename"`
		Count         int    `json:"count"`
		MD5           string `json:"md5"`
		ExportedAt    string `json:"exported_at"`
		Complete      bool   `json:"complete"`
		OldestCreated int64  `json:"oldest_created,omitempty"`
	}

	exportOptions struct {
		activeOnly              bool
		terminatedSubscriptions bool
		rewriter                *emailRewriter
	}

	// exportContext holds shared state for export functions.
	exportContext struct {
		ctx      context.Context
		dir      string
		opts     exportOptions
		limiter  *rate.Limiter
		manifest *exportManifest
		mu       *sync.Mutex // protects manifest reads/writes
		progress *concurrentProgress
	}

	// concurrentProgress provides a thread-safe multi-counter progress display.
	concurrentProgress struct {
		mu       sync.Mutex
		counters map[string]int
		labels   map[string]string // optional suffix like "[active]"
		bar      *progressbar.ProgressBar
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
				Name:  "active-only",
				Usage: "only export active products, prices, and promotion codes",
			},
			&cli.BoolFlag{
				Name:  "terminated-subscriptions",
				Usage: "include terminated subscriptions (canceled, unpaid, incomplete_expired) in the export",
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

func newConcurrentProgress() *concurrentProgress {
	return &concurrentProgress{
		counters: make(map[string]int),
		labels:   make(map[string]string),
		bar: progressbar.NewOptions(-1,
			progressbar.OptionSetWriter(os.Stderr),
			progressbar.OptionSpinnerType(14),
			progressbar.OptionShowCount(),
			progressbar.OptionClearOnFinish(),
		),
	}
}

func (p *concurrentProgress) Inc(name string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.counters[name]++
	p.bar.Add(1)
	p.refresh()
}

func (p *concurrentProgress) SetLabel(name, label string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.labels[name] = label
	p.refresh()
}

func (p *concurrentProgress) refresh() {
	var parts []string
	for _, name := range []string{"customers", "subscriptions"} {
		if count, ok := p.counters[name]; ok {
			label := name
			if l, ok := p.labels[name]; ok && l != "" {
				label = name + " " + l
			}
			parts = append(parts, fmt.Sprintf("%s: %d", label, count))
		}
	}
	p.bar.Describe("Exporting " + strings.Join(parts, " | "))
}

func (p *concurrentProgress) Finish() {
	p.bar.Finish()
}

// newStripeLimiter creates a rate limiter tuned to Stripe's API rate limits.
// Test mode: 25 req/s limit → 10 req/s with burst 3 (writes expand to multiple internal ops).
// Live mode: 100 req/s limit → 40 req/s with burst 5.
func newStripeLimiter(isTest bool) *rate.Limiter {
	if isTest {
		return rate.NewLimiter(rate.Limit(10), 3)
	}
	return rate.NewLimiter(rate.Limit(40), 5)
}

func stripeExport(ctx context.Context, cmd *cli.Command) error {
	acct := cmd.Root().Metadata["stripe_account"].(*stripe.Account)
	clean := cmd.Bool("clean")
	activeOnly := cmd.Bool("active-only")

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

	isTest := strings.HasPrefix(stripe.Key, "sk_test_")
	mode := "live"
	if isTest {
		mode = "test"
	}

	// load or initialize manifest
	manifest, err := loadManifest(exportDir)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("failed to load manifest: %w", err)
	}

	currentOpts := &exportManifestOptions{
		ActiveOnly:              activeOnly,
		TerminatedSubscriptions: cmd.Bool("terminated-subscriptions"),
		EmailDomainRewrite:      emailDomain,
		EmailTemplate:           emailTemplate,
	}

	opts := exportOptions{
		activeOnly:              activeOnly,
		terminatedSubscriptions: cmd.Bool("terminated-subscriptions"),
		rewriter:                rewriter,
	}

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

		// migrate v2 manifests
		if manifest.Version == "2" {
			for name, info := range manifest.Files {
				info.Complete = true
				manifest.Files[name] = info
			}
			manifest.Version = manifestVersion
		}

		// update stored options
		manifest.Options = currentOpts
	}

	shouldExport := func(name string) bool {
		return exportAll || typeSet[name]
	}

	// print resume status for types with existing data
	printResumeStatus(manifest, shouldExport)

	fmt.Fprintf(os.Stderr, "exporting account %s (%s mode) to %s\n", acct.ID, mode, exportDir)

	limiter := newStripeLimiter(isTest)

	ectx := &exportContext{
		ctx:      ctx,
		dir:      exportDir,
		opts:     opts,
		limiter:  limiter,
		manifest: manifest,
		mu:       &sync.Mutex{},
	}

	// Phase 1: sequential export of small types
	smallTypes := []struct {
		name string
		fn   func(*exportContext) (int, error)
		file string
	}{
		{"products", exportProducts, "products.jsonl"},
		{"prices", exportPrices, "prices.jsonl"},
		{"coupons", exportCoupons, "coupons.jsonl"},
		{"promotion-codes", exportPromotionCodes, "promotion_codes.jsonl"},
	}

	for _, et := range smallTypes {
		if ctx.Err() != nil {
			return fmt.Errorf("export interrupted")
		}
		if !shouldExport(et.name) {
			continue
		}

		count, err := et.fn(ectx)
		if err != nil {
			return fmt.Errorf("failed to export %s: %w", et.name, err)
		}

		filePath := filepath.Join(exportDir, et.file)
		md5sum, err := util.FileMD5(filePath)
		if err != nil {
			return fmt.Errorf("failed to compute md5 for %s: %w", et.file, err)
		}

		ectx.mu.Lock()
		if !containsString(manifest.Types, et.name) {
			manifest.Types = append(manifest.Types, et.name)
		}
		manifest.Files[et.name] = exportFileInfo{
			Filename:   et.file,
			Count:      count,
			MD5:        md5sum,
			ExportedAt: time.Now().UTC().Format(time.RFC3339),
			Complete:   true,
		}
		ectx.mu.Unlock()

		if err := writeManifestAtomic(exportDir, manifest); err != nil {
			return fmt.Errorf("failed to write manifest: %w", err)
		}
	}

	// Phase 2: concurrent export of large types (customers, subscriptions)
	exportCust := shouldExport("customers")
	exportSubs := shouldExport("subscriptions")

	if exportCust || exportSubs {
		ectx.progress = newConcurrentProgress()

		g, gctx := errgroup.WithContext(ctx)
		ectx.ctx = gctx

		if exportCust {
			g.Go(func() error {
				_, err := exportCustomers(ectx)
				return err
			})
		}

		if exportSubs {
			g.Go(func() error {
				_, err := exportSubscriptions(ectx)
				return err
			})
		}

		if err := g.Wait(); err != nil {
			ectx.progress.Finish()
			return err
		}

		ectx.progress.Finish()
		ectx.ctx = ctx
	}

	// post-pass: extract coupons from subscription and customer discounts
	refreshCouponsManifest := false

	if shouldExport("subscriptions") && shouldExport("coupons") {
		extracted, err := extractSubscriptionCoupons(exportDir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: failed to extract subscription coupons: %v\n", err)
		} else if extracted > 0 {
			fmt.Fprintf(os.Stderr, "merged %d subscription-referenced coupons into coupons.jsonl\n", extracted)
			refreshCouponsManifest = true
		}
	}

	if shouldExport("customers") && shouldExport("coupons") {
		extracted, err := extractCustomerCoupons(exportDir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: failed to extract customer coupons: %v\n", err)
		} else if extracted > 0 {
			fmt.Fprintf(os.Stderr, "merged %d customer-referenced coupons into coupons.jsonl\n", extracted)
			refreshCouponsManifest = true
		}
	}

	if refreshCouponsManifest {
		couponPath := filepath.Join(exportDir, "coupons.jsonl")
		if md5sum, err := util.FileMD5(couponPath); err == nil {
			count, _ := util.JSONLCount(couponPath)
			manifest.Files["coupons"] = exportFileInfo{
				Filename:   "coupons.jsonl",
				Count:      count,
				MD5:        md5sum,
				ExportedAt: time.Now().UTC().Format(time.RFC3339),
				Complete:   true,
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

// printResumeStatus prints a summary of per-type resume state.
func printResumeStatus(m *exportManifest, shouldExport func(string) bool) {
	var lines []string

	for _, name := range []string{"products", "prices", "coupons", "promotion-codes", "customers", "subscriptions"} {
		if !shouldExport(name) {
			continue
		}

		info, exists := m.Files[name]
		if !exists {
			lines = append(lines, fmt.Sprintf("  %-18s fresh export", name))
			continue
		}

		if !info.Complete {
			ts := "unknown"
			if info.OldestCreated > 0 {
				ts = time.Unix(info.OldestCreated, 0).UTC().Format(time.RFC3339)
			}
			lines = append(lines, fmt.Sprintf("  %-18s continuing from %s (%d records exported)", name, ts, info.Count))
		} else {
			lines = append(lines, fmt.Sprintf("  %-18s incremental sync (%d records)", name, info.Count))
		}
	}

	if len(lines) == 0 {
		return
	}

	// only print if there's something to resume (not all fresh)
	hasResume := false
	for _, name := range []string{"products", "prices", "coupons", "promotion-codes", "customers", "subscriptions"} {
		if _, exists := m.Files[name]; exists && shouldExport(name) {
			hasResume = true
			break
		}
	}

	if !hasResume {
		return
	}

	fmt.Fprintf(os.Stderr, "resume status:\n")
	for _, line := range lines {
		fmt.Fprintf(os.Stderr, "%s\n", line)
	}
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
// Incomplete files skip MD5 verification since they are still being written.
func verifyManifestFiles(dir string, m *exportManifest) {
	for typeName, info := range m.Files {
		filePath := filepath.Join(dir, info.Filename)

		if _, err := os.Stat(filePath); errors.Is(err, os.ErrNotExist) {
			fmt.Fprintf(os.Stderr, "warning: %s missing, will re-export\n", info.Filename)
			delete(m.Files, typeName)
			m.Types = removeString(m.Types, typeName)
			continue
		}

		// skip MD5 check for incomplete files — they are expected to change
		if !info.Complete {
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
		mismatches = append(mismatches, fmt.Sprintf("active-only changed: %v → %v", previous.ActiveOnly, current.ActiveOnly))
	}

	if previous.TerminatedSubscriptions != current.TerminatedSubscriptions {
		mismatches = append(mismatches, fmt.Sprintf("terminated-subscriptions changed: %v → %v", previous.TerminatedSubscriptions, current.TerminatedSubscriptions))
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
		if strings.HasSuffix(name, ".jsonl") || strings.HasSuffix(name, ".map.db") || strings.HasSuffix(name, ".tmp") || name == manifestFilename || name == importStateFilename {
			os.Remove(filepath.Join(dir, name))
		}
	}
}

// stripeIterSeq adapts a stripe-go list iterator into a rate-limited iter.Seq2[T, error].
func stripeIterSeq[T any, I interface {
	Next() bool
	Err() error
}](ctx context.Context, it I, extract func(I) *T, limiter *rate.Limiter, onEach func()) iter.Seq2[T, error] {
	return func(yield func(T, error) bool) {
		for {
			if limiter != nil {
				if err := limiter.Wait(ctx); err != nil {
					var zero T
					yield(zero, err)
					return
				}
			}

			if !it.Next() {
				break
			}

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

// resumeFilter determines the API filter for a type based on its manifest state.
// Returns the filter type ("fresh", "incremental", "continue") and the created timestamp filter.
func resumeFilter(info exportFileInfo, exists bool) (strategy string, createdGTE *int64, createdLT *int64) {
	if !exists {
		return "fresh", nil, nil
	}

	if info.Complete {
		// incremental sync: fetch records created since the export completed
		if info.ExportedAt != "" {
			t, err := time.Parse(time.RFC3339, info.ExportedAt)
			if err == nil {
				ts := t.Unix()
				return "incremental", &ts, nil
			}
		}
		return "fresh", nil, nil
	}

	// incomplete: continue from where we left off
	if info.OldestCreated > 0 {
		return "continue", nil, &info.OldestCreated
	}

	return "fresh", nil, nil
}

func exportProducts(ectx *exportContext) (int, error) {
	bar := newExportSpinner("Exporting products")

	info, exists := ectx.manifest.Files["products"]
	strategy, createdGTE, _ := resumeFilter(info, exists)

	params := &stripe.ProductListParams{}
	params.Limit = stripe.Int64(100)

	if ectx.opts.activeOnly {
		params.Active = stripe.Bool(true)
	}
	if createdGTE != nil {
		params.CreatedRange = &stripe.RangeQueryParams{GreaterThanOrEqual: *createdGTE}
	}

	_ = strategy

	seq := stripeIterSeq(ectx.ctx, product.List(params),
		func(i *product.Iter) *stripe.Product { return i.Product() },
		ectx.limiter,
		func() { bar.Add(1) },
	)

	path := filepath.Join(ectx.dir, "products.jsonl")
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

func exportPrices(ectx *exportContext) (int, error) {
	bar := newExportSpinner("Exporting prices")

	info, exists := ectx.manifest.Files["prices"]
	_, createdGTE, _ := resumeFilter(info, exists)

	params := &stripe.PriceListParams{}
	params.Limit = stripe.Int64(100)
	params.AddExpand("data.currency_options")
	params.AddExpand("data.tiers")

	if ectx.opts.activeOnly {
		params.Active = stripe.Bool(true)
	}
	if createdGTE != nil {
		params.CreatedRange = &stripe.RangeQueryParams{GreaterThanOrEqual: *createdGTE}
	}

	seq := stripeIterSeq(ectx.ctx, price.List(params),
		func(i *price.Iter) *stripe.Price { return i.Price() },
		ectx.limiter,
		func() { bar.Add(1) },
	)

	path := filepath.Join(ectx.dir, "prices.jsonl")
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

func exportCoupons(ectx *exportContext) (int, error) {
	bar := newExportSpinner("Exporting coupons")

	info, exists := ectx.manifest.Files["coupons"]
	_, createdGTE, _ := resumeFilter(info, exists)

	params := &stripe.CouponListParams{}
	params.Limit = stripe.Int64(100)

	if createdGTE != nil {
		params.CreatedRange = &stripe.RangeQueryParams{GreaterThanOrEqual: *createdGTE}
	}

	seq := stripeIterSeq(ectx.ctx, coupon.List(params),
		func(i *coupon.Iter) *stripe.Coupon { return i.Coupon() },
		ectx.limiter,
		func() { bar.Add(1) },
	)

	path := filepath.Join(ectx.dir, "coupons.jsonl")
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

func exportPromotionCodes(ectx *exportContext) (int, error) {
	bar := newExportSpinner("Exporting promotion codes")

	info, exists := ectx.manifest.Files["promotion-codes"]
	_, createdGTE, _ := resumeFilter(info, exists)

	params := &stripe.PromotionCodeListParams{}
	params.Limit = stripe.Int64(100)

	if ectx.opts.activeOnly {
		params.Active = stripe.Bool(true)
	}
	if createdGTE != nil {
		params.CreatedRange = &stripe.RangeQueryParams{GreaterThanOrEqual: *createdGTE}
	}

	seq := stripeIterSeq(ectx.ctx, promotioncode.List(params),
		func(i *promotioncode.Iter) *stripe.PromotionCode { return i.PromotionCode() },
		ectx.limiter,
		func() { bar.Add(1) },
	)

	path := filepath.Join(ectx.dir, "promotion_codes.jsonl")
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

func exportCustomers(ectx *exportContext) (int, error) {
	info, exists := ectx.manifest.Files["customers"]
	strategy, createdGTE, createdLT := resumeFilter(info, exists)

	filePath := filepath.Join(ectx.dir, "customers.jsonl")

	// incremental sync for completed types uses merge-write
	if strategy == "incremental" {
		return exportCustomersIncremental(ectx, createdGTE)
	}

	// fresh or continue: use append mode with periodic flushing
	var seenIDs map[string]bool
	var count int

	if strategy == "continue" {
		if repaired, err := util.JSONLRepair(filePath); err != nil {
			return 0, fmt.Errorf("failed to repair customers file: %w", err)
		} else if repaired {
			fmt.Fprintf(os.Stderr, "repaired truncated record in customers.jsonl\n")
		}

		var err error
		seenIDs, count, err = util.JSONLLoadIDs(filePath, func(c stripe.Customer) string { return c.ID })
		if err != nil {
			return 0, fmt.Errorf("failed to load existing customer IDs: %w", err)
		}
	} else {
		seenIDs = make(map[string]bool)
		// fresh: truncate any existing file
		os.Remove(filePath)
	}

	writer, err := util.NewJSONLFileAppendWriter[stripe.Customer](filePath)
	if err != nil {
		return 0, fmt.Errorf("failed to open customers file: %w", err)
	}
	defer writer.Close()

	params := &stripe.CustomerListParams{}
	params.Limit = stripe.Int64(100)
	params.AddExpand("data.default_source")
	params.AddExpand("data.discount")
	params.AddExpand("data.invoice_settings.default_payment_method")
	params.AddExpand("data.tax")

	if createdLT != nil {
		params.CreatedRange = &stripe.RangeQueryParams{LesserThan: *createdLT}
	}

	// mark as incomplete in manifest before starting
	ectx.mu.Lock()
	if !containsString(ectx.manifest.Types, "customers") {
		ectx.manifest.Types = append(ectx.manifest.Types, "customers")
	}
	ectx.manifest.Files["customers"] = exportFileInfo{
		Filename: "customers.jsonl",
		Count:    count,
		Complete: false,
	}
	ectx.mu.Unlock()

	var oldestCreated int64
	sinceFlush := 0

	it := customer.List(params)
	for {
		if err := ectx.limiter.Wait(ectx.ctx); err != nil {
			return count, err
		}

		if !it.Next() {
			break
		}

		c := *it.Customer()

		if seenIDs[c.ID] {
			continue
		}

		rewriteCustomerEmails(&c, ectx.opts.rewriter)

		if err := writer.Write(c); err != nil {
			return count, fmt.Errorf("failed to write customer: %w", err)
		}

		seenIDs[c.ID] = true
		count++
		sinceFlush++

		if c.Created > 0 && (oldestCreated == 0 || c.Created < oldestCreated) {
			oldestCreated = c.Created
		}

		if ectx.progress != nil {
			ectx.progress.Inc("customers")
		}

		if sinceFlush >= flushInterval {
			writer.Flush()
			ectx.mu.Lock()
			ectx.manifest.Files["customers"] = exportFileInfo{
				Filename:      "customers.jsonl",
				Count:         count,
				Complete:      false,
				OldestCreated: oldestCreated,
			}
			writeManifestAtomic(ectx.dir, ectx.manifest)
			ectx.mu.Unlock()
			sinceFlush = 0
		}
	}

	if err := it.Err(); err != nil {
		return count, fmt.Errorf("failed to list customers: %w", err)
	}

	writer.Flush()

	// compute MD5 and mark complete
	md5sum, _ := util.FileMD5(filePath)

	ectx.mu.Lock()
	ectx.manifest.Files["customers"] = exportFileInfo{
		Filename:      "customers.jsonl",
		Count:         count,
		MD5:           md5sum,
		ExportedAt:    time.Now().UTC().Format(time.RFC3339),
		Complete:      true,
		OldestCreated: oldestCreated,
	}
	writeManifestAtomic(ectx.dir, ectx.manifest)
	ectx.mu.Unlock()

	fmt.Fprintf(os.Stderr, "exported %d customers\n", count)
	return count, nil
}

func exportCustomersIncremental(ectx *exportContext, createdGTE *int64) (int, error) {
	params := &stripe.CustomerListParams{}
	params.Limit = stripe.Int64(100)
	params.AddExpand("data.default_source")
	params.AddExpand("data.discount")
	params.AddExpand("data.invoice_settings.default_payment_method")
	params.AddExpand("data.tax")

	if createdGTE != nil {
		params.CreatedRange = &stripe.RangeQueryParams{GreaterThanOrEqual: *createdGTE}
	}

	baseSeq := stripeIterSeq(ectx.ctx, customer.List(params),
		func(i *customer.Iter) *stripe.Customer { return i.Customer() },
		ectx.limiter,
		func() {
			if ectx.progress != nil {
				ectx.progress.Inc("customers")
			}
		},
	)

	seq := baseSeq
	if ectx.opts.rewriter != nil {
		seq = func(yield func(stripe.Customer, error) bool) {
			baseSeq(func(c stripe.Customer, err error) bool {
				if err == nil {
					rewriteCustomerEmails(&c, ectx.opts.rewriter)
				}
				return yield(c, err)
			})
		}
	}

	path := filepath.Join(ectx.dir, "customers.jsonl")
	count, err := util.JSONLMergeWrite(path,
		func(c stripe.Customer) string { return c.ID },
		seq,
	)

	if err != nil {
		return count, fmt.Errorf("failed to export customers: %w", err)
	}

	md5sum, _ := util.FileMD5(path)

	ectx.mu.Lock()
	if !containsString(ectx.manifest.Types, "customers") {
		ectx.manifest.Types = append(ectx.manifest.Types, "customers")
	}
	ectx.manifest.Files["customers"] = exportFileInfo{
		Filename:   "customers.jsonl",
		Count:      count,
		MD5:        md5sum,
		ExportedAt: time.Now().UTC().Format(time.RFC3339),
		Complete:   true,
	}
	writeManifestAtomic(ectx.dir, ectx.manifest)
	ectx.mu.Unlock()

	fmt.Fprintf(os.Stderr, "exported %d customers\n", count)
	return count, nil
}

func exportSubscriptions(ectx *exportContext) (int, error) {
	info, exists := ectx.manifest.Files["subscriptions"]
	strategy, createdGTE, createdLT := resumeFilter(info, exists)

	filePath := filepath.Join(ectx.dir, "subscriptions.jsonl")

	if strategy == "incremental" {
		return exportSubscriptionsIncremental(ectx, createdGTE)
	}

	// fresh or continue
	var seenIDs map[string]bool
	var count int

	if strategy == "continue" {
		if repaired, err := util.JSONLRepair(filePath); err != nil {
			return 0, fmt.Errorf("failed to repair subscriptions file: %w", err)
		} else if repaired {
			fmt.Fprintf(os.Stderr, "repaired truncated record in subscriptions.jsonl\n")
		}

		var err error
		seenIDs, count, err = util.JSONLLoadIDs(filePath, func(s stripe.Subscription) string { return s.ID })
		if err != nil {
			return 0, fmt.Errorf("failed to load existing subscription IDs: %w", err)
		}
	} else {
		seenIDs = make(map[string]bool)
		os.Remove(filePath)
	}

	writer, err := util.NewJSONLFileAppendWriter[stripe.Subscription](filePath)
	if err != nil {
		return 0, fmt.Errorf("failed to open subscriptions file: %w", err)
	}
	defer writer.Close()

	statuses := []string{"active", "past_due", "trialing", "paused"}
	if ectx.opts.terminatedSubscriptions {
		statuses = append(statuses, "canceled", "unpaid", "incomplete", "incomplete_expired")
	}

	// mark as incomplete
	ectx.mu.Lock()
	if !containsString(ectx.manifest.Types, "subscriptions") {
		ectx.manifest.Types = append(ectx.manifest.Types, "subscriptions")
	}
	ectx.manifest.Files["subscriptions"] = exportFileInfo{
		Filename: "subscriptions.jsonl",
		Count:    count,
		Complete: false,
	}
	ectx.mu.Unlock()

	var oldestCreated int64
	sinceFlush := 0

	for _, status := range statuses {
		if ectx.progress != nil {
			ectx.progress.SetLabel("subscriptions", fmt.Sprintf("[%s]", status))
		}

		params := &stripe.SubscriptionListParams{}
		params.Limit = stripe.Int64(100)
		params.Status = stripe.String(status)
		params.AddExpand("data.default_payment_method")
		params.AddExpand("data.default_source")
		params.AddExpand("data.discount")
		params.AddExpand("data.discounts")
		params.AddExpand("data.items.data.price")
		params.AddExpand("data.items.data.discounts")

		if createdLT != nil {
			params.CreatedRange = &stripe.RangeQueryParams{LesserThan: *createdLT}
		}

		it := subscription.List(params)
		for {
			if err := ectx.limiter.Wait(ectx.ctx); err != nil {
				return count, err
			}

			if !it.Next() {
				break
			}

			sub := *it.Subscription()

			if seenIDs[sub.ID] {
				continue
			}

			if err := writer.Write(sub); err != nil {
				return count, fmt.Errorf("failed to write subscription: %w", err)
			}

			seenIDs[sub.ID] = true
			count++
			sinceFlush++

			if sub.Created > 0 && (oldestCreated == 0 || sub.Created < oldestCreated) {
				oldestCreated = sub.Created
			}

			if ectx.progress != nil {
				ectx.progress.Inc("subscriptions")
			}

			if sinceFlush >= flushInterval {
				writer.Flush()
				ectx.mu.Lock()
				ectx.manifest.Files["subscriptions"] = exportFileInfo{
					Filename:      "subscriptions.jsonl",
					Count:         count,
					Complete:      false,
					OldestCreated: oldestCreated,
				}
				writeManifestAtomic(ectx.dir, ectx.manifest)
				ectx.mu.Unlock()
				sinceFlush = 0
			}
		}

		if err := it.Err(); err != nil {
			return count, fmt.Errorf("failed to list %s subscriptions: %w", status, err)
		}
	}

	writer.Flush()

	md5sum, _ := util.FileMD5(filePath)

	ectx.mu.Lock()
	ectx.manifest.Files["subscriptions"] = exportFileInfo{
		Filename:      "subscriptions.jsonl",
		Count:         count,
		MD5:           md5sum,
		ExportedAt:    time.Now().UTC().Format(time.RFC3339),
		Complete:      true,
		OldestCreated: oldestCreated,
	}
	writeManifestAtomic(ectx.dir, ectx.manifest)
	ectx.mu.Unlock()

	fmt.Fprintf(os.Stderr, "exported %d subscriptions\n", count)
	return count, nil
}

func exportSubscriptionsIncremental(ectx *exportContext, createdGTE *int64) (int, error) {
	statuses := []string{"active", "past_due", "trialing", "paused"}
	if ectx.opts.terminatedSubscriptions {
		statuses = append(statuses, "canceled", "unpaid", "incomplete", "incomplete_expired")
	}

	seq := func(yield func(stripe.Subscription, error) bool) {
		for _, status := range statuses {
			if ectx.progress != nil {
				ectx.progress.SetLabel("subscriptions", fmt.Sprintf("[%s]", status))
			}

			params := &stripe.SubscriptionListParams{}
			params.Limit = stripe.Int64(100)
			params.Status = stripe.String(status)
			params.AddExpand("data.default_payment_method")
			params.AddExpand("data.default_source")
			params.AddExpand("data.discount")
			params.AddExpand("data.discounts")
			params.AddExpand("data.items.data.price")
			params.AddExpand("data.items.data.discounts")

			if createdGTE != nil {
				params.CreatedRange = &stripe.RangeQueryParams{GreaterThanOrEqual: *createdGTE}
			}

			it := subscription.List(params)
			for {
				if ectx.limiter != nil {
					if err := ectx.limiter.Wait(ectx.ctx); err != nil {
						var zero stripe.Subscription
						yield(zero, err)
						return
					}
				}

				if !it.Next() {
					break
				}

				if ectx.progress != nil {
					ectx.progress.Inc("subscriptions")
				}

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

	path := filepath.Join(ectx.dir, "subscriptions.jsonl")
	count, err := util.JSONLMergeWrite(path,
		func(s stripe.Subscription) string { return s.ID },
		seq,
	)

	if err != nil {
		return count, fmt.Errorf("failed to export subscriptions: %w", err)
	}

	md5sum, _ := util.FileMD5(path)

	ectx.mu.Lock()
	if !containsString(ectx.manifest.Types, "subscriptions") {
		ectx.manifest.Types = append(ectx.manifest.Types, "subscriptions")
	}
	ectx.manifest.Files["subscriptions"] = exportFileInfo{
		Filename:   "subscriptions.jsonl",
		Count:      count,
		MD5:        md5sum,
		ExportedAt: time.Now().UTC().Format(time.RFC3339),
		Complete:   true,
	}
	writeManifestAtomic(ectx.dir, ectx.manifest)
	ectx.mu.Unlock()

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

// extractCustomerCoupons reads customers.jsonl, extracts coupons from
// customer discounts, and merges them into coupons.jsonl. Returns the number of new coupons added.
func extractCustomerCoupons(dir string) (int, error) {
	custReader, err := util.NewJSONLFileReader[stripe.Customer](filepath.Join(dir, "customers.jsonl"))
	if err != nil {
		return 0, err
	}
	defer custReader.Close()

	coupons := make(map[string]stripe.Coupon)

	for c, err := range custReader.All() {
		if err != nil {
			return 0, err
		}

		if c.Discount != nil && c.Discount.Coupon != nil && c.Discount.Coupon.ID != "" {
			coupons[c.Discount.Coupon.ID] = *c.Discount.Coupon
		}
	}

	if len(coupons) == 0 {
		return 0, nil
	}

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

// extractSubscriptionCoupons reads subscriptions.jsonl, extracts coupons from
// discounts, and merges them into coupons.jsonl. Returns the number of new coupons added.
func extractSubscriptionCoupons(dir string) (int, error) {
	subReader, err := util.NewJSONLFileReader[stripe.Subscription](filepath.Join(dir, "subscriptions.jsonl"))
	if err != nil {
		return 0, err
	}
	defer subReader.Close()

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
