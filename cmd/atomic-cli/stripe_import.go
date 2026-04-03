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
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/apex/log"
	"github.com/libatomic/atomic/pkg/ptr"
	"github.com/libatomic/atomic/pkg/util"
	"github.com/schollz/progressbar/v3"
	"github.com/stripe/stripe-go/v79"
	stripecoupon "github.com/stripe/stripe-go/v79/coupon"
	stripecustomer "github.com/stripe/stripe-go/v79/customer"
	"github.com/stripe/stripe-go/v79/paymentmethod"
	stripeprice "github.com/stripe/stripe-go/v79/price"
	stripeproduct "github.com/stripe/stripe-go/v79/product"
	stripepromo "github.com/stripe/stripe-go/v79/promotioncode"
	stripesub "github.com/stripe/stripe-go/v79/subscription"
	"github.com/urfave/cli/v3"
	"golang.org/x/time/rate"
)

const importStateFilename = "import-state.json"

type (
	importOptions struct {
		ctx                    context.Context
		inputDir               string
		abortOnError           bool
		rewriter               *emailRewriter
		createTestCards        bool
		defaultTestCard        string
		applicationFees        bool
		applicationFeeOverride *float64
		onBehalfOf             string
		importSubscriptions    bool
		liveMode               bool
		isConnectPlatform      bool
		importTime             string
		dryRun                 bool
		prorateSubscriptions   bool
		dropExpiredTrials      bool
		pastDueSubscriptions   bool
		limiter                *rate.Limiter
		workers                int
		updateExisting         bool
		state                  *importState
		stateMu                *sync.Mutex
	}

	importValidationError struct {
		Type    string
		ID      string
		Message string
	}

	importState struct {
		Version        string                     `json:"version"`
		CreatedAt      string                     `json:"created_at"`
		UpdatedAt      string                     `json:"updated_at"`
		SourceAccount  string                     `json:"source_account"`
		TargetAccount  string                     `json:"target_account"`
		TargetLivemode bool                       `json:"target_livemode"`
		ExportUpdated  string                     `json:"export_updated"`
		Types          map[string]importTypeState `json:"types"`
	}

	importTypeState struct {
		Complete   bool   `json:"complete"`
		SourceMD5  string `json:"source_md5"`
		Count      int    `json:"count"`
		Errors     int    `json:"errors"`
		Skipped    int    `json:"skipped,omitempty"`
		ImportedAt string `json:"imported_at,omitempty"`
	}
)

var (
	testCardByCurrency = map[string]string{
		"usd": "pm_card_us", "gbp": "pm_card_gb", "eur": "pm_card_de",
		"cad": "pm_card_ca", "aud": "pm_card_au", "jpy": "pm_card_jp",
		"sgd": "pm_card_sg", "hkd": "pm_card_hk", "nzd": "pm_card_nz",
		"chf": "pm_card_ch", "brl": "pm_card_br", "mxn": "pm_card_mx",
		"inr": "pm_card_in", "sek": "pm_card_se", "nok": "pm_card_no",
		"dkk": "pm_card_dk", "pln": "pm_card_pl", "czk": "pm_card_cz",
		"ron": "pm_card_ro", "bgn": "pm_card_bg", "huf": "pm_card_hu",
		"thb": "pm_card_th", "myr": "pm_card_my",
	}

	importTypeOrder = []string{"products", "prices", "coupons", "promotion-codes", "customers", "subscriptions"}

	importDependencies = map[string][]string{
		"prices":          {"products"},
		"promotion-codes": {"coupons"},
		"subscriptions":   {"prices", "customers"},
	}

	stripeImportCmd = &cli.Command{
		Name:   "import",
		Usage:  "import stripe data from an export directory",
		Action: stripeImport,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name: "input", Aliases: []string{"i"},
				Usage: "path to the export directory (containing manifest.json)", Required: true,
			},
			&cli.StringSliceFlag{
				Name: "types", Aliases: []string{"t"},
				Usage: "object types to import: products, prices, customers, subscriptions, coupons, promotion-codes, or all",
				Value: []string{"all"},
			},
			&cli.BoolFlag{Name: "validate", Usage: "validate export data before importing", Value: true},
			&cli.BoolFlag{Name: "dry-run", Usage: "report what would be imported without making any changes"},
			&cli.BoolFlag{Name: "clean", Usage: "clear import state and start a fresh import"},
			&cli.BoolFlag{Name: "update-existing", Usage: "update previously imported objects whose source data has changed (compared by SHA-256)", Value: true},
			&cli.StringFlag{Name: "email-domain-overwrite", Usage: "rewrite customer email addresses to use this domain; mutually exclusive with --email-template"},
			&cli.StringFlag{Name: "email-template", Usage: "generate customer email addresses from a template; mutually exclusive with --email-domain-overwrite"},
			&cli.BoolFlag{Name: "application-fees", Usage: "retain application fees from exported subscriptions (requires Connect platform)", Value: true},
			&cli.Float64Flag{Name: "application-fee-percent", Usage: "override application fee percentage for all subscriptions (requires Connect platform)"},
			&cli.StringFlag{Name: "on-behalf-of", Usage: "connected account ID for on_behalf_of on subscriptions"},
			&cli.BoolFlag{Name: "create-test-cards", Usage: "attach test payment methods to customers (test mode only)", Value: true},
			&cli.StringFlag{Name: "default-test-card", Usage: "override the auto-detected test card for all customers", Value: "pm_card_us"},
			&cli.BoolFlag{Name: "prorate-subscriptions", Usage: "prorate subscriptions on creation"},
			&cli.BoolFlag{Name: "drop-expired-trials", Usage: "shift expired trials forward with the same duration", Value: true},
			&cli.BoolFlag{Name: "past-due-subscriptions", Usage: "import past_due subscriptions (creates with a declining test card to trigger past_due status)"},
			&cli.BoolFlag{Name: "abort-on-error", Usage: "stop the entire import on the first failure"},
			&cli.BoolFlag{Name: "ignore-sandbox-email-warning", Usage: "skip the email rewriting requirement when importing live data into a test account"},
			&cli.IntFlag{Name: "workers", Usage: "number of concurrent workers for customer and subscription imports", Value: 2 * runtime.NumCPU()},
		},
	}
)

// --- state persistence ---

func loadImportState(dir string) (*importState, error) {
	data, err := os.ReadFile(filepath.Join(dir, importStateFilename))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, os.ErrNotExist
		}
		return nil, err
	}
	var s importState
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("corrupt import state: %w", err)
	}
	return &s, nil
}

func writeImportStateAtomic(dir string, s *importState) error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	tmpPath := filepath.Join(dir, importStateFilename+".tmp")
	if err := os.WriteFile(tmpPath, data, 0644); err != nil {
		return err
	}
	return os.Rename(tmpPath, filepath.Join(dir, importStateFilename))
}

func saveTypeState(opts importOptions, name string, ts importTypeState) {
	opts.stateMu.Lock()
	opts.state.Types[name] = ts
	opts.state.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	writeImportStateAtomic(opts.inputDir, opts.state)
	opts.stateMu.Unlock()
}

// --- helpers ---

func importMetadata(existing map[string]string, idKey, originalID, importTime string) map[string]string {
	m := make(map[string]string)
	for k, v := range existing {
		m[k] = v
	}
	m["atomic:import:time"] = importTime
	m["atomic:import:"+idKey] = originalID
	return m
}

func resolveTestCard(opts importOptions, currency string) string {
	if opts.defaultTestCard != "pm_card_us" || currency == "" {
		return opts.defaultTestCard
	}
	if card, ok := testCardByCurrency[strings.ToLower(currency)]; ok {
		return card
	}
	return opts.defaultTestCard
}

func newImportSpinner(description string) *progressbar.ProgressBar {
	return progressbar.NewOptions(-1,
		progressbar.OptionSetDescription(description),
		progressbar.OptionSetWriter(os.Stderr),
		progressbar.OptionSpinnerType(14),
		progressbar.OptionShowCount(),
		progressbar.OptionClearOnFinish(),
	)
}

func newImportProgressBar(total int, description string) *progressbar.ProgressBar {
	return progressbar.NewOptions(total,
		progressbar.OptionSetDescription(description),
		progressbar.OptionSetWriter(os.Stderr),
		progressbar.OptionShowCount(),
		progressbar.OptionShowIts(),
		progressbar.OptionSetItsString("rec"),
		progressbar.OptionClearOnFinish(),
	)
}

func importWarnf(bar *progressbar.ProgressBar, format string, args ...any) {
	bar.Clear()
	fmt.Fprintf(os.Stderr, "\r\033[K")
	log.Warnf(format, args...)
}

func isAlreadyExists(err error) bool {
	var stripeErr *stripe.Error
	if errors.As(err, &stripeErr) {
		return stripeErr.Code == stripe.ErrorCodeResourceAlreadyExists
	}
	return false
}

func isRateLimit(err error) bool {
	var stripeErr *stripe.Error
	if errors.As(err, &stripeErr) {
		return stripeErr.Code == stripe.ErrorCodeRateLimit || stripeErr.HTTPStatusCode == 429
	}
	return false
}

// retryOnRateLimit retries fn up to 5 times with exponential backoff on 429 errors.
func retryOnRateLimit(ctx context.Context, fn func() error) error {
	var err error
	for attempt := range 5 {
		err = fn()
		if err == nil || !isRateLimit(err) {
			return err
		}
		backoff := time.Duration(1<<uint(attempt)) * time.Second
		select {
		case <-time.After(backoff):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return err
}

// --- main flow ---

func stripeImport(ctx context.Context, cmd *cli.Command) error {
	inputDir := cmd.String("input")
	acct := cmd.Root().Metadata["stripe_account"].(*stripe.Account)
	liveMode := !strings.HasPrefix(stripe.Key, "sk_test_") && !strings.HasPrefix(stripe.Key, "rk_test_")
	dryRun := cmd.Bool("dry-run")
	clean := cmd.Bool("clean")

	isConnectPlatform := acct.Controller != nil && acct.Controller.Type == stripe.AccountControllerTypeApplication
	if isConnectPlatform {
		fmt.Fprintf(os.Stderr, "detected Connect platform account (%s)\n", acct.ID)
	}

	if liveMode && !dryRun {
		fmt.Fprintf(os.Stderr, "WARNING: you are about to import into a LIVE Stripe account (%s)\n", acct.ID)
		fmt.Fprintf(os.Stderr, "type 'confirm livemode import' to proceed: ")
		reader := bufio.NewReader(os.Stdin)
		answer, _ := reader.ReadString('\n')
		if strings.TrimSpace(answer) != "confirm livemode import" {
			return fmt.Errorf("import aborted")
		}
	}

	manifest, err := loadManifest(inputDir)
	if err != nil {
		return fmt.Errorf("failed to load manifest from %s: %w", inputDir, err)
	}
	verifyManifestFiles(inputDir, manifest)

	// clean import state + map files
	if clean {
		fmt.Fprintf(os.Stderr, "WARNING: this will clear all import state and ID mappings, starting a fresh import.\n")
		fmt.Fprintf(os.Stderr, "Previously imported objects will NOT be deleted from Stripe.\n")
		fmt.Fprintf(os.Stderr, "type 'yes' to proceed: ")
		reader := bufio.NewReader(os.Stdin)
		answer, _ := reader.ReadString('\n')
		if strings.TrimSpace(answer) != "yes" {
			return fmt.Errorf("import aborted")
		}
		os.Remove(filepath.Join(inputDir, importStateFilename))
		for _, info := range manifest.Files {
			os.Remove(filepath.Join(inputDir, strings.TrimSuffix(info.Filename, ".jsonl")+".map.db"))
		}
	}

	state, err := loadImportState(inputDir)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("failed to load import state: %w", err)
	}
	if state != nil && state.TargetAccount != acct.ID {
		return fmt.Errorf("import state targets account %s, current account is %s; use --clean to start fresh", state.TargetAccount, acct.ID)
	}
	if state == nil {
		now := time.Now().UTC().Format(time.RFC3339)
		state = &importState{
			Version: "1", CreatedAt: now, UpdatedAt: now,
			SourceAccount: manifest.AccountID, TargetAccount: acct.ID,
			TargetLivemode: liveMode, ExportUpdated: manifest.UpdatedAt,
			Types: make(map[string]importTypeState),
		}
	}

	// email rewriter
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

	// require email rewriting when importing live data into a test account,
	// unless the export itself already rewrote emails
	exportAlreadyRewrote := manifest.Options != nil &&
		(manifest.Options.EmailDomainRewrite != "" || manifest.Options.EmailTemplate != "")
	if manifest.Livemode && !liveMode && rewriter == nil && !exportAlreadyRewrote {
		if cmd.Bool("ignore-sandbox-email-warning") {
			fmt.Fprintf(os.Stderr, "WARNING: you are importing live customer data into a test account without email rewriting.\n")
			fmt.Fprintf(os.Stderr, "Real customer email addresses will be used, which may cause Stripe to send emails to real users.\n")
			fmt.Fprintf(os.Stderr, "Use --email-domain-overwrite or --email-template to rewrite emails.\n\n")
			fmt.Fprintf(os.Stderr, "Continue anyway? [y/N]: ")
			reader := bufio.NewReader(os.Stdin)
			answer, _ := reader.ReadString('\n')
			if a := strings.TrimSpace(strings.ToLower(answer)); a != "y" && a != "yes" {
				return fmt.Errorf("import aborted")
			}
		} else {
			return fmt.Errorf("importing live customer data into a test account requires email rewriting to prevent Stripe from sending emails to real users; use --email-domain-overwrite or --email-template, or --ignore-sandbox-email-warning to override")
		}
	}

	applicationFees := cmd.Bool("application-fees")
	var appFeeOverride *float64
	if cmd.IsSet("application-fee-percent") {
		if !isConnectPlatform {
			return fmt.Errorf("--application-fee-percent requires a Connect platform account")
		}
		v := cmd.Float64("application-fee-percent")
		appFeeOverride = &v
	}

	canImportSubs := true
	if liveMode {
		fmt.Fprintf(os.Stderr, "warning: live mode — subscriptions will be skipped (customers have no payment methods)\n")
		canImportSubs = false
	} else if !cmd.Bool("create-test-cards") {
		fmt.Fprintf(os.Stderr, "warning: --create-test-cards is disabled — subscriptions will be skipped\n")
		canImportSubs = false
	}

	isTest := strings.HasPrefix(stripe.Key, "sk_test_") || strings.HasPrefix(stripe.Key, "rk_test_")
	workers := int(cmd.Int("workers"))
	if workers < 1 {
		workers = 1
	}

	opts := importOptions{
		ctx: ctx, inputDir: inputDir,
		abortOnError: cmd.Bool("abort-on-error"), rewriter: rewriter,
		createTestCards: cmd.Bool("create-test-cards") && !liveMode,
		defaultTestCard: cmd.String("default-test-card"),
		applicationFees: applicationFees, applicationFeeOverride: appFeeOverride,
		onBehalfOf: cmd.String("on-behalf-of"), importSubscriptions: canImportSubs,
		liveMode: liveMode, isConnectPlatform: isConnectPlatform,
		importTime: time.Now().UTC().Format(time.RFC3339), dryRun: dryRun,
		prorateSubscriptions: cmd.Bool("prorate-subscriptions"),
		dropExpiredTrials:    cmd.Bool("drop-expired-trials"),
		pastDueSubscriptions: cmd.Bool("past-due-subscriptions"),
		limiter:              newStripeLimiter(isTest), workers: workers,
		updateExisting: cmd.Bool("update-existing"),
		state:          state, stateMu: &sync.Mutex{},
	}

	// type selection
	types := cmd.StringSlice("types")
	importAll := false
	typeSet := make(map[string]bool)
	for _, t := range types {
		if t == "all" {
			importAll = true
			break
		}
		typeSet[t] = true
	}
	shouldImport := func(name string) bool {
		if !importAll && !typeSet[name] {
			return false
		}
		_, ok := manifest.Files[name]
		return ok
	}

	printImportResumeStatus(state, manifest, shouldImport)
	printImportReport(acct, manifest, shouldImport, canImportSubs, rewriter, isConnectPlatform, applicationFees, appFeeOverride, liveMode, dryRun, workers)

	if cmd.Bool("validate") {
		bar := newImportSpinner("Validating export data")
		validationErrors := validateImportData(opts, manifest, shouldImport, func() { bar.Add(1) })
		bar.Finish()
		if len(validationErrors) > 0 {
			fmt.Fprintf(os.Stderr, "\nvalidation failed with %d errors:\n", len(validationErrors))
			for _, e := range validationErrors {
				fmt.Fprintf(os.Stderr, "  [%s] %s: %s\n", e.Type, e.ID, e.Message)
			}
			return fmt.Errorf("import aborted due to validation errors")
		}
		fmt.Fprintf(os.Stderr, "validation passed\n")
	}

	if dryRun {
		return nil
	}

	if !liveMode {
		fmt.Fprintf(os.Stderr, "proceed with import? [y/N]: ")
		reader := bufio.NewReader(os.Stdin)
		answer, _ := reader.ReadString('\n')
		if a := strings.TrimSpace(strings.ToLower(answer)); a != "y" && a != "yes" {
			return fmt.Errorf("import aborted")
		}
	}

	importStart := time.Now()
	fmt.Fprintf(os.Stderr, "importing from %s (source account: %s)\n", inputDir, manifest.AccountID)

	// bbolt-backed ID map stores per type
	errCounts := make(map[string]int)
	stores := make(map[string]*idMapStore)

	openStore := func(typeName string) (*idMapStore, error) {
		if s, ok := stores[typeName]; ok {
			return s, nil
		}
		info := manifest.Files[typeName]
		s, err := openIDMapStore(filepath.Join(inputDir, strings.TrimSuffix(info.Filename, ".jsonl")+".map.db"))
		if err != nil {
			return nil, err
		}
		stores[typeName] = s
		return s, nil
	}

	defer func() {
		for _, s := range stores {
			s.Close()
		}
	}()

	for _, typeName := range importTypeOrder {
		if ctx.Err() != nil {
			fmt.Fprintf(os.Stderr, "import interrupted, syncing state...\n")
			for _, s := range stores {
				s.Sync()
			}
			return fmt.Errorf("import interrupted (took %s)", time.Since(importStart).Truncate(time.Second))
		}

		if !shouldImport(typeName) {
			continue
		}
		if typeName == "subscriptions" && !opts.importSubscriptions {
			fmt.Fprintf(os.Stderr, "skipping subscriptions (see warnings above)\n")
			continue
		}

		exportInfo := manifest.Files[typeName]

		// skip if complete and unchanged
		if ts, ok := state.Types[typeName]; ok && ts.Complete && ts.SourceMD5 == exportInfo.MD5 {
			fmt.Fprintf(os.Stderr, "skipping %s: unchanged since last import (%d records)\n", typeName, ts.Count)
			continue
		}

		// check dependency errors
		if deps, ok := importDependencies[typeName]; ok {
			for _, dep := range deps {
				if errCounts[dep] > 0 {
					return fmt.Errorf("aborting %s import: %d %s errors would cause failures", typeName, errCounts[dep], dep)
				}
			}
		}

		store, err := openStore(typeName)
		if err != nil {
			return fmt.Errorf("failed to open id map for %s: %w", typeName, err)
		}

		saveTypeState(opts, typeName, importTypeState{SourceMD5: exportInfo.MD5, Count: store.Count()})

		total := exportInfo.Count
		var errCount, skipCount int
		var importErr error

		switch typeName {
		case "products":
			errCount, skipCount, importErr = importProducts(opts, store, total)
		case "prices":
			ps, _ := openStore("products")
			errCount, skipCount, importErr = importPrices(opts, ps, store, total)
		case "coupons":
			errCount, skipCount, importErr = importCoupons(opts, store, total)
		case "promotion-codes":
			cs, _ := openStore("coupons")
			errCount, skipCount, importErr = importPromotionCodes(opts, cs, store, total)
		case "customers":
			cs, _ := openStore("coupons")
			errCount, skipCount, importErr = importCustomers(opts, cs, store, total)
		case "subscriptions":
			custS, _ := openStore("customers")
			priceS, _ := openStore("prices")
			couponS, _ := openStore("coupons")
			errCount, skipCount, importErr = importSubscriptions(opts, custS, priceS, couponS, store, total)
		}

		if importErr != nil {
			return fmt.Errorf("failed to import %s: %w", typeName, importErr)
		}

		errCounts[typeName] = errCount
		store.Sync()

		saveTypeState(opts, typeName, importTypeState{
			Complete: errCount == 0, SourceMD5: exportInfo.MD5,
			Count: store.Count(), Errors: errCount, Skipped: skipCount,
			ImportedAt: time.Now().UTC().Format(time.RFC3339),
		})
	}

	fmt.Fprintf(os.Stderr, "import complete (took %s)\n", time.Since(importStart).Truncate(time.Second))
	return nil
}

// --- reporting ---

func printImportResumeStatus(state *importState, manifest *exportManifest, shouldImport func(string) bool) {
	hasResume := false
	for _, name := range importTypeOrder {
		if _, ok := state.Types[name]; ok && shouldImport(name) {
			hasResume = true
			break
		}
	}
	if !hasResume {
		return
	}

	fmt.Fprintf(os.Stderr, "import resume status:\n")
	for _, name := range importTypeOrder {
		if !shouldImport(name) {
			continue
		}
		ts, exists := state.Types[name]
		if !exists {
			fmt.Fprintf(os.Stderr, "  %-18s pending\n", name)
			continue
		}
		exportInfo := manifest.Files[name]
		if ts.Complete && ts.SourceMD5 == exportInfo.MD5 {
			fmt.Fprintf(os.Stderr, "  %-18s complete (%d records, unchanged)\n", name, ts.Count)
		} else if ts.Complete {
			fmt.Fprintf(os.Stderr, "  %-18s complete (%d records, export changed — will re-import)\n", name, ts.Count)
		} else {
			fmt.Fprintf(os.Stderr, "  %-18s resuming (%d records imported)\n", name, ts.Count)
		}
	}
}

func printImportReport(
	acct *stripe.Account, manifest *exportManifest, shouldImport func(string) bool,
	canImportSubs bool, rewriter *emailRewriter, isConnectPlatform bool,
	applicationFees bool, appFeeOverride *float64, liveMode, dryRun bool, workers int,
) {
	if dryRun {
		fmt.Fprintf(os.Stderr, "\n--- DRY RUN ---\n")
	} else {
		fmt.Fprintf(os.Stderr, "\n--- IMPORT PLAN ---\n")
	}

	keyPrefix := stripe.Key
	if len(keyPrefix) > 14 {
		keyPrefix = keyPrefix[:14] + "..."
	}
	fmt.Fprintf(os.Stderr, "api key: %s\n", keyPrefix)

	targetName := ""
	if acct.Settings != nil && acct.Settings.Dashboard != nil {
		targetName = acct.Settings.Dashboard.DisplayName
	}
	if targetName != "" {
		fmt.Fprintf(os.Stderr, "target account: %s (%s)\n", acct.ID, targetName)
	} else {
		fmt.Fprintf(os.Stderr, "target account: %s\n", acct.ID)
	}

	if manifest.AccountName != "" {
		fmt.Fprintf(os.Stderr, "source account: %s (%s)\n", manifest.AccountID, manifest.AccountName)
	} else {
		fmt.Fprintf(os.Stderr, "source account: %s\n", manifest.AccountID)
	}

	fmt.Fprintf(os.Stderr, "source exported: %s\n", manifest.UpdatedAt)
	fmt.Fprintf(os.Stderr, "source livemode: %v\n", manifest.Livemode)
	fmt.Fprintf(os.Stderr, "target livemode: %v\n", liveMode)
	fmt.Fprintf(os.Stderr, "connect platform: %v\n", isConnectPlatform)
	fmt.Fprintf(os.Stderr, "workers: %d\n", workers)

	if manifest.Options != nil {
		o := manifest.Options
		if o.EmailDomainRewrite != "" {
			fmt.Fprintf(os.Stderr, "export email-domain-overwrite: %s\n", o.EmailDomainRewrite)
		}
		if o.EmailTemplate != "" {
			fmt.Fprintf(os.Stderr, "export email-template: %s\n", o.EmailTemplate)
		}
		if o.ActiveOnly {
			fmt.Fprintf(os.Stderr, "export active-only: true\n")
		}
		if o.TerminatedSubscriptions {
			fmt.Fprintf(os.Stderr, "export terminated-subscriptions: true\n")
		}
	}

	fmt.Fprintf(os.Stderr, "\nobjects to import:\n")
	for _, name := range importTypeOrder {
		if !shouldImport(name) {
			continue
		}
		info := manifest.Files[name]
		status := fmt.Sprintf("%d records", info.Count)
		if name == "subscriptions" && !canImportSubs {
			status += " (SKIPPED — no payment methods)"
		}
		fmt.Fprintf(os.Stderr, "  %-18s %s\n", name, status)
	}

	if rewriter != nil {
		fmt.Fprintf(os.Stderr, "\nimport email rewriting: enabled\n")
	}
	if isConnectPlatform && applicationFees {
		if appFeeOverride != nil {
			fmt.Fprintf(os.Stderr, "application fee: %.2f%% (override)\n", *appFeeOverride)
		} else {
			fmt.Fprintf(os.Stderr, "application fee: retained from export data\n")
		}
	}

	if dryRun {
		fmt.Fprintf(os.Stderr, "\n--- END DRY RUN ---\n\n")
	} else {
		fmt.Fprintf(os.Stderr, "\n---\n\n")
	}
}

// --- validation ---

func validateImportData(opts importOptions, manifest *exportManifest, shouldImport func(string) bool, tick func()) []importValidationError {
	var errs []importValidationError

	for _, name := range importTypeOrder {
		if !shouldImport(name) {
			continue
		}
		info := manifest.Files[name]
		if !info.Complete {
			errs = append(errs, importValidationError{name, "", "export is incomplete — run 'stripe export' to complete it before importing"})
		}
	}

	productIDs := make(map[string]bool)
	couponIDs := make(map[string]bool)

	if shouldImport("products") {
		reader, err := util.NewJSONLFileReader[stripe.Product](filepath.Join(opts.inputDir, "products.jsonl"))
		if err != nil {
			errs = append(errs, importValidationError{"products", "", err.Error()})
		} else {
			for prod, err := range reader.All() {
				tick()
				if err != nil {
					errs = append(errs, importValidationError{"products", "", fmt.Sprintf("parse error: %v", err)})
					break
				}
				if prod.ID == "" {
					errs = append(errs, importValidationError{"products", "", "product with empty ID"})
					continue
				}
				if prod.Name == "" {
					errs = append(errs, importValidationError{"products", prod.ID, "missing name"})
				}
				productIDs[prod.ID] = true
			}
			reader.Close()
		}
	}

	if shouldImport("prices") {
		reader, err := util.NewJSONLFileReader[stripe.Price](filepath.Join(opts.inputDir, "prices.jsonl"))
		if err != nil {
			errs = append(errs, importValidationError{"prices", "", err.Error()})
		} else {
			for p, err := range reader.All() {
				tick()
				if err != nil {
					errs = append(errs, importValidationError{"prices", "", fmt.Sprintf("parse error: %v", err)})
					break
				}
				if p.ID == "" {
					errs = append(errs, importValidationError{"prices", "", "price with empty ID"})
					continue
				}
				if p.Product == nil || p.Product.ID == "" {
					errs = append(errs, importValidationError{"prices", p.ID, "missing product reference"})
				} else if shouldImport("products") && !productIDs[p.Product.ID] {
					errs = append(errs, importValidationError{"prices", p.ID, fmt.Sprintf("references product %s not found in products.jsonl", p.Product.ID)})
				}
				if p.Currency == "" {
					errs = append(errs, importValidationError{"prices", p.ID, "missing currency"})
				}
			}
			reader.Close()
		}
	}

	if shouldImport("coupons") {
		reader, err := util.NewJSONLFileReader[stripe.Coupon](filepath.Join(opts.inputDir, "coupons.jsonl"))
		if err != nil {
			errs = append(errs, importValidationError{"coupons", "", err.Error()})
		} else {
			for c, err := range reader.All() {
				tick()
				if err != nil {
					errs = append(errs, importValidationError{"coupons", "", fmt.Sprintf("parse error: %v", err)})
					break
				}
				if c.ID == "" {
					errs = append(errs, importValidationError{"coupons", "", "coupon with empty ID"})
					continue
				}
				if c.AmountOff == 0 && c.PercentOff == 0 {
					errs = append(errs, importValidationError{"coupons", c.ID, "missing amount_off or percent_off"})
				}
				couponIDs[c.ID] = true
			}
			reader.Close()
		}
	}

	if shouldImport("promotion-codes") {
		reader, err := util.NewJSONLFileReader[stripe.PromotionCode](filepath.Join(opts.inputDir, "promotion_codes.jsonl"))
		if err != nil {
			errs = append(errs, importValidationError{"promotion-codes", "", err.Error()})
		} else {
			for pc, err := range reader.All() {
				tick()
				if err != nil {
					errs = append(errs, importValidationError{"promotion-codes", "", fmt.Sprintf("parse error: %v", err)})
					break
				}
				if pc.Coupon == nil || pc.Coupon.ID == "" {
					errs = append(errs, importValidationError{"promotion-codes", pc.ID, "missing coupon reference"})
				} else if shouldImport("coupons") && !couponIDs[pc.Coupon.ID] {
					errs = append(errs, importValidationError{"promotion-codes", pc.ID, fmt.Sprintf("references coupon %s not found in coupons.jsonl", pc.Coupon.ID)})
				}
			}
			reader.Close()
		}
	}

	if shouldImport("customers") {
		reader, err := util.NewJSONLFileReader[stripe.Customer](filepath.Join(opts.inputDir, "customers.jsonl"))
		if err != nil {
			errs = append(errs, importValidationError{"customers", "", err.Error()})
		} else {
			for c, err := range reader.All() {
				tick()
				if err != nil {
					errs = append(errs, importValidationError{"customers", "", fmt.Sprintf("parse error: %v", err)})
					break
				}
				if c.ID == "" {
					errs = append(errs, importValidationError{"customers", "", "customer with empty ID"})
				}
			}
			reader.Close()
		}
	}

	if shouldImport("subscriptions") {
		reader, err := util.NewJSONLFileReader[stripe.Subscription](filepath.Join(opts.inputDir, "subscriptions.jsonl"))
		if err != nil {
			errs = append(errs, importValidationError{"subscriptions", "", err.Error()})
		} else {
			for sub, err := range reader.All() {
				tick()
				if err != nil {
					errs = append(errs, importValidationError{"subscriptions", "", fmt.Sprintf("parse error: %v", err)})
					break
				}
				if sub.ID == "" {
					errs = append(errs, importValidationError{"subscriptions", "", "subscription with empty ID"})
					continue
				}
				if sub.Customer == nil || sub.Customer.ID == "" {
					errs = append(errs, importValidationError{"subscriptions", sub.ID, "missing customer reference"})
				}
				if sub.Items == nil || len(sub.Items.Data) == 0 {
					errs = append(errs, importValidationError{"subscriptions", sub.ID, "no subscription items"})
				}
			}
			reader.Close()
		}
	}

	return errs
}

// --- import functions ---
// Each function computes a SHA-256 hash of the source record. Records already
// in the store with a matching hash are skipped. Records with a different hash
// are updated via the Stripe Update API. New records are created.

func importProducts(opts importOptions, store *idMapStore, total int) (int, int, error) {
	bar := newImportProgressBar(total, "Importing products")

	reader, err := util.NewJSONLFileReader[stripe.Product](filepath.Join(opts.inputDir, "products.jsonl"))
	if err != nil {
		return 0, 0, err
	}
	defer reader.Close()

	errCount := 0
	for prod, err := range reader.All() {
		if err != nil {
			return errCount, 0, err
		}
		if opts.ctx.Err() != nil {
			break
		}
		bar.Add(1)

		hash := recordHash(prod)
		mappedID, storedHash, found := store.Get(prod.ID)
		if found && storedHash == hash {
			continue
		}
		if found && !opts.updateExisting {
			continue
		}

		params := &stripe.ProductParams{
			Name:   stripe.String(prod.Name),
			Active: stripe.Bool(prod.Active), Metadata: importMetadata(prod.Metadata, "product_id", prod.ID, opts.importTime),
			Shippable: &prod.Shippable, StatementDescriptor: ptr.NilString(prod.StatementDescriptor),
			UnitLabel: ptr.NilString(prod.UnitLabel), URL: ptr.NilString(prod.URL),
		}
		if prod.TaxCode != nil && prod.TaxCode.ID != "" {
			params.TaxCode = stripe.String(prod.TaxCode.ID)
		}
		if prod.Description != "" {
			params.Description = stripe.String(prod.Description)
		}
		if len(prod.Images) > 0 {
			params.Images = stripe.StringSlice(prod.Images)
		}

		var newProd *stripe.Product
		if found {
			newProd, err = stripeproduct.Update(mappedID, params)
		} else {
			params.ID = stripe.String(prod.ID)
			newProd, err = stripeproduct.New(params)
			if isAlreadyExists(err) {
				newProd, err = stripeproduct.Update(prod.ID, params)
			}
		}
		if err != nil {
			errCount++
			if opts.abortOnError {
				bar.Finish()
				return errCount, 0, fmt.Errorf("product %s: %w", prod.ID, err)
			}
			op := "create"
			if found {
				op = "update"
			}
			importWarnf(bar, "failed to %s product %s: %v", op, prod.ID, err)
			continue
		}

		store.Put(prod.ID, newProd.ID, hash)
	}

	bar.Finish()
	fmt.Fprintf(os.Stderr, "imported %d products\n", store.Count())
	return errCount, 0, nil
}

func importPrices(opts importOptions, productStore, store *idMapStore, total int) (int, int, error) {
	bar := newImportProgressBar(total, "Importing prices")

	reader, err := util.NewJSONLFileReader[stripe.Price](filepath.Join(opts.inputDir, "prices.jsonl"))
	if err != nil {
		return 0, 0, err
	}
	defer reader.Close()

	errCount := 0
	for p, err := range reader.All() {
		if err != nil {
			return errCount, 0, err
		}
		if opts.ctx.Err() != nil {
			break
		}
		bar.Add(1)

		hash := recordHash(p)
		mappedID, storedHash, found := store.Get(p.ID)
		if found && storedHash == hash {
			continue
		}
		if found && !opts.updateExisting {
			continue
		}

		// prices are mostly immutable — updates can only change active/metadata/nickname
		if found {
			_, err := stripeprice.Update(mappedID, &stripe.PriceParams{
				Active:   stripe.Bool(p.Active),
				Metadata: importMetadata(p.Metadata, "price_id", p.ID, opts.importTime),
				Nickname: ptr.NilString(p.Nickname),
			})
			if err != nil {
				errCount++
				if opts.abortOnError {
					bar.Finish()
					return errCount, 0, fmt.Errorf("price %s: %w", p.ID, err)
				}
				importWarnf(bar, "failed to update price %s: %v", p.ID, err)
			}
			store.Put(p.ID, mappedID, hash)
			continue
		}

		productID := ""
		if p.Product != nil {
			newProdID, _, ok := productStore.Get(p.Product.ID)
			if ok {
				productID = newProdID
			} else {
				productID = p.Product.ID
			}
		}

		params := &stripe.PriceParams{
			Currency: stripe.String(string(p.Currency)), Product: stripe.String(productID),
			Active: stripe.Bool(p.Active), Metadata: importMetadata(p.Metadata, "price_id", p.ID, opts.importTime),
			UnitAmount: stripe.Int64(p.UnitAmount), Nickname: ptr.NilString(p.Nickname),
		}
		if p.BillingScheme == stripe.PriceBillingSchemeTiered {
			params.BillingScheme = stripe.String(string(p.BillingScheme))
			params.TiersMode = stripe.String(string(p.TiersMode))
		}
		if p.Recurring != nil {
			params.Recurring = &stripe.PriceRecurringParams{
				Interval: stripe.String(string(p.Recurring.Interval)), IntervalCount: stripe.Int64(p.Recurring.IntervalCount),
			}
			if p.Recurring.UsageType == stripe.PriceRecurringUsageTypeMetered {
				params.Recurring.UsageType = stripe.String(string(p.Recurring.UsageType))
			}
		}
		if len(p.CurrencyOptions) > 0 {
			params.CurrencyOptions = make(map[string]*stripe.PriceCurrencyOptionsParams)
			for cur, opt := range p.CurrencyOptions {
				if strings.EqualFold(cur, string(p.Currency)) {
					continue
				}
				params.CurrencyOptions[cur] = &stripe.PriceCurrencyOptionsParams{UnitAmount: stripe.Int64(opt.UnitAmount)}
			}
		}
		if p.TaxBehavior != "" {
			params.TaxBehavior = stripe.String(string(p.TaxBehavior))
		}

		newPrice, err := stripeprice.New(params)
		if err != nil {
			errCount++
			if opts.abortOnError {
				bar.Finish()
				return errCount, 0, fmt.Errorf("price %s: %w", p.ID, err)
			}
			importWarnf(bar, "failed to create price %s: %v", p.ID, err)
			continue
		}

		store.Put(p.ID, newPrice.ID, hash)
	}

	bar.Finish()
	fmt.Fprintf(os.Stderr, "imported %d prices\n", store.Count())
	return errCount, 0, nil
}

func importCoupons(opts importOptions, store *idMapStore, total int) (int, int, error) {
	bar := newImportProgressBar(total, "Importing coupons")

	reader, err := util.NewJSONLFileReader[stripe.Coupon](filepath.Join(opts.inputDir, "coupons.jsonl"))
	if err != nil {
		return 0, 0, err
	}
	defer reader.Close()

	errCount := 0
	for c, err := range reader.All() {
		if err != nil {
			return errCount, 0, err
		}
		if opts.ctx.Err() != nil {
			break
		}
		bar.Add(1)

		hash := recordHash(c)
		mappedID, storedHash, found := store.Get(c.ID)
		if found && storedHash == hash {
			continue
		}
		if found && !opts.updateExisting {
			continue
		}

		if found {
			_, err := stripecoupon.Update(mappedID, &stripe.CouponParams{
				Metadata: importMetadata(c.Metadata, "coupon_id", c.ID, opts.importTime),
				Name:     ptr.NilString(c.Name),
			})
			if err != nil {
				errCount++
				if opts.abortOnError {
					bar.Finish()
					return errCount, 0, fmt.Errorf("coupon %s: %w", c.ID, err)
				}
				importWarnf(bar, "failed to update coupon %s: %v", c.ID, err)
			}
			store.Put(c.ID, mappedID, hash)
			continue
		}

		params := &stripe.CouponParams{
			Duration: stripe.String(string(c.Duration)),
			Metadata: importMetadata(c.Metadata, "coupon_id", c.ID, opts.importTime),
			Name:     ptr.NilString(c.Name),
		}
		if c.AmountOff > 0 {
			params.AmountOff = stripe.Int64(c.AmountOff)
			params.Currency = stripe.String(string(c.Currency))
		} else if c.PercentOff > 0 {
			params.PercentOff = stripe.Float64(c.PercentOff)
		}
		if c.Duration == stripe.CouponDurationRepeating {
			params.DurationInMonths = stripe.Int64(c.DurationInMonths)
		}
		if c.MaxRedemptions > 0 {
			params.MaxRedemptions = stripe.Int64(c.MaxRedemptions)
		}
		if len(c.CurrencyOptions) > 0 {
			params.CurrencyOptions = make(map[string]*stripe.CouponCurrencyOptionsParams)
			for cur, opt := range c.CurrencyOptions {
				if strings.EqualFold(cur, string(c.Currency)) {
					continue
				}
				params.CurrencyOptions[cur] = &stripe.CouponCurrencyOptionsParams{AmountOff: stripe.Int64(opt.AmountOff)}
			}
		}

		newCoupon, err := stripecoupon.New(params)
		if err != nil {
			errCount++
			if opts.abortOnError {
				bar.Finish()
				return errCount, 0, fmt.Errorf("coupon %s: %w", c.ID, err)
			}
			importWarnf(bar, "failed to create coupon %s: %v", c.ID, err)
			continue
		}

		store.Put(c.ID, newCoupon.ID, hash)
	}

	bar.Finish()
	fmt.Fprintf(os.Stderr, "imported %d coupons\n", store.Count())
	return errCount, 0, nil
}

func importPromotionCodes(opts importOptions, couponStore, store *idMapStore, total int) (int, int, error) {
	bar := newImportProgressBar(total, "Importing promotion codes")

	reader, err := util.NewJSONLFileReader[stripe.PromotionCode](filepath.Join(opts.inputDir, "promotion_codes.jsonl"))
	if err != nil {
		return 0, 0, err
	}
	defer reader.Close()

	errCount := 0
	for pc, err := range reader.All() {
		if err != nil {
			return errCount, 0, err
		}
		if opts.ctx.Err() != nil {
			break
		}
		bar.Add(1)

		hash := recordHash(pc)
		mappedID, storedHash, found := store.Get(pc.ID)
		if found && storedHash == hash {
			continue
		}
		if found && !opts.updateExisting {
			continue
		}

		if found {
			_, err := stripepromo.Update(mappedID, &stripe.PromotionCodeParams{
				Active:   stripe.Bool(pc.Active),
				Metadata: importMetadata(pc.Metadata, "promotion_code_id", pc.ID, opts.importTime),
			})
			if err != nil {
				errCount++
				if opts.abortOnError {
					bar.Finish()
					return errCount, 0, fmt.Errorf("promotion code %s: %w", pc.ID, err)
				}
				importWarnf(bar, "failed to update promotion code %s: %v", pc.ID, err)
			}
			store.Put(pc.ID, mappedID, hash)
			continue
		}

		couponID := ""
		if pc.Coupon != nil {
			newCouponID, _, ok := couponStore.Get(pc.Coupon.ID)
			if ok {
				couponID = newCouponID
			} else {
				couponID = pc.Coupon.ID
			}
		}

		params := &stripe.PromotionCodeParams{
			Coupon: stripe.String(couponID), Code: stripe.String(pc.Code),
			Active: stripe.Bool(pc.Active), Metadata: importMetadata(pc.Metadata, "promotion_code_id", pc.ID, opts.importTime),
		}
		if pc.MaxRedemptions > 0 {
			params.MaxRedemptions = stripe.Int64(pc.MaxRedemptions)
		}

		newPC, err := stripepromo.New(params)
		if err != nil {
			errCount++
			if opts.abortOnError {
				bar.Finish()
				return errCount, 0, fmt.Errorf("promotion code %s: %w", pc.ID, err)
			}
			importWarnf(bar, "failed to create promotion code %s: %v", pc.ID, err)
			continue
		}

		store.Put(pc.ID, newPC.ID, hash)
	}

	bar.Finish()
	fmt.Fprintf(os.Stderr, "imported %d promotion codes\n", store.Count())
	return errCount, 0, nil
}

func importCustomers(opts importOptions, couponStore, store *idMapStore, total int) (int, int, error) {
	bar := newImportProgressBar(total, "Importing customers")

	reader, err := util.NewJSONLFileReader[stripe.Customer](filepath.Join(opts.inputDir, "customers.jsonl"))
	if err != nil {
		return 0, 0, err
	}
	defer reader.Close()

	var (
		mu       sync.Mutex
		wg       sync.WaitGroup
		sem      = make(chan struct{}, opts.workers)
		abort    error
		errCount int
		imported int
	)

	for c, err := range reader.All() {
		if err != nil {
			return errCount, 0, err
		}
		if opts.ctx.Err() != nil {
			break
		}
		bar.Add(1)

		hash := recordHash(c)
		_, storedHash, found := store.Get(c.ID)
		if found && storedHash == hash {
			continue
		}
		if found && !opts.updateExisting {
			continue
		}

		mu.Lock()
		if abort != nil {
			mu.Unlock()
			break
		}
		mu.Unlock()

		originalEmail := c.Email
		rewriteCustomerEmails(&c, opts.rewriter)

		if err := opts.limiter.Wait(opts.ctx); err != nil {
			return errCount, 0, err
		}

		wg.Add(1)
		sem <- struct{}{}

		go func(c stripe.Customer, isUpdate bool, hash, originalEmail string) {
			defer wg.Done()
			defer func() { <-sem }()

			metadata := importMetadata(c.Metadata, "customer_id", c.ID, opts.importTime)
			if opts.rewriter != nil && originalEmail != "" {
				metadata["atomic:import:customer_email"] = originalEmail
			}

			params := &stripe.CustomerParams{
				Email: ptr.NilString(c.Email), Name: ptr.NilString(c.Name),
				Description: ptr.NilString(c.Description), Phone: ptr.NilString(c.Phone),
				Metadata: metadata,
			}
			if c.Address != nil {
				params.Address = &stripe.AddressParams{
					City: ptr.NilString(c.Address.City), Country: ptr.NilString(c.Address.Country),
					Line1: ptr.NilString(c.Address.Line1), Line2: ptr.NilString(c.Address.Line2),
					PostalCode: ptr.NilString(c.Address.PostalCode), State: ptr.NilString(c.Address.State),
				}
			}
			if c.Shipping != nil && c.Shipping.Name != "" && c.Shipping.Address != nil &&
				(c.Shipping.Address.Line1 != "" || c.Shipping.Address.City != "" || c.Shipping.Address.Country != "" ||
					c.Shipping.Address.PostalCode != "" || c.Shipping.Address.State != "") {
				params.Shipping = &stripe.CustomerShippingParams{
					Name:  stripe.String(c.Shipping.Name),
					Phone: ptr.NilString(c.Shipping.Phone),
					Address: &stripe.AddressParams{
						City: ptr.NilString(c.Shipping.Address.City), Country: ptr.NilString(c.Shipping.Address.Country),
						Line1: ptr.NilString(c.Shipping.Address.Line1), Line2: ptr.NilString(c.Shipping.Address.Line2),
						PostalCode: ptr.NilString(c.Shipping.Address.PostalCode), State: ptr.NilString(c.Shipping.Address.State),
					},
				}
			}

			var newCust *stripe.Customer
			err := retryOnRateLimit(opts.ctx, func() error {
				var e error
				if isUpdate {
					mappedID, _, _ := store.Get(c.ID)
					newCust, e = stripecustomer.Update(mappedID, params)
				} else {
					newCust, e = stripecustomer.New(params)
				}
				return e
			})
			if err != nil {
				mu.Lock()
				errCount++
				mu.Unlock()
				if opts.abortOnError {
					mu.Lock()
					if abort == nil {
						abort = fmt.Errorf("customer %s: %w", c.ID, err)
					}
					mu.Unlock()
					return
				}
				op := "create"
				if isUpdate {
					op = "update"
				}
				importWarnf(bar, "failed to %s customer %s: %v", op, c.ID, err)
				return
			}

			// Attach test card, set it as default payment method, and apply
			// discount in as few API calls as possible.
			var attachedPM string
			if opts.createTestCards && !isUpdate {
				cardID := resolveTestCard(opts, string(c.Currency))
				if err := opts.limiter.Wait(opts.ctx); err != nil {
					return
				}
				pm, err := paymentmethod.Attach(cardID, &stripe.PaymentMethodAttachParams{Customer: stripe.String(newCust.ID)})
				if err != nil {
					importWarnf(bar, "failed to attach test card to customer %s: %v", newCust.ID, err)
				} else {
					attachedPM = pm.ID
					store.PutCard(newCust.ID, pm.ID)
				}
			}

			// Single update for default payment method + coupon
			needsUpdate := attachedPM != "" || (c.Discount != nil && c.Discount.Coupon != nil && c.Discount.Coupon.ID != "")
			if needsUpdate {
				updateParams := &stripe.CustomerParams{}
				if attachedPM != "" {
					updateParams.InvoiceSettings = &stripe.CustomerInvoiceSettingsParams{DefaultPaymentMethod: stripe.String(attachedPM)}
				}
				if c.Discount != nil && c.Discount.Coupon != nil && c.Discount.Coupon.ID != "" {
					newCouponID, _, ok := couponStore.Get(c.Discount.Coupon.ID)
					if !ok {
						newCouponID = c.Discount.Coupon.ID
					}
					updateParams.Coupon = stripe.String(newCouponID)
				}
				if err := opts.limiter.Wait(opts.ctx); err != nil {
					return
				}
				_, err := stripecustomer.Update(newCust.ID, updateParams)
				if err != nil {
					importWarnf(bar, "failed to update customer %s (payment method / discount): %v", newCust.ID, err)
				}
			}

			store.Put(c.ID, newCust.ID, hash)

			mu.Lock()
			imported++
			if imported%flushInterval == 0 {
				store.Sync()
				opts.stateMu.Lock()
				opts.state.Types["customers"] = importTypeState{SourceMD5: opts.state.Types["customers"].SourceMD5, Count: store.Count(), Errors: errCount}
				opts.state.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
				writeImportStateAtomic(opts.inputDir, opts.state)
				opts.stateMu.Unlock()
			}
			mu.Unlock()
		}(c, found, hash, originalEmail)
	}

	wg.Wait()
	bar.Finish()

	if abort != nil {
		return errCount, 0, abort
	}

	fmt.Fprintf(os.Stderr, "imported %d customers\n", store.Count())
	return errCount, 0, nil
}

func importSubscriptions(opts importOptions, custStore, priceStore, couponStore, store *idMapStore, total int) (int, int, error) {
	bar := newImportProgressBar(total, "Importing subscriptions")

	reader, err := util.NewJSONLFileReader[stripe.Subscription](filepath.Join(opts.inputDir, "subscriptions.jsonl"))
	if err != nil {
		return 0, 0, err
	}
	defer reader.Close()

	var (
		mu              sync.Mutex
		wg              sync.WaitGroup
		sem             = make(chan struct{}, opts.workers)
		abort           error
		errCount        int
		imported        int
		skippedStatus   = make(map[string]int)
		convertedTrials int
		shiftedTrials   int
	)

	for sub, err := range reader.All() {
		if err != nil {
			return errCount, 0, err
		}
		if opts.ctx.Err() != nil {
			break
		}
		bar.Add(1)

		switch sub.Status {
		case stripe.SubscriptionStatusActive, stripe.SubscriptionStatusTrialing:
			// importable
		case stripe.SubscriptionStatusPastDue:
			if !opts.pastDueSubscriptions {
				skippedStatus[string(sub.Status)]++
				continue
			}
		case stripe.SubscriptionStatusPaused, stripe.SubscriptionStatusCanceled,
			stripe.SubscriptionStatusUnpaid, stripe.SubscriptionStatusIncomplete,
			stripe.SubscriptionStatusIncompleteExpired:
			skippedStatus[string(sub.Status)]++
			continue
		default:
			skippedStatus[string(sub.Status)]++
			continue
		}

		hash := recordHash(sub)
		if _, storedHash, found := store.Get(sub.ID); found && storedHash == hash {
			continue
		}

		// subscriptions are not updated — too complex to diff safely
		if store.Has(sub.ID) {
			continue
		}

		mu.Lock()
		if abort != nil {
			mu.Unlock()
			break
		}
		mu.Unlock()

		newCustomerID, _, ok := custStore.Get(sub.Customer.ID)
		if !ok {
			newCustomerID = sub.Customer.ID
		}

		var items []*stripe.SubscriptionItemsParams
		for _, item := range sub.Items.Data {
			if item.Price == nil {
				continue
			}
			newPriceID, _, ok := priceStore.Get(item.Price.ID)
			if !ok {
				newPriceID = item.Price.ID
			}
			items = append(items, &stripe.SubscriptionItemsParams{Price: stripe.String(newPriceID), Quantity: stripe.Int64(item.Quantity)})
		}
		if len(items) == 0 {
			continue
		}

		params := &stripe.SubscriptionParams{
			Customer: stripe.String(newCustomerID), Items: items,
			Metadata: importMetadata(sub.Metadata, "subscription_id", sub.ID, opts.importTime),
		}

		isPastDue := sub.Status == stripe.SubscriptionStatusPastDue
		isExpiredTrial := sub.Status == stripe.SubscriptionStatusTrialing && sub.TrialEnd > 0 && sub.TrialEnd <= time.Now().Unix()
		isActiveTrial := sub.Status == stripe.SubscriptionStatusTrialing && sub.TrialEnd > 0 && sub.TrialEnd > time.Now().Unix()

		// handle expired trials
		if isExpiredTrial {
			if opts.dropExpiredTrials {
				// shift the trial forward preserving its original duration
				trialDuration := sub.TrialEnd - sub.TrialStart
				if trialDuration <= 0 {
					trialDuration = 7 * 24 * 3600 // fallback: 7 days
				}
				params.TrialEnd = stripe.Int64(time.Now().Unix() + trialDuration)
				shiftedTrials++
			} else {
				// --drop-expired-trials=false: convert to active subscription
				convertedTrials++
			}
		}

		if isActiveTrial {
			params.TrialEnd = stripe.Int64(sub.TrialEnd)
		}

		// Backdate to original creation date and set billing_cycle_anchor to the
		// source's current_period_end so that period dates and next invoice match
		// the export exactly.  Skip for shifted expired trials (new trial replaces
		// the original dates) and active trials (trial_end governs billing, but we
		// still backdate the start).
		if !(isExpiredTrial && opts.dropExpiredTrials) {
			params.BackdateStartDate = stripe.Int64(sub.Created)

			if !isActiveTrial && sub.CurrentPeriodEnd > 0 {
				anchor := sub.CurrentPeriodEnd
				now := time.Now().Unix()
				if anchor > now {
					params.BillingCycleAnchor = stripe.Int64(anchor)
				} else {
					// period end in the past — advance by one interval at a time
					interval := sub.CurrentPeriodEnd - sub.CurrentPeriodStart
					if interval <= 0 {
						interval = 30 * 24 * 3600 // fallback: 30 days
					}
					for anchor <= now {
						anchor += interval
					}
					params.BillingCycleAnchor = stripe.Int64(anchor)
				}
			}
		}

		if opts.prorateSubscriptions {
			params.ProrationBehavior = stripe.String("create_prorations")
		} else {
			params.ProrationBehavior = stripe.String("none")
		}

		// For past_due: use allow_incomplete so the subscription is created even
		// when the invoice payment fails.  The declining test card is attached
		// inside the worker goroutine before creating the subscription.
		if isPastDue {
			params.PaymentBehavior = stripe.String("allow_incomplete")
			params.Metadata["atomic:import:original_status"] = "past_due"
		} else {
			if pmID, ok := custStore.GetCard(newCustomerID); ok {
				params.DefaultPaymentMethod = stripe.String(pmID)
			}
		}
		if opts.applicationFees && opts.isConnectPlatform {
			if opts.applicationFeeOverride != nil {
				params.ApplicationFeePercent = stripe.Float64(*opts.applicationFeeOverride)
			} else if sub.ApplicationFeePercent > 0 {
				params.ApplicationFeePercent = stripe.Float64(sub.ApplicationFeePercent)
			}
		}
		if opts.onBehalfOf != "" {
			params.OnBehalfOf = stripe.String(opts.onBehalfOf)
		}
		if sub.Discount != nil && sub.Discount.Coupon != nil && sub.Discount.Coupon.ID != "" {
			newCouponID, _, ok := couponStore.Get(sub.Discount.Coupon.ID)
			if !ok {
				newCouponID = sub.Discount.Coupon.ID
			}
			params.Coupon = stripe.String(newCouponID)
		}

		// preserve cancellation state
		if sub.CancelAtPeriodEnd {
			params.CancelAtPeriodEnd = stripe.Bool(true)
		} else if sub.CancelAt > 0 {
			if sub.CancelAt <= time.Now().Unix() {
				skippedStatus["canceled"]++
				continue
			}
			params.CancelAt = stripe.Int64(sub.CancelAt)
		}

		if err := opts.limiter.Wait(opts.ctx); err != nil {
			return errCount, 0, err
		}

		wg.Add(1)
		sem <- struct{}{}

		go func(sub stripe.Subscription, params *stripe.SubscriptionParams, hash string, isPastDue bool) {
			defer wg.Done()
			defer func() { <-sem }()

			// For past_due subs, attach a declining test card so the first
			// invoice payment fails and Stripe transitions the sub to past_due.
			if isPastDue {
				if err := opts.limiter.Wait(opts.ctx); err != nil {
					return
				}
				pm, err := paymentmethod.Attach("pm_card_visa_chargeDeclined", &stripe.PaymentMethodAttachParams{
					Customer: params.Customer,
				})
				if err != nil {
					importWarnf(bar, "failed to attach declining card for past_due sub %s: %v", sub.ID, err)
					return
				}
				params.DefaultPaymentMethod = stripe.String(pm.ID)
			}

			var newSub *stripe.Subscription
			err := retryOnRateLimit(opts.ctx, func() error {
				var e error
				newSub, e = stripesub.New(params)
				return e
			})
			if err != nil {
				mu.Lock()
				errCount++
				mu.Unlock()
				if opts.abortOnError {
					mu.Lock()
					if abort == nil {
						abort = fmt.Errorf("subscription %s: %w", sub.ID, err)
					}
					mu.Unlock()
					return
				}
				importWarnf(bar, "failed to create subscription %s: %v", sub.ID, err)
				return
			}

			store.Put(sub.ID, newSub.ID, hash)

			mu.Lock()
			imported++
			if imported%flushInterval == 0 {
				store.Sync()
				opts.stateMu.Lock()
				opts.state.Types["subscriptions"] = importTypeState{SourceMD5: opts.state.Types["subscriptions"].SourceMD5, Count: store.Count(), Errors: errCount}
				opts.state.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
				writeImportStateAtomic(opts.inputDir, opts.state)
				opts.stateMu.Unlock()
			}
			mu.Unlock()
		}(sub, params, hash, isPastDue)
	}

	wg.Wait()
	bar.Finish()

	totalSkipped := 0
	for _, count := range skippedStatus {
		totalSkipped += count
	}

	if abort != nil {
		return errCount, totalSkipped, abort
	}

	fmt.Fprintf(os.Stderr, "imported %d subscriptions\n", store.Count())
	if shiftedTrials > 0 {
		fmt.Fprintf(os.Stderr, "  shifted %d expired trials forward with original duration\n", shiftedTrials)
	}
	if convertedTrials > 0 {
		fmt.Fprintf(os.Stderr, "  converted %d expired trials to active subscriptions\n", convertedTrials)
	}
	if len(skippedStatus) > 0 {
		for status, count := range skippedStatus {
			fmt.Fprintf(os.Stderr, "  skipped %d %s subscriptions\n", count, status)
		}
	}
	return errCount, totalSkipped, nil
}
