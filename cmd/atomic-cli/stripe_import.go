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
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/apex/log"
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
)

type (
	importOptions struct {
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
		retainBillingAnchor    bool
		prorateSubscriptions   bool
	}

	importValidationError struct {
		Type    string
		ID      string
		Message string
	}
)

var (
	testCardByCurrency = map[string]string{
		"usd": "pm_card_us",
		"gbp": "pm_card_gb",
		"eur": "pm_card_de",
		"cad": "pm_card_ca",
		"aud": "pm_card_au",
		"jpy": "pm_card_jp",
		"sgd": "pm_card_sg",
		"hkd": "pm_card_hk",
		"nzd": "pm_card_nz",
		"chf": "pm_card_ch",
		"brl": "pm_card_br",
		"mxn": "pm_card_mx",
		"inr": "pm_card_in",
		"sek": "pm_card_se",
		"nok": "pm_card_no",
		"dkk": "pm_card_dk",
		"pln": "pm_card_pl",
		"czk": "pm_card_cz",
		"ron": "pm_card_ro",
		"bgn": "pm_card_bg",
		"huf": "pm_card_hu",
		"thb": "pm_card_th",
		"myr": "pm_card_my",
	}

	stripeImportCmd = &cli.Command{
		Name:   "import",
		Usage:  "import stripe data from an export directory",
		Action: stripeImport,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     "input",
				Aliases:  []string{"i"},
				Usage:    "path to the export directory (containing manifest.json)",
				Required: true,
			},
			&cli.StringSliceFlag{
				Name:    "types",
				Aliases: []string{"t"},
				Usage:   "object types to import: products, prices, customers, subscriptions, coupons, promotion-codes, or all",
				Value:   []string{"all"},
			},
			&cli.BoolFlag{
				Name:  "validate",
				Usage: "validate export data before importing (checks referential integrity, required fields)",
				Value: true,
			},
			&cli.BoolFlag{
				Name:  "dry-run",
				Usage: "report what would be imported without making any changes",
			},
			&cli.StringFlag{
				Name:  "email-domain-overwrite",
				Usage: "rewrite customer email addresses to use this domain; mutually exclusive with --email-template",
			},
			&cli.StringFlag{
				Name:  "email-template",
				Usage: "generate customer email addresses from a template; mutually exclusive with --email-domain-overwrite",
			},
			&cli.BoolFlag{
				Name:  "application-fees",
				Usage: "retain application fees from exported subscriptions (requires Connect platform); set to false to ignore",
				Value: true,
			},
			&cli.Float64Flag{
				Name:  "application-fee-percent",
				Usage: "override application fee percentage for all subscriptions (requires Connect platform)",
			},
			&cli.StringFlag{
				Name:  "on-behalf-of",
				Usage: "connected account ID for on_behalf_of on subscriptions",
			},
			&cli.BoolFlag{
				Name:  "create-test-cards",
				Usage: "attach test payment methods to customers (test mode only)",
				Value: true,
			},
			&cli.StringFlag{
				Name:  "default-test-card",
				Usage: "override the auto-detected test card for all customers",
				Value: "pm_card_us",
			},
			&cli.BoolFlag{
				Name:  "retain-billing-anchor",
				Usage: "preserve billing_cycle_anchor from exported subscriptions",
				Value: true,
			},
			&cli.BoolFlag{
				Name:  "prorate-subscriptions",
				Usage: "prorate subscriptions on creation",
			},
			&cli.BoolFlag{
				Name:  "abort-on-error",
				Usage: "stop the entire import on the first failure",
			},
		},
	}
)

func stripeImport(_ context.Context, cmd *cli.Command) error {
	inputDir := cmd.String("input")
	acct := cmd.Root().Metadata["stripe_account"].(*stripe.Account)
	liveMode := !strings.HasPrefix(stripe.Key, "sk_test_") && !strings.HasPrefix(stripe.Key, "rk_test_")
	dryRun := cmd.Bool("dry-run")

	// detect connect platform account via controller type
	isConnectPlatform := acct.Controller != nil && acct.Controller.Type == stripe.AccountControllerTypeApplication
	if isConnectPlatform {
		fmt.Fprintf(os.Stderr, "detected Connect platform account (%s)\n", acct.ID)
	}

	// live mode confirmation
	if liveMode && !dryRun {
		fmt.Fprintf(os.Stderr, "WARNING: you are about to import into a LIVE Stripe account (%s)\n", acct.ID)
		fmt.Fprintf(os.Stderr, "type 'confirm livemode import' to proceed: ")

		reader := bufio.NewReader(os.Stdin)
		answer, err := reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("failed to read confirmation: %w", err)
		}

		if strings.TrimSpace(answer) != "confirm livemode import" {
			return fmt.Errorf("import aborted")
		}
	}

	// load and verify manifest
	manifest, err := loadManifest(inputDir)
	if err != nil {
		return fmt.Errorf("failed to load manifest from %s: %w", inputDir, err)
	}

	verifyManifestFiles(inputDir, manifest)

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

	// application fee handling
	applicationFees := cmd.Bool("application-fees")
	var appFeeOverride *float64
	if cmd.IsSet("application-fee-percent") {
		if !isConnectPlatform {
			return fmt.Errorf("--application-fee-percent requires a Connect platform account")
		}
		v := cmd.Float64("application-fee-percent")
		appFeeOverride = &v
	}

	// determine subscription import eligibility
	canImportSubs := true
	if liveMode {
		fmt.Fprintf(os.Stderr, "warning: live mode — subscriptions will be skipped (customers have no payment methods)\n")
		canImportSubs = false
	} else if !cmd.Bool("create-test-cards") {
		fmt.Fprintf(os.Stderr, "warning: --create-test-cards is disabled — subscriptions will be skipped\n")
		canImportSubs = false
	}

	opts := importOptions{
		inputDir:               inputDir,
		abortOnError:           cmd.Bool("abort-on-error"),
		rewriter:               rewriter,
		createTestCards:        cmd.Bool("create-test-cards") && !liveMode,
		defaultTestCard:        cmd.String("default-test-card"),
		applicationFees:        applicationFees,
		applicationFeeOverride: appFeeOverride,
		onBehalfOf:             cmd.String("on-behalf-of"),
		importSubscriptions:    canImportSubs,
		liveMode:               liveMode,
		isConnectPlatform:      isConnectPlatform,
		importTime:             time.Now().UTC().Format(time.RFC3339),
		dryRun:                 dryRun,
		retainBillingAnchor:    cmd.Bool("retain-billing-anchor"),
		prorateSubscriptions:   cmd.Bool("prorate-subscriptions"),
	}

	// determine which types to import
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
		if _, ok := manifest.Files[name]; !ok {
			return false
		}
		return true
	}

	// import report
	printImportReport(acct, manifest, shouldImport, canImportSubs, rewriter, isConnectPlatform, applicationFees, appFeeOverride, liveMode, dryRun)

	// validation pass
	if cmd.Bool("validate") {
		bar := newImportSpinner("Validating export data")
		validationErrors := validateImportData(opts, shouldImport, func() { bar.Add(1) })
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

	// confirmation prompt
	if !liveMode {
		fmt.Fprintf(os.Stderr, "proceed with import? [y/N]: ")
		reader := bufio.NewReader(os.Stdin)
		answer, err := reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("failed to read confirmation: %w", err)
		}
		answer = strings.TrimSpace(strings.ToLower(answer))
		if answer != "y" && answer != "yes" {
			return fmt.Errorf("import aborted")
		}
	}

	fmt.Fprintf(os.Stderr, "importing from %s (source account: %s)\n", inputDir, manifest.AccountID)

	// import in dependency order
	productIDMap := make(map[string]string)
	priceIDMap := make(map[string]string)
	couponIDMap := make(map[string]string)
	customerIDMap := make(map[string]string)
	customerCardMap := make(map[string]string)

	if shouldImport("products") {
		var err error
		productIDMap, err = importProducts(opts)
		if err != nil {
			return fmt.Errorf("failed to import products: %w", err)
		}
	}

	if shouldImport("prices") {
		var err error
		priceIDMap, err = importPrices(opts, productIDMap)
		if err != nil {
			return fmt.Errorf("failed to import prices: %w", err)
		}
	}

	if shouldImport("coupons") {
		var err error
		couponIDMap, err = importCoupons(opts)
		if err != nil {
			return fmt.Errorf("failed to import coupons: %w", err)
		}
	}

	if shouldImport("promotion-codes") {
		if err := importPromotionCodes(opts, couponIDMap); err != nil {
			return fmt.Errorf("failed to import promotion codes: %w", err)
		}
	}

	if shouldImport("customers") {
		var err error
		customerIDMap, customerCardMap, err = importCustomers(opts)
		if err != nil {
			return fmt.Errorf("failed to import customers: %w", err)
		}
	}

	if shouldImport("subscriptions") && opts.importSubscriptions {
		if err := importSubscriptions(opts, customerIDMap, priceIDMap, couponIDMap, customerCardMap); err != nil {
			return fmt.Errorf("failed to import subscriptions: %w", err)
		}
	} else if shouldImport("subscriptions") && !opts.importSubscriptions {
		fmt.Fprintf(os.Stderr, "skipping subscriptions (see warnings above)\n")
	}

	fmt.Fprintf(os.Stderr, "import complete\n")

	return nil
}

// validateImportData performs structural validation of export data without making API calls.
func printImportReport(
	acct *stripe.Account,
	manifest *exportManifest,
	shouldImport func(string) bool,
	canImportSubs bool,
	rewriter *emailRewriter,
	isConnectPlatform bool,
	applicationFees bool,
	appFeeOverride *float64,
	liveMode bool,
	dryRun bool,
) {
	if dryRun {
		fmt.Fprintf(os.Stderr, "\n--- DRY RUN ---\n")
	} else {
		fmt.Fprintf(os.Stderr, "\n--- IMPORT PLAN ---\n")
	}

	// key info (show prefix only)
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

	sourceName := manifest.AccountName
	if sourceName != "" {
		fmt.Fprintf(os.Stderr, "source account: %s (%s)\n", manifest.AccountID, sourceName)
	} else {
		fmt.Fprintf(os.Stderr, "source account: %s\n", manifest.AccountID)
	}

	fmt.Fprintf(os.Stderr, "source exported: %s\n", manifest.UpdatedAt)
	fmt.Fprintf(os.Stderr, "source livemode: %v\n", manifest.Livemode)
	fmt.Fprintf(os.Stderr, "target livemode: %v\n", liveMode)
	fmt.Fprintf(os.Stderr, "connect platform: %v\n", isConnectPlatform)

	// export options from manifest
	if manifest.Options != nil {
		opts := manifest.Options
		if opts.EmailDomainRewrite != "" {
			fmt.Fprintf(os.Stderr, "export email-domain-overwrite: %s\n", opts.EmailDomainRewrite)
		}
		if opts.EmailTemplate != "" {
			fmt.Fprintf(os.Stderr, "export email-template: %s\n", opts.EmailTemplate)
		}
		if opts.ActiveOnly {
			fmt.Fprintf(os.Stderr, "export active-only: true\n")
		}
	}

	fmt.Fprintf(os.Stderr, "\nobjects to import:\n")
	for _, name := range []string{"products", "prices", "coupons", "promotion-codes", "customers", "subscriptions"} {
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

func validateImportData(opts importOptions, shouldImport func(string) bool, tick func()) []importValidationError {
	var errs []importValidationError

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

func importMetadata(existing map[string]string, originalID, importTime string) map[string]string {
	m := make(map[string]string)
	for k, v := range existing {
		m[k] = v
	}
	m["atomic:import_time"] = importTime
	m["atomic:import_id"] = originalID
	return m
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

func importProducts(opts importOptions) (map[string]string, error) {
	idMap := make(map[string]string)
	bar := newImportSpinner("Importing products")

	reader, err := util.NewJSONLFileReader[stripe.Product](filepath.Join(opts.inputDir, "products.jsonl"))
	if err != nil {
		return nil, err
	}
	defer reader.Close()

	for prod, err := range reader.All() {
		if err != nil {
			return nil, err
		}

		bar.Add(1)

		params := &stripe.ProductParams{
			ID:                  stripe.String(prod.ID),
			Name:                stripe.String(prod.Name),
			Active:              stripe.Bool(prod.Active),
			Metadata:            importMetadata(prod.Metadata, prod.ID, opts.importTime),
			Shippable:           &prod.Shippable,
			StatementDescriptor: nilIfEmpty(prod.StatementDescriptor),
			UnitLabel:           nilIfEmpty(prod.UnitLabel),
			URL:                 nilIfEmpty(prod.URL),
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

		newProd, err := stripeproduct.New(params)
		if err != nil {
			if opts.abortOnError {
				bar.Finish()
				return nil, fmt.Errorf("product %s: %w", prod.ID, err)
			}
			log.Warnf("failed to create product %s: %v", prod.ID, err)
			continue
		}

		idMap[prod.ID] = newProd.ID
	}

	bar.Finish()
	fmt.Fprintf(os.Stderr, "imported %d products\n", len(idMap))
	return idMap, nil
}

func importPrices(opts importOptions, productIDMap map[string]string) (map[string]string, error) {
	idMap := make(map[string]string)
	bar := newImportSpinner("Importing prices")

	reader, err := util.NewJSONLFileReader[stripe.Price](filepath.Join(opts.inputDir, "prices.jsonl"))
	if err != nil {
		return nil, err
	}
	defer reader.Close()

	for p, err := range reader.All() {
		if err != nil {
			return nil, err
		}

		bar.Add(1)

		productID := ""
		if p.Product != nil {
			newProdID, ok := productIDMap[p.Product.ID]
			if !ok {
				if opts.abortOnError {
					bar.Finish()
					return nil, fmt.Errorf("price %s: product %s not found in import map", p.ID, p.Product.ID)
				}
				log.Warnf("skipping price %s: product %s not found in import map", p.ID, p.Product.ID)
				continue
			}
			productID = newProdID
		}

		params := &stripe.PriceParams{
			Currency:   stripe.String(string(p.Currency)),
			Product:    stripe.String(productID),
			Active:     stripe.Bool(p.Active),
			Metadata:   importMetadata(p.Metadata, p.ID, opts.importTime),
			UnitAmount: stripe.Int64(p.UnitAmount),
			Nickname:   nilIfEmpty(p.Nickname),
		}

		if p.BillingScheme == stripe.PriceBillingSchemeTiered {
			params.BillingScheme = stripe.String(string(p.BillingScheme))
			params.TiersMode = stripe.String(string(p.TiersMode))
		}

		if p.Recurring != nil {
			params.Recurring = &stripe.PriceRecurringParams{
				Interval:      stripe.String(string(p.Recurring.Interval)),
				IntervalCount: stripe.Int64(p.Recurring.IntervalCount),
			}
			if p.Recurring.UsageType == stripe.PriceRecurringUsageTypeMetered {
				params.Recurring.UsageType = stripe.String(string(p.Recurring.UsageType))
			}
		}

		if len(p.CurrencyOptions) > 0 {
			params.CurrencyOptions = make(map[string]*stripe.PriceCurrencyOptionsParams)
			for cur, opt := range p.CurrencyOptions {
				params.CurrencyOptions[cur] = &stripe.PriceCurrencyOptionsParams{
					UnitAmount: stripe.Int64(opt.UnitAmount),
				}
			}
		}

		if p.TaxBehavior != "" {
			params.TaxBehavior = stripe.String(string(p.TaxBehavior))
		}

		newPrice, err := stripeprice.New(params)
		if err != nil {
			if opts.abortOnError {
				bar.Finish()
				return nil, fmt.Errorf("price %s: %w", p.ID, err)
			}
			log.Warnf("failed to create price %s: %v", p.ID, err)
			continue
		}

		idMap[p.ID] = newPrice.ID
	}

	bar.Finish()
	fmt.Fprintf(os.Stderr, "imported %d prices\n", len(idMap))
	return idMap, nil
}

func importCoupons(opts importOptions) (map[string]string, error) {
	idMap := make(map[string]string)
	bar := newImportSpinner("Importing coupons")

	reader, err := util.NewJSONLFileReader[stripe.Coupon](filepath.Join(opts.inputDir, "coupons.jsonl"))
	if err != nil {
		return nil, err
	}
	defer reader.Close()

	for c, err := range reader.All() {
		if err != nil {
			return nil, err
		}

		bar.Add(1)

		params := &stripe.CouponParams{
			Duration: stripe.String(string(c.Duration)),
			Metadata: importMetadata(c.Metadata, c.ID, opts.importTime),
			Name:     nilIfEmpty(c.Name),
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
				params.CurrencyOptions[cur] = &stripe.CouponCurrencyOptionsParams{
					AmountOff: stripe.Int64(opt.AmountOff),
				}
			}
		}

		newCoupon, err := stripecoupon.New(params)
		if err != nil {
			if opts.abortOnError {
				bar.Finish()
				return nil, fmt.Errorf("coupon %s: %w", c.ID, err)
			}
			log.Warnf("failed to create coupon %s: %v", c.ID, err)
			continue
		}

		idMap[c.ID] = newCoupon.ID
	}

	bar.Finish()
	fmt.Fprintf(os.Stderr, "imported %d coupons\n", len(idMap))
	return idMap, nil
}

func importPromotionCodes(opts importOptions, couponIDMap map[string]string) error {
	bar := newImportSpinner("Importing promotion codes")
	count := 0

	reader, err := util.NewJSONLFileReader[stripe.PromotionCode](filepath.Join(opts.inputDir, "promotion_codes.jsonl"))
	if err != nil {
		return err
	}
	defer reader.Close()

	for pc, err := range reader.All() {
		if err != nil {
			return err
		}

		bar.Add(1)

		couponID := ""
		if pc.Coupon != nil {
			newCouponID, ok := couponIDMap[pc.Coupon.ID]
			if !ok {
				if opts.abortOnError {
					bar.Finish()
					return fmt.Errorf("promotion code %s: coupon %s not found in import map", pc.ID, pc.Coupon.ID)
				}
				log.Warnf("skipping promotion code %s: coupon %s not found in import map", pc.ID, pc.Coupon.ID)
				continue
			}
			couponID = newCouponID
		}

		params := &stripe.PromotionCodeParams{
			Coupon:   stripe.String(couponID),
			Code:     stripe.String(pc.Code),
			Active:   stripe.Bool(pc.Active),
			Metadata: importMetadata(pc.Metadata, pc.ID, opts.importTime),
		}

		if pc.MaxRedemptions > 0 {
			params.MaxRedemptions = stripe.Int64(pc.MaxRedemptions)
		}

		if _, err := stripepromo.New(params); err != nil {
			if opts.abortOnError {
				bar.Finish()
				return fmt.Errorf("promotion code %s: %w", pc.ID, err)
			}
			log.Warnf("failed to create promotion code %s: %v", pc.ID, err)
			continue
		}

		count++
	}

	bar.Finish()
	fmt.Fprintf(os.Stderr, "imported %d promotion codes\n", count)
	return nil
}

func importCustomers(opts importOptions) (map[string]string, map[string]string, error) {
	idMap := make(map[string]string)
	cardMap := make(map[string]string)
	bar := newImportSpinner("Importing customers")

	reader, err := util.NewJSONLFileReader[stripe.Customer](filepath.Join(opts.inputDir, "customers.jsonl"))
	if err != nil {
		return nil, nil, err
	}
	defer reader.Close()

	for c, err := range reader.All() {
		if err != nil {
			return nil, nil, err
		}

		bar.Add(1)

		email := c.Email
		if opts.rewriter != nil && email != "" {
			email = opts.rewriter.Rewrite(email)
		}

		params := &stripe.CustomerParams{
			Email:       nilIfEmpty(email),
			Name:        nilIfEmpty(c.Name),
			Description: nilIfEmpty(c.Description),
			Phone:       nilIfEmpty(c.Phone),
			Metadata:    importMetadata(c.Metadata, c.ID, opts.importTime),
		}

		if c.Address != nil {
			params.Address = &stripe.AddressParams{
				City:       nilIfEmpty(c.Address.City),
				Country:    nilIfEmpty(c.Address.Country),
				Line1:      nilIfEmpty(c.Address.Line1),
				Line2:      nilIfEmpty(c.Address.Line2),
				PostalCode: nilIfEmpty(c.Address.PostalCode),
				State:      nilIfEmpty(c.Address.State),
			}
		}

		if c.Shipping != nil {
			params.Shipping = &stripe.CustomerShippingParams{
				Name:  nilIfEmpty(c.Shipping.Name),
				Phone: nilIfEmpty(c.Shipping.Phone),
			}
			if c.Shipping.Address != nil {
				params.Shipping.Address = &stripe.AddressParams{
					City:       nilIfEmpty(c.Shipping.Address.City),
					Country:    nilIfEmpty(c.Shipping.Address.Country),
					Line1:      nilIfEmpty(c.Shipping.Address.Line1),
					Line2:      nilIfEmpty(c.Shipping.Address.Line2),
					PostalCode: nilIfEmpty(c.Shipping.Address.PostalCode),
					State:      nilIfEmpty(c.Shipping.Address.State),
				}
			}
		}

		newCust, err := stripecustomer.New(params)
		if err != nil {
			if opts.abortOnError {
				bar.Finish()
				return nil, nil, fmt.Errorf("customer %s: %w", c.ID, err)
			}
			log.Warnf("failed to create customer %s: %v", c.ID, err)
			continue
		}

		idMap[c.ID] = newCust.ID

		if opts.createTestCards {
			cardID := resolveTestCard(opts, string(c.Currency))

			pm, err := paymentmethod.Attach(cardID, &stripe.PaymentMethodAttachParams{
				Customer: stripe.String(newCust.ID),
			})
			if err != nil {
				log.Warnf("failed to attach test card to customer %s: %v", newCust.ID, err)
				continue
			}

			_, err = stripecustomer.Update(newCust.ID, &stripe.CustomerParams{
				InvoiceSettings: &stripe.CustomerInvoiceSettingsParams{
					DefaultPaymentMethod: stripe.String(pm.ID),
				},
			})
			if err != nil {
				log.Warnf("failed to set default payment method for customer %s: %v", newCust.ID, err)
			}

			cardMap[newCust.ID] = pm.ID
		}
	}

	bar.Finish()
	fmt.Fprintf(os.Stderr, "imported %d customers\n", len(idMap))
	return idMap, cardMap, nil
}

func importSubscriptions(opts importOptions, customerIDMap, priceIDMap, couponIDMap, customerCardMap map[string]string) error {
	bar := newImportSpinner("Importing subscriptions")
	count := 0

	reader, err := util.NewJSONLFileReader[stripe.Subscription](filepath.Join(opts.inputDir, "subscriptions.jsonl"))
	if err != nil {
		return err
	}
	defer reader.Close()

	for sub, err := range reader.All() {
		if err != nil {
			return err
		}

		bar.Add(1)

		if sub.Status != stripe.SubscriptionStatusActive && sub.Status != stripe.SubscriptionStatusTrialing {
			continue
		}

		newCustomerID, ok := customerIDMap[sub.Customer.ID]
		if !ok {
			if opts.abortOnError {
				bar.Finish()
				return fmt.Errorf("subscription %s: customer %s not found in import map", sub.ID, sub.Customer.ID)
			}
			log.Warnf("skipping subscription %s: customer %s not found in import map", sub.ID, sub.Customer.ID)
			continue
		}

		var items []*stripe.SubscriptionItemsParams
		skipSub := false
		for _, item := range sub.Items.Data {
			if item.Price == nil {
				continue
			}

			newPriceID, ok := priceIDMap[item.Price.ID]
			if !ok {
				if opts.abortOnError {
					bar.Finish()
					return fmt.Errorf("subscription %s: price %s not found in import map", sub.ID, item.Price.ID)
				}
				log.Warnf("skipping subscription %s: price %s not found in import map", sub.ID, item.Price.ID)
				skipSub = true
				break
			}

			items = append(items, &stripe.SubscriptionItemsParams{
				Price:    stripe.String(newPriceID),
				Quantity: stripe.Int64(item.Quantity),
			})
		}

		if skipSub || len(items) == 0 {
			continue
		}

		params := &stripe.SubscriptionParams{
			Customer: stripe.String(newCustomerID),
			Items:    items,
			Metadata: importMetadata(sub.Metadata, sub.ID, opts.importTime),
		}

		// billing anchor and proration
		if opts.retainBillingAnchor && sub.BillingCycleAnchor > 0 {
			params.BillingCycleAnchor = stripe.Int64(sub.BillingCycleAnchor)
		}

		if opts.prorateSubscriptions {
			params.ProrationBehavior = stripe.String("create_prorations")
		} else {
			params.ProrationBehavior = stripe.String("none")
		}

		// attach payment method
		if pmID, ok := customerCardMap[newCustomerID]; ok {
			params.DefaultPaymentMethod = stripe.String(pmID)
		}

		// application fee handling
		if opts.applicationFees && opts.isConnectPlatform {
			if opts.applicationFeeOverride != nil {
				params.ApplicationFeePercent = stripe.Float64(*opts.applicationFeeOverride)
			} else if sub.ApplicationFeePercent > 0 {
				params.ApplicationFeePercent = stripe.Float64(sub.ApplicationFeePercent)
			}
		}

		// on behalf of
		if opts.onBehalfOf != "" {
			params.OnBehalfOf = stripe.String(opts.onBehalfOf)
		}

		// apply coupon from subscription discount
		if sub.Discount != nil && sub.Discount.Coupon != nil && sub.Discount.Coupon.ID != "" {
			newCouponID, ok := couponIDMap[sub.Discount.Coupon.ID]
			if ok {
				params.Coupon = stripe.String(newCouponID)
			} else {
				log.Warnf("subscription %s: coupon %s not found in import map, skipping discount", sub.ID, sub.Discount.Coupon.ID)
			}
		}

		if _, err := stripesub.New(params); err != nil {
			if opts.abortOnError {
				bar.Finish()
				return fmt.Errorf("subscription %s: %w", sub.ID, err)
			}
			log.Warnf("failed to create subscription %s: %v", sub.ID, err)
			continue
		}

		count++
	}

	bar.Finish()
	fmt.Fprintf(os.Stderr, "imported %d subscriptions\n", count)
	return nil
}

func resolveTestCard(opts importOptions, currency string) string {
	if opts.defaultTestCard != "pm_card_us" || currency == "" {
		return opts.defaultTestCard
	}

	currency = strings.ToLower(currency)
	if card, ok := testCardByCurrency[currency]; ok {
		return card
	}

	return opts.defaultTestCard
}

func nilIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
