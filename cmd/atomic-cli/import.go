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
	"net/url"
	"os"
	"path"
	"strings"

	client "github.com/libatomic/atomic-go"
	"github.com/libatomic/atomic/pkg/atomic"
	"github.com/libatomic/atomic/pkg/ptr"
	"github.com/urfave/cli/v3"
)

var (
	importCmd = &cli.Command{
		Name:  "import",
		Usage: "import data from a remote Passport instance",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  "remote-profile",
				Usage: "use a profile from the credentials file as the source (host/access_token/client_id/client_secret/instance_id); mutually exclusive with --remote-host / --remote-token / --remote-client-id / --remote-client-secret",
			},
			&cli.StringFlag{
				Name:  "remote-host",
				Usage: "remote Passport API host (e.g. api.example.com); mutually exclusive with --remote-profile",
			},
			&cli.StringFlag{
				Name:  "remote-token",
				Usage: "remote access token (mutually exclusive with --remote-client-id/--remote-client-secret and --remote-profile)",
			},
			&cli.StringFlag{
				Name:  "remote-client-id",
				Usage: "remote client ID for client credentials auth (mutually exclusive with --remote-profile)",
			},
			&cli.StringFlag{
				Name:  "remote-client-secret",
				Usage: "remote client secret for client credentials auth (mutually exclusive with --remote-profile)",
			},
			&cli.StringSliceFlag{
				Name:     "types",
				Aliases:  []string{"t"},
				Usage:    "types to import: categories, plans, audiences, templates, assets, articles",
				Required: true,
			},
			&cli.StringFlag{
				Name:  "plan-types",
				Usage: "plan types to import: paid, free, all",
				Value: "all",
			},
			&cli.BoolFlag{
				Name:  "overwrite",
				Usage: "overwrite existing items",
				Value: true,
			},
			&cli.BoolFlag{
				Name:  "dry-run",
				Usage: "preview what would be imported without making changes",
			},
			&cli.StringFlag{
				Name:  "email-domain",
				Usage: "rewrite email domains in template metadata (from_address, reply_to) to this domain; defaults to the target instance name",
			},
			&cli.StringFlag{
				Name:  "email-name",
				Usage: "rewrite email display names in template metadata (from_address, reply_to) to this name; defaults to target instance title",
			},
		},
		Action: importAction,
	}
)

type (
	importStats struct {
		Type    string
		Found   int
		Created int
		Updated int
		Skipped int
		Errors  int
	}
)

func importAction(ctx context.Context, cmd *cli.Command) error {
	// import always writes to the target instance — fail fast if it's missing
	// rather than crashing somewhere downstream
	if inst == nil {
		return fmt.Errorf("a target instance is required: pass -i / --instance_id, or set instance_id in your credentials profile")
	}

	remoteProfile := cmd.String("remote-profile")
	remoteHost := cmd.String("remote-host")
	remoteToken := cmd.String("remote-token")
	remoteClientID := cmd.String("remote-client-id")
	remoteClientSecret := cmd.String("remote-client-secret")
	types := cmd.StringSlice("types")
	planTypes := cmd.String("plan-types")
	overwrite := cmd.Bool("overwrite")
	dryRun := cmd.Bool("dry-run")
	verbose := mainCmd.Bool("verbose")
	emailDomain := cmd.String("email-domain")
	if emailDomain == "" && inst != nil {
		emailDomain = inst.Name
	}
	emailName := cmd.String("email-name")

	// --remote-profile is mutually exclusive with the explicit --remote-* flags
	if remoteProfile != "" {
		if remoteHost != "" || remoteToken != "" || remoteClientID != "" || remoteClientSecret != "" {
			return fmt.Errorf("--remote-profile is mutually exclusive with --remote-host / --remote-token / --remote-client-id / --remote-client-secret")
		}

		credsPath := mainCmd.String("credentials")
		cf := loadCredentials(credsPath)
		if len(cf.Profiles()) == 0 {
			return fmt.Errorf("--remote-profile %q: no profiles found in %s", remoteProfile, credsPath)
		}
		host, ok := cf.Lookup(remoteProfile, "host")
		if !ok {
			return fmt.Errorf("--remote-profile %q: profile not found in %s (known: %v)", remoteProfile, credsPath, cf.Profiles())
		}
		remoteHost = host
		remoteToken, _ = cf.Lookup(remoteProfile, "access_token")
		remoteClientID, _ = cf.Lookup(remoteProfile, "client_id")
		remoteClientSecret, _ = cf.Lookup(remoteProfile, "client_secret")
	}

	if remoteHost == "" {
		return fmt.Errorf("--remote-host or --remote-profile is required")
	}

	if remoteToken == "" && (remoteClientID == "" || remoteClientSecret == "") {
		return fmt.Errorf("either --remote-token or --remote-client-id and --remote-client-secret are required")
	}

	// create remote client
	var opts []client.ApiOption
	opts = append(opts, client.WithHost(remoteHost))

	if remoteToken != "" {
		opts = append(opts, client.WithToken(remoteToken))
	} else {
		opts = append(opts, client.WithClientCredentials(remoteClientID, remoteClientSecret))
	}

	remote := client.New(opts...)

	// validate types
	validTypes := map[string]bool{
		"categories": true,
		"plans":      true,
		"audiences":  true,
		"templates":  true,
		"assets":     true,
		"articles":   true,
	}
	for _, t := range types {
		if !validTypes[strings.ToLower(t)] {
			return fmt.Errorf("invalid type %q; valid types: categories, plans, audiences, templates, assets, articles", t)
		}
	}

	typeSet := make(map[string]bool)
	for _, t := range types {
		typeSet[strings.ToLower(t)] = true
	}

	// announce the source and the target so the user can sanity-check before
	// any data moves
	srcLabel := remoteHost
	if remoteProfile != "" {
		srcLabel = fmt.Sprintf("%s (profile: %s)", remoteHost, remoteProfile)
	}
	targetLabel := mainCmd.String("host")
	if inst != nil {
		targetLabel = fmt.Sprintf("%s — instance %s (%s)", targetLabel, inst.Name, inst.UUID)
	}

	mode := "importing"
	if dryRun {
		mode = "[DRY RUN] previewing import"
	}
	fmt.Fprintf(os.Stderr, "%s\n  source: %s\n  target: %s\n\n", mode, srcLabel, targetLabel)

	var allStats []importStats

	// import in dependency order: categories -> plans -> audiences -> templates -> assets -> articles
	if typeSet["categories"] {
		stats, err := importCategories(ctx, remote, dryRun, overwrite, verbose)
		if err != nil {
			return fmt.Errorf("categories: %w", err)
		}
		allStats = append(allStats, stats)
	}

	if typeSet["plans"] {
		stats, err := importPlans(ctx, remote, dryRun, overwrite, planTypes, verbose)
		if err != nil {
			return fmt.Errorf("plans: %w", err)
		}
		allStats = append(allStats, stats...)
	}

	if typeSet["audiences"] {
		stats, err := importAudiences(ctx, remote, dryRun, overwrite, verbose)
		if err != nil {
			return fmt.Errorf("audiences: %w", err)
		}
		allStats = append(allStats, stats)
	}

	if typeSet["templates"] {
		stats, err := importTemplates(ctx, remote, dryRun, overwrite, verbose, emailDomain, emailName)
		if err != nil {
			return fmt.Errorf("templates: %w", err)
		}
		allStats = append(allStats, stats)
	}

	if typeSet["assets"] {
		stats, err := importAssets(ctx, remote, dryRun, verbose)
		if err != nil {
			return fmt.Errorf("assets: %w", err)
		}
		allStats = append(allStats, stats)
	}

	if typeSet["articles"] {
		stats, err := importArticles(ctx, remote, dryRun, verbose)
		if err != nil {
			return fmt.Errorf("articles: %w", err)
		}
		allStats = append(allStats, stats)
	}

	// print summary table
	fmt.Fprintf(os.Stderr, "\n")
	fmt.Fprintf(os.Stderr, "%-15s %8s %8s %8s %8s %8s\n", "Type", "Found", "Created", "Updated", "Skipped", "Errors")
	fmt.Fprintf(os.Stderr, "%s\n", strings.Repeat("-", 65))
	for _, s := range allStats {
		fmt.Fprintf(os.Stderr, "%-15s %8d %8d %8d %8d %8d\n", s.Type, s.Found, s.Created, s.Updated, s.Skipped, s.Errors)
	}
	fmt.Fprintf(os.Stderr, "%s\n", strings.Repeat("-", 65))

	if dryRun {
		fmt.Fprintf(os.Stderr, "[DRY RUN] no changes were made\n")
	} else {
		fmt.Fprintf(os.Stderr, "import complete\n")
	}

	return nil
}

func importCategories(ctx context.Context, remote *client.Client, dryRun bool, overwrite bool, verbose bool) (importStats, error) {
	stats := importStats{Type: "Categories"}

	bar := newMigrateSpinner("Fetching categories")
	cats, err := remote.CategoryList(ctx, &atomic.CategoryListInput{})
	bar.Finish()
	if err != nil {
		return stats, err
	}

	stats.Found = len(cats)
	fmt.Fprintf(os.Stderr, "found %d categories\n", len(cats))

	if len(cats) == 0 {
		return stats, nil
	}

	if verbose {
		for _, cat := range cats {
			fmt.Fprintf(os.Stderr, "  %s (%s)\n", cat.Name, cat.Slug)
		}
	}

	// cache existing categories by name for lookup
	existingCats, _ := backend.CategoryList(ctx, &atomic.CategoryListInput{InstanceID: inst.UUID})
	existingByName := make(map[string]*atomic.Category)
	for _, ec := range existingCats {
		existingByName[ec.Name] = ec
	}

	bar = newMigrateProgress(len(cats), "Importing categories")

	for _, cat := range cats {
		bar.Add(1)

		if dryRun {
			stats.Created++
			continue
		}

		existing := existingByName[cat.Name]

		if existing != nil && !overwrite {
			stats.Skipped++
			continue
		}

		if existing != nil {
			if _, err := backend.CategoryUpdate(ctx, &atomic.CategoryUpdateInput{
				InstanceID:  inst.UUID,
				CategoryID:  existing.ID,
				Name:        &cat.Name,
				Description: cat.Description,
				Active:      &cat.Active,
				Hidden:      &cat.Hidden,
				Metadata:    cat.Metadata,
			}); err != nil {
				stats.Errors++
				if verbose {
					fmt.Fprintf(os.Stderr, "\n  error updating %q: %s\n", cat.Name, err)
				}
				continue
			}
			stats.Updated++
		} else {
			if _, err := backend.CategoryCreate(ctx, &atomic.CategoryCreateInput{
				InstanceID:  inst.UUID,
				Name:        cat.Name,
				Description: cat.Description,
				Active:      &cat.Active,
				Hidden:      &cat.Hidden,
				Metadata:    cat.Metadata,
			}); err != nil {
				stats.Errors++
				if verbose {
					fmt.Fprintf(os.Stderr, "\n  error creating %q: %s\n", cat.Name, err)
				}
				continue
			}
			stats.Created++
		}
	}

	bar.Finish()
	return stats, nil
}

func importPlans(ctx context.Context, remote *client.Client, dryRun bool, overwrite bool, planTypes string, verbose bool) ([]importStats, error) {
	planStats := importStats{Type: "Plans"}
	priceStats := importStats{Type: "Prices"}
	volumeCreditMap := make(map[string]atomic.ID) // source credit ID → target credit ID

	bar := newMigrateSpinner("Fetching plans")
	plans, err := remote.PlanList(ctx, &atomic.PlanListInput{})
	bar.Finish()
	if err != nil {
		return []importStats{planStats, priceStats}, err
	}

	// fetch each plan with preload to get prices and categories
	bar = newMigrateSpinner("Loading plan details")
	var fullPlans []*atomic.Plan
	for _, p := range plans {
		full, err := remote.PlanGet(ctx, &atomic.PlanGetInput{
			PlanID:  &p.UUID,
			Preload: ptr.Bool(true),
		})
		if err != nil {
			if verbose {
				fmt.Fprintf(os.Stderr, "\n  error fetching plan %q: %s\n", p.Name, err)
			}
			fullPlans = append(fullPlans, p)
		} else {
			fullPlans = append(fullPlans, full)
		}
		bar.Add(1)
	}
	bar.Finish()

	var filtered []*atomic.Plan
	for _, p := range fullPlans {
		switch planTypes {
		case "paid":
			if p.Type != atomic.PlanTypePaid {
				continue
			}
		case "free":
			if p.Type != atomic.PlanTypeFree {
				continue
			}
		}
		filtered = append(filtered, p)
	}

	planStats.Found = len(filtered)
	fmt.Fprintf(os.Stderr, "found %d plans (%s)\n", len(filtered), planTypes)

	if len(filtered) == 0 {
		return []importStats{planStats, priceStats}, nil
	}

	if verbose {
		for _, plan := range filtered {
			fmt.Fprintf(os.Stderr, "  %s (%s) - %d prices\n", plan.Name, plan.Type, len(plan.Prices))
			for _, price := range plan.Prices {
				interval := ""
				if price.RecurringInterval != nil {
					interval = string(*price.RecurringInterval)
				}
				fmt.Fprintf(os.Stderr, "    %s: %d %s/%s\n", price.Name, ptr.Value(price.FlatAmount, 0), price.Currency, interval)
			}
		}
	}

	// count total prices across all plans
	for _, plan := range filtered {
		priceStats.Found += len(plan.Prices)
	}

	// cache target categories by slug for remapping plan categories
	targetCats, _ := backend.CategoryList(ctx, &atomic.CategoryListInput{InstanceID: inst.UUID})
	targetCatBySlug := make(map[string]*atomic.Category)
	for _, tc := range targetCats {
		targetCatBySlug[tc.Slug] = tc
	}

	// cache existing plans by name
	existingPlans, _ := backend.PlanList(ctx, &atomic.PlanListInput{InstanceID: inst.UUID})
	existingPlanByName := make(map[string]*atomic.Plan)
	for _, ep := range existingPlans {
		existingPlanByName[ep.Name] = ep
	}

	bar = newMigrateProgress(len(filtered), "Importing plans")

	for _, plan := range filtered {
		bar.Add(1)

		if dryRun {
			planStats.Created++
			priceStats.Created += len(plan.Prices)
			continue
		}

		existingPlan := existingPlanByName[plan.Name]

		var targetPlanID atomic.ID

		// remap categories from source to target by slug or name
		mappedCategories := make([]*atomic.PlanCategory, 0)
		for _, pc := range plan.Categories {
			tc := targetCatBySlug[pc.Slug]
			if tc == nil {
				// fallback: try matching by name
				for _, c := range targetCats {
					if c.Name == pc.Name {
						tc = c
						break
					}
				}
			}
			if tc == nil {
				if verbose {
					fmt.Fprintf(os.Stderr, "\n  skipping category %q slug=%q (not found in target)\n", pc.Name, pc.Slug)
				}
				continue
			}
			mappedCategories = append(mappedCategories, &atomic.PlanCategory{
				Category:   *tc,
				CategoryID: tc.ID,
				Channels:   pc.Channels,
			})
		}

		// import plan image as a local asset
		var localImage *string
		if plan.Image != nil && *plan.Image != "" {
			if link, err := importImageAsAsset(ctx, *plan.Image, verbose); err == nil {
				localImage = &link
			} else if verbose {
				fmt.Fprintf(os.Stderr, "\n  warning: failed to import image for %q: %s\n", plan.Name, err)
			}
		}

		if existingPlan != nil && !overwrite {
			planStats.Skipped++
			continue
		}

		if existingPlan != nil {
			if _, err := backend.PlanUpdate(ctx, &atomic.PlanUpdateInput{
				InstanceID:  inst.UUID,
				PlanID:      existingPlan.UUID,
				Name:        &plan.Name,
				Description: plan.Description,
				Active:      &plan.Active,
				Hidden:      &plan.Hidden,
				Image:       localImage,
				Metadata:    plan.Metadata,
				Categories:  mappedCategories,
			}); err != nil {
				planStats.Errors++
				if verbose {
					fmt.Fprintf(os.Stderr, "\n  error updating plan %q: %s\n", plan.Name, err)
				}
				continue
			}
			targetPlanID = existingPlan.UUID
			planStats.Updated++
		} else {
			createInput := &atomic.PlanCreateInput{
				InstanceID:  inst.UUID,
				Name:        plan.Name,
				Description: plan.Description,
				Type:        plan.Type,
				Active:      &plan.Active,
				Hidden:      &plan.Hidden,
				Image:       localImage,
				Metadata:    plan.Metadata,
				Categories:  mappedCategories,
			}
			if plan.Default {
				createInput.Default = &plan.Default
			}
			newPlan, err := backend.PlanCreate(ctx, createInput)
			if err != nil {
				planStats.Errors++
				if verbose {
					fmt.Fprintf(os.Stderr, "\n  error creating plan %q: %s\n", plan.Name, err)
				}
				continue
			}
			targetPlanID = newPlan.UUID
			planStats.Created++
		}

		for _, price := range plan.Prices {
			// migrate volume credit if needed
			var volumeCreditID *atomic.ID
			if price.VolumeCreditID != nil {
				if mapped, ok := volumeCreditMap[string(*price.VolumeCreditID)]; ok {
					volumeCreditID = &mapped
				} else if !dryRun {
					// use the volume credit from the preloaded price
					if price.VolumeCredit == nil {
						if verbose {
							fmt.Fprintf(os.Stderr, "\n  error fetching volume credit %s: credit not found on preloaded price\n", *price.VolumeCreditID)
						}
					} else {
						sourceCredit := price.VolumeCredit
						newCredit, err := backend.CreditCreate(ctx, &atomic.CreditCreateInput{
							InstanceID: inst.UUID,
							Type:       atomic.CreditTypeVolumeDiscount,
							Name:       sourceCredit.Name,
							PercentOff: sourceCredit.PercentOff,
							Amount:     sourceCredit.Amount,
							Term:       sourceCredit.Term,
							Duration:   sourceCredit.Duration,
							Metadata:   sourceCredit.Metadata,
						})
						if err != nil {
							if verbose {
								fmt.Fprintf(os.Stderr, "\n  error creating volume credit: %s\n", err)
							}
						} else {
							volumeCreditID = &newCredit.UUID
							volumeCreditMap[string(*price.VolumeCreditID)] = newCredit.UUID
							if verbose {
								fmt.Fprintf(os.Stderr, "\n  created volume credit %s → %s\n", *price.VolumeCreditID, newCredit.UUID)
							}
						}
					}
				}
			}

			priceInput := &atomic.PriceCreateInput{
				InstanceID:     &inst.UUID,
				PlanID:         targetPlanID,
				Name:           price.Name,
				Currency:       price.Currency,
				Active:         &price.Active,
				Hidden:         &price.Hidden,
				Amount:         price.FlatAmount,
				Type:           price.RecurringType,
				Metered:        price.Metered,
				Volume:         &price.Volume,
				VolumeCreditID: volumeCreditID,
				TierMode:       price.TierMode,
				Tiers:          price.Tiers,
			}

			if price.CurrencyOptions != nil {
				priceInput.CurrencyOptions = price.CurrencyOptions
			}

			if price.RecurringInterval != nil {
				priceInput.Recurring = &atomic.PriceRecurring{
					Interval:  string(*price.RecurringInterval),
					Frequency: int64(ptr.Value(price.RecurringFrequency, 1)),
				}
			}

			if price.TrialSettings != nil {
				priceInput.TrialSettings = price.TrialSettings
			}

			if _, err := backend.PriceCreate(ctx, priceInput); err != nil {
				if strings.Contains(err.Error(), "already exists") {
					priceStats.Skipped++
				} else {
					priceStats.Errors++
					if verbose {
						fmt.Fprintf(os.Stderr, "\n  error creating price %q for %q: %s\n", price.Name, plan.Name, err)
					}
				}
				continue
			}
			priceStats.Created++
		}
	}

	bar.Finish()
	return []importStats{planStats, priceStats}, nil
}

func importAudiences(ctx context.Context, remote *client.Client, dryRun bool, overwrite bool, verbose bool) (importStats, error) {
	stats := importStats{Type: "Audiences"}

	bar := newMigrateSpinner("Fetching audiences")
	auds, err := remote.AudienceList(ctx, &atomic.AudienceListInput{
		ReturnMemberCount: ptr.False,
	})
	bar.Finish()
	if err != nil {
		return stats, err
	}

	var filtered []*atomic.Audience
	for _, a := range auds {
		if !a.Internal {
			filtered = append(filtered, a)
		}
	}

	stats.Found = len(filtered)
	fmt.Fprintf(os.Stderr, "found %d non-internal audiences (of %d total)\n", len(filtered), len(auds))

	if len(filtered) == 0 {
		return stats, nil
	}

	if verbose {
		for _, aud := range filtered {
			static := ""
			if aud.Static {
				static = " [static]"
			}
			fmt.Fprintf(os.Stderr, "  %s%s\n", aud.Name, static)
		}
	}

	// build category UUID mapping: source UUID string → target UUID string
	// audiences reference categories by raw UUID in their expr filters
	remoteCats, _ := remote.CategoryList(ctx, &atomic.CategoryListInput{})
	targetCats, _ := backend.CategoryList(ctx, &atomic.CategoryListInput{InstanceID: inst.UUID})

	// source raw UUID → category name
	sourceCatUUIDToName := make(map[string]string)
	for _, rc := range remoteCats {
		sourceCatUUIDToName[rc.ID.UUID().String()] = rc.Name
	}

	// category name → target raw UUID
	targetCatNameToUUID := make(map[string]string)
	for _, tc := range targetCats {
		targetCatNameToUUID[tc.Name] = tc.ID.UUID().String()
	}

	// source raw UUID → target raw UUID
	catUUIDMap := make(map[string]string)
	for sourceUUID, name := range sourceCatUUIDToName {
		if targetUUID, ok := targetCatNameToUUID[name]; ok {
			catUUIDMap[sourceUUID] = targetUUID
		}
	}

	if verbose && len(catUUIDMap) > 0 {
		fmt.Fprintf(os.Stderr, "  mapped %d category UUIDs for expr remapping\n", len(catUUIDMap))
	}

	// cache existing audiences by name
	existingAuds, _ := backend.AudienceList(ctx, &atomic.AudienceListInput{
		InstanceID:        inst.UUID,
		ReturnMemberCount: ptr.False,
	})
	existingAudByName := make(map[string]*atomic.Audience)
	for _, ea := range existingAuds {
		existingAudByName[ea.Name] = ea
	}

	bar = newMigrateProgress(len(filtered), "Importing audiences")

	for _, aud := range filtered {
		bar.Add(1)

		if dryRun {
			stats.Created++
			continue
		}

		// remap category UUIDs in the audience expr
		remappedExpr := remapAudienceExpr(aud.Expr, catUUIDMap)

		existingAud := existingAudByName[aud.Name]

		if existingAud != nil && !overwrite {
			stats.Skipped++
			continue
		}

		if existingAud != nil {
			if _, err := backend.AudienceUpdate(ctx, &atomic.AudienceUpdateInput{
				InstanceID: inst.UUID,
				AudienceID: existingAud.UUID,
				Name:       &aud.Name,
				Expr:       &remappedExpr,
			}); err != nil {
				stats.Errors++
				if verbose {
					fmt.Fprintf(os.Stderr, "\n  error updating %q: %s\n", aud.Name, err)
				}
				continue
			}
			stats.Updated++
		} else {
			input := &atomic.AudienceCreateInput{
				InstanceID: inst.UUID,
				Name:       aud.Name,
				Metadata:   aud.Metadata,
			}
			if remappedExpr.Source != "" {
				input.Expr = &remappedExpr
			}
			if aud.Static {
				input.Static = &aud.Static
			}
			if _, err := backend.AudienceCreate(ctx, input); err != nil {
				stats.Errors++
				if verbose {
					fmt.Fprintf(os.Stderr, "\n  error creating %q: %s\n", aud.Name, err)
				}
				continue
			}
			stats.Created++
		}
	}

	bar.Finish()
	return stats, nil
}

func importTemplates(ctx context.Context, remote *client.Client, dryRun bool, overwrite bool, verbose bool, emailDomain string, emailName string) (importStats, error) {
	stats := importStats{Type: "Templates"}

	bar := newMigrateSpinner("Fetching templates")
	templates, err := remote.TemplateList(ctx, &atomic.TemplateListInput{})
	bar.Finish()
	if err != nil {
		return stats, err
	}

	stats.Found = len(templates)
	fmt.Fprintf(os.Stderr, "found %d templates\n", len(templates))

	if len(templates) == 0 {
		return stats, nil
	}

	if verbose {
		for _, tmpl := range templates {
			fmt.Fprintf(os.Stderr, "  %s (%s) [%s]\n", tmpl.Name, tmpl.Slug, tmpl.Type)
		}
	}

	// build audience ID mapping: source ID → name, name → target ID
	remoteAuds, _ := remote.AudienceList(ctx, &atomic.AudienceListInput{ReturnMemberCount: ptr.False})
	targetAuds, _ := backend.AudienceList(ctx, &atomic.AudienceListInput{InstanceID: inst.UUID, ReturnMemberCount: ptr.False})

	sourceAudIDToName := make(map[string]string)
	for _, a := range remoteAuds {
		sourceAudIDToName[string(a.UUID)] = a.Name
	}

	targetAudNameToID := make(map[string]string)
	for _, a := range targetAuds {
		targetAudNameToID[a.Name] = string(a.UUID)
	}

	audIDMap := make(map[string]string)
	for sourceID, name := range sourceAudIDToName {
		if targetID, ok := targetAudNameToID[name]; ok {
			audIDMap[sourceID] = targetID
		}
	}

	if verbose && len(audIDMap) > 0 {
		fmt.Fprintf(os.Stderr, "  mapped %d audience IDs for template metadata remapping\n", len(audIDMap))
	}

	bar = newMigrateProgress(len(templates), "Importing templates")

	for _, tmpl := range templates {
		bar.Add(1)

		if dryRun {
			stats.Created++
			continue
		}

		// remap audience IDs in template metadata
		metadata := remapTemplateAudiences(tmpl.Metadata, audIDMap)
		metadata = remapTemplateEmails(metadata, emailDomain, emailName)

		slug := tmpl.Slug
		input := &atomic.TemplateCreateInput{
			InstanceID: inst.UUID,
			Name:       tmpl.Name,
			Slug:       &slug,
			Type:       tmpl.Type,
			Title:      tmpl.Title,
			Body:       tmpl.Body,
			Settings:   tmpl.Settings,
			Defaults:   tmpl.Defaults,
			Metadata:   metadata,
			Events:     tmpl.Events,
			Overwrite:  overwrite,
		}

		if _, err := backend.TemplateCreate(ctx, input); err != nil {
			stats.Errors++
			if verbose {
				fmt.Fprintf(os.Stderr, "\n  error with template %q: %s\n", tmpl.Name, err)
			}
			continue
		}
		stats.Created++
	}

	bar.Finish()
	return stats, nil
}

// remapTemplateAudiences replaces audience IDs in template metadata.audiences
// using the provided source→target ID mapping.
func remapTemplateAudiences(metadata atomic.Metadata, audIDMap map[string]string) atomic.Metadata {
	if metadata == nil || len(audIDMap) == 0 {
		return metadata
	}

	rawAudiences, ok := metadata["audiences"]
	if !ok {
		return metadata
	}

	audiences, ok := rawAudiences.([]interface{})
	if !ok {
		return metadata
	}

	remapped := make([]interface{}, 0, len(audiences))
	for _, raw := range audiences {
		id, ok := raw.(string)
		if !ok {
			remapped = append(remapped, raw)
			continue
		}
		if targetID, mapped := audIDMap[id]; mapped {
			remapped = append(remapped, targetID)
		} else {
			remapped = append(remapped, id)
		}
	}

	// copy metadata to avoid mutating the original
	result := make(atomic.Metadata, len(metadata))
	for k, v := range metadata {
		result[k] = v
	}
	result["audiences"] = remapped

	return result
}

// remapTemplateEmails rewrites email domains and display names in template
// metadata fields (from_address, reply_to). If emailDomain is empty, no
// rewriting is performed.
func remapTemplateEmails(metadata atomic.Metadata, emailDomain, emailName string) atomic.Metadata {
	if metadata == nil || emailDomain == "" {
		return metadata
	}

	// if emailName is empty, retain the original name from the template

	changed := false
	result := make(atomic.Metadata, len(metadata))
	for k, v := range metadata {
		result[k] = v
	}

	for _, field := range []string{"from_address", "reply_to"} {
		raw, ok := result[field]
		if !ok {
			continue
		}

		addrMap, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}

		addr, _ := addrMap["address"].(string)
		if addr == "" {
			continue
		}

		// copy the address map
		newAddr := make(map[string]interface{}, len(addrMap))
		for k, v := range addrMap {
			newAddr[k] = v
		}

		// rewrite the domain part of the email
		if at := strings.LastIndex(addr, "@"); at >= 0 {
			localPart := addr[:at]
			newAddr["address"] = localPart + "@" + emailDomain
			newAddr["verified"] = false
			changed = true
		}

		if emailName != "" {
			newAddr["name"] = emailName
			changed = true
		}

		result[field] = newAddr
	}

	if !changed {
		return metadata
	}

	return result
}

func importAssets(ctx context.Context, remote *client.Client, dryRun bool, verbose bool) (importStats, error) {
	stats := importStats{Type: "Assets"}

	bar := newMigrateSpinner("Fetching assets")
	assets, err := remote.AssetList(ctx, &atomic.AssetListInput{})
	bar.Finish()
	if err != nil {
		return stats, err
	}

	stats.Found = len(assets)
	fmt.Fprintf(os.Stderr, "found %d assets\n", len(assets))

	if len(assets) == 0 {
		return stats, nil
	}

	if verbose {
		for _, asset := range assets {
			fmt.Fprintf(os.Stderr, "  %s (%s)\n", asset.Filename, asset.MimeType)
		}
	}

	bar = newMigrateProgress(len(assets), "Importing assets")

	for _, asset := range assets {
		bar.Add(1)

		if dryRun {
			stats.Created++
			continue
		}

		input := &atomic.AssetCreateInput{
			InstanceID:  &inst.UUID,
			Description: asset.Description,
			Filename:    asset.Filename,
			MimeType:    asset.MimeType,
			Public:      asset.Public,
			Overwrite:   ptr.Bool(true),
		}

		if _, err := backend.AssetCreate(ctx, input); err != nil {
			stats.Errors++
			if verbose {
				fmt.Fprintf(os.Stderr, "\n  error creating asset %q: %s\n", asset.Filename, err)
			}
			continue
		}
		stats.Created++
	}

	bar.Finish()
	return stats, nil
}

func importArticles(ctx context.Context, remote *client.Client, dryRun bool, verbose bool) (importStats, error) {
	stats := importStats{Type: "Articles"}

	bar := newMigrateSpinner("Fetching articles")

	// paginate through all articles
	var allArticles []*atomic.Article
	const pageSize = 100
	var offset uint64

	for {
		limit := uint64(pageSize)
		page, err := remote.ArticleList(ctx, &atomic.ArticleListInput{
			Limit:   &limit,
			Offset:  &offset,
			Preload: ptr.Bool(true),
		})
		if err != nil {
			bar.Finish()
			return stats, err
		}
		if len(page) == 0 {
			break
		}
		allArticles = append(allArticles, page...)
		bar.Add(len(page))
		offset += uint64(len(page))
		if len(page) < pageSize {
			break
		}
	}

	bar.Finish()

	stats.Found = len(allArticles)
	fmt.Fprintf(os.Stderr, "found %d articles\n", len(allArticles))

	if len(allArticles) == 0 {
		return stats, nil
	}

	bar = newMigrateProgress(len(allArticles), "Importing articles")

	for _, article := range allArticles {
		bar.Add(1)

		if dryRun {
			stats.Created++
			continue
		}

		var categories []string
		for _, cat := range article.Categories {
			categories = append(categories, string(cat.CategoryID))
		}

		input := &atomic.ArticleCreateInput{
			InstanceID:  inst.UUID,
			PublishedAt: article.PublishedAt,
			Status:      &article.Status,
			Author:      article.Author,
			AuthorEmail: article.AuthorEmail,
			Title:       article.Title,
			Summary:     article.Summary,
			Body:        article.Body,
			Language:    &article.Language,
			Public:      article.Public,
			Categories:  categories,
			URI:         article.URI,
			ImageURI:    article.ImageURI,
		}

		if _, err := backend.ArticleCreate(ctx, input); err != nil {
			stats.Errors++
			if verbose {
				fmt.Fprintf(os.Stderr, "\n  error creating article %q: %s\n", article.Title, err)
			}
			continue
		}
		stats.Created++
	}

	bar.Finish()
	return stats, nil
}

// remapAudienceExpr replaces source category UUIDs in the audience expression
// filter with target category UUIDs. Works by marshaling to JSON, doing string
// replacements, and unmarshaling back.
func remapAudienceExpr(expr atomic.AudienceExpr, uuidMap map[string]string) atomic.AudienceExpr {
	if len(uuidMap) == 0 {
		return expr
	}

	data, err := json.Marshal(expr)
	if err != nil {
		return expr
	}

	s := string(data)
	for sourceUUID, targetUUID := range uuidMap {
		s = strings.ReplaceAll(s, sourceUUID, targetUUID)
	}

	var result atomic.AudienceExpr
	if err := json.Unmarshal([]byte(s), &result); err != nil {
		return expr
	}

	return result
}

// importImageAsAsset creates a local asset from a remote image URL.
// The server downloads the image, determines size and mime type.
// Returns the local asset link URL on success.
func importImageAsAsset(ctx context.Context, imageURL string, _ bool) (string, error) {
	parsed, err := url.Parse(imageURL)
	if err != nil {
		return "", fmt.Errorf("invalid image URL: %w", err)
	}

	filename := path.Base(parsed.Path)
	if filename == "" || filename == "." || filename == "/" {
		filename = "image"
	}

	asset, err := backend.AssetCreate(ctx, &atomic.AssetCreateInput{
		InstanceID: &inst.UUID,
		Filename:   filename,
		URL:        &imageURL,
		Public:     true,
		Overwrite:  ptr.Bool(true),
	})
	if err != nil {
		return "", err
	}

	if asset.Link != nil {
		return *asset.Link, nil
	}

	return fmt.Sprintf("/assets/%s", asset.UUID), nil
}
