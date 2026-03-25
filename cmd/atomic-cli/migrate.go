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
	"os"

	"github.com/apex/log"
	"github.com/charmbracelet/bubbles/progress"
	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/huh"
	"github.com/gocarina/gocsv"
	"github.com/libatomic/atomic/pkg/atomic"
	"github.com/libatomic/atomic/pkg/ptr"
	"github.com/stripe/stripe-go/v79"
	stripeclient "github.com/stripe/stripe-go/v79/client"
	"github.com/urfave/cli/v3"
)

type (
	migrationRecord struct {
		CustomerID     string
		Email          string
		Name           string
		PlanID         string
		Interval       atomic.SubscriptionInterval
		Currency       string
		UserAmount     int64
		PassportAmount int64
		DiscountPct    *float64
		DiscountTerm   *atomic.CreditTerm
	}

	passportPlanMapping struct {
		SubscriberPlanID string
		FounderPlanID    string
		MonthlyPriceID   string
		AnnualPriceID    string
		FounderPriceID   string
		MonthlyAmounts   map[string]int64 // currency -> amount in cents
		AnnualAmounts    map[string]int64
		FounderAmounts   map[string]int64
	}

	sourcePriceInfo struct {
		StripePrice *stripe.Price
		PriceType   string // "monthly", "annual", "founding"
	}

	// bubbletea models

	spinnerModel struct {
		spinner spinner.Model
		status  string
		done    bool
		err     error
		result  any
		work    func() (any, error)
	}

	progressModel struct {
		progress progress.Model
		current  int
		total    int
		status   string
		done     bool
		err      error
		result   any
		work     func(send func(progressTickMsg)) (any, error)
	}

	// bubbletea messages

	spinnerDoneMsg struct {
		result any
		err    error
	}

	progressTickMsg struct {
		current int
		total   int
		status  string
	}

	progressDoneMsg struct {
		result any
		err    error
	}
)

var (
	migrateCommonFlags = []cli.Flag{
		&cli.StringFlag{
			Name:  "stripe-key",
			Usage: "Stripe API key for the source account",
			Sources: cli.NewValueSourceChain(
				cli.EnvVar("STRIPE_API_KEY"),
			),
			Required: true,
		},
		&cli.BoolFlag{
			Name:  "dry-run",
			Usage: "preview what would happen without making changes",
		},
		&cli.StringFlag{
			Name:    "output",
			Aliases: []string{"out"},
			Usage:   "output CSV file path",
			Value:   "migrate_users.csv",
		},
	}

	migrateCmd = &cli.Command{
		Name:  "migrate",
		Usage: "migrate users from external platforms",
		Commands: []*cli.Command{
			migrateSubstackCmd,
		},
	}
)

// spinner model implementation

func newSpinnerModel(status string, work func() (any, error)) spinnerModel {
	s := spinner.New()
	s.Spinner = spinner.Dot
	return spinnerModel{
		spinner: s,
		status:  status,
		work:    work,
	}
}

func (m spinnerModel) Init() tea.Cmd {
	return tea.Batch(
		m.spinner.Tick,
		func() tea.Msg {
			result, err := m.work()
			return spinnerDoneMsg{result: result, err: err}
		},
	)
}

func (m spinnerModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		if msg.String() == "ctrl+c" {
			m.err = fmt.Errorf("interrupted")
			return m, tea.Quit
		}
	case spinnerDoneMsg:
		m.done = true
		m.result = msg.result
		m.err = msg.err
		return m, tea.Quit
	default:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd
	}
	return m, nil
}

func (m spinnerModel) View() string {
	if m.done {
		if m.err != nil {
			return fmt.Sprintf("✗ %s\n", m.err)
		}
		return fmt.Sprintf("✓ %s\n", m.status)
	}
	return fmt.Sprintf("%s %s\n", m.spinner.View(), m.status)
}

func runSpinner(status string, work func() (any, error)) (any, error) {
	m := newSpinnerModel(status, work)
	p := tea.NewProgram(m)
	final, err := p.Run()
	if err != nil {
		return nil, err
	}
	fm := final.(spinnerModel)
	return fm.result, fm.err
}

// progress model implementation

func newProgressModel(status string, work func(send func(progressTickMsg)) (any, error)) progressModel {
	return progressModel{
		progress: progress.New(progress.WithDefaultGradient()),
		status:   status,
		work:     work,
	}
}

func (m progressModel) Init() tea.Cmd {
	return func() tea.Msg {
		// this is a placeholder; actual work is started via p.Send from the goroutine
		return nil
	}
}

func (m progressModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		if msg.String() == "ctrl+c" {
			m.err = fmt.Errorf("interrupted")
			return m, tea.Quit
		}
	case progressTickMsg:
		m.current = msg.current
		m.total = msg.total
		if msg.status != "" {
			m.status = msg.status
		}
		if m.total > 0 {
			cmd := m.progress.SetPercent(float64(m.current) / float64(m.total))
			return m, cmd
		}
		return m, nil
	case progressDoneMsg:
		m.done = true
		m.result = msg.result
		m.err = msg.err
		cmd := m.progress.SetPercent(1.0)
		return m, tea.Batch(cmd, tea.Quit)
	case progress.FrameMsg:
		var cmd tea.Cmd
		tmp, cmd := m.progress.Update(msg)
		m.progress = tmp.(progress.Model)
		if m.done {
			return m, tea.Batch(cmd, tea.Quit)
		}
		return m, cmd
	}
	return m, nil
}

func (m progressModel) View() string {
	if m.done {
		if m.err != nil {
			return fmt.Sprintf("✗ %s\n", m.err)
		}
		return fmt.Sprintf("✓ %s (%d items)\n", m.status, m.current)
	}

	countStr := ""
	if m.total > 0 {
		countStr = fmt.Sprintf(" %d/%d", m.current, m.total)
	} else if m.current > 0 {
		countStr = fmt.Sprintf(" %d", m.current)
	}

	return fmt.Sprintf("%s\n  %s%s\n", m.progress.View(), m.status, countStr)
}

func runProgress(status string, work func(send func(progressTickMsg)) (any, error)) (any, error) {
	m := newProgressModel(status, work)
	p := tea.NewProgram(m)

	go func() {
		result, err := work(func(tick progressTickMsg) {
			p.Send(tick)
		})
		p.Send(progressDoneMsg{result: result, err: err})
	}()

	final, err := p.Run()
	if err != nil {
		return nil, err
	}
	fm := final.(progressModel)
	return fm.result, fm.err
}

// common migrate functions

func initStripeClient(apiKey string) *stripeclient.API {
	sc := &stripeclient.API{}
	sc.Init(apiKey, nil)
	return sc
}

func validateMigrateFlags(cmd *cli.Command) (dryRun bool, output string, err error) {
	dryRun = cmd.Bool("dry-run")
	output = cmd.String("output")

	if inst == nil {
		err = fmt.Errorf("instance is required; use --instance_id or -i")
		return
	}

	return
}

func confirmAction(title string) (bool, error) {
	var confirmed bool
	err := huh.NewConfirm().
		Title(title).
		Affirmative("Yes").
		Negative("No").
		Value(&confirmed).
		Run()
	return confirmed, err
}

func handleCreatePlans(ctx context.Context, activePrices []*sourcePriceInfo, dryRun bool) (*passportPlanMapping, error) {
	mapping := &passportPlanMapping{
		MonthlyAmounts: make(map[string]int64),
		AnnualAmounts:  make(map[string]int64),
		FounderAmounts: make(map[string]int64),
	}

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
			buildAmountMap(monthlyPrice.StripePrice, mapping.MonthlyAmounts)
		}
		if annualPrice != nil {
			buildAmountMap(annualPrice.StripePrice, mapping.AnnualAmounts)
		}
		if founderPrice != nil {
			buildAmountMap(founderPrice.StripePrice, mapping.FounderAmounts)
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
				InstanceID: inst.UUID,
				Name:       "Subscriber",
				Type:       atomic.PlanTypePaid,
				Active:     ptr.Bool(true),
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
				buildAmountMap(monthlyPrice.StripePrice, mapping.MonthlyAmounts)
			}

			if annualPrice != nil {
				price, err := createPassportPrice(ctx, subscriberPlan.UUID, "Annual", annualPrice.StripePrice, "year")
				if err != nil {
					return nil, err
				}
				mapping.AnnualPriceID = string(price.UUID)
				buildAmountMap(annualPrice.StripePrice, mapping.AnnualAmounts)
			}
		}

		// Create Founder plan
		if founderPrice != nil {
			founderPlan, err := backend.PlanCreate(ctx, &atomic.PlanCreateInput{
				InstanceID: inst.UUID,
				Name:       "Founder",
				Type:       atomic.PlanTypePaid,
				Active:     ptr.Bool(true),
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
			buildAmountMap(founderPrice.StripePrice, mapping.FounderAmounts)
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
		mapping := &passportPlanMapping{
			MonthlyAmounts: make(map[string]int64),
			AnnualAmounts:  make(map[string]int64),
			FounderAmounts: make(map[string]int64),
		}

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
				if price.FlatAmount != nil {
					mapping.MonthlyAmounts[price.Currency] = *price.FlatAmount
				}
				for cur, opt := range price.CurrencyOptions {
					if opt.UnitAmount != nil {
						mapping.MonthlyAmounts[cur] = *opt.UnitAmount
					}
				}
			case atomic.SubscriptionIntervalYear:
				mapping.AnnualPriceID = string(price.UUID)
				if price.FlatAmount != nil {
					mapping.AnnualAmounts[price.Currency] = *price.FlatAmount
				}
				for cur, opt := range price.CurrencyOptions {
					if opt.UnitAmount != nil {
						mapping.AnnualAmounts[cur] = *opt.UnitAmount
					}
				}
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
					if price.FlatAmount != nil {
						mapping.FounderAmounts[price.Currency] = *price.FlatAmount
					}
					for cur, opt := range price.CurrencyOptions {
						if opt.UnitAmount != nil {
							mapping.FounderAmounts[cur] = *opt.UnitAmount
						}
					}
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

func calculatePerUserDiscounts(records []*migrationRecord, mapping *passportPlanMapping) {
	for _, rec := range records {
		if rec.PassportAmount <= 0 {
			log.Warnf("no Passport price found in %s for %s; skipping discount", rec.Currency, rec.Email)
			continue
		}

		if rec.UserAmount >= rec.PassportAmount {
			continue
		}

		pct := math.Round((1.0-float64(rec.UserAmount)/float64(rec.PassportAmount))*10000) / 100
		term := atomic.CreditTermForever
		rec.DiscountPct = &pct
		rec.DiscountTerm = &term
	}
}

func writeImportCSV(records []*migrationRecord, outputPath string, dryRun bool) error {
	importRecords := make([]*atomic.UserImportRecord, 0, len(records))

	for _, rec := range records {
		planID, err := atomic.ParseID(rec.PlanID)
		if err != nil && !dryRun {
			log.Warnf("invalid plan ID %s for %s; skipping", rec.PlanID, rec.Email)
			continue
		}

		ir := &atomic.UserImportRecord{
			Login:                rec.Email,
			Email:                &rec.Email,
			EmailVerified:        ptr.Bool(true),
			Name:                 &rec.Name,
			StripeCustomerID:     &rec.CustomerID,
			SubscriptionPlanID:   &planID,
			SubscriptionInterval: (*atomic.SubscriptionInterval)(&rec.Interval),
			SubscriptionCurrency: &rec.Currency,
		}

		if rec.DiscountPct != nil {
			ir.DiscountPercentage = rec.DiscountPct
			ir.DiscountTerm = rec.DiscountTerm
		}

		importRecords = append(importRecords, ir)
	}

	file, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer file.Close()

	return gocsv.MarshalFile(&importRecords, file)
}

func getPassportAmount(mapping *passportPlanMapping, priceType, currency string) int64 {
	var amounts map[string]int64

	switch priceType {
	case "monthly":
		amounts = mapping.MonthlyAmounts
	case "annual":
		amounts = mapping.AnnualAmounts
	case "founding":
		amounts = mapping.FounderAmounts
	}

	if amounts == nil {
		return 0
	}

	if amt, ok := amounts[currency]; ok {
		return amt
	}

	return 0
}

func getUserAmount(p *stripe.Price, currency string) int64 {
	if string(p.Currency) == currency {
		return p.UnitAmount
	}

	if opt, ok := p.CurrencyOptions[currency]; ok {
		return opt.UnitAmount
	}

	return p.UnitAmount
}

func buildAmountMap(sp *stripe.Price, amounts map[string]int64) {
	amounts[string(sp.Currency)] = sp.UnitAmount
	for cur, opt := range sp.CurrencyOptions {
		amounts[cur] = opt.UnitAmount
	}
}

func printStripeCurrencyOptions(sp *stripe.Price) {
	for cur, opt := range sp.CurrencyOptions {
		fmt.Printf("      └─ %s: %d\n", cur, opt.UnitAmount)
	}
}
