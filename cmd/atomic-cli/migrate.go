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
	"fmt"
	"os"
	"time"

	"github.com/apex/log"
	"github.com/charmbracelet/bubbles/progress"
	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/huh"
	"github.com/gocarina/gocsv"
	"github.com/libatomic/atomic/pkg/atomic"
	"github.com/libatomic/atomic/pkg/ptr"
	"github.com/libatomic/atomic/pkg/util"
	stripeclient "github.com/stripe/stripe-go/v79/client"
	"github.com/urfave/cli/v3"
)

type (
	migrationRecord struct {
		CustomerID    string
		Email         string
		Name          string
		PlanID        string
		Interval      atomic.SubscriptionInterval
		Currency      string
		Quantity      int
		AnchorDate    *time.Time
		EndAt         *time.Time
		UserAmount    int64
		DiscountPct   *float64
		DiscountTerm  *atomic.CreditTerm
		StripePriceID string
		StripeSubID   string
	}

	importRecord struct {
		atomic.UserImportRecord
		MigrateStripePrice        string `csv:"migrate_stripe_price,omitempty"`
		MigrateStripeSubscription string `csv:"migrate_stripe_subscription,omitempty"`
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
		&cli.BoolFlag{
			Name:  "subscription-prorate",
			Usage: "prorate subscriptions when migrating",
			Value: false,
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

func validateMigrateFlags(cmd *cli.Command) (dryRun bool, output string, prorate bool, err error) {
	dryRun = cmd.Bool("dry-run")
	output = cmd.String("output")
	prorate = cmd.Bool("subscription-prorate")

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

func writeImportCSV(records []*migrationRecord, outputPath string, dryRun bool, prorate bool) error {
	importRecords := make([]*importRecord, 0, len(records))

	for _, rec := range records {
		planID, err := atomic.ParseID(rec.PlanID)
		if err != nil && !dryRun {
			log.Warnf("invalid plan ID %s for %s; skipping", rec.PlanID, rec.Email)
			continue
		}

		ir := &importRecord{
			UserImportRecord: atomic.UserImportRecord{
				Login:                rec.Email,
				Email:                &rec.Email,
				EmailVerified:        ptr.Bool(true),
				Name:                 &rec.Name,
				StripeCustomerID:     &rec.CustomerID,
				SubscriptionPlanID:   &planID,
				SubscriptionQuantity: &rec.Quantity,
				SubscriptionInterval: (*atomic.SubscriptionInterval)(&rec.Interval),
				SubscriptionCurrency: &rec.Currency,
				SubscriptionProrate:  &prorate,
			},
			MigrateStripePrice:        rec.StripePriceID,
			MigrateStripeSubscription: rec.StripeSubID,
		}

		if rec.EndAt != nil {
			ir.SubscriptionEndAt = &util.Timestamp{Time: *rec.EndAt}
		} else if rec.AnchorDate != nil {
			ir.SubscriptionAnchorDate = &util.Date{Time: *rec.AnchorDate}
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
