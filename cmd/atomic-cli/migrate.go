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
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/apex/log"
	"github.com/gocarina/gocsv"
	"github.com/libatomic/atomic/pkg/atomic"
	"github.com/libatomic/atomic/pkg/ptr"
	"github.com/libatomic/atomic/pkg/util"
	"github.com/schollz/progressbar/v3"
	stripeclient "github.com/stripe/stripe-go/v79/client"
	"github.com/urfave/cli/v3"
)

type (
	migrationRecord struct {
		CustomerID    string
		Email         string
		BillingEmail  string
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
)

var (
	migrateCommonFlags = []cli.Flag{
		&cli.StringFlag{
			Name:  "stripe-key",
			Usage: "Stripe API key for the source account",
			Sources: cli.NewValueSourceChain(
				cli.EnvVar("STRIPE_API_KEY"),
			),
			Required: false,
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
		&cli.StringFlag{
			Name:  "email-domain-overwrite",
			Usage: "rewrite all email addresses to use this domain (e.g. passport.xyz); for testing",
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

func newMigrateSpinner(description string) *progressbar.ProgressBar {
	return progressbar.NewOptions(-1,
		progressbar.OptionSetDescription(description),
		progressbar.OptionSetWriter(os.Stderr),
		progressbar.OptionSpinnerType(14),
		progressbar.OptionShowCount(),
		progressbar.OptionClearOnFinish(),
	)
}

func newMigrateProgress(total int, description string) *progressbar.ProgressBar {
	return progressbar.NewOptions(total,
		progressbar.OptionSetDescription(description),
		progressbar.OptionSetWriter(os.Stderr),
		progressbar.OptionShowCount(),
		progressbar.OptionClearOnFinish(),
	)
}

func initStripeClient(apiKey string) (*stripeclient.API, error) {
	if apiKey == "" {
		return nil, fmt.Errorf("stripe API key is required")
	}

	return stripeclient.New(apiKey, nil), nil
}

func validateMigrateFlags(cmd *cli.Command) (dryRun bool, output string, prorate bool, emailDomain string, err error) {
	dryRun = cmd.Bool("dry-run")
	output = cmd.String("output")
	prorate = cmd.Bool("subscription-prorate")
	emailDomain = cmd.String("email-domain-overwrite")

	if inst == nil {
		err = fmt.Errorf("instance is required; use --instance_id or -i")
		return
	}

	return
}

func confirmAction(title string) (bool, error) {
	fmt.Fprintf(os.Stderr, "%s [y/N]: ", title)
	reader := bufio.NewReader(os.Stdin)
	answer, err := reader.ReadString('\n')
	if err != nil {
		return false, err
	}
	answer = strings.TrimSpace(strings.ToLower(answer))
	return answer == "y" || answer == "yes", nil
}

func rewriteEmail(email, domain string) string {
	return strings.Replace(email, "@", "-", 1) + "@" + domain
}

func writeImportCSV(records []*migrationRecord, outputPath string, dryRun bool, prorate bool, emailDomain string) error {
	importRecords := make([]*importRecord, 0, len(records))

	for _, rec := range records {
		planID, err := atomic.ParseID(rec.PlanID)
		if err != nil && !dryRun {
			log.Warnf("invalid plan ID %s for %s; skipping", rec.PlanID, rec.Email)
			continue
		}

		login := rec.Email
		email := rec.Email

		if emailDomain != "" {
			login = rewriteEmail(login, emailDomain)
			email = rewriteEmail(email, emailDomain)
		}

		ir := &importRecord{
			UserImportRecord: atomic.UserImportRecord{
				Login:                login,
				Email:                &email,
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

		if rec.BillingEmail != "" {
			billingEmail := rec.BillingEmail
			if emailDomain != "" {
				billingEmail = rewriteEmail(billingEmail, emailDomain)
			}
			ir.BillingEmail = &billingEmail
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
