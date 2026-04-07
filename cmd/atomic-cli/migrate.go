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
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/apex/log"
	"github.com/gocarina/gocsv"
	atomicpkg "github.com/libatomic/atomic/pkg/atomic"
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
		IsTeamOwner   bool
		TeamKey       string
		Interval      atomicpkg.SubscriptionInterval
		Currency      string
		Quantity      int
		AnchorDate    *time.Time
		EndAt         *time.Time
		UserAmount    int64
		DiscountPct   *float64
		DiscountTerm  *atomicpkg.CreditTerm
		StripePriceID string
		StripeSubID   string
	}

	importRecord struct {
		atomicpkg.UserImportRecord
		MigrateStripePrice        string `csv:"migrate_stripe_price,omitempty"`
		MigrateStripeSubscription string `csv:"migrate_stripe_subscription,omitempty"`
	}

	// emailRewriter rewrites email addresses for testing/sandbox environments.
	// It supports two mutually exclusive modes:
	//   - domain mode: rewrites the domain portion (e.g. bob@hotmail.com → bob-hotmail.com@sandbox.xyz)
	//   - template mode: generates emails from a template with functions like {{seq}}, {{hash}}, {{sanitize}}
	emailRewriter struct {
		domain   string // domain mode
		template string // template mode
		seq      atomic.Int64
		mu       sync.Mutex
	}
)

const (
	DefaultMigrateOutputPath = "migrate_users.csv"
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
			Aliases: []string{"out", "o"},
			Usage:   "output CSV file path",
			Value:   DefaultMigrateOutputPath,
		},
		&cli.BoolFlag{
			Name:  "subscription-prorate",
			Usage: "prorate subscriptions when migrating",
			Value: false,
		},
		&cli.StringFlag{
			Name:  "email-domain-overwrite",
			Usage: "rewrite all email addresses to use this domain (e.g. passport.xyz); mutually exclusive with --email-template",
		},
		&cli.StringFlag{
			Name: "email-template",
			Usage: `generate email addresses from a template; mutually exclusive with --email-domain-overwrite.
Supported functions:
  {{seq}}            sequential number (1, 2, 3, ...)
  {{seq "user"}}     prefixed sequential number (user1, user2, ...)
  {{hash}}           short hash of the original email
  {{hash "u"}}       prefixed hash (u3f2a1b, ...)
  {{sanitize}}       sanitized original email (bob+test@hot.com → bob_test_hot_com)
Example: "sandbox+{{seq "user"}}@inbox.mailtrap.io -> sandbox-12ab34+user1@inbox.mailtrap.io, sandbox-12ab34+user2@inbox.mailtrap.io, ...`,
		},
		&cli.BoolFlag{
			Name:  "append",
			Usage: "append to the output CSV instead of overwriting; deduplicates on login (existing rows win)",
			Value: true,
		},
		&cli.StringFlag{
			Name:  "source",
			Usage: "import source identifier set on each record's import_source field",
		},
		&cli.IntFlag{
			Name:  "limit",
			Usage: "limit the number of records in each output CSV; 0 = no limit",
			Value: 0,
		},
	}

	migrateCmd = &cli.Command{
		Name:  "migrate",
		Usage: "migrate users from external platforms",
		Commands: []*cli.Command{
			migrateSubstackCmd,
			migrateConvertCmd,
			migrateVerifyCmd,
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

func validateMigrateFlags(cmd *cli.Command, requireInstance ...bool) (dryRun bool, output string, prorate bool, rewriter *emailRewriter, appendMode bool, source string, limit int, err error) {
	dryRun = cmd.Bool("dry-run")
	output = cmd.String("output")
	prorate = cmd.Bool("subscription-prorate")
	appendMode = cmd.Bool("append")
	source = cmd.String("source")
	limit = int(cmd.Int("limit"))

	emailDomain := cmd.String("email-domain-overwrite")
	emailTemplate := cmd.String("email-template")

	if emailDomain != "" && emailTemplate != "" {
		err = fmt.Errorf("--email-domain-overwrite and --email-template are mutually exclusive")
		return
	}

	if emailDomain != "" {
		rewriter = &emailRewriter{domain: emailDomain}
	} else if emailTemplate != "" {
		rewriter = &emailRewriter{template: emailTemplate}
	}

	needsInstance := len(requireInstance) == 0 || requireInstance[0]
	if needsInstance && inst == nil {
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

// Rewrite rewrites an email address according to the configured mode.
// Returns the original email if the rewriter is nil.
func (r *emailRewriter) Rewrite(email string) string {
	if r == nil {
		return email
	}

	if r.domain != "" {
		return strings.Replace(email, "@", "-", 1) + "@" + r.domain
	}

	return r.applyTemplate(email)
}

func (r *emailRewriter) applyTemplate(original string) string {
	result := r.template

	// process {{sanitize}} first since other functions don't depend on it
	if strings.Contains(result, "{{sanitize}}") {
		result = strings.ReplaceAll(result, "{{sanitize}}", sanitizeEmail(original))
	}

	// process {{hash ...}} variants
	for {
		idx := strings.Index(result, "{{hash")
		if idx < 0 {
			break
		}
		end := strings.Index(result[idx:], "}}")
		if end < 0 {
			break
		}
		end += idx + 2

		tag := result[idx:end]
		prefix := extractTemplateArg(tag, "hash")
		h := shortHash(original)

		result = strings.Replace(result, tag, prefix+h, 1)
	}

	// process {{seq ...}} variants
	for {
		idx := strings.Index(result, "{{seq")
		if idx < 0 {
			break
		}
		end := strings.Index(result[idx:], "}}")
		if end < 0 {
			break
		}
		end += idx + 2

		tag := result[idx:end]
		prefix := extractTemplateArg(tag, "seq")
		n := r.seq.Add(1)

		result = strings.Replace(result, tag, fmt.Sprintf("%s%d", prefix, n), 1)
	}

	return result
}

// extractTemplateArg extracts the quoted string argument from a template tag.
// e.g. extractTemplateArg(`{{seq "user"}}`, "seq") returns "user"
// e.g. extractTemplateArg(`{{seq}}`, "seq") returns ""
func extractTemplateArg(tag, funcName string) string {
	inner := strings.TrimPrefix(tag, "{{"+funcName)
	inner = strings.TrimSuffix(inner, "}}")
	inner = strings.TrimSpace(inner)

	// check for quoted argument
	if len(inner) >= 2 && inner[0] == '"' && inner[len(inner)-1] == '"' {
		return inner[1 : len(inner)-1]
	}

	return ""
}

// sanitizeEmail converts an email to a safe string.
// bob+test@hotmail.com → bob_test_hotmail_com
func sanitizeEmail(email string) string {
	r := strings.NewReplacer("@", "_", ".", "_", "+", "_", "-", "_")
	return r.Replace(email)
}

// shortHash returns the first 8 hex characters of the SHA-256 hash.
func shortHash(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])[:8]
}

func writeImportCSV(records []*migrationRecord, outputPath string, dryRun bool, prorate bool, rewriter *emailRewriter, appendMode bool, source string, limit int) error {
	importRecords := make([]*importRecord, 0, len(records))

	for _, rec := range records {
		login := rewriter.Rewrite(rec.Email)
		email := login

		ir := &importRecord{
			UserImportRecord: atomicpkg.UserImportRecord{
				Login:                login,
				Email:                &email,
				EmailVerified:        ptr.Bool(true),
				Name:                 &rec.Name,
				StripeCustomerID:     &rec.CustomerID,
				SubscriptionQuantity: &rec.Quantity,
				SubscriptionInterval: (*atomicpkg.SubscriptionInterval)(&rec.Interval),
				SubscriptionCurrency: &rec.Currency,
				SubscriptionProrate:  &prorate,
			},
			MigrateStripePrice:        rec.StripePriceID,
			MigrateStripeSubscription: rec.StripeSubID,
		}

		if source != "" {
			ir.ImportSource = &source
		}

		if rec.IsTeamOwner {
			ir.IsTeamOwner = ptr.Bool(true)
		}

		if rec.TeamKey != "" {
			ir.TeamKey = &rec.TeamKey
		}

		if rec.PlanID != "" {
			planID, err := atomicpkg.ParseID(rec.PlanID)
			if err != nil && !dryRun {
				log.Warnf("invalid plan ID %s for %s; skipping", rec.PlanID, rec.Email)
				continue
			}
			ir.SubscriptionPlanID = &planID
		}

		if rec.BillingEmail != "" {
			billingEmail := rewriter.Rewrite(rec.BillingEmail)
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

	if limit > 0 && len(importRecords) > limit {
		importRecords = importRecords[:limit]
	}

	if appendMode {
		var appendErr error
		importRecords, appendErr = appendExistingCSV(outputPath, importRecords)
		if appendErr != nil {
			return appendErr
		}
	}

	file, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer file.Close()

	return gocsv.MarshalFile(&importRecords, file)
}

// appendExistingCSV reads existing records from the CSV file and merges them with new records.
// Existing records win on login conflict.
func appendExistingCSV(outputPath string, newRecords []*importRecord) ([]*importRecord, error) {
	existingFile, err := os.Open(outputPath)
	if err != nil {
		if os.IsNotExist(err) {
			return newRecords, nil
		}
		return nil, fmt.Errorf("failed to open existing CSV for append: %w", err)
	}
	defer existingFile.Close()

	var existingRecords []*importRecord
	if err := gocsv.UnmarshalFile(existingFile, &existingRecords); err != nil {
		return nil, fmt.Errorf("failed to parse existing CSV for append: %w", err)
	}

	seen := make(map[string]bool, len(existingRecords))
	for _, rec := range existingRecords {
		seen[strings.ToLower(rec.Login)] = true
	}

	for _, rec := range newRecords {
		if !seen[strings.ToLower(rec.Login)] {
			existingRecords = append(existingRecords, rec)
			seen[strings.ToLower(rec.Login)] = true
		}
	}

	return existingRecords, nil
}
