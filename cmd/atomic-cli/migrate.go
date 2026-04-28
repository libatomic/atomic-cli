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
		CustomerID        string
		Email             string
		Name              string
		PlanID            string
		IsTeamOwner       bool
		TeamKey           string
		Interval          atomicpkg.SubscriptionInterval
		Currency          string
		Quantity          int
		CreatedAt         *time.Time // user created_at; sourced from stripe customer.created
		AnchorDate        *time.Time
		EndAt             *time.Time // terminal end date — for subs that have already ended
		// CancelAt is a future scheduled cancellation date. The subscription
		// stays active until then. Sourced from stripe subscription.cancel_at.
		CancelAt *time.Time
		// CancelAtPeriodEnd indicates the subscription should cancel at the
		// end of the current billing period. Sourced from stripe
		// subscription.cancel_at_period_end.
		CancelAtPeriodEnd bool
		// TrialEndAt is the moment the trial converts to paid. Sourced from
		// stripe subscription.trial_end (when > 0).
		TrialEndAt *time.Time
		// TrialEndBehavior controls what happens when the trial ends without
		// a payment method. Sourced from
		// subscription.trial_settings.end_behavior.missing_payment_method.
		TrialEndBehavior *atomicpkg.PriceTrialEndBehavior
		UserAmount       int64
		DiscountPct       *float64
		DiscountTerm      *atomicpkg.CreditTerm
		PaymentMethod     string
		StripePriceID     string
		StripeSubID       string
		ImportComment     string
	}

	importRecord struct {
		atomicpkg.UserImportRecord
		MigrateStripePrice        string `csv:"migrate_stripe_price,omitempty"`
		MigrateStripeSubscription string `csv:"migrate_stripe_subscription,omitempty"`
		// MapError captures any non-fatal issue encountered while mapping the row
		// (e.g. a stripe customer that could not be found). Empty for clean rows.
		MapError string `csv:"map_error,omitempty"`
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
	DefaultMigrateOutputPath         = "migrate_users.csv"
	DefaultMigrateSubstackOutputPath = "migrate_substack.csv"
	DefaultMigrateMapOutputPath      = "migrate_map.csv"
)

// promptOverwriteIfExists checks whether the given output path already exists
// and, if so, prompts the user to confirm overwriting. Append mode is exempt
// since it merges into the existing file.
func promptOverwriteIfExists(path string, appendMode bool) error {
	if appendMode {
		return nil
	}
	if _, err := os.Stat(path); err != nil {
		return nil
	}
	confirmed, err := confirmAction(fmt.Sprintf("Output %s already exists; overwrite?", path))
	if err != nil {
		return err
	}
	if !confirmed {
		return fmt.Errorf("aborted — output file already exists")
	}
	return nil
}

var (
	migrateCommonFlags = []cli.Flag{
		&cli.BoolFlag{
			Name:  "dry-run",
			Usage: "preview without writing changes",
		},
		&cli.StringFlag{
			Name:    "output",
			Aliases: []string{"out", "o"},
			Usage:   "output CSV path",
			Value:   DefaultMigrateOutputPath,
		},
		&cli.BoolFlag{
			Name:  "subscription-prorate",
			Usage: "prorate subscriptions",
			Value: false,
		},
		&cli.StringFlag{
			Name:  "email-domain-overwrite",
			Usage: "rewrite email domains (mutually exclusive with --email-template)",
		},
		&cli.StringFlag{
			Name:  "email-template",
			Usage: "rewrite emails from template (see docs); mutually exclusive with --email-domain-overwrite",
		},
		&cli.BoolFlag{
			Name:  "append",
			Usage: "append to output CSV; dedupe on login",
			Value: true,
		},
		&cli.StringFlag{
			Name:  "source",
			Usage: "value for import_source on each record",
		},
		&cli.IntFlag{
			Name:  "limit",
			Usage: "max records per CSV (0 = no limit)",
			Value: 0,
		},
		&cli.IntFlag{
			Name:  "skip",
			Usage: "skip first N records (0 = none)",
			Value: 0,
		},
	}

	migrateCmd = &cli.Command{
		Name:  "migrate",
		Usage: "migrate users from external platforms",
		// these flags live on the parent command so every migrate subcommand
		// (map, substack, validate, and anything added later) shares the same
		// post-processing behavior without each one redeclaring the flags
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "stripe-key",
				Aliases: []string{"sk"},
				Usage:   "Stripe API key (sk_...) shared by all migrate subcommands; required by `migrate substack` and by stripe.* expr functions in `migrate map`",
				Sources: cli.NewValueSourceChain(
					cli.EnvVar("STRIPE_API_KEY"),
					NewCredentialsSource("stripe_key", func() string { return creds }, func() string { return profile }),
				),
			},
			&cli.BoolFlag{
				Name:  "validate",
				Usage: "validate the output CSV after mapping (structural checks + uniqueness report)",
				Value: true,
			},
			&cli.BoolFlag{
				Name:  "dedupe",
				Usage: "deduplicate the output CSV on --dedupe-columns after mapping; first occurrence wins",
				Value: true,
			},
			&cli.StringSliceFlag{
				Name:  "dedupe-columns",
				Usage: "columns used to detect duplicates when --dedupe is set (valid: login, email, phone_number, stripe_customer_id); repeatable, earlier columns act as tie-breakers",
				Value: []string{"login"},
			},
			&cli.BoolFlag{
				Name:  "merge",
				Usage: "when deduping, merge empty fields from duplicate rows into the first occurrence instead of dropping them outright",
				Value: true,
			},
		},
		Commands: []*cli.Command{
			migrateSubstackCmd,
			migrateConvertCmd,
			migrateValidateCmd,
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
		progressbar.OptionUseANSICodes(true),
	)
}

func newMigrateProgress(total int, description string) *progressbar.ProgressBar {
	return progressbar.NewOptions(total,
		progressbar.OptionSetDescription(description),
		progressbar.OptionSetWriter(os.Stderr),
		progressbar.OptionShowCount(),
		progressbar.OptionClearOnFinish(),
		progressbar.OptionUseANSICodes(true),
	)
}

func initStripeClient(apiKey string) (*stripeclient.API, error) {
	if apiKey == "" {
		return nil, fmt.Errorf("stripe API key is required")
	}

	return stripeclient.New(apiKey, nil), nil
}

func validateMigrateFlags(cmd *cli.Command, requireInstance ...bool) (dryRun bool, output string, prorate bool, rewriter *emailRewriter, appendMode bool, source string, limit, skip int, err error) {
	dryRun = cmd.Bool("dry-run")
	output = cmd.String("output")
	prorate = cmd.Bool("subscription-prorate")
	appendMode = cmd.Bool("append")
	source = cmd.String("source")
	limit = int(cmd.Int("limit"))
	skip = int(cmd.Int("skip"))

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

// sanitizeEmail converts an email to a lowercase login-safe string.
// Bob+Test@Hotmail.com → bob*test*hotmail.com
func sanitizeEmail(email string) string {
	r := strings.NewReplacer("@", "*", "+", "*")
	return strings.ToLower(r.Replace(email))
}

// shortHash returns the first 8 hex characters of the SHA-256 hash.
func shortHash(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])[:8]
}

func writeImportCSV(records []*migrationRecord, outputPath string, dryRun bool, prorate bool, rewriter *emailRewriter, appendMode bool, source string, limit, skip int, omitCustomerID ...bool) error {
	importRecords := make([]*importRecord, 0, len(records))

	for _, rec := range records {
		login := rewriter.Rewrite(rec.Email)
		email := login

		skipCustomer := len(omitCustomerID) > 0 && omitCustomerID[0]

		ir := &importRecord{
			UserImportRecord: atomicpkg.UserImportRecord{
				Login:                login,
				Email:                &email,
				EmailVerified:        ptr.Bool(true),
				Name:                 &rec.Name,
				SubscriptionQuantity: &rec.Quantity,
				SubscriptionInterval: (*atomicpkg.SubscriptionInterval)(&rec.Interval),
				SubscriptionCurrency: &rec.Currency,
				SubscriptionProrate:  &prorate,
			},
			MigrateStripePrice:        rec.StripePriceID,
			MigrateStripeSubscription: rec.StripeSubID,
		}

		if !skipCustomer && rec.CustomerID != "" {
			ir.StripeCustomerID = &rec.CustomerID
		}

		if rec.PaymentMethod != "" {
			ir.SubscriptionPaymentMethod = &rec.PaymentMethod
		}

		// when email rewriting is active, store the original email and customer ID
		// as stripe customer metadata so the migration can be traced back
		if rewriter != nil && rec.Email != "" {
			if ir.StripeCustomerMetadata == nil {
				ir.StripeCustomerMetadata = make(util.Map[string, string])
			}
			ir.StripeCustomerMetadata["atomic_migrate:customer_email"] = rec.Email
			if rec.CustomerID != "" {
				ir.StripeCustomerMetadata["atomic_migrate:customer_id"] = rec.CustomerID
			}
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

		if rec.EndAt != nil {
			ir.SubscriptionEndAt = &util.Timestamp{Time: rec.EndAt.UTC()}
		} else if rec.AnchorDate != nil {
			ir.SubscriptionAnchorDate = &util.Timestamp{Time: rec.AnchorDate.UTC()}
		}

		// scheduled cancellation state — distinct from EndAt; the sub stays
		// active until the cancel date / period end fires
		if rec.CancelAt != nil {
			ir.SubscriptionCancelAt = &util.Timestamp{Time: rec.CancelAt.UTC()}
		}
		if rec.CancelAtPeriodEnd {
			t := true
			ir.SubscriptionCancelAtPeriodEnd = &t
		}

		if rec.TrialEndAt != nil {
			ir.SubscriptionTrialEndAt = &util.Timestamp{Time: rec.TrialEndAt.UTC()}
		}
		if rec.TrialEndBehavior != nil {
			ir.SubscriptionTrialEndBehavior = rec.TrialEndBehavior
		}

		if rec.CreatedAt != nil {
			ir.CreatedAt = &util.Timestamp{Time: rec.CreatedAt.UTC()}
		}

		if rec.ImportComment != "" {
			comment := rec.ImportComment
			ir.ImportComment = &comment
		}

		if rec.DiscountPct != nil {
			ir.DiscountPercentage = rec.DiscountPct
			ir.DiscountTerm = rec.DiscountTerm
		}

		importRecords = append(importRecords, ir)
	}

	if skip > 0 && len(importRecords) > skip {
		importRecords = importRecords[skip:]
	} else if skip > 0 {
		importRecords = nil
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
