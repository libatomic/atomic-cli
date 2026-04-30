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
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/stripe/stripe-go/v79"
	stripeclient "github.com/stripe/stripe-go/v79/client"
	"github.com/urfave/cli/v3"
)

var (
	stripeInvoiceCmd = &cli.Command{
		Name:    "invoice",
		Aliases: []string{"invoices", "inv"},
		Usage:   "stripe invoice management",
		Commands: []*cli.Command{
			stripeInvoiceListCmd,
			stripeInvoiceGetCmd,
		},
	}

	stripeInvoiceListCmd = &cli.Command{
		Name:  "list",
		Usage: "list stripe invoices",
		Description: "List stripe invoices, optionally filtered by status, customer, " +
			"subscription, collection method, and time ranges. Defaults to status=open " +
			"so the typical use case (find unpaid invoices, including those tied to " +
			"canceled subscriptions) needs no flags. Use --past-due for the " +
			"open-and-overdue subset.",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  "status",
				Usage: "invoice status (one of: draft, open, paid, void, uncollectible). default: open",
				Value: "open",
			},
			&cli.BoolFlag{
				Name:  "past-due",
				Usage: "only invoices whose due_date is in the past (forces --status=open if not explicitly set)",
			},
			&cli.BoolFlag{
				Name:  "failed",
				Usage: "only invoices whose latest payment attempt actually failed. shorthand for --attempts 1 plus a check on the payment_intent / charge for a failure code or failed status",
			},
			&cli.StringFlag{
				Name:    "customer",
				Aliases: []string{"c"},
				Usage:   "filter to a single stripe customer id",
			},
			&cli.StringFlag{
				Name:    "subscription",
				Aliases: []string{"s"},
				Usage:   "filter to a single stripe subscription id (works for canceled subs too)",
			},
			&cli.StringFlag{
				Name:  "collection-method",
				Usage: "filter by collection method (charge_automatically, send_invoice)",
			},
			&cli.StringSliceFlag{
				Name:  "created",
				Usage: "filter on invoice.created, e.g. '>= now-30d'; repeatable for both bounds",
			},
			&cli.StringSliceFlag{
				Name:  "due",
				Usage: "filter on invoice.due_date (only set on send_invoice collection); same form as --created",
			},
			&cli.StringFlag{
				Name:  "created-before",
				Usage: "shorthand for --created '< T' (T is RFC3339 / date / unix-seconds / now+/-<duration>)",
			},
			&cli.StringFlag{
				Name:  "created-after",
				Usage: "shorthand for --created '>= T' (same time forms as --created-before)",
			},
			&cli.StringFlag{
				Name:  "due-before",
				Usage: "shorthand for --due '< T' (excludes invoices with no due_date)",
			},
			&cli.StringFlag{
				Name:  "due-after",
				Usage: "shorthand for --due '>= T' (excludes invoices with no due_date)",
			},
			&cli.BoolFlag{
				Name:  "collection-disabled",
				Usage: "only invoices with no next_payment_attempt scheduled (stripe has stopped retrying). useful for the charge_automatically invoices that have no due_date",
			},
			&cli.IntFlag{
				Name:  "attempts",
				Usage: "only invoices whose attempt_count is >= N",
			},
			&cli.IntFlag{
				Name:  "limit",
				Usage: "stop after N matching invoices; 0 = no limit",
				Value: 0,
			},
			&cli.StringFlag{
				Name:    "out",
				Aliases: []string{"O"},
				Usage:   "write rows to a file; format picked from extension (.csv, .json, .jsonl/.ndjson)",
			},
		},
		Action: stripeInvoiceListAction,
	}

	stripeInvoiceGetCmd = &cli.Command{
		Name:      "get",
		Usage:     "get a single stripe invoice by id",
		ArgsUsage: "<invoice_id>",
		Action:    stripeInvoiceGetAction,
	}
)

func stripeInvoiceListAction(ctx context.Context, cmd *cli.Command) error {
	sc := stripeclient.New(cmd.String("stripe-key"), nil)

	listParams := &stripe.InvoiceListParams{}

	status := cmd.String("status")
	pastDue := cmd.Bool("past-due")
	failed := cmd.Bool("failed")
	if (pastDue || failed) && !cmd.IsSet("status") {
		// past-due / failed are only meaningful for unpaid invoices
		status = "open"
	}
	if status != "" {
		if !validInvoiceStatuses[status] {
			return fmt.Errorf("invalid --status %q (valid: draft, open, paid, void, uncollectible)", status)
		}
		listParams.Status = stripe.String(status)
	}

	if v := cmd.String("customer"); v != "" {
		listParams.Customer = stripe.String(v)
	}
	if v := cmd.String("subscription"); v != "" {
		listParams.Subscription = stripe.String(v)
	}
	if v := cmd.String("collection-method"); v != "" {
		switch v {
		case string(stripe.InvoiceCollectionMethodChargeAutomatically),
			string(stripe.InvoiceCollectionMethodSendInvoice):
		default:
			return fmt.Errorf("invalid --collection-method %q (valid: charge_automatically, send_invoice)", v)
		}
		listParams.CollectionMethod = stripe.String(v)
	}

	for _, expr := range cmd.StringSlice("created") {
		r, err := mergeTimeFilterExpr(listParams.CreatedRange, expr)
		if err != nil {
			return fmt.Errorf("--created: %w", err)
		}
		listParams.CreatedRange = r
	}
	for _, expr := range cmd.StringSlice("due") {
		r, err := mergeTimeFilterExpr(listParams.DueDateRange, expr)
		if err != nil {
			return fmt.Errorf("--due: %w", err)
		}
		listParams.DueDateRange = r
	}

	for _, sh := range []struct {
		flag, op string
		into     **stripe.RangeQueryParams
	}{
		{"created-before", "<", &listParams.CreatedRange},
		{"created-after", ">=", &listParams.CreatedRange},
		{"due-before", "<", &listParams.DueDateRange},
		{"due-after", ">=", &listParams.DueDateRange},
	} {
		v := cmd.String(sh.flag)
		if v == "" {
			continue
		}
		r, err := mergeTimeFilterExpr(*sh.into, sh.op+" "+v)
		if err != nil {
			return fmt.Errorf("--%s: %w", sh.flag, err)
		}
		*sh.into = r
	}

	collectionDisabled := cmd.Bool("collection-disabled")
	minAttempts := int64(cmd.Int("attempts"))

	listParams.AddExpand("data.subscription")
	listParams.AddExpand("data.customer")
	listParams.AddExpand("data.payment_intent")
	listParams.AddExpand("data.charge")

	limit := int(cmd.Int("limit"))
	nowUnix := time.Now().Unix()
	verbose := mainCmd.Bool("verbose")

	// progress spinner on stderr — leaves stdout clean for json/jsonl output.
	scanned, kept := 0, 0
	startTime := time.Now()
	bar := newMigrateSpinner(invoiceListDescribe(scanned, kept, status, pastDue, failed, collectionDisabled, startTime))
	defer bar.Finish()
	updateBar := func() {
		bar.Describe(invoiceListDescribe(scanned, kept, status, pastDue, failed, collectionDisabled, startTime))
	}
	// vlogf clears the spinner before logging so verbose lines aren't shredded
	// by the bar's \r-based redraw.
	vlogf := func(format string, args ...any) {
		if !verbose {
			return
		}
		_ = bar.Clear()
		fmt.Fprintf(os.Stderr, format+"\n", args...)
	}

	var rows []invoiceRow

	iter := sc.Invoices.List(listParams)
	for iter.Next() {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		inv := iter.Invoice()
		scanned++
		bar.Add(1)

		if pastDue {
			if inv.DueDate == 0 || inv.DueDate >= nowUnix {
				updateBar()
				continue
			}
		}

		if failed {
			// "failed" matches the stripe dashboard's filter: an open invoice
			// that was attempted, has no next_payment_attempt scheduled, isn't
			// auto-advancing, and still has a non-zero balance.
			if !invoiceLooksFailed(inv) {
				updateBar()
				continue
			}
		}

		if collectionDisabled {
			if inv.NextPaymentAttempt > 0 {
				updateBar()
				continue
			}
		}

		if minAttempts > 0 {
			if !inv.Attempted || inv.AttemptCount < minAttempts {
				updateBar()
				continue
			}
		}

		row := invoiceRow{
			ID:               inv.ID,
			Number:           inv.Number,
			Status:           string(inv.Status),
			Currency:         string(inv.Currency),
			AmountDue:        formatStripeAmount(inv.AmountDue, string(inv.Currency)),
			AmountRemaining: formatStripeAmount(inv.AmountRemaining, string(inv.Currency)),
			AmountPaid:       formatStripeAmount(inv.AmountPaid, string(inv.Currency)),
			CollectionMethod: string(inv.CollectionMethod),
			Attempted:        inv.Attempted,
			AttemptCount:     inv.AttemptCount,
			HostedURL:        inv.HostedInvoiceURL,
		}
		if inv.Customer != nil {
			row.Customer = inv.Customer.ID
		}
		if inv.Subscription != nil {
			row.Subscription = inv.Subscription.ID
			row.SubStatus = string(inv.Subscription.Status)
		}
		if inv.Created > 0 {
			row.Created = time.Unix(inv.Created, 0).UTC().Format(time.RFC3339)
		}
		if inv.DueDate > 0 {
			row.DueDate = time.Unix(inv.DueDate, 0).UTC().Format(time.RFC3339)
		}
		if inv.NextPaymentAttempt > 0 {
			row.NextPaymentAttempt = time.Unix(inv.NextPaymentAttempt, 0).UTC().Format(time.RFC3339)
		}
		// failure info: prefer PaymentIntent.LastPaymentError (modern flow);
		// fall back to Charge.FailureCode/FailureMessage for older invoices
		// that pre-date the PaymentIntent rollout.
		if pi := inv.PaymentIntent; pi != nil && pi.LastPaymentError != nil {
			row.FailureCode = string(pi.LastPaymentError.Code)
			row.FailureDeclineCode = string(pi.LastPaymentError.DeclineCode)
			row.FailureMessage = pi.LastPaymentError.Msg
		}
		if row.FailureCode == "" && inv.Charge != nil {
			row.FailureCode = inv.Charge.FailureCode
			if row.FailureMessage == "" {
				row.FailureMessage = inv.Charge.FailureMessage
			}
		}

		rows = append(rows, row)
		kept++
		updateBar()

		if verbose {
			subPart := ""
			if row.Subscription != "" {
				subPart = fmt.Sprintf(" sub=%s(%s)", row.Subscription, row.SubStatus)
			}
			due := row.DueDate
			if due == "" {
				due = "—"
			}
			failPart := ""
			if row.FailureCode != "" {
				failPart = fmt.Sprintf(" failure=%s", row.FailureCode)
				if row.FailureDeclineCode != "" {
					failPart += "/" + row.FailureDeclineCode
				}
			}
			vlogf("  %s status=%s amount_due=%s %s attempts=%d due=%s customer=%s%s%s",
				row.ID, row.Status, row.AmountDue, row.Currency, row.AttemptCount, due, row.Customer, subPart, failPart)
		}

		if limit > 0 && len(rows) >= limit {
			break
		}
	}
	if err := iter.Err(); err != nil {
		return fmt.Errorf("listing invoices: %w", err)
	}

	bar.Finish()
	fmt.Fprintf(os.Stderr, "scanned %d invoice(s), kept %d in %s\n",
		scanned, kept, time.Since(startTime).Round(time.Millisecond))

	if len(rows) == 0 {
		fmt.Fprintln(os.Stderr, "no invoices matched")
		return nil
	}

	if outPath := cmd.String("out"); outPath != "" {
		if err := writeInvoiceRows(outPath, rows); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "wrote %d row(s) → %s\n", len(rows), outPath)
		return nil
	}

	PrintResult(cmd, rows,
		WithFields("id", "customer", "subscription", "subscription_status", "status",
			"amount_due", "currency", "attempt_count", "failure_code", "failure_decline_code", "due_date", "created"))
	return nil
}

// writeInvoiceRows writes the collected rows to disk in the format chosen by
// the file's extension: .csv, .json, .jsonl/.ndjson. Unknown extensions error.
func writeInvoiceRows(path string, rows []invoiceRow) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create %s: %w", path, err)
	}
	defer f.Close()

	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".csv":
		w := csv.NewWriter(f)
		defer w.Flush()

		if err := w.Write(invoiceCSVHeader); err != nil {
			return fmt.Errorf("write csv header: %w", err)
		}
		for _, r := range rows {
			if err := w.Write([]string{
				r.ID, r.Number, r.Customer, r.Subscription, r.SubStatus,
				r.Status, r.Currency, r.AmountDue, r.AmountRemaining, r.AmountPaid,
				r.Created, r.DueDate, r.CollectionMethod,
				strconv.FormatBool(r.Attempted), strconv.FormatInt(r.AttemptCount, 10), r.NextPaymentAttempt,
				r.FailureCode, r.FailureDeclineCode, r.FailureMessage,
				r.HostedURL,
			}); err != nil {
				return fmt.Errorf("write csv row: %w", err)
			}
		}
		w.Flush()
		return w.Error()

	case ".json":
		enc := json.NewEncoder(f)
		enc.SetIndent("", "  ")
		return enc.Encode(rows)

	case ".jsonl", ".ndjson":
		enc := json.NewEncoder(f)
		for _, r := range rows {
			if err := enc.Encode(r); err != nil {
				return fmt.Errorf("write jsonl row: %w", err)
			}
		}
		return nil

	default:
		return fmt.Errorf("--out: unsupported extension %q (use .csv, .json, .jsonl, or .ndjson)", ext)
	}
}

var invoiceCSVHeader = []string{
	"id", "number", "customer", "subscription", "subscription_status",
	"status", "currency", "amount_due", "amount_remaining", "amount_paid",
	"created", "due_date", "collection_method",
	"attempted", "attempt_count", "next_payment_attempt",
	"failure_code", "failure_decline_code", "failure_message",
	"hosted_invoice_url",
}

func stripeInvoiceGetAction(ctx context.Context, cmd *cli.Command) error {
	if cmd.NArg() < 1 {
		return fmt.Errorf("invoice id is required")
	}
	id := cmd.Args().First()

	sc := stripeclient.New(cmd.String("stripe-key"), nil)

	getParams := &stripe.InvoiceParams{}
	getParams.AddExpand("subscription")
	getParams.AddExpand("customer")

	inv, err := sc.Invoices.Get(id, getParams)
	if err != nil {
		return fmt.Errorf("failed to get invoice %s: %w", id, err)
	}

	// stripe.Invoice has too many nested fields to render as a table cleanly;
	// emit json regardless of --out-format.
	out, err := json.MarshalIndent(inv, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal invoice: %w", err)
	}
	fmt.Println(string(out))
	return nil
}

// invoiceListDescribe builds the spinner description shown to the user
// during a stripe invoice list run.
func invoiceListDescribe(scanned, kept int, status string, pastDue, failed, collectionDisabled bool, start time.Time) string {
	label := "Listing invoices"
	if status != "" {
		label = fmt.Sprintf("Listing [%s] invoices", status)
	}
	if pastDue {
		label += " [past due]"
	}
	if failed {
		label += " [failed]"
	}
	if collectionDisabled {
		label += " [no retry]"
	}
	elapsed := time.Since(start).Seconds()
	if elapsed < 1 || scanned == 0 {
		return fmt.Sprintf("%s (scanned: %d, kept: %d)", label, scanned, kept)
	}
	rate := float64(scanned) / elapsed
	return fmt.Sprintf("%s (scanned: %d, kept: %d, %.1f/s)", label, scanned, kept, rate)
}

// invoiceLooksFailed identifies invoices whose latest payment attempt
// actually failed (vs. attempts that succeeded or are still pending).
// Implies --attempts >= 1, plus evidence of a real failure: either
// PaymentIntent.LastPaymentError or Charge.FailureCode is set, or the
// charge.status is "failed". Used as the short-hand --failed filter.
func invoiceLooksFailed(inv *stripe.Invoice) bool {
	if !inv.Attempted || inv.AttemptCount < 1 {
		return false
	}
	if pi := inv.PaymentIntent; pi != nil && pi.LastPaymentError != nil {
		return true
	}
	if ch := inv.Charge; ch != nil {
		if ch.FailureCode != "" || ch.FailureMessage != "" {
			return true
		}
		if ch.Status == stripe.ChargeStatusFailed {
			return true
		}
	}
	return false
}

// invoiceRow is the flat shape used for the table / json / jsonl / csv
// output of stripe invoice list.
type invoiceRow struct {
	ID                 string `json:"id"`
	Number             string `json:"number"`
	Customer           string `json:"customer"`
	Subscription       string `json:"subscription"`
	SubStatus          string `json:"subscription_status"`
	Status             string `json:"status"`
	Currency           string `json:"currency"`
	AmountDue          string `json:"amount_due"`
	AmountRemaining    string `json:"amount_remaining"`
	AmountPaid         string `json:"amount_paid"`
	Created            string `json:"created"`
	DueDate            string `json:"due_date"`
	CollectionMethod   string `json:"collection_method"`
	Attempted          bool   `json:"attempted"`
	AttemptCount       int64  `json:"attempt_count"`
	NextPaymentAttempt string `json:"next_payment_attempt"`
	FailureCode        string `json:"failure_code"`
	FailureDeclineCode string `json:"failure_decline_code"`
	FailureMessage     string `json:"failure_message"`
	HostedURL          string `json:"hosted_invoice_url"`
}

var validInvoiceStatuses = map[string]bool{
	string(stripe.InvoiceStatusDraft):         true,
	string(stripe.InvoiceStatusOpen):          true,
	string(stripe.InvoiceStatusPaid):          true,
	string(stripe.InvoiceStatusUncollectible): true,
	string(stripe.InvoiceStatusVoid):          true,
}

// formatStripeAmount renders a Stripe minor-unit integer as a decimal string
// with the right number of fraction digits for the currency.
func formatStripeAmount(minor int64, currency string) string {
	digits := stripeCurrencyDigits(currency)
	if digits == 0 {
		return fmt.Sprintf("%d", minor)
	}
	div := int64(1)
	for i := 0; i < digits; i++ {
		div *= 10
	}
	whole := minor / div
	frac := minor % div
	if frac < 0 {
		frac = -frac
	}
	return fmt.Sprintf("%d.%0*d", whole, digits, frac)
}

// stripeCurrencyDigits returns the number of fractional digits stripe uses
// for a given currency. Defaults to 2; lists the zero-decimal and three-
// decimal currencies stripe documents.
// See https://stripe.com/docs/currencies#zero-decimal
func stripeCurrencyDigits(currency string) int {
	switch currency {
	case "bif", "clp", "djf", "gnf", "jpy", "kmf", "krw", "mga", "pyg", "rwf",
		"ugx", "vnd", "vuv", "xaf", "xof", "xpf":
		return 0
	case "bhd", "jod", "kwd", "omr", "tnd":
		return 3
	default:
		return 2
	}
}
