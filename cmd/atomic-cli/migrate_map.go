/*
 * This file is part of the Passport Atomic Stack (https://github.com/libatomic/atomic).
 * Copyright (c) 2026 Passport, Inc.
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
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/apex/log"
	"github.com/biter777/countries"
	"github.com/expr-lang/expr"
	"github.com/expr-lang/expr/vm"
	"github.com/gocarina/gocsv"
	"github.com/libatomic/atomic/pkg/atomic"
	"github.com/libatomic/atomic/pkg/util"
	"github.com/schollz/progressbar/v3"
	"github.com/stripe/stripe-go/v79"
	stripeclient "github.com/stripe/stripe-go/v79/client"
	"github.com/urfave/cli/v3"
)

type (
	// convertMappingFile is the JSON config file format for the map command.
	convertMappingFile struct {
		// Vars defines variables available in all expressions (string, []string, etc.)
		Vars map[string]any `json:"vars,omitempty"`
		// Filter is an optional global expr filter; only matching rows are processed
		Filter string `json:"filter,omitempty"`
		// Options contains shared settings (email rewriting, append, source)
		Options *convertMappingOptions `json:"options,omitempty"`
		// Outputs defines multiple output files with per-output filters;
		// mutually exclusive with the --output CLI flag
		Outputs []convertMappingOutput `json:"outputs,omitempty"`
		// Columns maps UserImportRecord field names to one of:
		//   - an expr expression or static value
		//   - a {"filter": <expr>, "value": <expr>} struct that only sets the
		//     value when the filter is truthy
		//   - an array of {filter, value} structs evaluated in order; the
		//     first matching filter wins. A filter of "default" (or an
		//     omitted filter) always matches, so it can be used as a final
		//     fallback. When no entry matches the column is left empty.
		Columns map[string]any `json:"columns"`
	}


	convertMappingOptions struct {
		Append               *bool  `json:"append,omitempty"`
		EmailDomainOverwrite string `json:"email_domain_overwrite,omitempty"`
		EmailTemplate        string `json:"email_template,omitempty"`
		Source               string `json:"source,omitempty"`
		Limit                *int   `json:"limit,omitempty"`
		Skip                 *int   `json:"skip,omitempty"`
		// Filter mirrors the top-level filter field for ergonomics; both forms work.
		// If both are set, top-level wins.
		Filter string `json:"filter,omitempty"`
		// MapErrors controls whether soft mapping errors (e.g. stripe customer
		// not found) populate the map_error column and the summary. Default true.
		MapErrors *bool `json:"map_errors,omitempty"`
		// SplitErrorRows mirrors --split-error-rows for config-file use.
		SplitErrorRows *bool `json:"split_error_rows,omitempty"`
	}

	convertMappingOutput struct {
		Path   string `json:"path"`
		Filter string `json:"filter,omitempty"`
	}

	// convertMapping is the resolved column mapping (used by both inline and file modes)
	convertMapping map[string]any
)

var (
	migrateConvertFlags = append(
		migrateCommonFlags,
		&cli.StringFlag{
			Name:     "input",
			Aliases:  []string{"in", "f"},
			Usage:    "input CSV file path",
			Required: true,
		},
		&cli.StringFlag{
			Name:    "config",
			Aliases: []string{"c"},
			Usage:   "JSON mapping file path",
		},
		&cli.StringSliceFlag{
			Name:    "columns",
			Aliases: []string{"col"},
			Usage:   "inline column mappings as target=expression pairs (e.g. -col login=Email -col 'name=trim(Name)'); can also use semicolons: -col 'login=Email; name=Name'",
		},
		&cli.StringFlag{
			Name:  "filter",
			Usage: "expression to filter rows (columns available as variables, e.g. 'STRIPE_CUSTOMER_ID == \"\" && STRIPE_SUBSCRIPTION_ID == \"\"')",
		},
		&cli.StringSliceFlag{
			Name:  "vars",
			Usage: "define vars for use in expressions as NAME=value (e.g. --vars 'ALL_CATS=News,Sports,Opinion')",
		},
		&cli.BoolFlag{
			Name:  "split-error-rows",
			Usage: "route rows with non-fatal mapping errors (e.g. stripe customer not found) to a separate <output>_errors.csv file instead of the main output",
		},
		&cli.BoolFlag{
			Name:  "map-errors",
			Usage: "track soft mapping errors (e.g. stripe customer not found) in the map_error column and summary; set to false when soft errors represent the desired outcome (default true)",
			Value: true,
		},
	)

	migrateConvertCmd = &cli.Command{
		Name:   "map",
		Usage:  "map and filter a third-party CSV to Passport user import format using a mapping file",
		Flags:  migrateConvertFlags,
		Action: migrateMapAction,
	}

	// importFieldSetters maps CSV tag names to functions that set the corresponding
	// field on a UserImportRecord from a string value.
	importFieldSetters = map[string]func(rec *atomic.UserImportRecord, val string){
		"created_at": func(rec *atomic.UserImportRecord, val string) {
			v := strings.TrimSpace(val)
			if v == "" {
				return
			}
			t, err := parseFlexibleTime(v)
			if err != nil {
				return
			}
			rec.CreatedAt = &util.Timestamp{Time: t.UTC()}
		},
		"login": func(rec *atomic.UserImportRecord, val string) {
			rec.Login = strings.TrimSpace(val)
		},
		"email": func(rec *atomic.UserImportRecord, val string) {
			v := strings.TrimSpace(val)
			rec.Email = &v
		},
		"email_verified": func(rec *atomic.UserImportRecord, val string) {
			b := parseBool(val)
			rec.EmailVerified = &b
		},
		"email_opt_in": func(rec *atomic.UserImportRecord, val string) {
			b := parseBool(val)
			rec.EmailOptIn = &b
		},
		"phone_number": func(rec *atomic.UserImportRecord, val string) {
			v := strings.TrimSpace(val)
			rec.PhoneNumber = &v
		},
		"phone_number_verified": func(rec *atomic.UserImportRecord, val string) {
			b := parseBool(val)
			rec.PhoneNumberVerified = &b
		},
		"phone_number_opt_in": func(rec *atomic.UserImportRecord, val string) {
			b := parseBool(val)
			rec.PhoneNumberOptIn = &b
		},
		"name": func(rec *atomic.UserImportRecord, val string) {
			v := strings.TrimSpace(val)
			rec.Name = &v
		},
		"roles": func(rec *atomic.UserImportRecord, val string) {
			parts := strings.Split(val, "|")
			for i := range parts {
				parts[i] = strings.TrimSpace(parts[i])
			}
			rec.Roles = parts
		},
		"stripe_customer_id": func(rec *atomic.UserImportRecord, val string) {
			v := strings.TrimSpace(val)
			rec.StripeCustomerID = &v
		},
		"channel_opt_in": func(rec *atomic.UserImportRecord, val string) {
			parts := strings.Split(val, "|")
			for i := range parts {
				parts[i] = strings.TrimSpace(parts[i])
			}
			rec.ChannelOptIn = parts
		},
		"category_opt_out": func(rec *atomic.UserImportRecord, val string) {
			parts := strings.Split(val, "|")
			for i := range parts {
				parts[i] = strings.TrimSpace(parts[i])
			}
			rec.CategoryOptOut = parts
		},
		"import_comment": func(rec *atomic.UserImportRecord, val string) {
			v := strings.TrimSpace(val)
			rec.ImportComment = &v
		},
		"import_source": func(rec *atomic.UserImportRecord, val string) {
			v := strings.TrimSpace(val)
			rec.ImportSource = &v
		},
		"metadata": func(rec *atomic.UserImportRecord, val string) {
			v := strings.TrimSpace(val)
			if v == "" {
				return
			}
			m := make(util.Map[string, any])
			if err := m.UnmarshalCSV(v); err == nil {
				rec.Metadata = m
			}
		},
		"stripe_customer_metadata": func(rec *atomic.UserImportRecord, val string) {
			v := strings.TrimSpace(val)
			if v == "" {
				return
			}
			m := make(util.Map[string, string])
			if err := m.UnmarshalCSV(v); err == nil {
				rec.StripeCustomerMetadata = m
			}
		},
		"subscription_plan_id": func(rec *atomic.UserImportRecord, val string) {
			v := strings.TrimSpace(val)
			if v == "" {
				return
			}
			id, err := atomic.ParseID(v)
			if err != nil {
				return
			}
			rec.SubscriptionPlanID = &id
		},
		"subscription_currency": func(rec *atomic.UserImportRecord, val string) {
			v := strings.TrimSpace(val)
			rec.SubscriptionCurrency = &v
		},
		"subscription_quantity": func(rec *atomic.UserImportRecord, val string) {
			v := strings.TrimSpace(val)
			if v == "" {
				return
			}
			n, err := strconv.Atoi(v)
			if err != nil {
				return
			}
			rec.SubscriptionQuantity = &n
		},
		"subscription_interval": func(rec *atomic.UserImportRecord, val string) {
			v := strings.TrimSpace(val)
			if v == "" {
				return
			}
			interval := atomic.SubscriptionInterval(strings.ToLower(v))
			rec.SubscriptionInterval = &interval
		},
		"subscription_anchor_date": func(rec *atomic.UserImportRecord, val string) {
			v := strings.TrimSpace(val)
			if v == "" {
				return
			}
			t, err := parseFlexibleTime(v)
			if err != nil {
				return
			}
			rec.SubscriptionAnchorDate = &util.Timestamp{Time: t.UTC()}
		},
		"subscription_end_at": func(rec *atomic.UserImportRecord, val string) {
			v := strings.TrimSpace(val)
			if v == "" {
				return
			}
			t, err := parseFlexibleTime(v)
			if err != nil {
				return
			}
			rec.SubscriptionEndAt = &util.Timestamp{Time: t.UTC()}
		},
		"subscription_trial_end_at": func(rec *atomic.UserImportRecord, val string) {
			v := strings.TrimSpace(val)
			if v == "" {
				return
			}
			t, err := parseFlexibleTime(v)
			if err != nil {
				return
			}
			rec.SubscriptionTrialEndAt = &util.Timestamp{Time: t.UTC()}
		},
		"subscription_trial_end_behavior": func(rec *atomic.UserImportRecord, val string) {
			v := strings.TrimSpace(strings.ToLower(val))
			if v == "" {
				return
			}
			behavior := atomic.PriceTrialEndBehavior(v)
			rec.SubscriptionTrialEndBehavior = &behavior
		},
		"subscription_prorate": func(rec *atomic.UserImportRecord, val string) {
			b := parseBool(val)
			rec.SubscriptionProrate = &b
		},
		"subscription_cancel_at": func(rec *atomic.UserImportRecord, val string) {
			v := strings.TrimSpace(val)
			if v == "" {
				return
			}
			t, err := parseFlexibleTime(v)
			if err != nil {
				return
			}
			rec.SubscriptionCancelAt = &util.Timestamp{Time: t.UTC()}
		},
		"subscription_cancel_at_period_end": func(rec *atomic.UserImportRecord, val string) {
			b := parseBool(val)
			rec.SubscriptionCancelAtPeriodEnd = &b
		},
		"subscription_payment_method": func(rec *atomic.UserImportRecord, val string) {
			v := strings.TrimSpace(val)
			rec.SubscriptionPaymentMethod = &v
		},
		"discount_percentage": func(rec *atomic.UserImportRecord, val string) {
			v := strings.TrimSpace(val)
			if v == "" {
				return
			}
			f, err := strconv.ParseFloat(v, 64)
			if err != nil {
				return
			}
			rec.DiscountPercentage = &f
		},
		"discount_term": func(rec *atomic.UserImportRecord, val string) {
			v := strings.TrimSpace(val)
			if v == "" {
				return
			}
			term := atomic.CreditTerm(strings.ToLower(v))
			rec.DiscountTerm = &term
		},
		"discount_duration_days": func(rec *atomic.UserImportRecord, val string) {
			v := strings.TrimSpace(val)
			if v == "" {
				return
			}
			n, err := strconv.Atoi(v)
			if err != nil {
				return
			}
			rec.DiscountDurationDays = &n
		},
		"is_team_owner": func(rec *atomic.UserImportRecord, val string) {
			b := parseBool(val)
			rec.IsTeamOwner = &b
		},
		"team_key": func(rec *atomic.UserImportRecord, val string) {
			v := strings.TrimSpace(val)
			rec.TeamKey = &v
		},
	}
)

func parseBool(val string) bool {
	val = strings.TrimSpace(strings.ToLower(val))
	return val == "true" || val == "1" || val == "yes"
}

// exprResultToString converts an expr evaluation result to a string suitable
// for the field setters. time.Time values are formatted as RFC3339 (UTC) so
// the time setters can parse them; everything else uses default Go formatting.
func exprResultToString(result any) string {
	switch v := result.(type) {
	case nil:
		return ""
	case string:
		return v
	case time.Time:
		return v.UTC().Format(time.RFC3339)
	case *time.Time:
		if v == nil {
			return ""
		}
		return v.UTC().Format(time.RFC3339)
	default:
		return fmt.Sprintf("%v", result)
	}
}

// parseFlexibleTime parses a timestamp string in a few common formats
// (RFC3339 with or without nanos, ISO date, unix seconds). The result is
// caller-normalized to UTC where used.
func parseFlexibleTime(val string) (time.Time, error) {
	val = strings.TrimSpace(val)
	if val == "" {
		return time.Time{}, fmt.Errorf("empty time value")
	}
	formats := []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02T15:04:05.999999999",
		"2006-01-02 15:04:05.999999999",
		"2006-01-02T15:04:05",
		"2006-01-02 15:04:05",
		"2006-01-02T15:04",
		"2006-01-02 15:04",
		"2006-01-02",
		"01/02/2006 15:04:05",
		"01/02/2006 15:04",
		"01/02/2006",
		"1/2/2006 15:04:05",
		"1/2/2006 15:04",
		"1/2/2006",
		time.RFC1123,
		time.RFC1123Z,
		time.RFC822,
		time.RFC822Z,
		time.RFC850,
		"15:04:05",
	}
	for _, f := range formats {
		if t, err := time.Parse(f, val); err == nil {
			return t, nil
		}
	}
	// try unix seconds
	if secs, err := strconv.ParseInt(val, 10, 64); err == nil {
		return time.Unix(secs, 0), nil
	}
	return time.Time{}, fmt.Errorf("unrecognized time format: %s", val)
}

func migrateMapAction(ctx context.Context, cmd *cli.Command) error {
	_, outputPath, _, rewriter, appendMode, source, limit, skip, err := validateMigrateFlags(cmd, false)
	if err != nil {
		return err
	}

	// map-specific default output (only when the user did not explicitly set --output)
	if !cmd.IsSet("output") {
		outputPath = DefaultMigrateMapOutputPath
	}

	inputPath := cmd.String("input")
	mappingFilePath := cmd.String("config")
	inlineColumns := cmd.StringSlice("columns")

	if mappingFilePath == "" && len(inlineColumns) == 0 {
		return fmt.Errorf("either --config or --columns is required")
	}
	if mappingFilePath != "" && len(inlineColumns) > 0 {
		return fmt.Errorf("--config and --columns are mutually exclusive")
	}

	var (
		mapping    convertMapping
		fileVars   map[string]any
		fileFilter string
		outputs    []convertMappingOutput
	)

	// defaults come from the CLI; config-file options may override when the
	// user did not explicitly pass the flag
	trackMapErrors := cmd.Bool("map-errors")
	splitErrorRows := cmd.Bool("split-error-rows")

	if mappingFilePath != "" {
		// load from JSON config file
		mappingData, err := os.ReadFile(mappingFilePath)
		if err != nil {
			return fmt.Errorf("failed to read mapping file: %w", err)
		}

		var mf convertMappingFile
		if err := json.Unmarshal(mappingData, &mf); err != nil {
			return fmt.Errorf("failed to parse mapping file: %w", err)
		}
		if len(mf.Columns) == 0 {
			return fmt.Errorf("mapping file must have a \"columns\" object")
		}
		mapping = mf.Columns
		fileVars = mf.Vars
		fileFilter = mf.Filter
		outputs = mf.Outputs

		// allow filter inside options as a fallback for users who put it there
		if fileFilter == "" && mf.Options != nil && mf.Options.Filter != "" {
			fileFilter = mf.Options.Filter
		}

		// config file options override CLI defaults (CLI flags still win if explicitly set)
		if mf.Options != nil {
			if mf.Options.EmailDomainOverwrite != "" && rewriter == nil {
				rewriter = &emailRewriter{domain: mf.Options.EmailDomainOverwrite}
			}
			if mf.Options.EmailTemplate != "" && rewriter == nil {
				rewriter = &emailRewriter{template: mf.Options.EmailTemplate}
			}
			if mf.Options.Append != nil && !cmd.IsSet("append") {
				appendMode = *mf.Options.Append
			}
			if mf.Options.Source != "" && source == "" {
				source = mf.Options.Source
			}
			if mf.Options.Limit != nil && !cmd.IsSet("limit") {
				limit = *mf.Options.Limit
			}
			if mf.Options.Skip != nil && !cmd.IsSet("skip") {
				skip = *mf.Options.Skip
			}
			if mf.Options.MapErrors != nil && !cmd.IsSet("map-errors") {
				trackMapErrors = *mf.Options.MapErrors
			}
			if mf.Options.SplitErrorRows != nil && !cmd.IsSet("split-error-rows") {
				splitErrorRows = *mf.Options.SplitErrorRows
			}
		}

		// validate outputs vs --output mutual exclusivity
		if len(outputs) > 0 && cmd.IsSet("output") {
			return fmt.Errorf("config file \"outputs\" and --output are mutually exclusive")
		}
	} else {
		// parse inline columns: each entry can be "target=expr" or "target=expr; target2=expr2"
		mapping = make(convertMapping)
		for _, entry := range inlineColumns {
			parts := strings.Split(entry, ";")
			for _, part := range parts {
				part = strings.TrimSpace(part)
				if part == "" {
					continue
				}
				kv := strings.SplitN(part, "=", 2)
				if len(kv) != 2 {
					return fmt.Errorf("invalid mapping %q: expected target=SourceColumn", part)
				}
				target := strings.TrimSpace(kv[0])
				source := strings.TrimSpace(kv[1])
				if target == "" || source == "" {
					return fmt.Errorf("invalid mapping %q: target and source must not be empty", part)
				}
				// check for static boolean/number values
				switch strings.ToLower(source) {
				case "true":
					mapping[target] = true
				case "false":
					mapping[target] = false
				default:
					mapping[target] = source
				}
			}
		}
	}

	if err := validateMapping(mapping); err != nil {
		return err
	}

	// read the source CSV
	inputFile, err := os.Open(inputPath)
	if err != nil {
		return fmt.Errorf("failed to open input file: %w", err)
	}
	defer inputFile.Close()

	reader := csv.NewReader(inputFile)
	allRows, err := reader.ReadAll()
	if err != nil {
		return fmt.Errorf("failed to read input CSV: %w", err)
	}

	if len(allRows) < 2 {
		return fmt.Errorf("input CSV has no data rows")
	}

	headers := allRows[0]
	headerIndex := make(map[string]int, len(headers))
	for i, h := range headers {
		headerIndex[strings.TrimSpace(strings.ToLower(h))] = i
	}

	// build expr environment from CSV headers so expressions can reference columns;
	// headers with spaces/special chars also get a sanitized alias (e.g. "Emails opened (6mo)" -> "Emails_opened__6mo_")
	exprEnv := make(map[string]any, len(headers)*2)
	headerAlias := make(map[string]string, len(headers)) // sanitized name -> original name
	for _, h := range headers {
		exprEnv[h] = ""
		sanitized := sanitizeHeader(h)
		if sanitized != h {
			exprEnv[sanitized] = ""
			headerAlias[sanitized] = h
		}
	}

	// custom expr functions registered via expr.Function for proper variadic support
	splitTrimFn := expr.Function(
		"splitTrim",
		func(params ...any) (any, error) {
			s, ok := params[0].(string)
			if !ok {
				return nil, fmt.Errorf("splitTrim: first argument must be a string")
			}
			sep := ","
			if len(params) > 1 {
				sep, ok = params[1].(string)
				if !ok {
					return nil, fmt.Errorf("splitTrim: second argument must be a string")
				}
			}
			parts := strings.Split(s, sep)
			var result []string
			for _, p := range parts {
				p = strings.TrimSpace(p)
				if p != "" {
					result = append(result, p)
				}
			}
			return result, nil
		},
		// type signatures: splitTrim(string) and splitTrim(string, string)
		func(s string) []string { return nil },
		func(s, sep string) []string { return nil },
	)

	withoutFn := expr.Function(
		"without",
		func(params ...any) (any, error) {
			a, ok := params[0].([]string)
			if !ok {
				// expr may pass []any from array constants
				if arr, ok2 := params[0].([]any); ok2 {
					a = make([]string, len(arr))
					for i, v := range arr {
						a[i] = fmt.Sprintf("%v", v)
					}
				} else {
					return nil, fmt.Errorf("without: first argument must be a string array")
				}
			}
			b, ok := params[1].([]string)
			if !ok {
				if arr, ok2 := params[1].([]any); ok2 {
					b = make([]string, len(arr))
					for i, v := range arr {
						b[i] = fmt.Sprintf("%v", v)
					}
				} else {
					return nil, fmt.Errorf("without: second argument must be a string array")
				}
			}
			return util.Slice[string](a).Without(b...), nil
		},
		func(a, b []string) []string { return nil },
	)

	sprintfFn := expr.Function(
		"sprintf",
		func(params ...any) (any, error) {
			if len(params) < 1 {
				return nil, fmt.Errorf("sprintf requires at least 1 argument")
			}
			format, ok := params[0].(string)
			if !ok {
				return nil, fmt.Errorf("sprintf: first argument must be a string")
			}
			return fmt.Sprintf(format, params[1:]...), nil
		},
		func(format string, args ...any) string { return "" },
	)

	// stripe customer search function — bound to the global --stripe-key.
	// Lazily inits the client; if the function is referenced in any column or
	// filter expression and --stripe-key is unset, we fail at compile time so
	// the user gets immediate feedback (instead of a per-row error).
	stripeKey := cmd.String("stripe-key")
	var stripeOnce sync.Once
	var stripeClient *stripeclient.API
	var stripeNotFound int
	var stripeMu sync.Mutex
	stripeUsed := false

	// progressBar holds the active progress bar (set later, after compile).
	// stripeLogf clears the bar so warnings appear above it instead of being
	// chopped up by the bar's \r-based redraw.
	var progressBar *progressbar.ProgressBar
	stripeLogf := func(format string, args ...any) {
		if progressBar != nil {
			progressBar.Clear()
		}
		log.Warnf(format, args...)
	}

	// per-row soft error accumulator. Reset at the top of each row iteration;
	// after column evaluation, joined into rec.MapError. When --map-errors=false
	// this is a no-op — rowSoftErrors stays empty, so the map_error column, the
	// errored count, and --split-error-rows routing all quietly drop out.
	var rowSoftErrors []string
	addRowError := func(msg string) {
		if !trackMapErrors {
			return
		}
		rowSoftErrors = append(rowSoftErrors, msg)
	}

	getStripeClient := func() (*stripeclient.API, error) {
		var initErr error
		stripeOnce.Do(func() {
			if stripeKey == "" {
				initErr = fmt.Errorf("--stripe-key is required to use stripe.* expr functions (set via --stripe-key/--sk or $STRIPE_API_KEY)")
				return
			}
			stripeClient = stripeclient.New(stripeKey, nil)
		})
		return stripeClient, initErr
	}

	// the stripe namespace is exposed as a struct in the env so callers can
	// use dotted-name syntax like stripe.customer_search(field, value).
	// Returns ("", err) on real stripe errors (auth, network, rate limit) so
	// the row loop can fail fast. "Not found" is treated as a soft error: the
	// function returns "" and records a per-row error message for map_error.
	stripeCustomerSearch := func(field, val string) (string, error) {
		val = strings.TrimSpace(val)
		if val == "" {
			return "", nil
		}
		sc, err := getStripeClient()
		if err != nil {
			return "", err
		}

		// stripe search query language: field:'value' (single quotes around value)
		escaped := strings.ReplaceAll(val, `'`, `\'`)
		query := fmt.Sprintf("%s:'%s'", field, escaped)

		searchParams := &stripe.CustomerSearchParams{}
		searchParams.Query = query
		searchParams.Limit = stripe.Int64(1)

		iter := sc.Customers.Search(searchParams)
		if iter.Next() {
			cust := iter.Customer()
			return cust.ID, nil
		}
		if iterErr := iter.Err(); iterErr != nil {
			// any real stripe error is fatal — we don't want to silently
			// produce hundreds of empty IDs because of an auth or rate-limit issue
			return "", fmt.Errorf("stripe.customer_search %s=%s: %w", field, val, iterErr)
		}

		// soft error: customer not found. Bookkeeping (counter + row error)
		// is skipped when --map-errors=false so the lookup behaves like an
		// ordinary "empty result" outcome.
		if trackMapErrors {
			stripeMu.Lock()
			stripeNotFound++
			stripeMu.Unlock()
			addRowError(fmt.Sprintf("stripe customer not found for %s=%s", field, val))
		}
		if mainCmd.Bool("verbose") {
			stripeLogf("stripe.customer_search: no customer found for %s=%s", field, val)
		}
		return "", nil
	}

	type stripeNS struct {
		CustomerSearch func(field, val string) (string, error) `expr:"customer_search"`
	}
	exprEnv["stripe"] = stripeNS{CustomerSearch: stripeCustomerSearch}

	exprOpts := []expr.Option{expr.Env(exprEnv), splitTrimFn, withoutFn, sprintfFn, atoiFn(), sinceFn(), untilFn(), dateFn(), currencyForCountryFn(), shiftAnchorDateFn()}

	// add consts from file first, then CLI flags (CLI wins on conflict)
	for name, value := range fileVars {
		// JSON arrays decode as []any — convert to []string for expr compatibility
		if arr, ok := value.([]any); ok {
			strs := make([]string, 0, len(arr))
			for _, v := range arr {
				strs = append(strs, fmt.Sprintf("%v", v))
			}
			exprEnv[name] = strs
		} else {
			exprEnv[name] = value
		}
	}
	for _, c := range cmd.StringSlice("vars") {
		kv := strings.SplitN(c, "=", 2)
		if len(kv) != 2 {
			return fmt.Errorf("invalid --vars %q: expected NAME=value", c)
		}
		name := strings.TrimSpace(kv[0])
		value := strings.TrimSpace(kv[1])
		if name == "" {
			return fmt.Errorf("invalid --vars %q: name must not be empty", c)
		}
		exprEnv[name] = value
	}

	// build the resolved mapping: target field -> ordered list of compiled
	// alternatives. The row loop walks each list in order and uses the first
	// alternative whose filter evaluates truthy (an unset filter — or one
	// literally set to "default" — always matches).
	type fieldSource struct {
		program   *vm.Program // non-nil for expr-based mappings
		static    string      // used when program is nil
		filter    *vm.Program // optional per-column filter; value is only set when truthy
		filterSrc string      // raw filter source (for reporting)
	}

	// helper to compile a single value (string → expr program, otherwise static)
	compileColumnValue := func(targetField string, raw any) (fieldSource, error) {
		switch v := raw.(type) {
		case string:
			program, err := expr.Compile(v, exprOpts...)
			if err != nil {
				return fieldSource{}, fmt.Errorf("mapping field %q: invalid expression %q: %w", targetField, v, err)
			}
			if strings.Contains(v, "stripe.customer_search") {
				stripeUsed = true
			}
			return fieldSource{program: program}, nil
		case bool:
			if v {
				return fieldSource{static: "true"}, nil
			}
			return fieldSource{static: "false"}, nil
		case float64:
			return fieldSource{static: fmt.Sprintf("%g", v)}, nil
		default:
			return fieldSource{static: fmt.Sprintf("%v", v)}, nil
		}
	}

	// compileColumnEntry handles a single mapping entry which may be a
	// scalar/expr value or a {filter, value} struct.
	compileColumnEntry := func(targetField string, raw any) (fieldSource, error) {
		if obj, ok := raw.(map[string]any); ok {
			filterRaw, hasFilter := obj["filter"]
			valueRaw, hasValue := obj["value"]
			if hasFilter || hasValue {
				if !hasValue {
					return fieldSource{}, fmt.Errorf("mapping field %q: struct form requires \"value\"", targetField)
				}
				fs, err := compileColumnValue(targetField, valueRaw)
				if err != nil {
					return fieldSource{}, err
				}
				if hasFilter {
					filterStr, ok := filterRaw.(string)
					if !ok {
						return fieldSource{}, fmt.Errorf("mapping field %q: \"filter\" must be a string expression", targetField)
					}
					trimmed := strings.TrimSpace(filterStr)
					// "default" is a sentinel meaning "always matches"; an
					// empty filter behaves the same way.
					if trimmed != "" && !strings.EqualFold(trimmed, "default") {
						filterProg, err := expr.Compile(filterStr, append(exprOpts, expr.AsBool())...)
						if err != nil {
							return fieldSource{}, fmt.Errorf("mapping field %q: invalid filter %q: %w", targetField, filterStr, err)
						}
						if strings.Contains(filterStr, "stripe.customer_search") {
							stripeUsed = true
						}
						fs.filter = filterProg
						fs.filterSrc = filterStr
					}
				}
				return fs, nil
			}
		}
		return compileColumnValue(targetField, raw)
	}

	resolved := make(map[string][]fieldSource)
	columnFilterSources := make(map[string][]string) // target field -> filter expr(s) (for reporting)
	for targetField, sourceVal := range mapping {
		var entries []fieldSource
		if arr, ok := sourceVal.([]any); ok {
			for i, item := range arr {
				fs, err := compileColumnEntry(targetField, item)
				if err != nil {
					return fmt.Errorf("mapping field %q[%d]: %w", targetField, i, err)
				}
				entries = append(entries, fs)
			}
		} else {
			fs, err := compileColumnEntry(targetField, sourceVal)
			if err != nil {
				return err
			}
			entries = append(entries, fs)
		}
		resolved[targetField] = entries
		for _, e := range entries {
			if e.filterSrc != "" {
				columnFilterSources[targetField] = append(columnFilterSources[targetField], e.filterSrc)
			}
		}
	}

	// validate stripe key early when any expression references stripe.* — gives
	// the user immediate feedback instead of a per-row failure later
	if stripeUsed {
		if _, err := getStripeClient(); err != nil {
			return err
		}
	}

	// compile filter expression: CLI --filter takes precedence over file filter
	filterExpr := cmd.String("filter")
	if filterExpr == "" {
		filterExpr = fileFilter
	}
	var filterProgram *vm.Program
	if filterExpr != "" {
		var compileErr error
		filterProgram, compileErr = expr.Compile(filterExpr, append(exprOpts, expr.AsBool())...)
		if compileErr != nil {
			return fmt.Errorf("invalid filter expression: %w", compileErr)
		}
	}

	// determine output targets up front so the row loop can route directly
	type outputTarget struct {
		path       string
		errorPath  string // sibling _errors file when --split-error-rows is set
		filterSrc  string
		filter     *vm.Program
		records    []*importRecord
		errRecords []*importRecord // populated when split-error-rows routes a row here
		skipped    int             // count of rows consumed by --skip for this target
	}

	allTargetsSaturated := func(ts []outputTarget, limit int) bool {
		for _, t := range ts {
			if len(t.records) < limit {
				return false
			}
		}
		return true
	}

	// when map-errors is off, no row is classified as errored, so split-error-rows
	// has nothing to route — warn so the user isn't surprised by a missing _errors file
	if !trackMapErrors && splitErrorRows {
		log.Warnf("--split-error-rows has no effect when --map-errors=false (no rows will be classified as errored)")
		splitErrorRows = false
	}

	addErrorPath := func(p string) string {
		ext := filepath.Ext(p)
		base := strings.TrimSuffix(p, ext)
		return base + "_errors" + ext
	}

	var targets []outputTarget

	if len(outputs) > 0 {
		for _, out := range outputs {
			t := outputTarget{path: out.Path, filterSrc: out.Filter}
			if out.Filter != "" {
				prog, err := expr.Compile(out.Filter, append(exprOpts, expr.AsBool())...)
				if err != nil {
					return fmt.Errorf("output %q: invalid filter expression: %w", out.Path, err)
				}
				t.filter = prog
			}
			if splitErrorRows {
				t.errorPath = addErrorPath(out.Path)
			}
			targets = append(targets, t)
		}
	} else {
		t := outputTarget{path: outputPath}
		if splitErrorRows {
			t.errorPath = addErrorPath(outputPath)
		}
		targets = []outputTarget{t}
	}

	// prompt up front before doing any work — the user can bail out before
	// we make any (potentially expensive) stripe.* calls
	if !appendMode {
		for _, t := range targets {
			if err := promptOverwriteIfExists(t.path, false); err != nil {
				return err
			}
			if t.errorPath != "" {
				if err := promptOverwriteIfExists(t.errorPath, false); err != nil {
					return err
				}
			}
		}
	}

	// summarize filters in effect so the user can see what's being applied,
	// and warn about redundant copies of the same expression in multiple places
	type filterLoc struct {
		kind string // "global" | "output:<path>" | "column:<field>"
		expr string
	}
	var filterLocs []filterLoc
	if filterExpr != "" {
		filterLocs = append(filterLocs, filterLoc{kind: "global", expr: filterExpr})
	}
	for _, t := range targets {
		if t.filterSrc != "" {
			filterLocs = append(filterLocs, filterLoc{kind: "output:" + t.path, expr: t.filterSrc})
		}
	}
	if len(columnFilterSources) > 0 {
		fields := make([]string, 0, len(columnFilterSources))
		for f := range columnFilterSources {
			fields = append(fields, f)
		}
		sort.Strings(fields)
		for _, f := range fields {
			for _, e := range columnFilterSources[f] {
				filterLocs = append(filterLocs, filterLoc{kind: "column:" + f, expr: e})
			}
		}
	}

	for _, fl := range filterLocs {
		fmt.Fprintf(os.Stderr, "filter (%s): %s\n", fl.kind, fl.expr)
	}

	// detect duplicates: same expression text used in multiple places
	if len(filterLocs) > 1 {
		byExpr := make(map[string][]string)
		for _, fl := range filterLocs {
			byExpr[fl.expr] = append(byExpr[fl.expr], fl.kind)
		}
		for expr, kinds := range byExpr {
			if len(kinds) > 1 {
				log.Warnf("redundant filter %q is set in multiple places: %s", expr, strings.Join(kinds, ", "))
			}
		}
	}

	// convert rows — pre-counted so the progress bar has a known total
	totalRows := len(allRows) - 1
	if totalRows < 0 {
		totalRows = 0
	}
	var skipLimitNote string
	if skip > 0 || limit > 0 {
		switch {
		case skip > 0 && limit > 0:
			skipLimitNote = fmt.Sprintf(" (skipping first %d, limit %d)", skip, limit)
		case skip > 0:
			skipLimitNote = fmt.Sprintf(" (skipping first %d)", skip)
		default:
			skipLimitNote = fmt.Sprintf(" (limit %d)", limit)
		}
	}
	if filterExpr != "" || len(targets) > 1 || len(columnFilterSources) > 0 {
		fmt.Fprintf(os.Stderr, "scanning %d source rows%s (filters may reduce the mapped count)\n", totalRows, skipLimitNote)
	} else {
		fmt.Fprintf(os.Stderr, "mapping %d rows%s\n", totalRows, skipLimitNote)
	}

	bar := newMigrateProgress(totalRows, "Mapping records")
	progressBar = bar
	defer bar.Finish()

	mapped := 0
	ignored := 0  // rows with no login (or otherwise unmappable)
	excluded := 0 // rows removed by the global filter
	limitHit := false
	errored := 0  // rows that picked up at least one soft error (e.g. stripe not-found)

	updateBarDesc := func() {
		if trackMapErrors {
			bar.Describe(fmt.Sprintf("Mapping (mapped:%d excluded:%d ignored:%d errors:%d)", mapped, excluded, ignored, errored))
		} else {
			bar.Describe(fmt.Sprintf("Mapping (mapped:%d excluded:%d ignored:%d)", mapped, excluded, ignored))
		}
	}
	updateBarDesc()

	for rowIdx, row := range allRows[1:] {
		// honor ctrl+c — stop processing immediately
		if err := ctx.Err(); err != nil {
			bar.Finish()
			return fmt.Errorf("interrupted: %w", err)
		}

		bar.Add(1)
		// refresh the description periodically so the live counts don't churn
		// the redraw on every row (every 100 keeps it fluid without thrashing)
		if (rowIdx+1)%100 == 0 {
			updateBarDesc()
		}

		// reset per-row soft error accumulator (populated by stripe.* functions
		// when they hit a recoverable problem like "not found")
		rowSoftErrors = rowSoftErrors[:0]

		// build row environment for expr evaluation (shared by filter and mappings);
		// start from the compile-time env (functions, constants) and overlay row values
		rowEnv := make(map[string]any, len(exprEnv)+len(headers))
		for k, v := range exprEnv {
			rowEnv[k] = v
		}
		for i, h := range headers {
			val := ""
			if i < len(row) {
				val = row[i]
			}
			rowEnv[h] = val
			if sanitized := sanitizeHeader(h); sanitized != h {
				rowEnv[sanitized] = val
			}
		}

		// apply global filter
		if filterProgram != nil {
			result, err := expr.Run(filterProgram, rowEnv)
			if err != nil {
				return fmt.Errorf("filter evaluation failed: %w", err)
			}
			if match, ok := result.(bool); !ok || !match {
				excluded++
				continue
			}
		}

		// map the record (this is the loop that may make stripe.* calls — only
		// runs once per row regardless of how many output targets exist)
		rec := &atomic.UserImportRecord{}

		for targetField, entries := range resolved {
			var val string
			matched := false
			for _, src := range entries {
				if src.filter != nil {
					fres, ferr := expr.Run(src.filter, rowEnv)
					if ferr != nil {
						return fmt.Errorf("mapping field %q: filter evaluation failed on row %d: %w", targetField, rowIdx+1, ferr)
					}
					if m, ok := fres.(bool); !ok || !m {
						continue
					}
				}
				if src.program != nil {
					result, err := expr.Run(src.program, rowEnv)
					if err != nil {
						return fmt.Errorf("mapping field %q: expression evaluation failed on row %d: %w", targetField, rowIdx+1, err)
					}
					val = exprResultToString(result)
				} else {
					val = src.static
				}
				matched = true
				break
			}

			if !matched || val == "" {
				continue
			}

			setter, ok := importFieldSetters[targetField]
			if !ok {
				continue
			}
			setter(rec, val)
		}

		// ignore rows with no login (unmappable)
		if rec.Login == "" {
			ignored++
			continue
		}

		// apply email rewriting
		if rewriter != nil {
			rec.Login = rewriter.Rewrite(rec.Login)
			if rec.Email != nil && *rec.Email != "" {
				rewritten := rewriter.Rewrite(*rec.Email)
				rec.Email = &rewritten
			}
		}

		// default email to login if not explicitly mapped
		if rec.Email == nil || *rec.Email == "" {
			login := rec.Login
			rec.Email = &login
		}

		// default import_source from --source flag if not set by columns
		if (rec.ImportSource == nil || *rec.ImportSource == "") && source != "" {
			rec.ImportSource = &source
		}

		// capture any soft errors picked up during column evaluation
		hasError := len(rowSoftErrors) > 0
		if hasError {
			errored++
		}

		ir := &importRecord{UserImportRecord: *rec}
		if hasError {
			ir.MapError = strings.Join(rowSoftErrors, "; ")
		}

		// route to all matching output targets. With --split-error-rows, error
		// rows go ONLY to the target's _errors sibling (not the main file).
		// skip/limit are applied inline, per-target, so we can short-circuit the
		// outer loop once every target has filled its quota.
		routed := false
		for i, t := range targets {
			if t.filter != nil {
				result, err := expr.Run(t.filter, rowEnv)
				if err != nil {
					return fmt.Errorf("output %q filter evaluation failed on row %d: %w", t.path, rowIdx+1, err)
				}
				if match, ok := result.(bool); !ok || !match {
					continue
				}
			}
			if hasError && splitErrorRows && t.errorPath != "" {
				targets[i].errRecords = append(targets[i].errRecords, ir)
				routed = true
				continue
			}
			// honor --skip on the main record stream
			if skip > 0 && targets[i].skipped < skip {
				targets[i].skipped++
				continue
			}
			// honor --limit on the main record stream
			if limit > 0 && len(targets[i].records) >= limit {
				continue
			}
			targets[i].records = append(targets[i].records, ir)
			routed = true
		}
		if routed {
			mapped++
		}

		// break as soon as every target has reached its limit; nothing further
		// to collect, so avoid spending more stripe/expr calls on rows that
		// would be discarded.
		if limit > 0 && allTargetsSaturated(targets, limit) {
			limitHit = true
			break
		}
	}

	updateBarDesc()
	bar.Finish()

	// helper to write a slice of import records to a CSV path
	writeRecords := func(path string, recs []*importRecord, label string) error {
		if appendMode {
			var appendErr error
			recs, appendErr = appendExistingCSV(path, recs)
			if appendErr != nil {
				return appendErr
			}
		}

		outFile, err := os.Create(path)
		if err != nil {
			return fmt.Errorf("failed to create output file %s: %w", path, err)
		}

		if err := gocsv.MarshalFile(&recs, outFile); err != nil {
			outFile.Close()
			return fmt.Errorf("failed to write output CSV %s: %w", path, err)
		}
		outFile.Close()

		fmt.Fprintf(os.Stderr, "%s %d records to %s\n", label, len(recs), path)
		return nil
	}

	// skip/limit are applied inline during row processing (see the routing
	// block above) so the main loop can short-circuit once every target is
	// saturated. The error sibling is written as-is so the user sees every
	// problem row.

	// write each output target
	for _, t := range targets {
		mainRecs := t.records
		if err := writeRecords(t.path, mainRecs, "mapped"); err != nil {
			return err
		}

		if t.errorPath != "" && len(t.errRecords) > 0 {
			if err := writeRecords(t.errorPath, t.errRecords, "errors"); err != nil {
				return err
			}
		}
	}

	// aggregate per-target skip counts for reporting (max across targets is
	// representative since skip is the same threshold for all targets)
	skippedTotal := 0
	for _, t := range targets {
		if t.skipped > skippedTotal {
			skippedTotal = t.skipped
		}
	}

	fmt.Fprintf(os.Stderr, "mapped %d records\n", mapped)

	if excluded > 0 || ignored > 0 || errored > 0 || skippedTotal > 0 || limitHit {
		var parts []string
		if skippedTotal > 0 {
			parts = append(parts, fmt.Sprintf("%d skipped by --skip", skippedTotal))
		}
		if excluded > 0 {
			parts = append(parts, fmt.Sprintf("%d excluded by filter", excluded))
		}
		if ignored > 0 {
			parts = append(parts, fmt.Sprintf("%d ignored — no login", ignored))
		}
		if errored > 0 {
			parts = append(parts, fmt.Sprintf("%d errors (see map_error column)", errored))
		}
		if limitHit {
			parts = append(parts, fmt.Sprintf("stopped early — --limit=%d reached", limit))
		}
		fmt.Fprintf(os.Stderr, "(%s)\n", strings.Join(parts, ", "))
	}

	if stripeUsed && trackMapErrors {
		stripeMu.Lock()
		nf := stripeNotFound
		stripeMu.Unlock()
		if nf > 0 {
			fmt.Fprintf(os.Stderr, "stripe.customer_search: %d not found\n", nf)
		} else {
			fmt.Fprintf(os.Stderr, "stripe.customer_search: all lookups resolved\n")
		}
	}

	// automatic validate + dedupe post-pass (inherited from `migrate` parent
	// command). Runs in-place against each target's main output — the user
	// can disable via --validate=false and --dedupe=false.
	outputPaths := make([]string, 0, len(targets))
	for _, t := range targets {
		if len(t.records) > 0 {
			outputPaths = append(outputPaths, t.path)
		}
	}
	if err := postProcessMigrateOutputs(cmd, outputPaths); err != nil {
		return err
	}

	return nil
}

// postProcessMigrateOutputs runs the validate/dedupe pass on every main
// output path written by a migrate subcommand. Writes in place so the final
// file on disk is ready for `user import`.
func postProcessMigrateOutputs(cmd *cli.Command, paths []string) error {
	opts := validateAndDedupeOptions{
		validate:      cmd.Bool("validate"),
		dedupe:        cmd.Bool("dedupe"),
		dedupeColumns: cmd.StringSlice("dedupe-columns"),
		merge:         cmd.Bool("merge"),
		verbose:       mainCmd.Bool("verbose"),
		// no prompt: the file was just written by this same run, so
		// overwriting it with the deduped version is expected
		promptOverwrite: false,
	}
	if !opts.validate && !opts.dedupe {
		return nil
	}
	for _, p := range paths {
		if err := runValidateAndDedupe(p, p, opts); err != nil {
			return err
		}
	}
	return nil
}

func validateMapping(mapping convertMapping) error {
	if len(mapping) == 0 {
		return fmt.Errorf("mapping file is empty")
	}

	// login must be mapped
	if _, ok := mapping["login"]; !ok {
		return fmt.Errorf("mapping must include a \"login\" field")
	}

	// validate that all target fields are known (drives off importFieldSetters
	// so this stays in sync as new setters are added)
	for field := range mapping {
		if _, ok := importFieldSetters[field]; !ok {
			valid := make([]string, 0, len(importFieldSetters))
			for k := range importFieldSetters {
				valid = append(valid, k)
			}
			return fmt.Errorf("unknown target field %q in mapping; valid fields: %s", field, strings.Join(valid, ", "))
		}
	}

	return nil
}

var headerSanitizeRe = regexp.MustCompile(`[^a-zA-Z0-9_]+`)

// sanitizeHeader converts a CSV header to a valid expr identifier. Runs of
// non-alphanumeric characters collapse to a single underscore and
// leading/trailing underscores are trimmed, so "Trial_End (UTC)" -> "Trial_End_UTC"
// and "Emails opened (6mo)" -> "Emails_opened_6mo". Returns the original
// header when the sanitized form would be empty.
func sanitizeHeader(h string) string {
	s := headerSanitizeRe.ReplaceAllString(h, "_")
	s = strings.Trim(s, "_")
	if s == "" {
		return h
	}
	return s
}

// atoiFn converts a string to an integer for use in expr expressions.
func atoiFn() expr.Option {
	return expr.Function(
		"atoi",
		func(params ...any) (any, error) {
			s, ok := params[0].(string)
			if !ok {
				return 0, fmt.Errorf("atoi: argument must be a string")
			}
			s = strings.TrimSpace(s)
			if s == "" {
				return 0, nil
			}
			n, err := strconv.Atoi(s)
			if err != nil {
				return 0, fmt.Errorf("atoi: %w", err)
			}
			return n, nil
		},
		new(func(string) int),
	)
}

// shiftAnchorDateFn rolls a date forward by whole intervals until it's in
// the future, mirroring the anchor-date normalization the user_import job
// applies before sending to Stripe (Stripe rejects past anchor dates).
//
// Signatures:
//
//	shiftAnchorDate(date)             — month interval, default
//	shiftAnchorDate(date, interval)   — interval ∈ year/y, month/M, week/w, day/d (long forms case-insensitive; singular accepted)
//
// `date` may be a time.Time or any string parseFlexibleTime accepts. Empty
// dates and zero times return the zero time. Dates already in the future
// are returned unchanged. Returns time.Time, so it can be assigned directly
// to e.g. subscription_anchor_date.
func shiftAnchorDateFn() expr.Option {
	return expr.Function(
		"shiftAnchorDate",
		func(params ...any) (any, error) {
			if len(params) < 1 {
				return time.Time{}, fmt.Errorf("shiftAnchorDate: requires (date [, interval])")
			}

			var t time.Time
			switch v := params[0].(type) {
			case time.Time:
				t = v
			case *time.Time:
				if v == nil {
					return time.Time{}, nil
				}
				t = *v
			case string:
				s := strings.TrimSpace(v)
				if s == "" {
					return time.Time{}, nil
				}
				parsed, err := parseFlexibleTime(s)
				if err != nil {
					return time.Time{}, fmt.Errorf("shiftAnchorDate: invalid date %q: %w", s, err)
				}
				t = parsed
			default:
				return time.Time{}, fmt.Errorf("shiftAnchorDate: date must be a time or string, got %T", params[0])
			}

			if t.IsZero() {
				return t, nil
			}

			interval := "month"
			if len(params) >= 2 {
				iv, ok := params[1].(string)
				if !ok {
					return time.Time{}, fmt.Errorf("shiftAnchorDate: interval must be a string, got %T", params[1])
				}
				interval = strings.TrimSpace(iv)
			}

			var addYears, addMonths, addDays int
			// short forms are case-sensitive ("M" vs "m" — but only "M" and
			// "y"/"d"/"w" are defined). long forms are case-insensitive.
			switch interval {
			case "y", "M", "w", "d":
				switch interval {
				case "y":
					addYears = 1
				case "M":
					addMonths = 1
				case "w":
					addDays = 7
				case "d":
					addDays = 1
				}
			default:
				switch strings.ToLower(interval) {
				case "year", "years":
					addYears = 1
				case "", "month", "months":
					addMonths = 1
				case "week", "weeks":
					addDays = 7
				case "day", "days":
					addDays = 1
				default:
					return time.Time{}, fmt.Errorf("shiftAnchorDate: unknown interval %q (valid: year/y, month/M, week/w, day/d)", interval)
				}
			}

			now := time.Now().UTC()
			out := t.UTC()
			for !out.After(now) {
				out = out.AddDate(addYears, addMonths, addDays)
			}
			return out, nil
		},
		new(func(date string) time.Time),
		new(func(date, interval string) time.Time),
		new(func(date time.Time) time.Time),
		new(func(date time.Time, interval string) time.Time),
	)
}

// currencyForCountryFn returns the lowercased ISO 4217 currency code for the
// given country. The country argument accepts an Alpha-2 ("US"), Alpha-3
// ("USA"), or full name ("United States"), case-insensitive.
//
// If the country's native currency is in atomic.LocalizedCurrencies, that
// currency is returned. Otherwise the optional fallback is returned (which
// must itself be in LocalizedCurrencies). If no fallback is provided, USD
// is returned.
func currencyForCountryFn() expr.Option {
	return expr.Function(
		"currencyForCountry",
		func(params ...any) (any, error) {
			if len(params) < 1 {
				return nil, fmt.Errorf("currencyForCountry: requires at least 1 argument")
			}
			country, ok := params[0].(string)
			if !ok {
				return nil, fmt.Errorf("currencyForCountry: country must be a string, got %T", params[0])
			}

			fallback := "usd"
			if len(params) >= 2 {
				fb, ok := params[1].(string)
				if !ok {
					return nil, fmt.Errorf("currencyForCountry: fallback must be a string, got %T", params[1])
				}
				fb = strings.ToLower(strings.TrimSpace(fb))
				if fb != "" {
					if !util.Slice[string](atomic.LocalizedCurrencies).Contains(fb) {
						return nil, fmt.Errorf("currencyForCountry: fallback %q is not in LocalizedCurrencies (valid: %s)", fb, strings.Join(atomic.LocalizedCurrencies, ", "))
					}
					fallback = fb
				}
			}

			country = strings.TrimSpace(country)
			if country == "" {
				return fallback, nil
			}

			cc := countries.ByName(country)
			if cc == countries.Unknown {
				return fallback, nil
			}

			// CurrencyCode.Alpha() returns the ISO 4217 code (e.g. "GBP");
			// String() returns the English name ("pound sterling"), which
			// would never match LocalizedCurrencies.
			currency := strings.ToLower(cc.Currency().Alpha())
			if util.Slice[string](atomic.LocalizedCurrencies).Contains(currency) {
				return currency, nil
			}
			return fallback, nil
		},
		new(func(country string) string),
		new(func(country, fallback string) string),
	)
}

// dateFn overrides expr's built-in date() with a flexible version. Accepts
//
//	date(s)                    — auto-detect format
//	date(s, layout)            — try explicit layout, fall back to auto-detect
//	date(s, layout, location)  — try explicit layout in tz, fall back to auto-detect
//
// Auto-detection uses parseFlexibleTime, which understands a broad set of
// ISO/RFC layouts as well as US-style MM/DD/YYYY with optional times.
func dateFn() expr.Option {
	return expr.Function(
		"date",
		func(params ...any) (any, error) {
			if len(params) == 0 {
				return nil, fmt.Errorf("date: requires at least 1 argument")
			}
			s, ok := params[0].(string)
			if !ok {
				return nil, fmt.Errorf("date: first argument must be a string, got %T", params[0])
			}
			s = strings.TrimSpace(s)
			if s == "" {
				return time.Time{}, nil
			}

			var layout, tzName string
			if len(params) >= 2 {
				if l, ok := params[1].(string); ok {
					layout = l
				}
			}
			if len(params) >= 3 {
				if z, ok := params[2].(string); ok {
					tzName = z
				}
			}

			loc := time.UTC
			if tzName != "" {
				l, err := time.LoadLocation(tzName)
				if err != nil {
					return nil, fmt.Errorf("date: unknown timezone %q: %w", tzName, err)
				}
				loc = l
			}

			if layout != "" {
				if t, err := time.ParseInLocation(layout, s, loc); err == nil {
					return t, nil
				}
				// fall through to auto-detect when the explicit layout doesn't match
			}

			t, err := parseFlexibleTime(s)
			if err != nil {
				return nil, fmt.Errorf("date: %w", err)
			}
			// If a tz was provided and the parsed time has no offset (UTC default
			// from naked layouts), reinterpret in the requested location so the
			// instant matches the user's intent.
			if tzName != "" {
				_, offset := t.Zone()
				if offset == 0 && loc != time.UTC {
					t = time.Date(t.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), t.Nanosecond(), loc)
				}
			}
			return t, nil
		},
		new(func(s string) time.Time),
		new(func(s, layout string) time.Time),
		new(func(s, layout, location string) time.Time),
	)
}

// sinceFn returns the integer count of <unit>s elapsed from <when> until now.
// Example: since("days", LastSeen) — useful in filters/values to compare ages.
func sinceFn() expr.Option {
	return expr.Function(
		"since",
		func(params ...any) (any, error) {
			return diffInUnits(params, true)
		},
		new(func(unit, when string) int),
		new(func(unit string, when time.Time) int),
	)
}

// untilFn returns the integer count of <unit>s from now until <when>.
// Example: until("days", TrialEnd).
func untilFn() expr.Option {
	return expr.Function(
		"until",
		func(params ...any) (any, error) {
			return diffInUnits(params, false)
		},
		new(func(unit, when string) int),
		new(func(unit string, when time.Time) int),
	)
}

// diffInUnits is the shared body for since/until. fromPast=true means
// "from <when> to now" (since); false means "from now to <when>" (until).
func diffInUnits(params []any, fromPast bool) (int, error) {
	if len(params) != 2 {
		return 0, fmt.Errorf("requires (unit, time)")
	}
	unit, ok := params[0].(string)
	if !ok {
		return 0, fmt.Errorf("first argument must be a string unit")
	}

	var t time.Time
	switch v := params[1].(type) {
	case time.Time:
		t = v
	case *time.Time:
		if v == nil {
			return 0, nil
		}
		t = *v
	case string:
		s := strings.TrimSpace(v)
		if s == "" {
			return 0, nil
		}
		parsed, err := parseFlexibleTime(s)
		if err != nil {
			return 0, fmt.Errorf("invalid time %q: %w", s, err)
		}
		t = parsed
	default:
		return 0, fmt.Errorf("second argument must be a time or string, got %T", params[1])
	}

	now := time.Now().UTC()
	t = t.UTC()

	from, to := t, now
	if !fromPast {
		from, to = now, t
	}

	// short forms are case-sensitive so "M" (months) doesn't collide with
	// "m" (minutes); long forms are case-insensitive.
	switch strings.TrimSpace(unit) {
	case "s":
		return int(to.Sub(from).Seconds()), nil
	case "m":
		return int(to.Sub(from).Minutes()), nil
	case "h":
		return int(to.Sub(from).Hours()), nil
	case "d":
		return int(to.Sub(from).Hours() / 24), nil
	case "M":
		return calendarMonthsBetween(from, to), nil
	case "y":
		return calendarYearsBetween(from, to), nil
	}
	switch strings.ToLower(strings.TrimSpace(unit)) {
	case "second", "seconds":
		return int(to.Sub(from).Seconds()), nil
	case "minute", "minutes":
		return int(to.Sub(from).Minutes()), nil
	case "hour", "hours":
		return int(to.Sub(from).Hours()), nil
	case "day", "days":
		return int(to.Sub(from).Hours() / 24), nil
	case "month", "months":
		return calendarMonthsBetween(from, to), nil
	case "year", "years":
		return calendarYearsBetween(from, to), nil
	default:
		return 0, fmt.Errorf("unknown unit %q (valid: seconds/s, minutes/m, hours/h, days/d, months/M, years/y)", unit)
	}
}

// calendarMonthsBetween counts whole calendar months from a to b. Negative
// when a is after b. Truncates toward zero on partial months (anniversary
// semantics): from 2024-01-15 to 2024-02-14 = 0; to 2024-02-15 = 1.
func calendarMonthsBetween(a, b time.Time) int {
	months := (b.Year()-a.Year())*12 + int(b.Month()-a.Month())
	switch {
	case months > 0 && b.Day() < a.Day():
		months--
	case months < 0 && b.Day() > a.Day():
		months++
	}
	return months
}

// calendarYearsBetween counts whole calendar years from a to b. Negative
// when a is after b. Anniversary semantics: 2024-03-15 to 2025-03-14 = 0;
// to 2025-03-15 = 1.
func calendarYearsBetween(a, b time.Time) int {
	years := b.Year() - a.Year()
	switch {
	case years > 0 && (b.Month() < a.Month() || (b.Month() == a.Month() && b.Day() < a.Day())):
		years--
	case years < 0 && (b.Month() > a.Month() || (b.Month() == a.Month() && b.Day() > a.Day())):
		years++
	}
	return years
}
