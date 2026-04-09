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
	"regexp"
	"strconv"
	"strings"

	"github.com/expr-lang/expr"
	"github.com/expr-lang/expr/vm"
	"github.com/gocarina/gocsv"
	"github.com/libatomic/atomic/pkg/atomic"
	"github.com/libatomic/atomic/pkg/util"
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
		// Columns maps UserImportRecord field names to expr expressions or static values
		Columns map[string]any `json:"columns"`
	}

	convertMappingOptions struct {
		Append               *bool  `json:"append,omitempty"`
		EmailDomainOverwrite string `json:"email_domain_overwrite,omitempty"`
		EmailTemplate        string `json:"email_template,omitempty"`
		Source               string `json:"source,omitempty"`
		Limit                *int   `json:"limit,omitempty"`
		Skip                 *int   `json:"skip,omitempty"`
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
		"billing_email": func(rec *atomic.UserImportRecord, val string) {
			v := strings.TrimSpace(val)
			rec.BillingEmail = &v
		},
		"billing_phone_number": func(rec *atomic.UserImportRecord, val string) {
			v := strings.TrimSpace(val)
			rec.BillingPhoneNumber = &v
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
	}
)

func parseBool(val string) bool {
	val = strings.TrimSpace(strings.ToLower(val))
	return val == "true" || val == "1" || val == "yes"
}

func migrateMapAction(ctx context.Context, cmd *cli.Command) error {
	_, outputPath, _, rewriter, appendMode, source, limit, skip, err := validateMigrateFlags(cmd, false)
	if err != nil {
		return err
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

	exprOpts := []expr.Option{expr.Env(exprEnv), splitTrimFn, withoutFn, sprintfFn, atoiFn()}

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

	// build the resolved mapping: target field -> compiled expr program or static value
	type fieldSource struct {
		program *vm.Program // non-nil for expr-based mappings
		static  string      // used when program is nil
	}

	resolved := make(map[string]fieldSource)
	for targetField, sourceVal := range mapping {
		switch v := sourceVal.(type) {
		case string:
			program, err := expr.Compile(v, exprOpts...)
			if err != nil {
				return fmt.Errorf("mapping field %q: invalid expression %q: %w", targetField, v, err)
			}
			resolved[targetField] = fieldSource{program: program}
		case bool:
			if v {
				resolved[targetField] = fieldSource{static: "true"}
			} else {
				resolved[targetField] = fieldSource{static: "false"}
			}
		case float64:
			resolved[targetField] = fieldSource{static: fmt.Sprintf("%g", v)}
		default:
			resolved[targetField] = fieldSource{static: fmt.Sprintf("%v", v)}
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

	// convert rows
	var records []*atomic.UserImportRecord
	skipped := 0
	filtered := 0

	for _, row := range allRows[1:] {
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

		// apply filter
		if filterProgram != nil {
			result, err := expr.Run(filterProgram, rowEnv)
			if err != nil {
				return fmt.Errorf("filter evaluation failed: %w", err)
			}
			if match, ok := result.(bool); !ok || !match {
				filtered++
				continue
			}
		}

		rec := &atomic.UserImportRecord{}

		for targetField, src := range resolved {
			var val string
			if src.program != nil {
				result, err := expr.Run(src.program, rowEnv)
				if err != nil {
					return fmt.Errorf("mapping field %q: expression evaluation failed on row %d: %w", targetField, len(records)+skipped+filtered+1, err)
				}
				val = fmt.Sprintf("%v", result)
			} else {
				val = src.static
			}

			if val == "" {
				continue
			}

			setter, ok := importFieldSetters[targetField]
			if !ok {
				continue
			}
			setter(rec, val)
		}

		// skip rows with no login
		if rec.Login == "" {
			skipped++
			continue
		}

		// apply email rewriting
		if rewriter != nil {
			rec.Login = rewriter.Rewrite(rec.Login)
			if rec.Email != nil && *rec.Email != "" {
				rewritten := rewriter.Rewrite(*rec.Email)
				rec.Email = &rewritten
			}
			if rec.BillingEmail != nil && *rec.BillingEmail != "" {
				rewritten := rewriter.Rewrite(*rec.BillingEmail)
				rec.BillingEmail = &rewritten
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

		records = append(records, rec)
	}

	// determine output targets
	type outputTarget struct {
		path    string
		filter  *vm.Program
		records []*importRecord
	}

	var targets []outputTarget

	if len(outputs) > 0 {
		// multi-output mode from config file
		for _, out := range outputs {
			t := outputTarget{path: out.Path}
			if out.Filter != "" {
				prog, err := expr.Compile(out.Filter, append(exprOpts, expr.AsBool())...)
				if err != nil {
					return fmt.Errorf("output %q: invalid filter expression: %w", out.Path, err)
				}
				t.filter = prog
			}
			targets = append(targets, t)
		}
	} else {
		// single output mode
		targets = []outputTarget{{path: outputPath}}
	}

	// route records to output targets
	for _, rec := range records {
		ir := &importRecord{UserImportRecord: *rec}

		if len(outputs) > 0 {
			// evaluate each output's filter against the original row env
			// we need the raw row data; reconstruct from record fields is not practical,
			// so we re-evaluate filters against the stored row environments
			// Instead, route during the row loop above. Let's restructure.
		}
		// for single output, just collect all
		if len(outputs) == 0 {
			targets[0].records = append(targets[0].records, ir)
		}
	}

	// If multi-output, we need to route during row processing. Let me restructure
	// to collect per-output during the main loop instead.
	if len(outputs) > 0 {
		// clear - we'll redo this properly
		for i := range targets {
			targets[i].records = nil
		}

		for rowIdx, row := range allRows[1:] {
			_ = rowIdx
			rowEnv := make(map[string]any, len(exprEnv)+len(headers))
			for k, v := range exprEnv {
				rowEnv[k] = v
			}
			for i, h := range headers {
				if i < len(row) {
					rowEnv[h] = row[i]
				} else {
					rowEnv[h] = ""
				}
			}

			// apply global filter
			if filterProgram != nil {
				result, err := expr.Run(filterProgram, rowEnv)
				if err != nil {
					continue
				}
				if match, ok := result.(bool); !ok || !match {
					continue
				}
			}

			// map the record
			rec := &atomic.UserImportRecord{}
			for targetField, src := range resolved {
				var val string
				if src.program != nil {
					result, err := expr.Run(src.program, rowEnv)
					if err != nil {
						return fmt.Errorf("mapping field %q: expression evaluation failed: %w", targetField, err)
					}
					val = fmt.Sprintf("%v", result)
				} else {
					val = src.static
				}
				if val == "" {
					continue
				}
				if setter, ok := importFieldSetters[targetField]; ok {
					setter(rec, val)
				}
			}

			if rec.Login == "" {
				continue
			}

			if rewriter != nil {
				rec.Login = rewriter.Rewrite(rec.Login)
				if rec.Email != nil && *rec.Email != "" {
					rewritten := rewriter.Rewrite(*rec.Email)
					rec.Email = &rewritten
				}
				if rec.BillingEmail != nil && *rec.BillingEmail != "" {
					rewritten := rewriter.Rewrite(*rec.BillingEmail)
					rec.BillingEmail = &rewritten
				}
			}

			if rec.Email == nil || *rec.Email == "" {
				login := rec.Login
				rec.Email = &login
			}

			if (rec.ImportSource == nil || *rec.ImportSource == "") && source != "" {
				rec.ImportSource = &source
			}

			ir := &importRecord{UserImportRecord: *rec}

			// route to matching outputs
			for i, t := range targets {
				if t.filter != nil {
					result, err := expr.Run(t.filter, rowEnv)
					if err != nil {
						continue
					}
					if match, ok := result.(bool); !ok || !match {
						continue
					}
				}
				targets[i].records = append(targets[i].records, ir)
			}
		}
	}

	// write each output target
	for _, t := range targets {
		outRecords := t.records

		// for single-output mode, wrap from records slice
		if len(outputs) == 0 {
			outRecords = make([]*importRecord, 0, len(records))
			for _, rec := range records {
				outRecords = append(outRecords, &importRecord{UserImportRecord: *rec})
			}
		}

		// apply skip and limit per output
		if skip > 0 && len(outRecords) > skip {
			outRecords = outRecords[skip:]
		} else if skip > 0 {
			outRecords = nil
		}
		if limit > 0 && len(outRecords) > limit {
			outRecords = outRecords[:limit]
		}

		if appendMode {
			var appendErr error
			outRecords, appendErr = appendExistingCSV(t.path, outRecords)
			if appendErr != nil {
				return appendErr
			}
		}

		outFile, err := os.Create(t.path)
		if err != nil {
			return fmt.Errorf("failed to create output file %s: %w", t.path, err)
		}

		if err := gocsv.MarshalFile(&outRecords, outFile); err != nil {
			outFile.Close()
			return fmt.Errorf("failed to write output CSV %s: %w", t.path, err)
		}
		outFile.Close()

		fmt.Fprintf(os.Stderr, "mapped %d records to %s\n", len(outRecords), t.path)
	}

	totalMapped := len(records)
	if len(outputs) > 0 {
		totalMapped = 0
		for _, t := range targets {
			totalMapped += len(t.records)
		}
	}

	if filtered > 0 || skipped > 0 {
		var parts []string
		if filtered > 0 {
			parts = append(parts, fmt.Sprintf("%d filtered out", filtered))
		}
		if skipped > 0 {
			parts = append(parts, fmt.Sprintf("%d skipped — no login", skipped))
		}
		fmt.Fprintf(os.Stderr, "(%s)\n", strings.Join(parts, ", "))
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

	// validate that all target fields are known
	knownFields := map[string]bool{
		"login": true, "email": true, "email_verified": true, "email_opt_in": true,
		"phone_number": true, "phone_number_verified": true, "phone_number_opt_in": true,
		"billing_email": true, "billing_phone_number": true, "name": true, "roles": true,
		"stripe_customer_id": true, "channel_opt_in": true, "category_opt_out": true,
		"import_comment": true, "import_source": true,
	}

	for field := range mapping {
		if !knownFields[field] {
			valid := make([]string, 0, len(knownFields))
			for k := range knownFields {
				valid = append(valid, k)
			}
			return fmt.Errorf("unknown target field %q in mapping; valid fields: %s", field, strings.Join(valid, ", "))
		}
	}

	return nil
}

var headerSanitizeRe = regexp.MustCompile(`[^a-zA-Z0-9_]`)

// sanitizeHeader converts a CSV header to a valid expr identifier.
// "Emails opened (6mo)" -> "Emails_opened__6mo_"
func sanitizeHeader(h string) string {
	return headerSanitizeRe.ReplaceAllString(h, "_")
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
