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
	//
	// Example:
	//
	//	{
	//	  "consts": {
	//	    "ALL_SECTIONS": "News,Sports,Opinion,Tech"
	//	  },
	//	  "filter": "Type != \"Comp\"",
	//	  "columns": {
	//	    "login": "trim(lower(Email))",
	//	    "email": "Email",
	//	    "name": "Name",
	//	    "category_opt_out": "join(without(splitTrim(ALL_SECTIONS), splitTrim(Sections)), \"|\")",
	//	    "email_verified": true
	//	  }
	//	}
	convertMappingFile struct {
		// Consts defines constants available in all expressions (string or []string)
		Consts map[string]any `json:"const,omitempty"`
		// Filter is an expr expression that must evaluate to bool; only matching rows are included
		Filter string `json:"filter,omitempty"`
		// Columns maps UserImportRecord field names to expr expressions or static values
		Columns map[string]any `json:"columns"`
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
			Name:  "const",
			Usage: "define constants for use in expressions as NAME=value (e.g. --const 'ALL_CATS=News,Sports,Opinion')",
		},
	)

	migrateConvertCmd = &cli.Command{
		Name:   "map",
		Usage:  "map and filter a third-party CSV to Passport user import format using a mapping file",
		Flags:  migrateConvertFlags,
		Action: migrateConvertAction,
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

func migrateConvertAction(ctx context.Context, cmd *cli.Command) error {
	_, outputPath, _, rewriter, appendMode, source, err := validateMigrateFlags(cmd, false)
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
		fileConsts map[string]any
		fileFilter string
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
		if mf.Columns == nil || len(mf.Columns) == 0 {
			return fmt.Errorf("mapping file must have a \"columns\" object")
		}
		mapping = mf.Columns
		fileConsts = mf.Consts
		fileFilter = mf.Filter
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

	// build expr environment from CSV headers so expressions can reference columns
	exprEnv := make(map[string]any, len(headers))
	for _, h := range headers {
		exprEnv[h] = ""
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

	exprOpts := []expr.Option{expr.Env(exprEnv), splitTrimFn, withoutFn, sprintfFn}

	// add consts from file first, then CLI flags (CLI wins on conflict)
	for name, value := range fileConsts {
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
	for _, c := range cmd.StringSlice("const") {
		kv := strings.SplitN(c, "=", 2)
		if len(kv) != 2 {
			return fmt.Errorf("invalid --const %q: expected NAME=value", c)
		}
		name := strings.TrimSpace(kv[0])
		value := strings.TrimSpace(kv[1])
		if name == "" {
			return fmt.Errorf("invalid --const %q: name must not be empty", c)
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
			if i < len(row) {
				rowEnv[h] = row[i]
			} else {
				rowEnv[h] = ""
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

	// wrap as importRecords for shared append logic
	importRecords := make([]*importRecord, 0, len(records))
	for _, rec := range records {
		importRecords = append(importRecords, &importRecord{UserImportRecord: *rec})
	}

	if appendMode {
		var appendErr error
		importRecords, appendErr = appendExistingCSV(outputPath, importRecords)
		if appendErr != nil {
			return appendErr
		}
	}

	outFile, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer outFile.Close()

	if err := gocsv.MarshalFile(&importRecords, outFile); err != nil {
		return fmt.Errorf("failed to write output CSV: %w", err)
	}

	fmt.Fprintf(os.Stderr, "mapped %d records to %s", len(records), outputPath)
	if filtered > 0 || skipped > 0 {
		var parts []string
		if filtered > 0 {
			parts = append(parts, fmt.Sprintf("%d filtered out", filtered))
		}
		if skipped > 0 {
			parts = append(parts, fmt.Sprintf("%d skipped — no login", skipped))
		}
		fmt.Fprintf(os.Stderr, " (%s)", strings.Join(parts, ", "))
	}
	fmt.Fprintln(os.Stderr)

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
