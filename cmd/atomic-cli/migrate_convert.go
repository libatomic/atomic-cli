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

	"github.com/gocarina/gocsv"
	"github.com/libatomic/atomic/pkg/atomic"
	"github.com/urfave/cli/v3"
)

// convertMapping maps UserImportRecord field names to source CSV column names.
// Multiple target fields can reference the same source column.
//
// Example:
//
//	{
//	  "login": "email",
//	  "email": "email",
//	  "name": "name",
//	  "email_verified": true
//	}
//
// Values can be:
//   - string: the source CSV column name to read from
//   - bool/number/etc: a static value applied to every row
type convertMapping map[string]any

var (
	migrateConvertFlags = append(
		migrateCommonFlags,
		&cli.StringFlag{
			Name:     "input",
			Aliases:  []string{"in"},
			Usage:    "input CSV file path",
			Required: true,
		},
		&cli.StringFlag{
			Name:     "mapping",
			Aliases:  []string{"m"},
			Usage:    "JSON mapping file path",
			Required: true,
		},
	)

	migrateConvertCmd = &cli.Command{
		Name:   "convert",
		Usage:  "convert a third-party CSV to Passport user import format using a mapping file",
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
	}
)

func parseBool(val string) bool {
	val = strings.TrimSpace(strings.ToLower(val))
	return val == "true" || val == "1" || val == "yes"
}

func migrateConvertAction(ctx context.Context, cmd *cli.Command) error {
	_, outputPath, _, rewriter, appendMode, err := validateMigrateFlags(cmd, false)
	if err != nil {
		return err
	}

	inputPath := cmd.String("input")
	mappingPath := cmd.String("mapping")

	// load the mapping file
	mappingData, err := os.ReadFile(mappingPath)
	if err != nil {
		return fmt.Errorf("failed to read mapping file: %w", err)
	}

	var mapping convertMapping
	if err := json.Unmarshal(mappingData, &mapping); err != nil {
		return fmt.Errorf("failed to parse mapping file: %w", err)
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

	// validate that all column references in the mapping exist in the source CSV
	for targetField, sourceVal := range mapping {
		sourceCol, ok := sourceVal.(string)
		if !ok {
			continue // static value, not a column reference
		}
		if _, exists := headerIndex[strings.ToLower(sourceCol)]; !exists {
			return fmt.Errorf("mapping field %q references source column %q which does not exist in the input CSV; available columns: %s",
				targetField, sourceCol, strings.Join(headers, ", "))
		}
	}

	// build the resolved mapping: target field -> (column index or static value)
	type fieldSource struct {
		colIndex int    // >= 0 means read from this column
		static   string // used when colIndex < 0
	}

	resolved := make(map[string]fieldSource)
	for targetField, sourceVal := range mapping {
		switch v := sourceVal.(type) {
		case string:
			idx := headerIndex[strings.ToLower(v)]
			resolved[targetField] = fieldSource{colIndex: idx}
		case bool:
			if v {
				resolved[targetField] = fieldSource{colIndex: -1, static: "true"}
			} else {
				resolved[targetField] = fieldSource{colIndex: -1, static: "false"}
			}
		case float64:
			resolved[targetField] = fieldSource{colIndex: -1, static: fmt.Sprintf("%g", v)}
		default:
			resolved[targetField] = fieldSource{colIndex: -1, static: fmt.Sprintf("%v", v)}
		}
	}

	// convert rows
	var records []*atomic.UserImportRecord
	skipped := 0

	for _, row := range allRows[1:] {
		rec := &atomic.UserImportRecord{}

		for targetField, src := range resolved {
			var val string
			if src.colIndex >= 0 && src.colIndex < len(row) {
				val = row[src.colIndex]
			} else if src.colIndex < 0 {
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

	fmt.Fprintf(os.Stderr, "converted %d records to %s", len(records), outputPath)
	if skipped > 0 {
		fmt.Fprintf(os.Stderr, " (%d rows skipped — no login value)", skipped)
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
		"stripe_customer_id": true,
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

