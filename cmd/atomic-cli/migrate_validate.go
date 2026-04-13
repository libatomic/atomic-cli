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
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"

	"github.com/gocarina/gocsv"
	"github.com/urfave/cli/v3"
)

var (
	migrateValidateFlags = append(
		migrateCommonFlags,
		&cli.StringFlag{
			Name:  "dedupe",
			Usage: "deduplicate records on the specified field; first occurrence wins (valid: login, email, phone_number, stripe_customer_id)",
		},
		&cli.BoolFlag{
			Name:  "merge",
			Usage: "when deduping, merge empty fields from duplicate rows into the first occurrence instead of dropping them outright",
			Value: true,
		},
	)

	migrateValidateCmd = &cli.Command{
		Name:      "validate",
		Usage:     "validate a user import CSV and optionally deduplicate records",
		ArgsUsage: "<input.csv>",
		Flags:     migrateValidateFlags,
		Action:    migrateValidateAction,
	}
)

type validateIssue struct {
	Row     int
	Login   string
	Field   string
	Value   string
	Message string
}

func migrateValidateAction(ctx context.Context, cmd *cli.Command) error {
	_, outputPath, _, _, _, _, _, _, err := validateMigrateFlags(cmd, false)
	if err != nil {
		return err
	}

	inputPath := cmd.Args().First()
	if inputPath == "" {
		return fmt.Errorf("input CSV file path is required")
	}
	dedupeField := cmd.String("dedupe")
	mergeDupes := cmd.Bool("merge")
	verbose := mainCmd.Bool("verbose")

	// default output to <input_basename>+deduped<ext> when user didn't override
	if outputPath == DefaultMigrateOutputPath {
		outputPath = dedupedOutputPath(inputPath)
	}

	if dedupeField != "" {
		validFields := map[string]bool{"login": true, "email": true, "phone_number": true, "stripe_customer_id": true}
		if !validFields[dedupeField] {
			return fmt.Errorf("invalid --dedupe field %q; valid values: login, email, phone_number, stripe_customer_id", dedupeField)
		}
	}

	inputFile, err := os.Open(inputPath)
	if err != nil {
		return fmt.Errorf("failed to open input file: %w", err)
	}
	defer inputFile.Close()

	var records []*importRecord
	if err := gocsv.UnmarshalFile(inputFile, &records); err != nil {
		return fmt.Errorf("failed to parse input CSV: %w", err)
	}

	fmt.Fprintf(os.Stderr, "loaded %d records from %s\n", len(records), inputPath)

	// per-record validation
	var issues []validateIssue
	for i, rec := range records {
		row := i + 1
		if err := rec.Validate(); err != nil {
			issues = append(issues, validateIssue{
				Row:     row,
				Login:   rec.Login,
				Field:   "record",
				Message: err.Error(),
			})
		}
	}

	// uniqueness checks
	type uniqueField struct {
		name   string
		getter func(rec *importRecord) string
	}

	uniqueFields := []uniqueField{
		{"login", func(rec *importRecord) string { return strings.ToLower(rec.Login) }},
		{"email", func(rec *importRecord) string {
			if rec.Email != nil && *rec.Email != "" {
				return strings.ToLower(*rec.Email)
			}
			return ""
		}},
		{"phone_number", func(rec *importRecord) string {
			if rec.PhoneNumber != nil {
				return *rec.PhoneNumber
			}
			return ""
		}},
		{"stripe_customer_id", func(rec *importRecord) string {
			if rec.StripeCustomerID != nil && *rec.StripeCustomerID != "" {
				return *rec.StripeCustomerID
			}
			return ""
		}},
	}

	// track duplicates: field name -> count
	duplicateCounts := make(map[string]int)
	// track rows already flagged as duplicates to avoid double-counting
	// when login and email have the same value
	dupeRows := make(map[int]bool)

	for _, uf := range uniqueFields {
		seen := make(map[string]int) // value -> first row (1-based)
		for i, rec := range records {
			row := i + 1
			val := uf.getter(rec)
			if val == "" {
				continue
			}
			if firstRow, exists := seen[val]; exists {
				// only report if this row hasn't already been flagged as a duplicate
				if !dupeRows[row] {
					issues = append(issues, validateIssue{
						Row:     row,
						Login:   rec.Login,
						Field:   uf.name,
						Value:   val,
						Message: fmt.Sprintf("duplicate %s (first seen at row %d)", uf.name, firstRow),
					})
					duplicateCounts[uf.name]++
					dupeRows[row] = true
				}
			} else {
				seen[val] = row
			}
		}
	}

	// report
	validationErrors := 0
	dupeErrors := 0
	validationBreakdown := make(map[string]int) // field name from validation error -> count

	for _, issue := range issues {
		if issue.Field == "record" {
			validationErrors++
			// parse ozzo-validation error keys from the message (e.g. "login: cannot be blank; email: ...")
			for _, fieldErr := range strings.Split(issue.Message, "; ") {
				if parts := strings.SplitN(fieldErr, ":", 2); len(parts) == 2 {
					validationBreakdown[strings.TrimSpace(parts[0])]++
				} else {
					validationBreakdown["other"]++
				}
			}
		} else {
			dupeErrors++
		}
	}

	if verbose && len(issues) > 0 {
		fmt.Fprintf(os.Stderr, "\n")
		for _, issue := range issues {
			if issue.Field == "record" {
				fmt.Fprintf(os.Stderr, "  row %d [%s] (validation): %s\n", issue.Row, issue.Login, issue.Message)
			} else {
				fmt.Fprintf(os.Stderr, "  row %d [%s] %s=%q: %s\n", issue.Row, issue.Login, issue.Field, issue.Value, issue.Message)
			}
		}
		fmt.Fprintf(os.Stderr, "\n")
	}

	fmt.Fprintf(os.Stderr, "\ntotal rows: %d\n", len(records))

	if validationErrors > 0 {
		fmt.Fprintf(os.Stderr, "validation errors: %d\n", validationErrors)
		for field, count := range validationBreakdown {
			fmt.Fprintf(os.Stderr, "  %s: %d\n", field, count)
		}
	}

	if len(duplicateCounts) > 0 {
		fmt.Fprintf(os.Stderr, "duplicate errors: %d\n", dupeErrors)
		for field, count := range duplicateCounts {
			fmt.Fprintf(os.Stderr, "  %s: %d\n", field, count)
		}
	}

	if validationErrors == 0 && dupeErrors == 0 {
		fmt.Fprintf(os.Stderr, "all records valid, no duplicates found\n")
	}

	// dedupe if requested
	if dedupeField != "" {
		var dedupeGetter func(rec *importRecord) string
		for _, uf := range uniqueFields {
			if uf.name == dedupeField {
				dedupeGetter = uf.getter
				break
			}
		}

		seen := make(map[string]int) // value -> index in deduped slice
		deduped := make([]*importRecord, 0, len(records))
		removed := 0
		mergedCount := 0
		totalFieldsFilled := 0

		type mergeEvent struct {
			dupRow   int
			baseRow  int
			fields   []string
			merged   bool // false = dropped (nothing to fill or merge disabled)
		}
		var events []mergeEvent
		rowOfIdx := make([]int, 0, len(records)) // deduped idx -> original 1-based row

		for i, rec := range records {
			row := i + 1
			val := dedupeGetter(rec)
			if val == "" {
				deduped = append(deduped, rec)
				rowOfIdx = append(rowOfIdx, row)
				continue
			}
			if baseIdx, exists := seen[val]; exists {
				if mergeDupes {
					filled := mergeInto(deduped[baseIdx], rec)
					if len(filled) > 0 {
						mergedCount++
						totalFieldsFilled += len(filled)
						events = append(events, mergeEvent{dupRow: row, baseRow: rowOfIdx[baseIdx], fields: filled, merged: true})
					} else {
						events = append(events, mergeEvent{dupRow: row, baseRow: rowOfIdx[baseIdx], merged: false})
					}
				} else {
					events = append(events, mergeEvent{dupRow: row, baseRow: rowOfIdx[baseIdx], merged: false})
				}
				removed++
				continue
			}
			seen[val] = len(deduped)
			deduped = append(deduped, rec)
			rowOfIdx = append(rowOfIdx, row)
		}

		if verbose && len(events) > 0 {
			fmt.Fprintf(os.Stderr, "\ndedupe actions:\n")
			for _, ev := range events {
				if ev.merged {
					fmt.Fprintf(os.Stderr, "  row %d → row %d: filled [%s]\n", ev.dupRow, ev.baseRow, strings.Join(ev.fields, ", "))
				} else {
					fmt.Fprintf(os.Stderr, "  row %d → row %d: dropped (no fields to merge)\n", ev.dupRow, ev.baseRow)
				}
			}
		}

		// check if input and output resolve to the same file
		if isSameFile(inputPath, outputPath) {
			confirmed, err := confirmAction(fmt.Sprintf("Output %s is the same as input; overwrite?", outputPath))
			if err != nil {
				return err
			}
			if !confirmed {
				return fmt.Errorf("aborted — output file is the same as input")
			}
		}

		outFile, err := os.Create(outputPath)
		if err != nil {
			return fmt.Errorf("failed to create output file: %w", err)
		}
		defer outFile.Close()

		if err := gocsv.MarshalFile(&deduped, outFile); err != nil {
			return fmt.Errorf("failed to write output CSV: %w", err)
		}

		if mergeDupes {
			fmt.Fprintf(os.Stderr, "deduplicated on %s: %d duplicates, %d merged (%d fields filled), %d dropped, %d remaining → %s\n",
				dedupeField, removed, mergedCount, totalFieldsFilled, removed-mergedCount, len(deduped), outputPath)
		} else {
			fmt.Fprintf(os.Stderr, "deduplicated on %s: %d removed, %d remaining → %s\n", dedupeField, removed, len(deduped), outputPath)
		}
	}

	if validationErrors > 0 || (dupeErrors > 0 && dedupeField == "") {
		return fmt.Errorf("validation failed with %d validation errors and %d duplicate issues", validationErrors, dupeErrors)
	}

	return nil
}

// validateImportCSV validates import records for structural errors and uniqueness.
// Returns an error if validation or uniqueness checks fail.
func validateImportCSV(records []*importRecord) error {
	var validationErrors, dupeErrors int

	for _, rec := range records {
		if err := rec.Validate(); err != nil {
			validationErrors++
		}
	}

	type uniqueField struct {
		name   string
		getter func(rec *importRecord) string
	}

	uniqueFields := []uniqueField{
		{"login", func(rec *importRecord) string { return strings.ToLower(rec.Login) }},
		{"email", func(rec *importRecord) string {
			if rec.Email != nil && *rec.Email != "" {
				return strings.ToLower(*rec.Email)
			}
			return ""
		}},
		{"phone_number", func(rec *importRecord) string {
			if rec.PhoneNumber != nil {
				return *rec.PhoneNumber
			}
			return ""
		}},
		{"stripe_customer_id", func(rec *importRecord) string {
			if rec.StripeCustomerID != nil && *rec.StripeCustomerID != "" {
				return *rec.StripeCustomerID
			}
			return ""
		}},
	}

	for _, uf := range uniqueFields {
		seen := make(map[string]bool)
		for _, rec := range records {
			val := uf.getter(rec)
			if val == "" {
				continue
			}
			if seen[val] {
				dupeErrors++
			} else {
				seen[val] = true
			}
		}
	}

	if validationErrors > 0 || dupeErrors > 0 {
		return fmt.Errorf("CSV validation failed: %d validation errors, %d duplicate issues; run 'migrate validate' for details", validationErrors, dupeErrors)
	}

	return nil
}

// mergeInto fills empty fields on dst with values from src. Returns the names
// of the fields that were modified (CSV tag when available, else Go field name).
// Rules:
//   - scalar/pointer/string/numeric: copied only when dst is zero/nil/"".
//   - slices: src elements not already present in dst are appended (union).
//   - maps: src entries are added for keys dst doesn't have (union).
//
// dst always wins on conflict so the first-occurrence tie-breaker is preserved.
func mergeInto(dst, src *importRecord) []string {
	filled := make([]string, 0)
	mergeValue(reflect.ValueOf(dst).Elem(), reflect.ValueOf(src).Elem(), "", &filled)
	sort.Strings(filled)
	return filled
}

func mergeValue(dst, src reflect.Value, prefix string, filled *[]string) {
	t := dst.Type()
	for i := 0; i < dst.NumField(); i++ {
		field := t.Field(i)
		if !field.IsExported() {
			continue
		}
		dv := dst.Field(i)
		sv := src.Field(i)
		name := fieldName(field)
		if prefix != "" && name != "" {
			// keep top-level name, no nesting prefix needed in practice
		}

		// recurse into anonymous embedded structs
		if field.Anonymous && dv.Kind() == reflect.Struct {
			mergeValue(dv, sv, name, filled)
			continue
		}

		switch dv.Kind() {
		case reflect.Ptr:
			if dv.IsNil() && !sv.IsNil() {
				dv.Set(sv)
				*filled = append(*filled, name)
			}
		case reflect.String:
			if dv.Len() == 0 && sv.Len() > 0 {
				dv.Set(sv)
				*filled = append(*filled, name)
			}
		case reflect.Slice:
			// union: append src elements not already present in dst
			added := false
			for j := 0; j < sv.Len(); j++ {
				item := sv.Index(j)
				if !sliceContains(dv, item) {
					dv.Set(reflect.Append(dv, item))
					added = true
				}
			}
			if added {
				*filled = append(*filled, name)
			}
		case reflect.Map:
			if sv.Len() == 0 {
				continue
			}
			if dv.IsNil() {
				dv.Set(reflect.MakeMapWithSize(dv.Type(), sv.Len()))
			}
			added := false
			iter := sv.MapRange()
			for iter.Next() {
				k := iter.Key()
				if !dv.MapIndex(k).IsValid() {
					dv.SetMapIndex(k, iter.Value())
					added = true
				}
			}
			if added {
				*filled = append(*filled, name)
			}
		case reflect.Struct:
			// wrapped value types (e.g. util.Timestamp) — only fill if dst is zero
			if dv.IsZero() && !sv.IsZero() {
				dv.Set(sv)
				*filled = append(*filled, name)
			}
		default:
			if dv.IsZero() && !sv.IsZero() {
				dv.Set(sv)
				*filled = append(*filled, name)
			}
		}
	}
}

func fieldName(f reflect.StructField) string {
	if tag := f.Tag.Get("csv"); tag != "" && tag != "-" {
		return strings.SplitN(tag, ",", 2)[0]
	}
	if tag := f.Tag.Get("json"); tag != "" && tag != "-" {
		return strings.SplitN(tag, ",", 2)[0]
	}
	return f.Name
}

func sliceContains(s, v reflect.Value) bool {
	for i := 0; i < s.Len(); i++ {
		if reflect.DeepEqual(s.Index(i).Interface(), v.Interface()) {
			return true
		}
	}
	return false
}

// dedupedOutputPath returns inputPath with "+deduped" inserted before the extension.
func dedupedOutputPath(inputPath string) string {
	dir := filepath.Dir(inputPath)
	base := filepath.Base(inputPath)
	ext := filepath.Ext(base)
	stem := strings.TrimSuffix(base, ext)
	return filepath.Join(dir, stem+"+deduped"+ext)
}

// isSameFile checks whether two paths resolve to the same file.
func isSameFile(a, b string) bool {
	absA, errA := filepath.Abs(a)
	absB, errB := filepath.Abs(b)
	if errA != nil || errB != nil {
		return a == b
	}
	return absA == absB
}
