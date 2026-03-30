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
	"strings"

	"github.com/gocarina/gocsv"
	"github.com/urfave/cli/v3"
)

var (
	migrateVerifyFlags = append(
		migrateCommonFlags,
		&cli.StringFlag{
			Name:     "input",
			Aliases:  []string{"in"},
			Usage:    "input CSV file path to verify",
			Required: true,
		},
		&cli.StringFlag{
			Name:  "dedupe",
			Usage: "deduplicate records on the specified field; first occurrence wins (valid: login, email, phone_number, stripe_customer_id)",
		},
		&cli.BoolFlag{
			Name:    "verbose",
			Aliases: []string{"v"},
			Usage:   "print each duplicate row with the colliding field and value",
		},
	)

	migrateVerifyCmd = &cli.Command{
		Name:   "verify",
		Usage:  "validate a user import CSV and optionally deduplicate records",
		Flags:  migrateVerifyFlags,
		Action: migrateVerifyAction,
	}
)

type verifyIssue struct {
	Row     int
	Login   string
	Field   string
	Value   string
	Message string
}

func migrateVerifyAction(ctx context.Context, cmd *cli.Command) error {
	_, outputPath, _, _, _, err := validateMigrateFlags(cmd)
	if err != nil {
		return err
	}

	inputPath := cmd.String("input")
	dedupeField := cmd.String("dedupe")
	verbose := cmd.Bool("verbose")

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
	var issues []verifyIssue
	for i, rec := range records {
		row := i + 1
		if err := rec.Validate(); err != nil {
			issues = append(issues, verifyIssue{
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

	for _, uf := range uniqueFields {
		seen := make(map[string]int) // value -> first row (1-based)
		for i, rec := range records {
			row := i + 1
			val := uf.getter(rec)
			if val == "" {
				continue
			}
			if firstRow, exists := seen[val]; exists {
				issues = append(issues, verifyIssue{
					Row:     row,
					Login:   rec.Login,
					Field:   uf.name,
					Value:   val,
					Message: fmt.Sprintf("duplicate %s (first seen at row %d)", uf.name, firstRow),
				})
				duplicateCounts[uf.name]++
			} else {
				seen[val] = row
			}
		}
	}

	// report
	validationErrors := 0
	dupeErrors := 0
	for _, issue := range issues {
		if issue.Field == "record" {
			validationErrors++
		} else {
			dupeErrors++
		}
	}

	if len(issues) > 0 {
		fmt.Fprintf(os.Stderr, "\n")
		for _, issue := range issues {
			if issue.Field == "record" {
				fmt.Fprintf(os.Stderr, "  row %d [%s] (validation): %s\n", issue.Row, issue.Login, issue.Message)
			} else if verbose {
				fmt.Fprintf(os.Stderr, "  row %d [%s] %s=%q: %s\n", issue.Row, issue.Login, issue.Field, issue.Value, issue.Message)
			}
		}
		fmt.Fprintf(os.Stderr, "\n")
	}

	fmt.Fprintf(os.Stderr, "validation: %d errors\n", validationErrors)
	for field, count := range duplicateCounts {
		fmt.Fprintf(os.Stderr, "duplicates on %s: %d\n", field, count)
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

		seen := make(map[string]bool)
		deduped := make([]*importRecord, 0, len(records))
		removed := 0

		for _, rec := range records {
			val := dedupeGetter(rec)
			if val != "" && seen[val] {
				removed++
				continue
			}
			if val != "" {
				seen[val] = true
			}
			deduped = append(deduped, rec)
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

		fmt.Fprintf(os.Stderr, "deduplicated on %s: %d removed, %d remaining → %s\n", dedupeField, removed, len(deduped), outputPath)
	}

	if validationErrors > 0 || (dupeErrors > 0 && dedupeField == "") {
		return fmt.Errorf("verification failed with %d validation errors and %d duplicate issues", validationErrors, dupeErrors)
	}

	if len(issues) == 0 {
		fmt.Fprintf(os.Stderr, "all records valid, no duplicates found\n")
	}

	return nil
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
