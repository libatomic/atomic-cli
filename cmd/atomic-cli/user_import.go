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
	"encoding/json"
	"fmt"
	"os"

	"github.com/gocarina/gocsv"
	"github.com/libatomic/atomic/pkg/atomic"
	"github.com/urfave/cli/v3"
)

var userImportCmd = &cli.Command{
	Name:      "import",
	Usage:     "import users from a file",
	ArgsUsage: "import <file>",
	Action:    userImport,
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:    "config",
			Aliases: []string{"c"},
			Usage:   "JSON config file with import parameters (all flags can also be set in the config)",
		},
		&cli.StringFlag{
			Name:  "mime_type",
			Usage: "mime type of the import file",
			Value: "text/csv",
		},
		&cli.StringFlag{
			Name:  "source",
			Usage: "source identifier (atomic, ghost, substack, etc.)",
			Value: "atomic",
		},
		// import behavior
		&cli.BoolFlag{
			Name:  "dry_run",
			Usage: "preview import without creating or updating users",
		},
		&cli.BoolFlag{
			Name:  "ignore_created_at",
			Usage: "ignore the created_at column from the CSV; users are created with the current timestamp",
		},
		&cli.StringFlag{
			Name:  "existing_user_behavior",
			Usage: "behavior for existing users: skip, merge, recreate",
		},
		&cli.BoolFlag{
			Name:  "validate_user_email",
			Usage: "validate user email addresses",
		},
		&cli.StringFlag{
			Name:  "user_event_options",
			Usage: "user event options: pipe-delimited flags (LOG|EMIT|SYNC|CHILDREN|CONTEXT|SUPPRESS)",
			Value: atomic.EventLogOptionLog.String(),
		},
		&cli.BoolFlag{
			Name:  "rebuild_audiences",
			Usage: "rebuild audiences after import",
			Value: true,
		},
		// audience
		&cli.StringFlag{
			Name:  "import_audience_id",
			Usage: "audience ID to add imported users to",
		},
		&cli.StringFlag{
			Name:  "import_audience_behavior",
			Usage: "audience membership behavior: add_all_users, add_new_users, add_existing_users",
			Value: string(atomic.UserImportAudienceBehaviorNone),
		},
		// stripe
		&cli.StringFlag{
			Name:  "stripe_account_behavior",
			Usage: "stripe account behavior: existing, create, none",
			Value: "existing",
		},
		// plans
		&cli.StringFlag{
			Name:  "default_plan_behavior",
			Usage: "default plan behavior: all, non_subscribers, none",
			Value: "all",
		},
		&cli.StringSliceFlag{
			Name:  "subscribe_plans",
			Usage: "plan IDs to subscribe users to (repeatable)",
		},
		&cli.StringFlag{
			Name:  "subscribe_behavior",
			Usage: "subscribe behavior: all_users, subscribers_only, non_subscribers_only, subscribers_skip_paid, none",
			Value: "subscribers_skip_paid",
		},
		// trials
		&cli.StringFlag{
			Name:  "trial_plan_id",
			Usage: "trial plan ID",
		},
		&cli.StringFlag{
			Name:  "trial_price_id",
			Usage: "trial price ID",
		},
		&cli.TimestampFlag{
			Name:  "trial_end_at",
			Usage: "trial end date/time",
		},
		&cli.BoolFlag{
			Name:  "trial_existing_users",
			Usage: "apply trial to existing users without a subscription",
		},
		&cli.StringFlag{
			Name:  "trial_behavior",
			Usage: "trial behavior: all, non_subscribers, none",
		},
		// expired subscriptions
		&cli.StringFlag{
			Name:  "expired_subscription_behavior",
			Usage: "behavior when subscription_end_at is in the past: none (skip the sub), trial (start a trial of the same plan)",
		},
		&cli.IntFlag{
			Name:  "expired_subscription_trial_days",
			Usage: "trial length in days when expired_subscription_behavior=trial",
			Value: 15,
		},
		// discounts
		&cli.StringFlag{
			Name:  "discount_behavior",
			Usage: "discount behavior: aggregate (shared coupons), individual (per-user coupons), none",
			Value: "aggregate",
		},
		// default subscription settings
		&cli.Float64Flag{
			Name:  "default_discount_percentage",
			Usage: "default discount percentage for subscriptions",
		},
		&cli.StringFlag{
			Name:  "default_discount_term",
			Usage: "default discount term: once, repeating, forever",
		},
		&cli.IntFlag{
			Name:  "default_discount_duration_days",
			Usage: "default discount duration in days",
		},
		&cli.BoolFlag{
			Name:  "default_subscription_prorate",
			Usage: "prorate subscriptions by default",
		},
		&cli.StringFlag{
			Name:  "default_subscription_anchor_date",
			Usage: "default subscription anchor date (RFC3339, e.g. 2026-05-08T21:29:00Z)",
		},
		// teams
		&cli.BoolFlag{
			Name:  "create_teams",
			Usage: "enable team import processing",
		},
		&cli.StringFlag{
			Name:  "team_limit_behavior",
			Usage: "team seat limit behavior: drop_admin, drop_user, expand_subscription",
		},
		// email
		&cli.BoolFlag{
			Name:  "verify_user_email",
			Usage: "override email_verified on all imported users (true=verified, false=unverified); when not set, uses each record's email_verified field",
			Value: true,
		},
		// job completion event
		&cli.StringFlag{
			Name:  "job_event_options",
			Usage: "event options for the job completed event: pipe-delimited flags (LOG|EMIT|SYNC|CHILDREN|CONTEXT|SUPPRESS)",
		},
		// worker concurrency override (server-side ceiling is UserImportMaxWorkers,
		// clamped to [1, NumCPU])
		&cli.IntFlag{
			Name:  "job_max_workers",
			Usage: "override the per-job worker concurrency; capped by the server's UserImportMaxWorkers and [1, NumCPU]",
		},
		// wait
		&cli.BoolFlag{
			Name:  "wait",
			Usage: "wait for the import job to complete, showing a progress bar; Ctrl+C detaches the tail (the import keeps running, manage it via `atomic-cli job …`)",
		},
	},
}

func userImport(ctx context.Context, cmd *cli.Command) error {
	var input atomic.UserImportInput

	// load config file first (if provided), then overlay CLI flags
	if configPath := cmd.String("config"); configPath != "" {
		configData, err := os.ReadFile(configPath)
		if err != nil {
			return fmt.Errorf("failed to read config file: %w", err)
		}
		if err := json.Unmarshal(configData, &input); err != nil {
			return fmt.Errorf("failed to parse config file: %w", err)
		}
	}

	// CLI flags override config file values
	if err := BindFlagsFromContext(cmd, &input, "config", "user_event_options", "job_event_options"); err != nil {
		return err
	}

	// parse user_event_options string flag
	if evtStr := cmd.String("user_event_options"); evtStr != "" {
		opts, err := parseEventLogOptions(evtStr)
		if err != nil {
			return err
		}
		input.UserEventOptions = &opts
	}

	// parse job_event_options string flag
	if evtStr := cmd.String("job_event_options"); evtStr != "" {
		opts, err := parseEventLogOptions(evtStr)
		if err != nil {
			return err
		}
		input.JobCompletedEventOptions = &opts
	}

	// set fields that are json:"-" and can't be bound via BindFlagsFromContext
	input.MimeType = cmd.String("mime_type")

	if cmd.Args().First() != "" {
		var err error

		input.Filename = cmd.Args().First()

		file, err := os.Open(cmd.Args().First())
		if err != nil {
			return fmt.Errorf("failed to open user import input file: %w", err)
		}

		info, err := os.Stat(cmd.Args().First())
		if err != nil {
			return fmt.Errorf("failed to get user import input file size: %w", err)
		}
		input.Size = info.Size()

		input.File = file
	} else {
		return fmt.Errorf("file is required")
	}

	// validate the CSV before sending to the API
	csvFile, err := os.Open(cmd.Args().First())
	if err != nil {
		return fmt.Errorf("failed to open file for validation: %w", err)
	}
	var records []*importRecord
	if err := gocsv.UnmarshalFile(csvFile, &records); err != nil {
		csvFile.Close()
		return fmt.Errorf("failed to parse CSV for validation: %w", err)
	}
	csvFile.Close()

	if err := validateImportCSV(records); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "validated %d records\n", len(records))

	job, err := backend.UserImport(ctx, &input)
	if err != nil {
		return err
	}

	PrintResult(cmd, []*atomic.Job{job}, WithFields("id", "type", "queue_status", "created_at"))

	if cmd.Bool("wait") {
		// Ctrl+C detaches the tail; the import keeps running on the server
		// and can be managed via `atomic-cli job …` commands
		return waitForJob(ctx, job, mainCmd.Bool("verbose"), false)
	}

	return nil
}
