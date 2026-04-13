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
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/gocarina/gocsv"
	"github.com/libatomic/atomic/pkg/atomic"
	"github.com/libatomic/atomic/pkg/ptr"
	"github.com/libatomic/atomic/pkg/queue"
	"github.com/schollz/progressbar/v3"
	"github.com/urfave/cli/v3"
)

var (
	userUpdateFlags = []cli.Flag{
		&cli.BoolFlag{
			Name:  "file",
			Usage: "set the user input from a JSON file",
		},
		&cli.StringFlag{
			Name:    "login",
			Aliases: []string{"email"},
			Usage:   "set the user login",
		},
		&cli.StringFlag{
			Name:  "password",
			Usage: "set the user password",
		},
		&cli.StringFlag{
			Name:  "profile",
			Usage: "set the user profile from a JSON file",
		},
		&cli.StringSliceFlag{
			Name:  "roles",
			Usage: "set the user roles from a JSON file",
		},
		&cli.StringFlag{
			Name:  "metadata",
			Usage: "set the user metadata from a JSON file",
		},
		&cli.StringFlag{
			Name:  "stripe_account",
			Usage: "set the user stripe account",
		},
		&cli.IntFlag{
			Name:  "event_options",
			Usage: "event log options bitmask (1=Log, 2=Emit, 4=Sync, 8=Children, 16=Context, 32=Suppress)",
		},
		&cli.BoolFlag{
			Name:  "subscribe_default_plans",
			Usage: "subscribe to default plans",
		},
		&cli.StringFlag{
			Name:  "preferences",
			Usage: "set the user preferences from a JSON file",
		},
	}

	userCreateFlags = append(userUpdateFlags, []cli.Flag{
		&cli.BoolFlag{
			Name:  "create_only",
			Usage: "create the user only",
		},
		&cli.BoolFlag{
			Name:  "suppress_validation",
			Usage: "suppress user validation",
		},
		&cli.BoolFlag{
			Name:  "suppress_parent_triggers",
			Usage: "suppress parent triggers",
		},
		&cli.BoolFlag{
			Name:  "rebuild_audiences",
			Usage: "rebuild the user audiences",
		},
	}...)

	userCmd = &cli.Command{
		Name:    "user",
		Aliases: []string{"users"},
		Usage:   "manage users",
		Commands: []*cli.Command{
			{
				Name:      "create",
				Usage:     "create a user",
				Flags:     userCreateFlags,
				ArgsUsage: "create <login>",
				Action:    userCreate,
			},
			{
				Name:      "update",
				Usage:     "update a user",
				Flags:     userUpdateFlags,
				ArgsUsage: "<user_id>",
				Action:    userUpdate,
			},
			{
				Name:      "get",
				Usage:     "get a user",
				ArgsUsage: "get <user_id>",
				Flags: []cli.Flag{
					&cli.BoolFlag{
						Name:    "stripe_customer",
						Aliases: []string{"stripe", "sc"},
						Usage:   "get by stripe customer id",
					},
					&cli.BoolFlag{
						Name:    "subject",
						Aliases: []string{"sub"},
						Usage:   "get by subject",
					},
					&cli.StringSliceFlag{
						Name:  "expand",
						Usage: "expand the user",
					},
				},
				Action: userGet,
			},
			{
				Name:      "list",
				Usage:     "list users",
				ArgsUsage: "list",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:  "audience",
						Usage: "list by audience",
					},
					&cli.StringSliceFlag{
						Name:  "roles",
						Usage: "list by role",
					},
					&cli.StringFlag{
						Name:  "status",
						Usage: "list by status",
					},
					&cli.StringFlag{
						Name:  "login",
						Usage: "list by login",
					},
					&cli.StringFlag{
						Name:  "stripe_account",
						Usage: "list by stripe account",
					},
					&cli.IntFlag{
						Name:  "limit",
						Usage: "limit the number of users",
					},
					&cli.IntFlag{
						Name:  "offset",
						Usage: "offset the number of users",
					},
					&cli.StringSliceFlag{
						Name:  "expand",
						Usage: "expand the user",
					},
				},
				Action: userList,
			},
			{
				Name:      "delete",
				Usage:     "delete a user",
				ArgsUsage: "<user_id>",
				Flags: []cli.Flag{
					&cli.BoolFlag{
						Name:    "admin_delete_override",
						Aliases: []string{"admin-override"},
						Usage:   "force the deletion of the user",
					},
					&cli.BoolFlag{
						Name:    "delete_stripe_account",
						Aliases: []string{"stripe"},
						Usage:   "delete the stripe account",
					},
					&cli.BoolFlag{
						Name:    "prorate_subscriptions",
						Aliases: []string{"prorate"},
						Usage:   "prorate the subscriptions",
					},
				},
				Action: userDelete,
			},
			{
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
					// wait
					&cli.BoolFlag{
						Name:  "wait",
						Usage: "wait for the import job to complete, showing a progress bar",
					},
				},
			},
		},
	}
)

func userCreate(ctx context.Context, cmd *cli.Command) error {
	var input atomic.UserCreateInput

	if cmd.IsSet("file") && cmd.Bool("file") {
		content, err := os.ReadFile(cmd.Args().First())
		if err != nil {
			return fmt.Errorf("failed to read user create input file: %w", err)
		}

		if err := json.Unmarshal(content, &input); err != nil {
			return fmt.Errorf("failed to unmarshal user create input: %w", err)
		}
	} else if cmd.Args().First() != "" {
		input.Login = cmd.Args().First()
	}

	if err := BindFlagsFromContext(cmd, &input, "profile", "metadata", "preferences"); err != nil {
		return err
	}

	if cmd.IsSet("profile") {
		content, err := os.ReadFile(cmd.Args().First())
		if err != nil {
			return fmt.Errorf("failed to read user create input file: %w", err)
		}

		if err := json.Unmarshal(content, &input.Profile); err != nil {
			return fmt.Errorf("failed to unmarshal user create input: %w", err)
		}
	}

	if cmd.IsSet("metadata") {
		content, err := os.ReadFile(cmd.Args().First())
		if err != nil {
			return fmt.Errorf("failed to read user create input file: %w", err)
		}

		if err := json.Unmarshal(content, &input.Metadata); err != nil {
			return fmt.Errorf("failed to unmarshal user create input: %w", err)
		}
	}

	if cmd.IsSet("preferences") {
		content, err := os.ReadFile(cmd.Args().First())
		if err != nil {
			return fmt.Errorf("failed to read user create input file: %w", err)
		}

		if err := json.Unmarshal(content, &input.Preferences); err != nil {
			return fmt.Errorf("failed to unmarshal user create input: %w", err)
		}
	}

	user, err := backend.UserCreate(ctx, &input)
	if err != nil {
		return err
	}

	PrintResult(cmd, []*atomic.User{user}, WithFields("id", "login", "created_at", "updated_at", "roles", "instance_id"))

	return nil
}

func userUpdate(ctx context.Context, cmd *cli.Command) error {
	var input atomic.UserUpdateInput

	if cmd.IsSet("file") && cmd.Bool("file") {
		content, err := os.ReadFile(cmd.Args().First())
		if err != nil {
			return fmt.Errorf("failed to read user update input file: %w", err)
		}

		if err := json.Unmarshal(content, &input); err != nil {
			return fmt.Errorf("failed to unmarshal user update input: %w", err)
		}
	} else {
		id, err := atomic.ParseID(cmd.Args().First())
		if err != nil {
			return fmt.Errorf("failed to parse user id: %w", err)
		}

		input.UserID = &id
	}

	if err := BindFlagsFromContext(cmd, &input, "profile", "metadata", "preferences"); err != nil {
		return err
	}

	if cmd.IsSet("profile") {
		content, err := os.ReadFile(cmd.Args().First())
		if err != nil {
			return fmt.Errorf("failed to read user create input file: %w", err)
		}

		if err := json.Unmarshal(content, &input.Profile); err != nil {
			return fmt.Errorf("failed to unmarshal user create input: %w", err)
		}
	}

	if cmd.IsSet("metadata") {
		content, err := os.ReadFile(cmd.Args().First())
		if err != nil {
			return fmt.Errorf("failed to read user create input file: %w", err)
		}

		if err := json.Unmarshal(content, &input.Metadata); err != nil {
			return fmt.Errorf("failed to unmarshal user create input: %w", err)
		}
	}

	if cmd.IsSet("preferences") {
		content, err := os.ReadFile(cmd.Args().First())
		if err != nil {
			return fmt.Errorf("failed to read user create input file: %w", err)
		}

		if err := json.Unmarshal(content, &input.Preferences); err != nil {
			return fmt.Errorf("failed to unmarshal user create input: %w", err)
		}
	}

	user, err := backend.UserUpdate(ctx, &input)
	if err != nil {
		return err
	}

	PrintResult(cmd, []*atomic.User{user}, WithFields("id", "login", "created_at", "updated_at", "roles", "instance_id"))

	return nil
}

func userGet(ctx context.Context, cmd *cli.Command) error {
	var input atomic.UserGetInput

	if cmd.NArg() < 1 {
		return fmt.Errorf("user id is required")
	}

	var expand atomic.ExpandFields

	if expand := cmd.StringSlice("expand"); len(expand) > 0 {
		input.Expand = expand
	}

	expand = expand.Append("stripe_account", "roles", "permissions").Unique()

	if cmd.Bool("stripe_customer") || cmd.Bool("subject") {
		input := &atomic.UserListInput{
			Limit:  ptr.Uint64(1),
			Expand: expand,
		}

		if cmd.Bool("stripe_customer") {
			input.StripeCustomer = ptr.String(cmd.Args().First())
		}

		if cmd.Bool("subject") {
			input.Subject = ptr.String(cmd.Args().First())
		}

		users, err := backend.UserList(ctx, input)
		if err != nil {
			return err
		}

		if len(users) == 0 {
			return fmt.Errorf("user not found")
		}

		PrintResult(cmd, users,
			WithSingleValue(true),
			WithFields("id", "subject", "login", "created_at", "roles", "instance_id", "stripe_account.stripe_customer"),
			WithVirtualField("subject", func(v any) string {
				if user, ok := v.(atomic.User); ok {
					return user.ProfileVal.Subject
				}

				return ""
			}))

		return nil
	}

	id, err := atomic.ParseID(cmd.Args().First())
	if err != nil {
		return fmt.Errorf("failed to parse application id: %w", err)
	}

	input.UserID = &id

	user, err := backend.UserGet(ctx, &input)
	if err != nil {
		return err
	}

	PrintResult(cmd, []*atomic.User{user},
		WithSingleValue(true),
		WithFields("id", "subject", "login", "created_at", "roles", "instance_id", "stripe_account.stripe_customer"),
		WithVirtualField("subject", func(v any) string {
			if user, ok := v.(atomic.User); ok {
				return user.ProfileVal.Subject
			}

			return ""
		}))

	return nil
}

func userList(ctx context.Context, cmd *cli.Command) error {
	var input atomic.UserListInput

	if err := BindFlagsFromContext(cmd, &input); err != nil {
		return err
	}

	if expand := cmd.StringSlice("expand"); len(expand) > 0 {
		input.Expand = expand
	}

	input.Expand = input.Expand.Append("stripe_account", "roles", "permissions").Unique()

	users, err := backend.UserList(ctx, &input)
	if err != nil {
		return err
	}

	PrintResult(cmd, users,
		WithFields("id", "subject", "login", "created_at", "roles", "instance_id", "stripe_account.stripe_customer"),
		WithVirtualField("subject", func(v any) string {
			if user, ok := v.(atomic.User); ok {
				return user.ProfileVal.Subject
			}

			return ""
		}))

	return nil
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
		return waitForJob(ctx, job, mainCmd.Bool("verbose"))
	}

	return nil
}

func userDelete(ctx context.Context, cmd *cli.Command) error {
	var input atomic.UserDeleteInput

	if cmd.Args().First() == "" {
		return fmt.Errorf("user id is required")
	}

	id, err := atomic.ParseID(cmd.Args().First())
	if err != nil {
		return fmt.Errorf("failed to parse user id: %w", err)
	}

	input.UserID = &id

	if err := BindFlagsFromContext(cmd, &input); err != nil {
		return err
	}

	if err := backend.UserDelete(ctx, &input); err != nil {
		return err
	}

	fmt.Println("User deleted")

	return nil
}

func waitForJob(ctx context.Context, job *atomic.Job, verbose bool) error {
	fmt.Fprintf(os.Stderr, "\nwaiting for job %s...\n", job.UUID)

	var bar *progressbar.ProgressBar
	var barTotal int64

	// start with an indeterminate spinner until we know the total
	bar = progressbar.NewOptions(-1,
		progressbar.OptionSetDescription("Starting"),
		progressbar.OptionSetWriter(os.Stderr),
		progressbar.OptionSpinnerType(14),
		progressbar.OptionClearOnFinish(),
	)

	var logSinceMs *int64
	pollInterval := time.Second
	logLimit := ptr.Uint64(20)

	for {
		select {
		case <-ctx.Done():
			bar.Finish()
			return cancelAndWaitJob(job)
		case <-time.After(pollInterval):
		}

		getInput := &atomic.JobGetInput{
			JobID:    &job.UUID,
			LogLimit: logLimit,
			LogSince: logSinceMs,
		}

		updated, err := backend.JobGet(ctx, getInput)
		if err != nil {
			bar.Finish()
			return fmt.Errorf("failed to poll job: %w", err)
		}

		// show new logs above the progress bar if verbose
		if verbose && len(updated.Logs) > 0 {
			bar.Clear()

			// logs come in reverse chronological order, print oldest first
			for i := len(updated.Logs) - 1; i >= 0; i-- {
				entry := updated.Logs[i]
				fmt.Fprintf(os.Stderr, "  [%s] %s: %s\n", entry.Timestamp.Format("15:04:05"), entry.Level, entry.Message)
			}

			// update logSince to the most recent log timestamp (unix millis)
			ms := updated.Logs[0].Timestamp.UnixMilli()
			logSinceMs = &ms
		}

		// update progress bar from state status
		if updated.State != nil {
			status := updated.State.Status()

			// find the current stage for precise unit-based progress
			var currentStage *atomic.JobStateStage
			if status.CurrentStage != "" && status.Stages != nil {
				currentStage = status.Stages[status.CurrentStage]
			}

			if currentStage != nil && currentStage.UnitsTotal > 0 {
				// switch to a unit-based progress bar if the total changed
				if barTotal != currentStage.UnitsTotal {
					bar.Finish()
					barTotal = currentStage.UnitsTotal
					bar = progressbar.NewOptions(int(barTotal),
						progressbar.OptionSetDescription(currentStage.Name),
						progressbar.OptionSetWriter(os.Stderr),
						progressbar.OptionShowCount(),
						progressbar.OptionClearOnFinish(),
						progressbar.OptionSetPredictTime(true),
					)
				}
				bar.Set(int(currentStage.UnitsCompleted))
			} else {
				// fallback to percentage-based progress
				if barTotal == 0 && status.Progress > 0 {
					bar.Finish()
					barTotal = 100
					bar = progressbar.NewOptions(100,
						progressbar.OptionSetDescription("Processing"),
						progressbar.OptionSetWriter(os.Stderr),
						progressbar.OptionShowCount(),
						progressbar.OptionClearOnFinish(),
					)
				}
				if barTotal > 0 {
					pct := int(status.Progress * 100)
					if pct > 100 {
						pct = 100
					}
					bar.Set(pct)
				}
			}

			if status.Message != "" {
				bar.Describe(status.Message)
			}
		}

		// check terminal states
		switch updated.Status {
		case queue.StatusSuccess:
			bar.Finish()
			// jobs can finish faster than a poll tick — fetch any remaining
			// logs so verbose users see the tail, and so we don't miss errors.
			flushRemainingLogs(ctx, job, &logSinceMs, verbose)

			// queue success only means "the handler returned without a queue
			// error"; check the job-reported status for internal success/failure
			reported := reportedJobStatus(updated)
			if reported == atomic.JobStatusFailed {
				printJobErrors(updated)
				printJobSummary(updated)
				return fmt.Errorf("job %s reported internal failure", job.UUID)
			}
			fmt.Fprintf(os.Stderr, "\njob %s completed successfully\n", job.UUID)
			printJobErrors(updated) // non-fatal errors can coexist with success
			printJobSummary(updated)
			return nil

		case queue.StatusError:
			bar.Finish()
			flushRemainingLogs(ctx, job, &logSinceMs, verbose)
			errMsg := "unknown error"
			if updated.Error != nil {
				errMsg = *updated.Error
			}
			printJobErrors(updated)
			return fmt.Errorf("job %s failed: %s", job.UUID, errMsg)

		case queue.StatusCanceled:
			bar.Finish()
			flushRemainingLogs(ctx, job, &logSinceMs, verbose)
			printJobErrors(updated)
			return fmt.Errorf("job %s was canceled", job.UUID)
		}
	}
}

// reportedJobStatus returns the job-handler-reported status from state when
// present, falling back to "" if the job never published one.
func reportedJobStatus(job *atomic.Job) atomic.JobStatus {
	if job.State == nil {
		return ""
	}
	return job.State.Status().Status
}

// flushRemainingLogs fetches any logs newer than logSinceMs and prints them
// (verbose only). Used right before reporting a terminal state so short-lived
// jobs don't drop their log tail.
func flushRemainingLogs(ctx context.Context, job *atomic.Job, logSinceMs **int64, verbose bool) {
	if !verbose {
		return
	}
	limit := ptr.Uint64(1000)
	tail, err := backend.JobGet(ctx, &atomic.JobGetInput{
		JobID:    &job.UUID,
		LogLimit: limit,
		LogSince: *logSinceMs,
	})
	if err != nil || len(tail.Logs) == 0 {
		return
	}
	for i := len(tail.Logs) - 1; i >= 0; i-- {
		e := tail.Logs[i]
		fmt.Fprintf(os.Stderr, "  [%s] %s: %s\n", e.Timestamp.Format("15:04:05"), e.Level, e.Message)
	}
	ms := tail.Logs[0].Timestamp.UnixMilli()
	*logSinceMs = &ms
}

// printJobErrors prints any per-row errors captured in job.Errors. Safe to
// call when the job succeeded — many jobs (like user import) treat individual
// row failures as non-fatal but still want the user to see them.
func printJobErrors(job *atomic.Job) {
	if len(job.Errors) == 0 {
		return
	}
	fmt.Fprintf(os.Stderr, "\njob errors (%d):\n", len(job.Errors))
	for _, e := range job.Errors {
		fmt.Fprintf(os.Stderr, "  [%s] %s\n", e.CreatedAt.Format("15:04:05"), e.Error)
	}
}

// printJobSummary prints total duration and a per-stage breakdown (duration
// and items/sec) for a completed job. Falls back gracefully when timing or
// unit counts are missing (e.g. stages that don't track units).
func printJobSummary(job *atomic.Job) {
	// total wall time: CompletedAt - CreatedAt (CreatedAt is the enqueue time;
	// server-side start is approximated with the first stage's StartedAt when
	// available).
	if job.CompletedAt != nil {
		total := job.CompletedAt.Sub(job.CreatedAt)
		fmt.Fprintf(os.Stderr, "total duration: %s\n", total.Round(time.Millisecond))
	}

	if job.State == nil {
		return
	}
	status := job.State.Status()
	if len(status.Stages) == 0 {
		return
	}

	stages := make([]*atomic.JobStateStage, 0, len(status.Stages))
	for _, s := range status.Stages {
		stages = append(stages, s)
	}
	sort.Slice(stages, func(i, j int) bool {
		if stages[i].Order != stages[j].Order {
			return stages[i].Order < stages[j].Order
		}
		return stages[i].Name < stages[j].Name
	})

	fmt.Fprintf(os.Stderr, "stages:\n")
	for _, s := range stages {
		var (
			dur     time.Duration
			durStr  = "—"
			rateStr = ""
		)
		if s.StartedAt != nil && s.CompletedAt != nil {
			dur = s.CompletedAt.Sub(*s.StartedAt)
			durStr = dur.Round(time.Millisecond).String()
		} else if s.StartedAt != nil && !s.Completed {
			dur = time.Since(*s.StartedAt)
			durStr = dur.Round(time.Millisecond).String() + " (ongoing)"
		}
		if s.UnitsCompleted > 0 && dur > 0 {
			rate := float64(s.UnitsCompleted) / dur.Seconds()
			rateStr = fmt.Sprintf(" — %d/%d units @ %.1f/s", s.UnitsCompleted, s.UnitsTotal, rate)
		} else if s.UnitsCompleted > 0 {
			rateStr = fmt.Sprintf(" — %d/%d units", s.UnitsCompleted, s.UnitsTotal)
		}
		fmt.Fprintf(os.Stderr, "  %-30s %s%s\n", s.Name, durStr, rateStr)
	}
}

// cancelAndWaitJob requests cancellation of the job and polls until it reaches
// a terminal state, timing out after 90s.  A second interrupt abandons the wait
// and returns immediately (the job may still be running on the server).
func cancelAndWaitJob(job *atomic.Job) error {
	const (
		cancelTimeout = 90 * time.Second
		pollInterval  = 2 * time.Second
	)

	fmt.Fprintf(os.Stderr, "\ninterrupt received, attempting to cancel job %s (timeout %s, Ctrl+C again to abandon wait)...\n", job.UUID, cancelTimeout)

	// Fresh background context — the inherited ctx is already canceled.
	cancelCtx, cancelFn := context.WithTimeout(context.Background(), cancelTimeout)
	defer cancelFn()

	if err := backend.JobCancel(cancelCtx, &atomic.JobCancelInput{JobID: job.UUID}); err != nil {
		return fmt.Errorf("failed to request job cancel: %w", err)
	}

	// Register our own signal channel so a second Ctrl+C abandons the wait.
	// signal.Notify is additive, so this coexists with the parent's NotifyContext.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-cancelCtx.Done():
			return fmt.Errorf("timed out after %s waiting for job %s to cancel (job may still be running)", cancelTimeout, job.UUID)
		case <-sigCh:
			return fmt.Errorf("abandoned wait for job %s cancel (job may still be running)", job.UUID)
		case <-ticker.C:
		}

		updated, err := backend.JobGet(cancelCtx, &atomic.JobGetInput{JobID: &job.UUID})
		if err != nil {
			fmt.Fprintf(os.Stderr, "  failed to poll job during cancel: %s\n", err)
			continue
		}

		switch updated.Status {
		case queue.StatusCanceled:
			fmt.Fprintf(os.Stderr, "job %s canceled\n", job.UUID)
			return fmt.Errorf("job %s was canceled", job.UUID)
		case queue.StatusSuccess:
			fmt.Fprintf(os.Stderr, "job %s completed before cancel took effect\n", job.UUID)
			return nil
		case queue.StatusError:
			errMsg := "unknown error"
			if updated.Error != nil {
				errMsg = *updated.Error
			}
			return fmt.Errorf("job %s failed: %s", job.UUID, errMsg)
		}
	}
}

var eventLogOptionNames = map[string]atomic.EventLogOption{
	"LOG":      atomic.EventLogOptionLog,
	"EMIT":     atomic.EventLogOptionEmit,
	"SYNC":     atomic.EventLogOptionSync,
	"CHILDREN": atomic.EventLogOptionChildren,
	"CONTEXT":  atomic.EventLogOptionContext,
	"SUPPRESS": atomic.EventLogOptionSuppress,
}

func parseEventLogOptions(s string) (atomic.EventLogOption, error) {
	var opts atomic.EventLogOption
	for _, part := range strings.Split(s, "|") {
		name := strings.TrimSpace(strings.ToUpper(part))
		if name == "" {
			continue
		}
		val, ok := eventLogOptionNames[name]
		if !ok {
			valid := make([]string, 0, len(eventLogOptionNames))
			for k := range eventLogOptionNames {
				valid = append(valid, k)
			}
			return 0, fmt.Errorf("unknown event option %q; valid values: %s", name, strings.Join(valid, ", "))
		}
		opts |= val
	}
	return opts, nil
}
