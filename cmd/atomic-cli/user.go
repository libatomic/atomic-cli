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
	"github.com/libatomic/atomic/pkg/ptr"
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
		&cli.BoolFlag{
			Name:  "suppress_events",
			Usage: "suppress user events",
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
						Name:  "update_existing_users",
						Usage: "update existing users with CSV data",
					},
					&cli.BoolFlag{
						Name:  "validate_user_email",
						Usage: "validate user email addresses",
					},
					&cli.BoolFlag{
						Name:  "suppress_events",
						Usage: "suppress user events during import",
					},
					&cli.BoolFlag{
						Name:  "suppress_triggers",
						Usage: "suppress parent triggers during import",
					},
					&cli.BoolFlag{
						Name:  "rebuild_audiences",
						Usage: "rebuild audiences after import",
					},
					// audience
					&cli.StringFlag{
						Name:  "import_audience_id",
						Usage: "audience ID to add imported users to",
					},
					&cli.StringFlag{
						Name:  "import_audience_behavior",
						Usage: "audience membership behavior: add_all_users, add_new_users, add_existing_users",
					},
					// stripe
					&cli.StringFlag{
						Name:  "stripe_account_behavior",
						Usage: "stripe account behavior: existing, create, none",
					},
					// default plans
					&cli.BoolFlag{
						Name:  "subscribe_default_plans",
						Usage: "subscribe new users to instance default plans",
					},
					&cli.StringFlag{
						Name:  "default_plan_behavior",
						Usage: "default plan behavior: all, non_subscribers, none",
					},
					// auto subscribe plans
					&cli.StringSliceFlag{
						Name:  "auto_subscribe_plans",
						Usage: "plan IDs to auto-subscribe users to (repeatable)",
					},
					&cli.StringFlag{
						Name:  "auto_subscribe_behavior",
						Usage: "auto subscribe behavior: all_users, subscribers_only, non_subscribers_only, subscribers_skip_paid, none",
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
						Usage: "default subscription anchor date (YYYYMMDD)",
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
						Name:  "user_email_verified",
						Usage: "mark all imported user emails as verified",
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
	if err := BindFlagsFromContext(cmd, &input, "config"); err != nil {
		return err
	}

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
