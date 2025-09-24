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
				ArgsUsage: "<login>",
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
				ArgsUsage: "<user_id>",
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
				ArgsUsage: "<file>",
				Action:    userImport,
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:  "mime_type",
						Usage: "specify the mime type of the file to import",
						Value: "text/csv",
					},
					&cli.StringFlag{
						Name:  "source",
						Usage: "specify the source file to import, i.e. atomic, ghost, substack, etc.",
						Value: "atomic",
					},
					&cli.StringFlag{
						Name:  "trial_plan_id",
						Usage: "specify the trial plan id",
					},
					&cli.StringFlag{
						Name:  "trial_price_id",
						Usage: "specify the trial price id",
					},
					&cli.TimestampFlag{
						Name:  "trial_end_at",
						Usage: "specify the trial end at",
					},
					&cli.BoolFlag{
						Name:  "trial_existing_users",
						Usage: "specify if the trial should be applied to existing users",
					},
					&cli.BoolFlag{
						Name:  "user_email_verified",
						Usage: "specify if the user email should be verified",
					},
					&cli.StringFlag{
						Name:  "source_params",
						Usage: "paths to source params json",
					},
					&cli.StringFlag{
						Name:  "import_audience_id",
						Usage: "specify the import audience id",
					},
					&cli.StringFlag{
						Name:  "import_audience_behavior",
						Usage: "specify the import audience behavior (add_all_users, add_new_users, add_existing_users)",
					},
					&cli.BoolFlag{
						Name:  "suppress_parent_triggers",
						Usage: "suppress parent triggers",
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

	if err := BindFlagsFromContext(cmd, &input); err != nil {
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

	if cmd.IsSet("source_params") {
		content, err := os.ReadFile(cmd.Args().First())
		if err != nil {
			return fmt.Errorf("failed to read user import input file: %w", err)
		}

		if err := json.Unmarshal(content, &input.SourceParams); err != nil {
			return fmt.Errorf("failed to unmarshal user import input: %w", err)
		}
	}

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
