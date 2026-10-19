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
	"fmt"
	"strings"

	"github.com/libatomic/atomic/v2/pkg/atomic"
	"github.com/libatomic/atomic/v2/pkg/ptr"
	"github.com/urfave/cli/v3"
)

// userExpandUsage enumerates the valid `--expand` values so MCP/LLM
// callers can pick the right keys without trial and error. Mirrors the
// expand handlers in atomic/pkg/atomic/user.go.
const userExpandUsage = "expand related objects inline; valid values: " +
	"subscriptions, entitlements, credits, audiences, access_tokens, " +
	"roles, permissions, account (alias: stripe_account), preferences. " +
	"Repeat the flag to expand multiple."

var (
	userUpdateFlags = []cli.Flag{
		&cli.BoolFlag{
			Name:  "file",
			Usage: "treat the positional argument as a JSON file holding the full input (for update it must include user_id)",
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
			Usage: "set the user profile" + jsonInputUsage + `, e.g. '{"name":"Ada","email":"ada@example.com"}'`,
		},
		&cli.StringSliceFlag{
			Name:  "roles",
			Usage: "set the user roles (repeatable, e.g. --roles member --roles admin)",
		},
		&cli.StringFlag{
			Name:  "metadata",
			Usage: "set the user metadata" + jsonInputUsage,
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
			Usage: "set the user preferences" + jsonInputUsage,
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
				Usage:     "get a user by id (use --expand to include subscriptions, entitlements, etc.)",
				ArgsUsage: "<user_id>",
				Flags: []cli.Flag{
					&cli.BoolFlag{
						Name:    "stripe_customer",
						Aliases: []string{"stripe", "sc"},
						Usage:   "treat the positional arg as a stripe customer id",
					},
					&cli.BoolFlag{
						Name:    "subject",
						Aliases: []string{"sub"},
						Usage:   "treat the positional arg as an oauth subject",
					},
					&cli.StringSliceFlag{
						Name:  "expand",
						Usage: userExpandUsage,
					},
				},
				Action: userGet,
			},
			{
				Name:      "list",
				Usage:     "list/search users (filter by --login/email, --audience, --roles, --status; use --expand=entitlements,subscriptions to include them inline)",
				ArgsUsage: "list",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:  "audience",
						Usage: "filter by audience id",
					},
					&cli.StringSliceFlag{
						Name:  "roles",
						Usage: "filter by role (member, admin, editor, author, contrib)",
					},
					&cli.StringFlag{
						Name:  "status",
						Usage: "filter by subscription status (one of: active, canceled, past_due, unpaid, incomplete, incomplete_expired, trialing, pending, deleted, paused, deferred)",
					},
					&cli.StringFlag{
						Name:    "login",
						Aliases: []string{"email"},
						Usage:   "filter by login (the user's email address)",
					},
					&cli.StringFlag{
						Name:  "stripe_account",
						Usage: "filter by stripe customer id",
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
						Usage: userExpandUsage,
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
			userImportCmd,
		},
	}
)

func userCreate(ctx context.Context, cmd *cli.Command) error {
	var input atomic.UserCreateInput

	if cmd.IsSet("file") && cmd.Bool("file") {
		path := cmd.Args().First()
		if path == "" {
			return fmt.Errorf("--file: pass the JSON file path as the positional argument")
		}
		if err := readJSONInput("file", path, &input); err != nil {
			return err
		}
	} else if cmd.Args().First() != "" {
		input.Login = cmd.Args().First()
	}

	if err := BindFlagsFromContext(cmd, &input, "profile", "metadata", "preferences"); err != nil {
		return err
	}

	if err := readJSONFlag(cmd, "profile", &input.Profile); err != nil {
		return err
	}
	if err := readJSONFlag(cmd, "metadata", &input.Metadata); err != nil {
		return err
	}
	if err := readJSONFlag(cmd, "preferences", &input.Preferences); err != nil {
		return err
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
		path := cmd.Args().First()
		if path == "" {
			return fmt.Errorf("--file: pass the JSON file path as the positional argument")
		}
		if err := readJSONInput("file", path, &input); err != nil {
			return err
		}
		if input.UserID == nil && input.Subject == nil {
			return fmt.Errorf("--file: the JSON must include user_id (or subject)")
		}
	} else {
		if cmd.Args().First() == "" {
			return fmt.Errorf("user id is required (or pass --file with a JSON file path)")
		}
		id, err := atomic.ParseID(cmd.Args().First())
		if err != nil {
			return fmt.Errorf("failed to parse user id %q: %w", cmd.Args().First(), err)
		}

		input.UserID = &id
	}

	if err := BindFlagsFromContext(cmd, &input, "profile", "metadata", "preferences"); err != nil {
		return err
	}

	if err := readJSONFlag(cmd, "profile", &input.Profile); err != nil {
		return err
	}
	if err := readJSONFlag(cmd, "metadata", &input.Metadata); err != nil {
		return err
	}
	if err := readJSONFlag(cmd, "preferences", &input.Preferences); err != nil {
		return err
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
