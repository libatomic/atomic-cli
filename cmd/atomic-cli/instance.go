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
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/libatomic/atomic/v2/pkg/atomic"
	"github.com/libatomic/atomic/v2/pkg/oauth"
	"github.com/libatomic/atomic/v2/pkg/ptr"
	"github.com/urfave/cli/v3"
)

var (
	instCommonFlags = []cli.Flag{
		&cli.BoolFlag{
			Name:  "file",
			Usage: "read the instance parameters from a `FILE`",
			Value: true,
		},
		&cli.StringFlag{
			Name:  "title",
			Usage: "set the instance display title",
		},
		&cli.StringFlag{
			Name:  "description",
			Usage: "set the instance description",
		},
		&cli.StringFlag{
			Name:  "session_key",
			Usage: "set the session key",
		},
		&cli.StringFlag{
			Name:  "session_cookie",
			Usage: "set the session cookie",
		},
		&cli.Int64Flag{
			Name:  "session_lifetime",
			Usage: "set the session lifetime in milliseconds",
			Value: 3600,
		},
		&cli.StringFlag{
			Name:  "metadata",
			Usage: "source `FILE` to set the metadata for the instance",
		},
		&cli.StringSliceFlag{
			Name:  "origins",
			Usage: "set the origins for the instance (comma separated)",
		},
		&cli.StringSliceFlag{
			Name:  "domains",
			Usage: "set the domains for the instance (comma separated)",
		},
	}

	instCreateFlags = append(instCommonFlags, &cli.StringFlag{
		Name:  "parent_id",
		Usage: "set the parent instance id",
	})

	instUpdateFlags = append(instCommonFlags, &cli.BoolFlag{
		Name:  "recreate_jobs",
		Usage: "recreate the instance jobs",
	})

	instCmd = &cli.Command{
		Name:    "instance",
		Aliases: []string{"inst"},
		Usage:   "instance management",
		Commands: []*cli.Command{
			{
				Name:      "create",
				Usage:     "create a new instance",
				ArgsUsage: "create <name>",
				Action:    instCreate,
				Flags:     instCreateFlags,
			},
			{
				Name:      "get",
				Usage:     "get an instance",
				Action:    instGet,
				ArgsUsage: "get <instance-id>",
			},
			{
				Name:      "update",
				Usage:     "update an instance",
				Action:    instUpdate,
				ArgsUsage: "update <instance-id>",
				Flags:     instUpdateFlags,
			},
			{
				Name:      "delete",
				Usage:     "delete an instance",
				Action:    instDelete,
				ArgsUsage: "delete <instance-id>",
			},
			{
				Name:      "token-rotate",
				Usage:     "replace the token signing key, keeping the old one for a grace period (direct database access)",
				ArgsUsage: "token-rotate <instance id or name>",
				Description: "Generates a new signing key and moves the current one into the previous slot, where it keeps " +
					"verifying bearers, link tokens and webhook signatures until the grace period ends; everything new is " +
					"signed with the new key. Keys are told apart by algorithm, so the algorithm must change unless --force. " +
					"Needs --db_source and --db_cache so the nodes' cached copies of the instance are flushed.",
				Action: instTokenRotate,
				Before: requireDirectDB,
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:  "alg",
						Usage: "the new token algorithm: ES256 or HS256 (RS256 is slow to verify)",
						Value: "ES256",
					},
					&cli.StringFlag{
						Name:  "grace",
						Usage: "how long the previous key keeps verifying, e.g. 90d, 120d or 2160h (1 day to 365 days)",
						Value: "90d",
					},
					&cli.BoolFlag{
						Name:  "retire",
						Usage: "drop the previous key now instead of rotating",
					},
					&cli.BoolFlag{
						Name:  "force",
						Usage: "rotate even if the algorithm is unchanged or a previous key is still in its grace period (what they signed stops verifying)",
					},
					&cli.BoolFlag{
						Name:  "no-cache-flush",
						Usage: "allow running without --db_cache; the instance stays cached on the nodes for up to 15 minutes",
					},
				},
			},
			{
				Name:      "list",
				Usage:     "list instances",
				Action:    instList,
				ArgsUsage: "list",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:  "name",
						Usage: "return only instances with the given name (regex)",
					},
					&cli.BoolFlag{
						Name:  "is_parent",
						Usage: "return only parent instances",
					},
					&cli.BoolFlag{
						Name:  "has_parent",
						Usage: "return only instances that have a parent",
					},
				},
			},
		},
	}
)

func instCreate(ctx context.Context, cmd *cli.Command) error {
	var input atomic.InstanceCreateInput

	if cmd.IsSet("file") && cmd.Bool("file") {
		content, err := os.ReadFile(cmd.Args().First())
		if err != nil {
			return fmt.Errorf("failed to read instance create input file: %w", err)
		}

		if err := json.Unmarshal(content, &input); err != nil {
			return fmt.Errorf("failed to unmarshal instance create input: %w", err)
		}
	} else if cmd.Args().First() != "" {
		input.Name = cmd.Args().First()
	}

	if err := BindFlagsFromContext(cmd, &input, "metadata"); err != nil {
		return err
	}

	if cmd.IsSet("metadata") {
		fd, err := os.Open(cmd.String("metadata"))
		if err != nil {
			return fmt.Errorf("failed to open metadata file: %w", err)
		}
		defer fd.Close()

		input.Metadata = atomic.Metadata{}

		if err := json.NewDecoder(fd).Decode(&input.Metadata); err != nil {
			return fmt.Errorf("failed to decode metadata: %w", err)
		}
	}

	inst, err := backend.InstanceCreate(ctx, &input)
	if err != nil {
		return err
	}

	PrintResult(cmd, []*atomic.Instance{inst}, WithFields("id", "name", "title", "created_at", "parent_id"))

	return nil
}

func instUpdate(ctx context.Context, cmd *cli.Command) error {
	var input atomic.InstanceUpdateInput

	if cmd.IsSet("file") && cmd.Bool("file") {
		content, err := os.ReadFile(cmd.Args().First())
		if err != nil {
			return fmt.Errorf("failed to read instance update input file: %w", err)
		}

		if err := json.Unmarshal(content, &input); err != nil {
			return fmt.Errorf("failed to unmarshal instance update input: %w", err)
		}
	} else if id, err := atomic.ParseID(cmd.Args().First()); err != nil {
		return fmt.Errorf("failed to parse instance id: %w", err)
	} else {
		input.InstanceID = id
	}

	if err := BindFlagsFromContext(cmd, &input, "metadata"); err != nil {
		return err
	}

	if cmd.IsSet("metadata") {
		fd, err := os.Open(cmd.String("metadata"))
		if err != nil {
			return fmt.Errorf("failed to open metadata file: %w", err)
		}
		defer fd.Close()

		input.Metadata = atomic.Metadata{}

		if err := json.NewDecoder(fd).Decode(&input.Metadata); err != nil {
			return fmt.Errorf("failed to decode metadata: %w", err)
		}
	}

	inst, err := backend.InstanceUpdate(ctx, &input)
	if err != nil {
		return err
	}

	PrintResult(cmd, []*atomic.Instance{inst}, WithFields("id", "name", "title", "created_at", "parent_id"))

	return nil
}

func instGet(ctx context.Context, cmd *cli.Command) error {
	var input atomic.InstanceGetInput

	id, err := atomic.ParseID(cmd.Args().First())
	if err != nil {

		insts, err := backend.InstanceList(ctx, &atomic.InstanceListInput{
			Name: ptr.String(cmd.Args().First()),
		})
		if err != nil {
			return err
		}

		if len(insts) == 0 {
			return fmt.Errorf("instance not found")
		}

		PrintResult(cmd, insts, WithFields("id", "name", "title", "created_at", "parent_id"))
		return nil
	}

	input.InstanceID = &id

	inst, err := backend.InstanceGet(ctx, &input)
	if err != nil {
		return err
	}

	PrintResult(cmd, []*atomic.Instance{inst}, WithFields("id", "name", "title", "created_at", "parent_id"))

	return nil
}

func instDelete(ctx context.Context, cmd *cli.Command) error {
	var input atomic.InstanceDeleteInput

	id, err := atomic.ParseID(cmd.Args().First())
	if err != nil {
		return fmt.Errorf("failed to parse instance id: %w", err)
	}

	input.InstanceID = id

	if err := backend.InstanceDelete(ctx, &input); err != nil {
		return err
	}

	return nil
}

func instList(ctx context.Context, cmd *cli.Command) error {
	var input atomic.InstanceListInput

	if cmd.IsSet("is_parent") {
		isParent := cmd.Bool("is-parent")
		input.IsParent = &isParent
	}

	if cmd.IsSet("has_parent") {
		hasParent := cmd.Bool("has-parent")
		input.HasParent = &hasParent
	}

	if cmd.IsSet("name") {
		input.Name = ptr.String(cmd.String("name"))
	}

	insts, err := backend.InstanceList(ctx, &input)
	if err != nil {
		return err
	}

	PrintResult(cmd, insts, WithFields("id", "name", "title", "created_at", "parent_id"))

	return nil
}

// requireDirectDB is for commands that write what the API does not expose:
// they need db_source, and db_cache unless the caller accepts stale nodes.
func requireDirectDB(ctx context.Context, cmd *cli.Command) (context.Context, error) {
	if _, ok := backend.(*atomic.Atomic); !ok {
		return nil, fmt.Errorf("this command needs direct database access: set --db_source (and --db_cache)")
	}

	if cmd.Root().String("db_cache") == "" && !cmd.Bool("no-cache-flush") {
		return nil, fmt.Errorf("set --db_cache to the nodes' cache (redis://...) so the change reaches them, or pass --no-cache-flush and wait up to 15 minutes")
	}

	return ctx, nil
}

// parseGrace reads a duration that may end in d for days.
func parseGrace(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)

	if strings.HasSuffix(s, "d") {
		days, err := strconv.Atoi(strings.TrimSuffix(s, "d"))
		if err != nil {
			return 0, fmt.Errorf("invalid grace %q", s)
		}

		return time.Duration(days) * 24 * time.Hour, nil
	}

	return time.ParseDuration(s)
}

func instTokenRotate(ctx context.Context, cmd *cli.Command) error {
	a := backend.(*atomic.Atomic)

	target, err := resolveInstanceArg(ctx, cmd.Args().First())
	if err != nil {
		return err
	}

	in := &atomic.InstanceTokenRotateInput{InstanceID: target.UUID}

	if cmd.Bool("retire") {
		in.Retire = ptr.True
	} else {
		alg := oauth.TokenAlgorithm(strings.ToUpper(strings.TrimSpace(cmd.String("alg"))))
		in.Algorithm = &alg

		grace, err := parseGrace(cmd.String("grace"))
		if err != nil {
			return err
		}

		in.Grace = &grace
	}

	if cmd.Bool("force") {
		in.Force = ptr.True
	}

	inst, err := a.InstanceTokenRotate(ctx, in)
	if err != nil {
		return err
	}

	PrintResult(cmd, []*atomic.Instance{inst}, WithFields("id", "name", "token_algorithm", "token_algorithm_prev", "token_rotated_at", "token_prev_expires_at"))

	if cmd.Root().String("db_cache") == "" {
		fmt.Fprintln(os.Stderr, "note: no --db_cache; nodes keep the old key for up to 15 minutes")
	}

	return nil
}

// resolveInstanceArg finds an instance by id or by name.
func resolveInstanceArg(ctx context.Context, arg string) (*atomic.Instance, error) {
	if arg == "" {
		return nil, fmt.Errorf("an instance id or name is required")
	}

	if id, err := atomic.ParseID(arg); err == nil {
		return backend.InstanceGet(ctx, &atomic.InstanceGetInput{InstanceID: &id})
	}

	insts, err := backend.InstanceList(ctx, &atomic.InstanceListInput{Name: ptr.String("^" + regexp.QuoteMeta(arg) + "$")})
	if err != nil {
		return nil, err
	}

	if len(insts) != 1 {
		return nil, fmt.Errorf("instance %q not found", arg)
	}

	return insts[0], nil
}
