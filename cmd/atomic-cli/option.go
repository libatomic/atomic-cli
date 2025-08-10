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
	optionCmd = &cli.Command{
		Name:    "option",
		Aliases: []string{"options"},
		Usage:   "Manage options",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  "instance_id",
				Usage: "The instance id",
			},
		},
		Commands: []*cli.Command{
			{
				Name:   "list",
				Usage:  "List options",
				Action: optionList,
				Flags: []cli.Flag{
					&cli.BoolFlag{
						Name:  "protected",
						Usage: "Include protected options",
					},
				},
			},
			{
				Name:      "get",
				Usage:     "Get an option",
				ArgsUsage: "<name>",
				Action:    optionGet,
				Flags: []cli.Flag{
					&cli.BoolFlag{
						Name:  "protected",
						Usage: "Include protected options",
					},
					&cli.BoolFlag{
						Name:  "value",
						Usage: "Print the value",
					},
				},
			},
			{
				Name:      "create",
				Aliases:   []string{"update"},
				Usage:     "Set an option",
				ArgsUsage: "<name> <value>",
				Action:    optionUpdate,
				Flags: []cli.Flag{
					&cli.BoolFlag{
						Name:  "force",
						Usage: "Force the update, overrides the protected flag (requires partner role)",
					},
					&cli.BoolFlag{
						Name:  "file",
						Usage: "Create or Update the option value from a json file",
					},
					&cli.BoolFlag{
						Name:  "validate",
						Usage: "Validate the option value",
					},
				},
			},
			{
				Name:      "delete",
				Usage:     "Delete an option",
				ArgsUsage: "<name>",
				Action:    optionDelete,
				Flags: []cli.Flag{
					&cli.BoolFlag{
						Name:  "force",
						Usage: "Force the delete, overrides the protected flag (requires partner role)",
					},
				},
			},
		},
	}
)

func optionList(ctx context.Context, cmd *cli.Command) error {
	var input atomic.OptionListInput

	if cmd.IsSet("instance_id") {
		id, err := atomic.ParseID(cmd.String("instance_id"))
		if err != nil {
			return fmt.Errorf("invalid instance id: %w", err)
		}

		input.InstanceID = id
	}

	if cmd.IsSet("protected") {
		input.OverrideProtected = ptr.Bool(cmd.Bool("protected"))
	}

	opts, err := backend.OptionList(ctx, &input)
	if err != nil {
		return err
	}

	PrintResult(cmd, opts,
		WithFields("name", "protected", "read_only"))

	return nil
}

func optionGet(ctx context.Context, cmd *cli.Command) error {
	var input atomic.OptionGetInput

	input.ReturnStruct = ptr.Bool(true)

	if cmd.Args().Len() == 0 {
		return fmt.Errorf("option name is required")
	}

	input.Name = cmd.Args().First()

	if cmd.IsSet("instance_id") {
		id, err := atomic.ParseID(cmd.String("instance_id"))
		if err != nil {
			return fmt.Errorf("invalid instance id: %w", err)
		}

		input.InstanceID = id
	}

	if cmd.IsSet("protected") {
		input.OverrideProtected = ptr.Bool(cmd.Bool("protected"))
	}

	opt, err := backend.OptionGet(ctx, &input)
	if err != nil {
		return err
	}

	out, err := json.MarshalIndent(opt, "", "\t")
	if err != nil {
		return err
	}

	if cmd.IsSet("value") && cmd.Bool("value") {
		fmt.Println(string(out))
		return nil
	}

	PrintResult(cmd, []*atomic.Option{opt},
		WithFields("name", "protected", "read_only"),
	)

	fmt.Println("Value:")

	fmt.Println(string(out))

	return nil
}

func optionUpdate(ctx context.Context, cmd *cli.Command) error {
	var input atomic.OptionUpdateInput

	if cmd.IsSet("file") && cmd.Bool("file") {
		content, err := os.ReadFile(cmd.Args().First())
		if err != nil {
			return fmt.Errorf("failed to read option update input file: %w", err)
		}

		if err := json.Unmarshal(content, &input); err != nil {
			return fmt.Errorf("failed to unmarshal option update input: %w", err)
		}
	} else {
		input.Name = cmd.Args().First()
	}

	if input.Name == "" {
		return fmt.Errorf("option name is required")
	}

	if cmd.IsSet("force") && cmd.Bool("force") {
		input.Force = ptr.Bool(true)
	}

	if cmd.IsSet("validate") && cmd.Bool("validate") {
		input.ValidateOnly = true
	}

	opt, err := backend.OptionUpdate(ctx, &input)
	if err != nil {
		return err
	}

	PrintResult(cmd, []*atomic.Option{opt},
		WithFields("name", "protected", "read_only", "updated_at"))

	fmt.Println("Value:")

	val, err := json.MarshalIndent(opt.Value, "", "\t")
	if err != nil {
		return err
	}

	fmt.Println(string(val))

	return nil
}

func optionDelete(ctx context.Context, cmd *cli.Command) error {
	var input atomic.OptionRemoveInput

	if cmd.Args().Len() == 0 {
		return fmt.Errorf("option name is required")
	}

	input.Name = cmd.Args().First()

	if cmd.IsSet("force") && cmd.Bool("force") {
		input.Force = ptr.Bool(true)
	}

	if err := backend.OptionRemove(ctx, &input); err != nil {
		return err
	}

	PrintResult(cmd, []*atomic.Option{},
		WithFields("name", "protected", "read_only", "updated_at"))

	return nil
}
