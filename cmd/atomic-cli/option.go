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
