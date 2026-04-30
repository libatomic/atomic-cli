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

	"github.com/libatomic/atomic/pkg/atomic"
	"github.com/urfave/cli/v3"
)

var (
	templateCmd = &cli.Command{
		Name:    "template",
		Aliases: []string{"templates"},
		Usage:   "manage templates",
		Commands: []*cli.Command{
			{
				Name:   "list",
				Usage:  "list templates",
				Action: templateList,
				Flags: []cli.Flag{
					&cli.IntFlag{
						Name:  "limit",
						Usage: "limit the number of templates",
					},
					&cli.IntFlag{
						Name:  "offset",
						Usage: "offset the number of templates",
					},
				},
			},
			{
				Name:      "get",
				Usage:     "get a template by id",
				ArgsUsage: "<template_id>",
				Action:    templateGet,
			},
			templateEventCmd,
		},
	}
)

// resolveTemplate looks up a template by ID. The REST surface only exposes
// id-based lookup, so callers must pass a UUID — name/slug forms are not
// supported here.
func resolveTemplate(ctx context.Context, ref string) (*atomic.Template, error) {
	id, err := atomic.ParseID(ref)
	if err != nil {
		return nil, fmt.Errorf("failed to parse template id %q: %w", ref, err)
	}

	instID := inst.UUID
	tmp, err := backend.TemplateGet(ctx, &atomic.TemplateGetInput{
		InstanceID: instID,
		TemplateID: &id,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get template %s: %w", ref, err)
	}
	return tmp, nil
}

func templateList(ctx context.Context, cmd *cli.Command) error {
	var input atomic.TemplateListInput

	if err := BindFlagsFromContext(cmd, &input); err != nil {
		return err
	}

	input.InstanceID = inst.UUID

	tmps, err := backend.TemplateList(ctx, &input)
	if err != nil {
		return err
	}

	PrintResult(cmd, tmps,
		WithFields("id", "name", "slug", "type", "title", "created_at"),
	)

	return nil
}

func templateGet(ctx context.Context, cmd *cli.Command) error {
	if cmd.NArg() < 1 {
		return fmt.Errorf("template id is required")
	}

	tmp, err := resolveTemplate(ctx, cmd.Args().First())
	if err != nil {
		return err
	}

	PrintResult(cmd, []*atomic.Template{tmp},
		WithSingleValue(true),
		WithFields("id", "name", "slug", "type", "title", "events", "metadata", "created_at", "updated_at"),
	)

	return nil
}
