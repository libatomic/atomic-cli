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

	"github.com/libatomic/atomic/pkg/atomic"
	"github.com/libatomic/atomic/pkg/ptr"
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
			{
				Name:      "create",
				Usage:     "create a template",
				ArgsUsage: "[name]",
				Action:    templateCreate,
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "name", Usage: "template name"},
					&cli.StringFlag{Name: "slug", Usage: "template slug"},
					&cli.StringFlag{Name: "type", Usage: "template type"},
					&cli.StringFlag{Name: "title", Usage: "template title"},
					&cli.StringFlag{Name: "body", Usage: "template body inline"},
					&cli.StringFlag{Name: "body-file", Usage: "read body from a `FILE`"},
					&cli.StringFlag{Name: "metadata", Usage: "read metadata from a JSON `FILE`"},
					&cli.StringFlag{Name: "defaults", Usage: "read defaults from a JSON `FILE`"},
					&cli.BoolFlag{Name: "overwrite", Usage: "overwrite if exists"},
					&cli.StringFlag{Name: "file", Usage: "read full input from JSON `FILE`"},
				},
			},
			{
				Name:      "update",
				Usage:     "update a template",
				ArgsUsage: "<template_id>",
				Action:    templateUpdate,
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "name", Usage: "template name"},
					&cli.BoolFlag{Name: "update_slug", Usage: "regenerate slug from name"},
					&cli.StringFlag{Name: "type", Usage: "template type"},
					&cli.StringFlag{Name: "title", Usage: "template title"},
					&cli.StringFlag{Name: "body", Usage: "template body inline"},
					&cli.StringFlag{Name: "body-file", Usage: "read body from a `FILE`"},
					&cli.StringFlag{Name: "metadata", Usage: "read metadata from a JSON `FILE`"},
					&cli.StringFlag{Name: "defaults", Usage: "read defaults from a JSON `FILE`"},
					&cli.BoolFlag{Name: "republish", Usage: "republish associated distributions"},
					&cli.StringFlag{Name: "file", Usage: "read full input from JSON `FILE`"},
				},
			},
			{
				Name:      "delete",
				Usage:     "delete a template",
				ArgsUsage: "<template_id>",
				Action:    templateDelete,
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

func templateCreate(ctx context.Context, cmd *cli.Command) error {
	var input atomic.TemplateCreateInput

	if cmd.IsSet("file") {
		if err := readJSONFile(cmd.String("file"), &input); err != nil {
			return err
		}
	} else {
		if cmd.NArg() >= 1 {
			input.Name = cmd.Args().First()
		}
		if cmd.IsSet("name") {
			input.Name = cmd.String("name")
		}
		if cmd.IsSet("slug") {
			input.Slug = ptr.String(cmd.String("slug"))
		}
		if cmd.IsSet("type") {
			input.Type = atomic.TemplateType(cmd.String("type"))
		}
		if cmd.IsSet("title") {
			input.Title = ptr.String(cmd.String("title"))
		}
		if cmd.IsSet("body") {
			input.Body = cmd.String("body")
		}
		if cmd.IsSet("body-file") {
			body, err := readFileBytes(cmd.String("body-file"))
			if err != nil {
				return err
			}
			input.Body = string(body)
		}
		if cmd.IsSet("metadata") {
			md, err := readMetadataFile(cmd.String("metadata"))
			if err != nil {
				return err
			}
			input.Metadata = md
		}
		if cmd.IsSet("defaults") {
			md, err := readMetadataFile(cmd.String("defaults"))
			if err != nil {
				return err
			}
			input.Defaults = md
		}
		if cmd.IsSet("overwrite") {
			input.Overwrite = cmd.Bool("overwrite")
		}
	}

	input.InstanceID = inst.UUID

	if input.Name == "" {
		return fmt.Errorf("--name is required")
	}
	if input.Body == "" {
		return fmt.Errorf("--body or --body-file is required")
	}

	tmp, err := backend.TemplateCreate(ctx, &input)
	if err != nil {
		return err
	}

	PrintResult(cmd, []*atomic.Template{tmp},
		WithSingleValue(true),
		WithFields("id", "name", "slug", "type", "title", "created_at"),
	)
	return nil
}

func templateUpdate(ctx context.Context, cmd *cli.Command) error {
	if cmd.NArg() < 1 {
		return fmt.Errorf("template id is required")
	}

	id, err := atomic.ParseID(cmd.Args().First())
	if err != nil {
		return fmt.Errorf("failed to parse template id: %w", err)
	}

	var input atomic.TemplateUpdateInput

	if cmd.IsSet("file") {
		if err := readJSONFile(cmd.String("file"), &input); err != nil {
			return err
		}
	} else {
		if cmd.IsSet("name") {
			input.Name = ptr.String(cmd.String("name"))
		}
		if cmd.IsSet("update_slug") {
			v := cmd.Bool("update_slug")
			input.UpdateSlug = &v
		}
		if cmd.IsSet("type") {
			t := atomic.TemplateType(cmd.String("type"))
			input.Type = &t
		}
		if cmd.IsSet("title") {
			input.Title = ptr.String(cmd.String("title"))
		}
		if cmd.IsSet("body") {
			input.Body = ptr.String(cmd.String("body"))
		}
		if cmd.IsSet("body-file") {
			body, err := readFileBytes(cmd.String("body-file"))
			if err != nil {
				return err
			}
			input.Body = ptr.String(string(body))
		}
		if cmd.IsSet("metadata") {
			md, err := readMetadataFile(cmd.String("metadata"))
			if err != nil {
				return err
			}
			input.Metadata = md
		}
		if cmd.IsSet("defaults") {
			md, err := readMetadataFile(cmd.String("defaults"))
			if err != nil {
				return err
			}
			input.Defaults = md
		}
		if cmd.IsSet("republish") {
			v := cmd.Bool("republish")
			input.Republish = &v
		}
	}

	input.InstanceID = inst.UUID
	input.TemplateID = id

	tmp, err := backend.TemplateUpdate(ctx, &input)
	if err != nil {
		return err
	}

	PrintResult(cmd, []*atomic.Template{tmp},
		WithSingleValue(true),
		WithFields("id", "name", "slug", "type", "title", "updated_at"),
	)
	return nil
}

func templateDelete(ctx context.Context, cmd *cli.Command) error {
	if cmd.NArg() < 1 {
		return fmt.Errorf("template id is required")
	}

	id, err := atomic.ParseID(cmd.Args().First())
	if err != nil {
		return fmt.Errorf("failed to parse template id: %w", err)
	}

	if err := backend.TemplateDelete(ctx, &atomic.TemplateDeleteInput{
		InstanceID: inst.UUID,
		TemplateID: id,
	}); err != nil {
		return err
	}

	fmt.Println("Template deleted")
	return nil
}
