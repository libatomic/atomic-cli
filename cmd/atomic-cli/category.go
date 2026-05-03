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

	"github.com/libatomic/atomic/pkg/atomic"
	"github.com/libatomic/atomic/pkg/ptr"
	"github.com/urfave/cli/v3"
)

var (
	categoryUpdateFlags = []cli.Flag{
		&cli.StringFlag{
			Name:  "name",
			Usage: "category name",
		},
		&cli.StringFlag{
			Name:  "description",
			Usage: "category description",
		},
		&cli.BoolFlag{
			Name:  "active",
			Usage: "set the category as active",
		},
		&cli.BoolFlag{
			Name:  "hidden",
			Usage: "set the category as hidden",
		},
	}

	categoryCreateFlags = append(categoryUpdateFlags, []cli.Flag{
		&cli.BoolFlag{
			Name:  "file",
			Usage: "read category parameters from a JSON file",
		},
	}...)

	categoryCmd = &cli.Command{
		Name:    "category",
		Aliases: []string{"categories"},
		Usage:   "manage categories",
		Commands: []*cli.Command{
			{
				Name:      "create",
				Usage:     "create a category",
				Flags:     categoryCreateFlags,
				ArgsUsage: "<name>",
				Action:    categoryCreate,
			},
			{
				Name:      "update",
				Usage:     "update a category",
				Flags:     categoryUpdateFlags,
				ArgsUsage: "<category_id>",
				Action:    categoryUpdate,
			},
			{
				Name:      "get",
				Usage:     "get a category",
				ArgsUsage: "<category_id>",
				Action:    categoryGet,
			},
			{
				Name:   "list",
				Usage:  "list categories",
				Action: categoryList,
				Flags: []cli.Flag{
					&cli.IntFlag{
						Name:  "limit",
						Usage: "limit the number of categories",
					},
					&cli.IntFlag{
						Name:  "offset",
						Usage: "offset the number of categories",
					},
				},
			},
			{
				Name:      "delete",
				Usage:     "delete a category",
				ArgsUsage: "<category_id>",
				Action:    categoryDelete,
			},
			{
				Name:      "import",
				Usage:     "import categories from a JSON file",
				ArgsUsage: "<file>",
				Action:    categoryImport,
				Flags: []cli.Flag{
					&cli.BoolFlag{
						Name:  "dry-run",
						Usage: "preview what would be created without making changes",
					},
				},
			},
		},
	}
)

func categoryCreate(ctx context.Context, cmd *cli.Command) error {
	var input atomic.CategoryCreateInput

	if cmd.IsSet("file") && cmd.Bool("file") {
		content, err := os.ReadFile(cmd.Args().First())
		if err != nil {
			return fmt.Errorf("failed to read category create input file: %w", err)
		}

		if err := json.Unmarshal(content, &input); err != nil {
			return fmt.Errorf("failed to unmarshal category create input: %w", err)
		}
	} else if cmd.Args().First() != "" {
		input.Name = cmd.Args().First()
	}

	if err := BindFlagsFromContext(cmd, &input); err != nil {
		return err
	}

	input.InstanceID = inst.UUID

	if input.Active == nil {
		input.Active = ptr.Bool(true)
	}

	cat, err := backend.CategoryCreate(ctx, &input)
	if err != nil {
		return err
	}

	PrintResult(cmd, []*atomic.Category{cat},
		WithSingleValue(true),
		WithFields("id", "name", "slug", "active", "hidden", "created_at"),
	)

	return nil
}

func categoryUpdate(ctx context.Context, cmd *cli.Command) error {
	if cmd.NArg() < 1 {
		return fmt.Errorf("category ID is required")
	}

	categoryID, err := atomic.ParseID(cmd.Args().First())
	if err != nil {
		return fmt.Errorf("failed to parse category ID: %w", err)
	}

	var input atomic.CategoryUpdateInput

	if err := BindFlagsFromContext(cmd, &input); err != nil {
		return err
	}

	input.InstanceID = inst.UUID
	input.CategoryID = categoryID

	cat, err := backend.CategoryUpdate(ctx, &input)
	if err != nil {
		return err
	}

	PrintResult(cmd, []*atomic.Category{cat},
		WithSingleValue(true),
		WithFields("id", "name", "slug", "active", "hidden", "updated_at"),
	)

	return nil
}

func categoryGet(ctx context.Context, cmd *cli.Command) error {
	if cmd.NArg() < 1 {
		return fmt.Errorf("category ID is required")
	}

	categoryID, err := atomic.ParseID(cmd.Args().First())
	if err != nil {
		return fmt.Errorf("failed to parse category ID: %w", err)
	}

	input := &atomic.CategoryGetInput{
		InstanceID: inst.UUID,
		CategoryID: &categoryID,
	}

	cat, err := backend.CategoryGet(ctx, input)
	if err != nil {
		return err
	}

	PrintResult(cmd, []*atomic.Category{cat},
		WithSingleValue(true),
		WithFields("id", "name", "slug", "description", "active", "hidden", "created_at"),
	)

	return nil
}

func categoryList(ctx context.Context, cmd *cli.Command) error {
	var input atomic.CategoryListInput

	if err := BindFlagsFromContext(cmd, &input); err != nil {
		return err
	}

	input.InstanceID = inst.UUID

	cats, err := backend.CategoryList(ctx, &input)
	if err != nil {
		return err
	}

	PrintResult(cmd, cats,
		WithFields("id", "name", "slug", "active", "hidden", "created_at"),
	)

	return nil
}

func categoryDelete(ctx context.Context, cmd *cli.Command) error {
	if cmd.NArg() < 1 {
		return fmt.Errorf("category ID is required")
	}

	categoryID, err := atomic.ParseID(cmd.Args().First())
	if err != nil {
		return fmt.Errorf("failed to parse category ID: %w", err)
	}

	if err := backend.CategoryDelete(ctx, &atomic.CategoryDeleteInput{
		InstanceID: inst.UUID,
		CategoryID: &categoryID,
	}); err != nil {
		return err
	}

	fmt.Println("Category deleted")

	return nil
}

func categoryImport(ctx context.Context, cmd *cli.Command) error {
	if cmd.NArg() < 1 {
		return fmt.Errorf("JSON file is required")
	}

	dryRun := cmd.Bool("dry-run")

	content, err := os.ReadFile(cmd.Args().First())
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	var categories []atomic.Category
	if err := json.Unmarshal(content, &categories); err != nil {
		return fmt.Errorf("failed to parse JSON: %w", err)
	}

	fmt.Fprintf(os.Stderr, "parsed %d categories\n", len(categories))

	var created int
	for _, cat := range categories {
		if dryRun {
			fmt.Fprintf(os.Stderr, "[DRY RUN] would create: %s (%s)\n", cat.Name, cat.Slug)
			created++
			continue
		}

		input := &atomic.CategoryCreateInput{
			InstanceID:  inst.UUID,
			Name:        cat.Name,
			Description: cat.Description,
			Active:      &cat.Active,
			Hidden:      &cat.Hidden,
			Metadata:    cat.Metadata,
		}

		result, err := backend.CategoryCreate(ctx, input)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to create %q: %s\n", cat.Name, err)
			continue
		}

		fmt.Fprintf(os.Stderr, "created: %s (%s) -> %s\n", result.Name, result.Slug, result.ID)
		created++
	}

	fmt.Fprintf(os.Stderr, "%d of %d categories created\n", created, len(categories))

	return nil
}
