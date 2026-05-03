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
	"time"

	"github.com/libatomic/atomic/pkg/atomic"
	"github.com/libatomic/atomic/pkg/ptr"
	"github.com/urfave/cli/v3"
)

var (
	articleWriteFlags = []cli.Flag{
		&cli.StringFlag{
			Name:  "author",
			Usage: "set the author",
		},
		&cli.StringFlag{
			Name:  "author_email",
			Usage: "set the author email",
		},
		&cli.StringFlag{
			Name:  "title",
			Usage: "set the title",
		},
		&cli.StringFlag{
			Name:  "body",
			Usage: "set the body inline (use --body-file for large bodies)",
		},
		&cli.StringFlag{
			Name:  "body-file",
			Usage: "read the body from a `FILE`",
		},
		&cli.StringFlag{
			Name:  "summary",
			Usage: "set the summary",
		},
		&cli.StringFlag{
			Name:  "language",
			Usage: "BCP-47 language tag",
		},
		&cli.StringFlag{
			Name:  "status",
			Usage: "draft|published|scheduled|archived",
		},
		&cli.BoolFlag{
			Name:  "public",
			Usage: "mark the article as public",
		},
		&cli.StringFlag{
			Name:  "uri",
			Usage: "set the canonical URI",
		},
		&cli.StringFlag{
			Name:  "image_uri",
			Usage: "set the image URI",
		},
		&cli.StringFlag{
			Name:  "published_at",
			Usage: "RFC3339 publish timestamp",
		},
		&cli.StringSliceFlag{
			Name:  "categories",
			Usage: "category ids/slugs to assign",
		},
		&cli.StringFlag{
			Name:  "metadata",
			Usage: "read metadata from a JSON `FILE`",
		},
		&cli.StringFlag{
			Name:  "file",
			Usage: "read the full input from a JSON `FILE` (other flags are ignored)",
		},
	}

	articleCmd = &cli.Command{
		Name:    "article",
		Aliases: []string{"articles"},
		Usage:   "manage articles",
		Commands: []*cli.Command{
			{
				Name:   "list",
				Usage:  "list articles",
				Action: articleList,
				Flags: []cli.Flag{
					&cli.IntFlag{Name: "limit", Usage: "limit"},
					&cli.IntFlag{Name: "offset", Usage: "offset"},
					&cli.StringFlag{Name: "status", Usage: "filter by status"},
					&cli.StringFlag{Name: "title", Usage: "filter by title"},
					&cli.BoolFlag{Name: "public", Usage: "filter by public flag"},
					&cli.StringSliceFlag{Name: "categories", Usage: "filter by category ids"},
					&cli.BoolFlag{Name: "preload", Usage: "preload related entities"},
				},
			},
			{
				Name:      "get",
				Usage:     "get an article",
				ArgsUsage: "<article_id>",
				Action:    articleGet,
				Flags: []cli.Flag{
					&cli.BoolFlag{Name: "preload", Usage: "preload related entities"},
				},
			},
			{
				Name:      "create",
				Usage:     "create an article",
				ArgsUsage: "[title]",
				Action:    articleCreate,
				Flags:     articleWriteFlags,
			},
			{
				Name:      "update",
				Usage:     "update an article",
				ArgsUsage: "<article_id>",
				Action:    articleUpdate,
				Flags:     articleWriteFlags,
			},
			{
				Name:      "delete",
				Usage:     "delete an article",
				ArgsUsage: "<article_id>",
				Action:    articleDelete,
			},
		},
	}
)

func articleList(ctx context.Context, cmd *cli.Command) error {
	var input atomic.ArticleListInput

	if err := BindFlagsFromContext(cmd, &input, "categories", "public"); err != nil {
		return err
	}

	input.InstanceID = inst.UUID

	for _, raw := range cmd.StringSlice("categories") {
		id, err := atomic.ParseID(raw)
		if err != nil {
			return fmt.Errorf("failed to parse category id %q: %w", raw, err)
		}
		input.Categories = append(input.Categories, id)
	}

	if cmd.IsSet("public") {
		v := cmd.Bool("public")
		input.Public = &v
	}

	if cmd.IsSet("preload") {
		v := cmd.Bool("preload")
		input.Preload = &v
	}

	arts, err := backend.ArticleList(ctx, &input)
	if err != nil {
		return err
	}

	PrintResult(cmd, arts,
		WithFields("id", "title", "author", "status", "language", "published_at", "created_at"),
	)

	return nil
}

func articleGet(ctx context.Context, cmd *cli.Command) error {
	if cmd.NArg() < 1 {
		return fmt.Errorf("article id is required")
	}

	id, err := atomic.ParseID(cmd.Args().First())
	if err != nil {
		return fmt.Errorf("failed to parse article id: %w", err)
	}

	input := &atomic.ArticleGetInput{
		InstanceID: inst.UUID,
		ArticleID:  id,
	}
	if cmd.IsSet("preload") {
		v := cmd.Bool("preload")
		input.Preload = &v
	}

	art, err := backend.ArticleGet(ctx, input)
	if err != nil {
		return err
	}

	PrintResult(cmd, []*atomic.Article{art},
		WithSingleValue(true),
		WithFields("id", "title", "author", "status", "language", "summary", "published_at", "created_at"),
	)

	return nil
}

func articleCreate(ctx context.Context, cmd *cli.Command) error {
	var input atomic.ArticleCreateInput

	if cmd.IsSet("file") {
		if err := readJSONFile(cmd.String("file"), &input); err != nil {
			return err
		}
	} else {
		if cmd.NArg() >= 1 {
			input.Title = cmd.Args().First()
		}
		if err := applyArticleCreateFlags(cmd, &input); err != nil {
			return err
		}
	}

	input.InstanceID = inst.UUID

	if input.Title == "" {
		return fmt.Errorf("title is required")
	}
	if input.Author == "" {
		return fmt.Errorf("--author is required")
	}
	if input.Body == "" {
		return fmt.Errorf("--body or --body-file is required")
	}

	art, err := backend.ArticleCreate(ctx, &input)
	if err != nil {
		return err
	}

	PrintResult(cmd, []*atomic.Article{art},
		WithSingleValue(true),
		WithFields("id", "title", "author", "status", "language", "published_at", "created_at"),
	)
	return nil
}

func articleUpdate(ctx context.Context, cmd *cli.Command) error {
	if cmd.NArg() < 1 {
		return fmt.Errorf("article id is required")
	}

	id, err := atomic.ParseID(cmd.Args().First())
	if err != nil {
		return fmt.Errorf("failed to parse article id: %w", err)
	}

	var input atomic.ArticleUpdateInput

	if cmd.IsSet("file") {
		if err := readJSONFile(cmd.String("file"), &input); err != nil {
			return err
		}
	} else {
		if err := applyArticleUpdateFlags(cmd, &input); err != nil {
			return err
		}
	}

	input.InstanceID = inst.UUID
	input.ArticleID = id

	art, err := backend.ArticleUpdate(ctx, &input)
	if err != nil {
		return err
	}

	PrintResult(cmd, []*atomic.Article{art},
		WithSingleValue(true),
		WithFields("id", "title", "author", "status", "language", "published_at", "updated_at"),
	)
	return nil
}

func articleDelete(ctx context.Context, cmd *cli.Command) error {
	if cmd.NArg() < 1 {
		return fmt.Errorf("article id is required")
	}

	id, err := atomic.ParseID(cmd.Args().First())
	if err != nil {
		return fmt.Errorf("failed to parse article id: %w", err)
	}

	if err := backend.ArticleDelete(ctx, &atomic.ArticleDeleteInput{
		InstanceID: inst.UUID,
		ArticleID:  id,
	}); err != nil {
		return err
	}

	fmt.Println("Article deleted")
	return nil
}

func applyArticleCreateFlags(cmd *cli.Command, input *atomic.ArticleCreateInput) error {
	if cmd.IsSet("author") {
		input.Author = cmd.String("author")
	}
	if cmd.IsSet("author_email") {
		input.AuthorEmail = ptr.String(cmd.String("author_email"))
	}
	if cmd.IsSet("title") {
		input.Title = cmd.String("title")
	}
	if cmd.IsSet("body") {
		input.Body = cmd.String("body")
	}
	if cmd.IsSet("body-file") {
		body, err := os.ReadFile(cmd.String("body-file"))
		if err != nil {
			return fmt.Errorf("failed to read body file: %w", err)
		}
		input.Body = string(body)
	}
	if cmd.IsSet("summary") {
		input.Summary = ptr.String(cmd.String("summary"))
	}
	if cmd.IsSet("language") {
		input.Language = ptr.String(cmd.String("language"))
	}
	if cmd.IsSet("status") {
		input.Status = ptr.String(cmd.String("status"))
	}
	if cmd.IsSet("public") {
		input.Public = cmd.Bool("public")
	}
	if cmd.IsSet("uri") {
		input.URI = ptr.String(cmd.String("uri"))
	}
	if cmd.IsSet("image_uri") {
		input.ImageURI = ptr.String(cmd.String("image_uri"))
	}
	if cmd.IsSet("published_at") {
		t, err := time.Parse(time.RFC3339, cmd.String("published_at"))
		if err != nil {
			return fmt.Errorf("failed to parse published_at: %w", err)
		}
		input.PublishedAt = &t
	}
	if cmd.IsSet("categories") {
		input.Categories = cmd.StringSlice("categories")
	}
	if cmd.IsSet("metadata") {
		md, err := readMetadataFile(cmd.String("metadata"))
		if err != nil {
			return err
		}
		input.Metadata = md
	}
	return nil
}

func applyArticleUpdateFlags(cmd *cli.Command, input *atomic.ArticleUpdateInput) error {
	if cmd.IsSet("author") {
		input.Author = ptr.String(cmd.String("author"))
	}
	if cmd.IsSet("author_email") {
		input.AuthorEmail = ptr.String(cmd.String("author_email"))
	}
	if cmd.IsSet("title") {
		input.Title = ptr.String(cmd.String("title"))
	}
	if cmd.IsSet("body") {
		input.Body = ptr.String(cmd.String("body"))
	}
	if cmd.IsSet("body-file") {
		body, err := os.ReadFile(cmd.String("body-file"))
		if err != nil {
			return fmt.Errorf("failed to read body file: %w", err)
		}
		input.Body = ptr.String(string(body))
	}
	if cmd.IsSet("summary") {
		input.Summary = ptr.String(cmd.String("summary"))
	}
	if cmd.IsSet("language") {
		input.Language = ptr.String(cmd.String("language"))
	}
	if cmd.IsSet("status") {
		input.Status = ptr.String(cmd.String("status"))
	}
	if cmd.IsSet("public") {
		v := cmd.Bool("public")
		input.Public = &v
	}
	if cmd.IsSet("uri") {
		input.URI = ptr.String(cmd.String("uri"))
	}
	if cmd.IsSet("image_uri") {
		input.ImageURI = ptr.String(cmd.String("image_uri"))
	}
	if cmd.IsSet("published_at") {
		t, err := time.Parse(time.RFC3339, cmd.String("published_at"))
		if err != nil {
			return fmt.Errorf("failed to parse published_at: %w", err)
		}
		input.PublishedAt = &t
	}
	if cmd.IsSet("categories") {
		input.Categories = cmd.StringSlice("categories")
	}
	if cmd.IsSet("metadata") {
		md, err := readMetadataFile(cmd.String("metadata"))
		if err != nil {
			return err
		}
		input.Metadata = md
	}
	return nil
}

func readJSONFile(path string, dst any) error {
	content, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}
	if err := json.Unmarshal(content, dst); err != nil {
		return fmt.Errorf("failed to parse JSON: %w", err)
	}
	return nil
}

func readMetadataFile(path string) (atomic.Metadata, error) {
	md := atomic.Metadata{}
	if err := readJSONFile(path, &md); err != nil {
		return nil, err
	}
	return md, nil
}

func readFileBytes(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}
	return b, nil
}
