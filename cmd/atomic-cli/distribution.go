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
	distributionListFlags = []cli.Flag{
		&cli.StringFlag{
			Name:  "article_id",
			Usage: "filter by article id",
		},
		&cli.StringSliceFlag{
			Name:  "audience_id",
			Usage: "filter by audience id (repeatable)",
		},
		&cli.StringSliceFlag{
			Name:  "channel",
			Usage: "filter by channel (web, email, rss, podcast, sms)",
		},
		&cli.StringSliceFlag{
			Name:  "categories",
			Usage: "filter by category ids",
		},
		&cli.BoolFlag{
			Name:  "active",
			Usage: "filter by active distributions",
		},
		&cli.StringFlag{
			Name:  "scheduled_before",
			Usage: "filter to distributions scheduled before this RFC3339 timestamp",
		},
		&cli.IntFlag{
			Name:  "limit",
			Usage: "limit the number of distributions",
		},
		&cli.IntFlag{
			Name:  "offset",
			Usage: "offset the number of distributions",
		},
		&cli.BoolFlag{
			Name:  "with_audience",
			Usage: "include the audience in the response",
		},
	}

	distributionUpdateFlags = []cli.Flag{
		&cli.StringFlag{
			Name:  "article_id",
			Usage: "set the article id",
		},
		&cli.StringFlag{
			Name:  "template_id",
			Usage: "set the template id",
		},
		&cli.StringFlag{
			Name:  "asset_id",
			Usage: "set the asset id",
		},
		&cli.StringFlag{
			Name:  "audience_id",
			Usage: "set the audience id",
		},
		&cli.StringFlag{
			Name:  "title",
			Usage: "set the title",
		},
		&cli.StringFlag{
			Name:  "description",
			Usage: "set the description",
		},
		&cli.StringFlag{
			Name:  "summary",
			Usage: "set the summary",
		},
		&cli.StringFlag{
			Name:  "language",
			Usage: "set the language",
		},
		&cli.StringFlag{
			Name:  "body",
			Usage: "set the body (overrides article body)",
		},
		&cli.StringFlag{
			Name:  "scheduled_at",
			Usage: "set the scheduled time as an RFC3339 timestamp",
		},
		&cli.StringFlag{
			Name:  "status",
			Usage: "set the queue status",
		},
		&cli.StringSliceFlag{
			Name:  "categories",
			Usage: "set the category ids (replaces existing)",
		},
		&cli.StringFlag{
			Name:  "file",
			Usage: "read the full DistributionUpdateInput from a JSON `FILE` (other flags are ignored)",
		},
	}

	distributionCreateFlags = append([]cli.Flag{
		&cli.StringFlag{
			Name:  "channel",
			Usage: "channel: web, email, rss, podcast, sms",
		},
	}, distributionUpdateFlags...)

	distributionCmd = &cli.Command{
		Name:    "distribution",
		Aliases: []string{"distributions", "distro", "distros"},
		Usage:   "manage distributions",
		Commands: []*cli.Command{
			{
				Name:   "list",
				Usage:  "list distributions",
				Action: distributionList,
				Flags:  distributionListFlags,
			},
			{
				Name:      "get",
				Usage:     "get a distribution",
				ArgsUsage: "<distribution_id>",
				Action:    distributionGet,
				Flags: []cli.Flag{
					&cli.BoolFlag{
						Name:  "preload",
						Usage: "preload related entities",
					},
				},
			},
			{
				Name:      "create",
				Usage:     "create a distribution (use --file for full settings/context payloads)",
				ArgsUsage: "[audience_id]",
				Action:    distributionCreate,
				Flags:     distributionCreateFlags,
			},
			{
				Name:      "update",
				Usage:     "update a distribution",
				ArgsUsage: "<distribution_id>",
				Action:    distributionUpdate,
				Flags:     distributionUpdateFlags,
			},
			{
				Name:      "delete",
				Usage:     "delete a distribution",
				ArgsUsage: "<distribution_id>",
				Action:    distributionDelete,
			},
		},
	}
)

func distributionList(ctx context.Context, cmd *cli.Command) error {
	var input atomic.DistributionListInput

	if err := BindFlagsFromContext(cmd, &input, "article_id", "audience_id", "channel", "categories", "active", "scheduled_before"); err != nil {
		return err
	}

	input.InstanceID = inst.UUID

	if cmd.IsSet("article_id") {
		id, err := atomic.ParseID(cmd.String("article_id"))
		if err != nil {
			return fmt.Errorf("failed to parse article_id: %w", err)
		}
		input.ArticleID = &id
	}

	for _, raw := range cmd.StringSlice("audience_id") {
		id, err := atomic.ParseID(raw)
		if err != nil {
			return fmt.Errorf("failed to parse audience_id %q: %w", raw, err)
		}
		input.AudienceID = append(input.AudienceID, id)
	}

	for _, raw := range cmd.StringSlice("categories") {
		id, err := atomic.ParseID(raw)
		if err != nil {
			return fmt.Errorf("failed to parse category id %q: %w", raw, err)
		}
		input.Categories = append(input.Categories, id)
	}

	for _, raw := range cmd.StringSlice("channel") {
		ch := atomic.Channel(raw)
		if err := ch.Validate(); err != nil {
			return fmt.Errorf("invalid channel %q: %w", raw, err)
		}
		input.Channel = append(input.Channel, ch)
	}

	if cmd.IsSet("active") {
		v := cmd.Bool("active")
		input.Active = &v
	}

	if cmd.IsSet("scheduled_before") {
		t, err := time.Parse(time.RFC3339, cmd.String("scheduled_before"))
		if err != nil {
			return fmt.Errorf("failed to parse scheduled_before: %w", err)
		}
		input.ScheduledBefore = &t
	}

	distros, err := backend.DistributionList(ctx, &input)
	if err != nil {
		return err
	}

	PrintResult(cmd, distros,
		WithFields("id", "title", "channel", "audience_id", "scheduled_at", "published_at", "created_at"),
	)

	return nil
}

func distributionGet(ctx context.Context, cmd *cli.Command) error {
	if cmd.NArg() < 1 {
		return fmt.Errorf("distribution id is required")
	}

	distroID, err := atomic.ParseID(cmd.Args().First())
	if err != nil {
		return fmt.Errorf("failed to parse distribution id: %w", err)
	}

	distro, err := backend.DistributionGet(ctx, &atomic.DistributionGetInput{
		InstanceID:     inst.UUID,
		DistributionID: distroID,
		Preload:        cmd.Bool("preload"),
	})
	if err != nil {
		return err
	}

	PrintResult(cmd, []*atomic.Distribution{distro},
		WithSingleValue(true),
		WithFields("id", "title", "channel", "audience_id", "article_id", "template_id", "asset_id", "scheduled_at", "published_at", "created_at"),
	)

	return nil
}

func distributionCreate(ctx context.Context, cmd *cli.Command) error {
	var input atomic.DistributionCreateInput

	if cmd.IsSet("file") {
		content, err := os.ReadFile(cmd.String("file"))
		if err != nil {
			return fmt.Errorf("failed to read distribution file: %w", err)
		}
		if err := json.Unmarshal(content, &input); err != nil {
			return fmt.Errorf("failed to parse distribution file: %w", err)
		}
	} else {
		if cmd.NArg() >= 1 {
			id, err := atomic.ParseID(cmd.Args().First())
			if err != nil {
				return fmt.Errorf("failed to parse audience_id: %w", err)
			}
			input.AudienceID = id
		}

		if cmd.IsSet("audience_id") {
			id, err := atomic.ParseID(cmd.String("audience_id"))
			if err != nil {
				return fmt.Errorf("failed to parse audience_id: %w", err)
			}
			input.AudienceID = id
		}

		if cmd.IsSet("article_id") {
			id, err := atomic.ParseID(cmd.String("article_id"))
			if err != nil {
				return fmt.Errorf("failed to parse article_id: %w", err)
			}
			input.ArticleID = &id
		}

		if cmd.IsSet("template_id") {
			id, err := atomic.ParseID(cmd.String("template_id"))
			if err != nil {
				return fmt.Errorf("failed to parse template_id: %w", err)
			}
			input.TemplateID = &id
		}

		if cmd.IsSet("asset_id") {
			id, err := atomic.ParseID(cmd.String("asset_id"))
			if err != nil {
				return fmt.Errorf("failed to parse asset_id: %w", err)
			}
			input.AssetID = &id
		}

		if cmd.IsSet("channel") {
			input.Channel = atomic.Channel(cmd.String("channel"))
		}

		if cmd.IsSet("title") {
			input.Title = ptr.String(cmd.String("title"))
		}

		if cmd.IsSet("description") {
			input.Description = ptr.String(cmd.String("description"))
		}

		if cmd.IsSet("summary") {
			input.Summary = ptr.String(cmd.String("summary"))
		}

		if cmd.IsSet("language") {
			input.Language = ptr.String(cmd.String("language"))
		}

		if cmd.IsSet("body") {
			input.Body = ptr.String(cmd.String("body"))
		}

		if cmd.IsSet("scheduled_at") {
			t, err := time.Parse(time.RFC3339, cmd.String("scheduled_at"))
			if err != nil {
				return fmt.Errorf("failed to parse scheduled_at: %w", err)
			}
			input.ScheduledAt = &t
		}
	}

	input.InstanceID = inst.UUID

	distro, err := backend.DistributionCreate(ctx, &input)
	if err != nil {
		return err
	}

	PrintResult(cmd, []*atomic.Distribution{distro},
		WithSingleValue(true),
		WithFields("id", "title", "channel", "audience_id", "article_id", "scheduled_at", "created_at"),
	)

	return nil
}

func distributionUpdate(ctx context.Context, cmd *cli.Command) error {
	if cmd.NArg() < 1 {
		return fmt.Errorf("distribution id is required")
	}

	distroID, err := atomic.ParseID(cmd.Args().First())
	if err != nil {
		return fmt.Errorf("failed to parse distribution id: %w", err)
	}

	var input atomic.DistributionUpdateInput

	if cmd.IsSet("file") {
		content, err := os.ReadFile(cmd.String("file"))
		if err != nil {
			return fmt.Errorf("failed to read distribution file: %w", err)
		}
		if err := json.Unmarshal(content, &input); err != nil {
			return fmt.Errorf("failed to parse distribution file: %w", err)
		}
	} else {
		if cmd.IsSet("article_id") {
			id, err := atomic.ParseID(cmd.String("article_id"))
			if err != nil {
				return fmt.Errorf("failed to parse article_id: %w", err)
			}
			input.ArticleID = &id
		}

		if cmd.IsSet("template_id") {
			id, err := atomic.ParseID(cmd.String("template_id"))
			if err != nil {
				return fmt.Errorf("failed to parse template_id: %w", err)
			}
			input.TemplateID = &id
		}

		if cmd.IsSet("asset_id") {
			id, err := atomic.ParseID(cmd.String("asset_id"))
			if err != nil {
				return fmt.Errorf("failed to parse asset_id: %w", err)
			}
			input.AssetID = &id
		}

		if cmd.IsSet("audience_id") {
			id, err := atomic.ParseID(cmd.String("audience_id"))
			if err != nil {
				return fmt.Errorf("failed to parse audience_id: %w", err)
			}
			input.AudienceID = &id
		}

		if cmd.IsSet("title") {
			input.Title = ptr.String(cmd.String("title"))
		}

		if cmd.IsSet("description") {
			input.Description = ptr.String(cmd.String("description"))
		}

		if cmd.IsSet("summary") {
			input.Summary = ptr.String(cmd.String("summary"))
		}

		if cmd.IsSet("language") {
			input.Language = ptr.String(cmd.String("language"))
		}

		if cmd.IsSet("body") {
			input.Body = ptr.String(cmd.String("body"))
		}

		if cmd.IsSet("scheduled_at") {
			t, err := time.Parse(time.RFC3339, cmd.String("scheduled_at"))
			if err != nil {
				return fmt.Errorf("failed to parse scheduled_at: %w", err)
			}
			input.ScheduledAt = &t
		}

		if cmd.IsSet("categories") {
			input.Categories = cmd.StringSlice("categories")
		}
	}

	input.InstanceID = inst.UUID
	input.DistributionID = distroID

	distro, err := backend.DistributionUpdate(ctx, &input)
	if err != nil {
		return err
	}

	PrintResult(cmd, []*atomic.Distribution{distro},
		WithSingleValue(true),
		WithFields("id", "title", "channel", "audience_id", "article_id", "scheduled_at", "updated_at"),
	)

	return nil
}

func distributionDelete(ctx context.Context, cmd *cli.Command) error {
	if cmd.NArg() < 1 {
		return fmt.Errorf("distribution id is required")
	}

	distroID, err := atomic.ParseID(cmd.Args().First())
	if err != nil {
		return fmt.Errorf("failed to parse distribution id: %w", err)
	}

	if err := backend.DistributionDelete(ctx, &atomic.DistributionDeleteInput{
		InstanceID:     inst.UUID,
		DistributionID: distroID,
	}); err != nil {
		return err
	}

	fmt.Println("Distribution deleted")

	return nil
}
