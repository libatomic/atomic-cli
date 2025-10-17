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
	"github.com/libatomic/atomic/pkg/rss/spotify"
	"github.com/urfave/cli/v3"
)

var (
	distributionCmd = &cli.Command{
		Name:    "distribution",
		Aliases: []string{"dist"},
		Usage:   "manage content distribution to various platforms",
		Commands: []*cli.Command{
			spotifyCmd,
		},
	}

	spotifyCmd = &cli.Command{
		Name:    "spotify",
		Aliases: []string{"spot"},
		Usage:   "manage Spotify Distribution API integration",
		Commands: []*cli.Command{
			spotifyShowCmd,
			spotifyEpisodeCmd,
		},
	}

	spotifyShowCmd = &cli.Command{
		Name:    "show",
		Aliases: []string{"shows"},
		Usage:   "manage Spotify shows",
		Commands: []*cli.Command{
			{
				Name:      "create",
				Usage:     "create a new show on Spotify",
				ArgsUsage: "<show title>",
				Description: `Create a new show on Spotify via the Distribution API.

Examples:
  # Create from JSON file
  atomic-cli spotify show create --file show.json

  # Create with inline parameters
  atomic-cli spotify show create "My Podcast" \
    --summary "Description of my podcast" \
    --language en \
    --categories "Comedy" "Technology" \
    --owner-name "John Doe" \
    --owner-email "john@example.com" \
    --image-url "https://example.com/image.jpg" \
    --show-type episodic \
    --explicit no`,
				Flags: []cli.Flag{
					&cli.BoolFlag{
						Name:  "file",
						Usage: "read show data from JSON file (first arg is file path)",
					},
					&cli.StringFlag{
						Name:  "summary",
						Usage: "show summary/description",
					},
					&cli.StringFlag{
						Name:  "language",
						Usage: "two-character ISO 639-1 language code (e.g. 'en')",
						Value: "en",
					},
					&cli.StringSliceFlag{
						Name:  "categories",
						Usage: "iTunes categories (can specify multiple)",
					},
					&cli.StringFlag{
						Name:  "owner-name",
						Usage: "owner's full name",
					},
					&cli.StringFlag{
						Name:  "owner-email",
						Usage: "owner's email address",
					},
					&cli.StringFlag{
						Name:  "image-url",
						Usage: "URL to show artwork (recommended: 3000x3000px JPEG/PNG)",
					},
					&cli.StringFlag{
						Name:  "link",
						Usage: "website or landing page URL",
					},
					&cli.StringFlag{
						Name:  "show-type",
						Usage: "show type: 'serial' or 'episodic'",
						Value: "episodic",
					},
					&cli.StringFlag{
						Name:  "explicit",
						Usage: "explicit content: 'yes', 'no', 'clean'",
						Value: "no",
					},
					&cli.StringFlag{
						Name:  "soa-partner-id",
						Usage: "Spotify Open Access Partner ID",
					},
					&cli.BoolFlag{
						Name:  "sandbox",
						Usage: "create as sandbox show",
					},
				},
				Action: spotifyShowCreate,
			},
			{
				Name:      "get",
				Usage:     "get a Spotify show",
				ArgsUsage: "<show id or uri>",
				Action:    spotifyShowGet,
			},
			{
				Name:  "list",
				Usage: "list all Spotify shows",
				Flags: []cli.Flag{
					&cli.IntFlag{
						Name:  "page",
						Usage: "page number",
						Value: 1,
					},
					&cli.IntFlag{
						Name:  "per-page",
						Usage: "items per page (max 500)",
						Value: 50,
					},
					&cli.StringFlag{
						Name:  "updated-since",
						Usage: "filter shows updated since ISO8601 timestamp",
					},
				},
				Action: spotifyShowList,
			},
			{
				Name:      "update",
				Usage:     "update a Spotify show",
				ArgsUsage: "<show id or uri>",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:  "title",
						Usage: "update show title",
					},
					&cli.StringFlag{
						Name:  "summary",
						Usage: "update show summary",
					},
					&cli.StringSliceFlag{
						Name:  "categories",
						Usage: "update iTunes categories",
					},
					&cli.StringFlag{
						Name:  "image-url",
						Usage: "update show artwork URL",
					},
					&cli.StringFlag{
						Name:  "link",
						Usage: "update website URL",
					},
					&cli.StringFlag{
						Name:  "explicit",
						Usage: "update explicit content flag",
					},
				},
				Action: spotifyShowUpdate,
			},
			{
				Name:      "delete",
				Usage:     "delete a Spotify show",
				ArgsUsage: "<show id or uri>",
				Action:    spotifyShowDelete,
			},
		},
	}

	spotifyEpisodeCmd = &cli.Command{
		Name:    "episode",
		Aliases: []string{"episodes", "ep"},
		Usage:   "manage Spotify episodes",
		Commands: []*cli.Command{
			{
				Name:      "create",
				Usage:     "create a new episode on Spotify",
				ArgsUsage: "<show id> <episode title>",
				Description: `Create a new episode for a show on Spotify.

Examples:
  # Create from JSON file
  atomic-cli spotify episode create <show-id> --file episode.json

  # Create video episode with inline parameters
  atomic-cli spotify episode create <show-id> "Episode 1" \
    --pubdate "2024-01-15T12:00:00Z" \
    --media-url "https://example.com/episode1.mp4" \
    --image-url "https://example.com/episode1.jpg" \
    --guid "ep001" \
    --summary "First episode description" \
    --content-rating eighteen_plus \
    --explicit no`,
				Flags: []cli.Flag{
					&cli.BoolFlag{
						Name:  "file",
						Usage: "read episode data from JSON file (second arg is file path)",
					},
					&cli.StringFlag{
						Name:     "pubdate",
						Usage:    "publication date in ISO8601 format",
						Required: true,
					},
					&cli.StringFlag{
						Name:     "media-url",
						Usage:    "URL to media file (MP3/M4A/MP4/MOV - MP4/MOV for video)",
						Required: true,
					},
					&cli.StringFlag{
						Name:  "image-url",
						Usage: "URL to episode artwork (3000x3000px)",
					},
					&cli.StringFlag{
						Name:  "thumbnail-url",
						Usage: "URL to video thumbnail (16:9, 1920x1080 recommended)",
					},
					&cli.StringFlag{
						Name:     "guid",
						Usage:    "unique identifier for the episode",
						Required: true,
					},
					&cli.StringFlag{
						Name:  "summary",
						Usage: "episode summary (plain text or HTML)",
					},
					&cli.StringFlag{
						Name:  "link",
						Usage: "link to episode webpage",
					},
					&cli.IntFlag{
						Name:  "episode-number",
						Usage: "episode number",
					},
					&cli.IntFlag{
						Name:  "season-number",
						Usage: "season number",
					},
					&cli.StringFlag{
						Name:  "episode-type",
						Usage: "episode type: 'bonus', 'full', 'trailer'",
						Value: "full",
					},
					&cli.StringFlag{
						Name:  "content-rating",
						Usage: "content rating: 'eighteen_plus' or 'unspecified'",
						Value: "unspecified",
					},
					&cli.StringFlag{
						Name:  "explicit",
						Usage: "explicit content: 'yes', 'no', 'clean'",
						Value: "no",
					},
					&cli.StringSliceFlag{
						Name:  "entitlements",
						Usage: "entitlements for gating (can specify multiple)",
					},
				},
				Action: spotifyEpisodeCreate,
			},
			{
				Name:      "get",
				Usage:     "get a Spotify episode",
				ArgsUsage: "<episode id or uri>",
				Action:    spotifyEpisodeGet,
			},
			{
				Name:      "list",
				Usage:     "list episodes for a show",
				ArgsUsage: "<show id or uri>",
				Flags: []cli.Flag{
					&cli.IntFlag{
						Name:  "page",
						Usage: "page number",
						Value: 1,
					},
					&cli.IntFlag{
						Name:  "per-page",
						Usage: "items per page (max 500)",
						Value: 50,
					},
					&cli.StringFlag{
						Name:  "updated-since",
						Usage: "filter episodes updated since ISO8601 timestamp",
					},
				},
				Action: spotifyEpisodeList,
			},
			{
				Name:      "update",
				Usage:     "update a Spotify episode",
				ArgsUsage: "<episode id or uri>",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:  "title",
						Usage: "update episode title",
					},
					&cli.StringFlag{
						Name:  "media-url",
						Usage: "update media file URL",
					},
					&cli.StringFlag{
						Name:  "summary",
						Usage: "update episode summary",
					},
					&cli.StringFlag{
						Name:  "image-url",
						Usage: "update episode artwork URL",
					},
					&cli.StringFlag{
						Name:  "thumbnail-url",
						Usage: "update video thumbnail URL",
					},
				},
				Action: spotifyEpisodeUpdate,
			},
			{
				Name:      "delete",
				Usage:     "delete a Spotify episode",
				ArgsUsage: "<episode id or uri>",
				Action:    spotifyEpisodeDelete,
			},
			{
				Name:      "backfill",
				Usage:     "backfill audio episode to video",
				ArgsUsage: "<episode id or uri> <video url>",
				Description: `Update an existing audio episode to video by replacing the media file URL.

Example:
  atomic-cli spotify episode backfill spotify:episode:abc123 https://cdn.example.com/video.mp4`,
				Action: spotifyEpisodeBackfill,
			},
		},
	}
)

func getSpotifyIntegration(ctx context.Context, cmd *cli.Command) (*atomic.SpotifyIntegration, error) {
	if inst == nil {
		return nil, fmt.Errorf("no instance selected, use --instance_id flag")
	}

	// Check if backend supports integration methods
	integrationBackend, ok := backend.(atomic.IntegrationBackend)
	if !ok {
		return nil, fmt.Errorf("integration methods not supported by this backend (use local atomic backend)")
	}

	// Check if we have Spotify credentials from CLI flags or configuration sources
	clientID := cmd.String("spotify_client_id")
	clientSecret := cmd.String("spotify_client_secret")
	partnerName := cmd.String("spotify_partner_name")
	partnerID := cmd.String("spotify_partner_id")

	if clientID == "" || clientSecret == "" {
		return nil, fmt.Errorf("spotify credentials required: set spotify_client_id and spotify_client_secret in credentials file or as flags")
	}

	// Try to get existing integration first
	intr, err := integrationBackend.IntegrationGet(ctx, &atomic.IntegrationGetInput{
		InstanceID: inst.UUID,
		Provider:   "spotify",
	})
	if err != nil {
		// If no existing integration, create a temporary one with CLI credentials
		// Create metadata from CLI flags
		metadata := atomic.Metadata{
			"spotify": map[string]interface{}{
				"client_id":     clientID,
				"client_secret": clientSecret,
			},
		}

		if partnerName != "" {
			metadata["spotify"].(map[string]any)["partner_name"] = partnerName
		}
		if partnerID != "" {
			metadata["spotify"].(map[string]any)["partner_id"] = partnerID
		}

		// Create a temporary application for the integration
		appBackend, ok := backend.(atomic.ApplicationBackend)
		if !ok {
			return nil, fmt.Errorf("application backend not supported")
		}

		app, err := appBackend.ApplicationCreate(ctx, &atomic.ApplicationCreateInput{
			InstanceID: inst.UUID,
			Name:       "Spotify CLI Integration",
			Type:       "internal",
			Metadata:   metadata,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to create spotify integration application: %w", err)
		}

		// Parse the config from the metadata
		config, err := atomic.SpotifyConfigParse(app.Metadata)
		if err != nil {
			return nil, fmt.Errorf("failed to parse spotify config: %w", err)
		}

		config.ApplicationID = app.UUID.String()

		// Debug output removed

		// Create a temporary integration using the SpotifyProvider directly
		provider := &atomic.SpotifyProvider{}

		// Create a temporary integration
		integration, err := provider.Connect(ctx, app)
		if err != nil {
			return nil, fmt.Errorf("failed to connect spotify integration: %w", err)
		}

		spotifyIntegration, ok := integration.(*atomic.SpotifyIntegration)
		if !ok {
			return nil, fmt.Errorf("invalid spotify integration type")
		}

		return spotifyIntegration, nil
	}

	spotifyIntegration, ok := intr.(*atomic.SpotifyIntegration)
	if !ok {
		return nil, fmt.Errorf("invalid spotify integration type")
	}

	return spotifyIntegration, nil
}

func spotifyShowCreate(ctx context.Context, cmd *cli.Command) error {
	integration, err := getSpotifyIntegration(ctx, cmd)
	if err != nil {
		return err
	}

	client, err := integration.DistributionClient(ctx)
	if err != nil {
		return err
	}

	var input spotify.CreateShowInput

	if cmd.Bool("file") {
		filePath := cmd.Args().Get(0)
		if filePath == "" {
			return fmt.Errorf("file path required when --file flag is set")
		}

		data, err := os.ReadFile(filePath)
		if err != nil {
			return fmt.Errorf("failed to read file: %w", err)
		}

		if err := json.Unmarshal(data, &input); err != nil {
			return fmt.Errorf("failed to parse JSON: %w", err)
		}
	} else {
		title := cmd.Args().Get(0)
		if title == "" {
			return fmt.Errorf("show title required")
		}

		input = spotify.CreateShowInput{
			Title:            title,
			Summary:          cmd.String("summary"),
			Language:         cmd.String("language"),
			ItunesCategories: cmd.StringSlice("categories"),
			OwnerName:        cmd.String("owner-name"),
			OwnerEmail:       cmd.String("owner-email"),
			ImageFileURL:     cmd.String("image-url"),
			Link:             cmd.String("link"),
			ShowType:         cmd.String("show-type"),
			Explicit:         cmd.String("explicit"),
			SOAPartnerID:     cmd.String("soa-partner-id"),
			IsSandbox:        cmd.Bool("sandbox"),
		}
	}

	show, err := client.CreateShow(ctx, input)
	if err != nil {
		return fmt.Errorf("failed to create show: %w", err)
	}

	PrintResult(cmd, []*spotify.Show{show})
	return nil
}

func spotifyShowGet(ctx context.Context, cmd *cli.Command) error {
	integration, err := getSpotifyIntegration(ctx, cmd)
	if err != nil {
		return err
	}

	client, err := integration.DistributionClient(ctx)
	if err != nil {
		return err
	}

	showIDOrURI := cmd.Args().Get(0)
	if showIDOrURI == "" {
		return fmt.Errorf("show id or uri required")
	}

	showID := spotify.ExtractShowIDFromURI(showIDOrURI)

	show, err := client.GetShow(ctx, showID)
	if err != nil {
		return fmt.Errorf("failed to get show: %w", err)
	}

	PrintResult(cmd, []*spotify.Show{show})
	return nil
}

func spotifyShowList(ctx context.Context, cmd *cli.Command) error {
	integration, err := getSpotifyIntegration(ctx, cmd)
	if err != nil {
		return err
	}

	client, err := integration.DistributionClient(ctx)
	if err != nil {
		return err
	}

	params := &spotify.PaginationParams{
		Page:         cmd.Int("page"),
		PerPage:      cmd.Int("per-page"),
		UpdatedSince: cmd.String("updated-since"),
	}

	shows, _, err := client.ListShows(ctx, params)
	if err != nil {
		return fmt.Errorf("failed to list shows: %w", err)
	}

	PrintResult(cmd, shows)
	return nil
}

func spotifyShowUpdate(ctx context.Context, cmd *cli.Command) error {
	integration, err := getSpotifyIntegration(ctx, cmd)
	if err != nil {
		return err
	}

	client, err := integration.DistributionClient(ctx)
	if err != nil {
		return err
	}

	showIDOrURI := cmd.Args().Get(0)
	if showIDOrURI == "" {
		return fmt.Errorf("show id or uri required")
	}

	showID := spotify.ExtractShowIDFromURI(showIDOrURI)

	input := spotify.UpdateShowInput{
		Title:            cmd.String("title"),
		Summary:          cmd.String("summary"),
		ItunesCategories: cmd.StringSlice("categories"),
		ImageFileURL:     cmd.String("image-url"),
		Link:             cmd.String("link"),
		Explicit:         cmd.String("explicit"),
	}

	show, err := client.UpdateShow(ctx, showID, input)
	if err != nil {
		return fmt.Errorf("failed to update show: %w", err)
	}

	PrintResult(cmd, []*spotify.Show{show})
	return nil
}

func spotifyShowDelete(ctx context.Context, cmd *cli.Command) error {
	integration, err := getSpotifyIntegration(ctx, cmd)
	if err != nil {
		return err
	}

	client, err := integration.DistributionClient(ctx)
	if err != nil {
		return err
	}

	showIDOrURI := cmd.Args().Get(0)
	if showIDOrURI == "" {
		return fmt.Errorf("show id or uri required")
	}

	showID := spotify.ExtractShowIDFromURI(showIDOrURI)

	if err := client.DeleteShow(ctx, showID); err != nil {
		return fmt.Errorf("failed to delete show: %w", err)
	}

	fmt.Println("Show deleted successfully")
	return nil
}

func spotifyEpisodeCreate(ctx context.Context, cmd *cli.Command) error {
	integration, err := getSpotifyIntegration(ctx, cmd)
	if err != nil {
		return err
	}

	client, err := integration.DistributionClient(ctx)
	if err != nil {
		return err
	}

	showIDOrURI := cmd.Args().Get(0)
	if showIDOrURI == "" {
		return fmt.Errorf("show id or uri required")
	}

	showID := spotify.ExtractShowIDFromURI(showIDOrURI)

	var input spotify.CreateEpisodeInput

	if cmd.Bool("file") {
		filePath := cmd.Args().Get(1)
		if filePath == "" {
			return fmt.Errorf("file path required when --file flag is set")
		}

		data, err := os.ReadFile(filePath)
		if err != nil {
			return fmt.Errorf("failed to read file: %w", err)
		}

		if err := json.Unmarshal(data, &input); err != nil {
			return fmt.Errorf("failed to parse JSON: %w", err)
		}
	} else {
		title := cmd.Args().Get(1)
		if title == "" {
			return fmt.Errorf("episode title required")
		}

		input = spotify.CreateEpisodeInput{
			Title:            title,
			Pubdate:          cmd.String("pubdate"),
			MediaFileURL:     cmd.String("media-url"),
			ImageFileURL:     cmd.String("image-url"),
			ThumbnailFileURL: cmd.String("thumbnail-url"),
			GUID:             cmd.String("guid"),
			Summary:          cmd.String("summary"),
			Link:             cmd.String("link"),
			EpisodeType:      cmd.String("episode-type"),
			ContentRating:    cmd.String("content-rating"),
			Explicit:         cmd.String("explicit"),
			Entitlements:     cmd.StringSlice("entitlements"),
		}

		if cmd.IsSet("episode-number") {
			num := cmd.Int("episode-number")
			input.EpisodeNumber = &num
		}
		if cmd.IsSet("season-number") {
			num := cmd.Int("season-number")
			input.SeasonNumber = &num
		}
	}

	episode, err := client.CreateEpisode(ctx, showID, input)
	if err != nil {
		return fmt.Errorf("failed to create episode: %w", err)
	}

	PrintResult(cmd, []*spotify.Episode{episode})
	return nil
}

func spotifyEpisodeGet(ctx context.Context, cmd *cli.Command) error {
	integration, err := getSpotifyIntegration(ctx, cmd)
	if err != nil {
		return err
	}

	client, err := integration.DistributionClient(ctx)
	if err != nil {
		return err
	}

	episodeIDOrURI := cmd.Args().Get(0)
	if episodeIDOrURI == "" {
		return fmt.Errorf("episode id or uri required")
	}

	episodeID := spotify.ExtractEpisodeIDFromURI(episodeIDOrURI)

	episode, err := client.GetEpisode(ctx, episodeID)
	if err != nil {
		return fmt.Errorf("failed to get episode: %w", err)
	}

	PrintResult(cmd, []*spotify.Episode{episode})
	return nil
}

func spotifyEpisodeList(ctx context.Context, cmd *cli.Command) error {
	integration, err := getSpotifyIntegration(ctx, cmd)
	if err != nil {
		return err
	}

	client, err := integration.DistributionClient(ctx)
	if err != nil {
		return err
	}

	showIDOrURI := cmd.Args().Get(0)
	if showIDOrURI == "" {
		return fmt.Errorf("show id or uri required")
	}

	showID := spotify.ExtractShowIDFromURI(showIDOrURI)

	params := &spotify.PaginationParams{
		Page:         cmd.Int("page"),
		PerPage:      cmd.Int("per-page"),
		UpdatedSince: cmd.String("updated-since"),
	}

	episodes, _, err := client.ListEpisodes(ctx, showID, params)
	if err != nil {
		return fmt.Errorf("failed to list episodes: %w", err)
	}

	PrintResult(cmd, episodes)
	return nil
}

func spotifyEpisodeUpdate(ctx context.Context, cmd *cli.Command) error {
	integration, err := getSpotifyIntegration(ctx, cmd)
	if err != nil {
		return err
	}

	client, err := integration.DistributionClient(ctx)
	if err != nil {
		return err
	}

	episodeIDOrURI := cmd.Args().Get(0)
	if episodeIDOrURI == "" {
		return fmt.Errorf("episode id or uri required")
	}

	episodeID := spotify.ExtractEpisodeIDFromURI(episodeIDOrURI)

	input := spotify.UpdateEpisodeInput{
		Title:            cmd.String("title"),
		MediaFileURL:     cmd.String("media-url"),
		Summary:          cmd.String("summary"),
		ImageFileURL:     cmd.String("image-url"),
		ThumbnailFileURL: cmd.String("thumbnail-url"),
	}

	episode, err := client.UpdateEpisode(ctx, episodeID, input)
	if err != nil {
		return fmt.Errorf("failed to update episode: %w", err)
	}

	PrintResult(cmd, []*spotify.Episode{episode})
	return nil
}

func spotifyEpisodeDelete(ctx context.Context, cmd *cli.Command) error {
	integration, err := getSpotifyIntegration(ctx, cmd)
	if err != nil {
		return err
	}

	client, err := integration.DistributionClient(ctx)
	if err != nil {
		return err
	}

	episodeIDOrURI := cmd.Args().Get(0)
	if episodeIDOrURI == "" {
		return fmt.Errorf("episode id or uri required")
	}

	episodeID := spotify.ExtractEpisodeIDFromURI(episodeIDOrURI)

	if err := client.DeleteEpisode(ctx, episodeID); err != nil {
		return fmt.Errorf("failed to delete episode: %w", err)
	}

	fmt.Println("Episode deleted successfully")
	return nil
}

func spotifyEpisodeBackfill(ctx context.Context, cmd *cli.Command) error {
	integration, err := getSpotifyIntegration(ctx, cmd)
	if err != nil {
		return err
	}

	client, err := integration.DistributionClient(ctx)
	if err != nil {
		return err
	}

	episodeIDOrURI := cmd.Args().Get(0)
	videoURL := cmd.Args().Get(1)

	if episodeIDOrURI == "" || videoURL == "" {
		return fmt.Errorf("episode id/uri and video url required")
	}

	episodeID := spotify.ExtractEpisodeIDFromURI(episodeIDOrURI)

	episode, err := client.BackfillEpisodeToVideo(ctx, episodeID, videoURL)
	if err != nil {
		return fmt.Errorf("failed to backfill episode: %w", err)
	}

	fmt.Printf("Successfully backfilled episode to video: %s\n", episode.EpisodeURI)
	PrintResult(cmd, []*spotify.Episode{episode})
	return nil
}

func init() {
	// mainCmd will be initialized in main() function
	// We'll register the command there instead of in init()
}
