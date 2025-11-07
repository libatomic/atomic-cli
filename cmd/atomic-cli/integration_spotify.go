package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/libatomic/atomic/pkg/atomic"
	"github.com/urfave/cli/v3"
)

var (
	spotifyCmd = &cli.Command{
		Name:    "spotify",
		Aliases: []string{"sp"},
		Usage:   "manage Spotify integration",
		Commands: []*cli.Command{
			spotifyVideoCmd,
		},
	}

	spotifyVideoCmd = &cli.Command{
		Name:    "video",
		Aliases: []string{"v"},
		Usage:   "manage Spotify video distribution",
		Commands: []*cli.Command{
			spotifyVideoShowsCmd,
			spotifyVideoEpisodesCmd,
		},
	}

	spotifyVideoShowsCmd = &cli.Command{
		Name:    "shows",
		Aliases: []string{"show"},
		Usage:   "manage Spotify video shows",
		Commands: []*cli.Command{
			spotifyVideoShowCreateCmd,
			spotifyVideoShowGetCmd,
			spotifyVideoShowListCmd,
			spotifyVideoShowUpdateCmd,
			spotifyVideoShowDeleteCmd,
		},
	}

	spotifyVideoShowCreateCmd = &cli.Command{
		Name:      "create",
		Usage:     "create a Spotify video show",
		ArgsUsage: "[input.json]",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  "input",
				Usage: "read input from JSON file (or pass JSON via stdin)",
			},
		},
		Action: spotifyVideoShowCreate,
	}

	spotifyVideoShowGetCmd = &cli.Command{
		Name:      "get",
		Usage:     "get a Spotify video show",
		ArgsUsage: "<show_id>",
		Action:    spotifyVideoShowGet,
	}

	spotifyVideoShowListCmd = &cli.Command{
		Name:   "list",
		Usage:  "list Spotify video shows",
		Action: spotifyVideoShowList,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  "updated_since",
				Usage: "only shows updated since this date (ISO8601 format)",
			},
		},
	}

	spotifyVideoShowUpdateCmd = &cli.Command{
		Name:      "update",
		Usage:     "update a Spotify video show",
		ArgsUsage: "<show_id> [input.json]",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  "input",
				Usage: "read input from JSON file (or pass JSON via stdin)",
			},
		},
		Action: spotifyVideoShowUpdate,
	}

	spotifyVideoShowDeleteCmd = &cli.Command{
		Name:      "delete",
		Usage:     "delete a Spotify video show",
		ArgsUsage: "<show_id>",
		Action:    spotifyVideoShowDelete,
	}

	spotifyVideoEpisodesCmd = &cli.Command{
		Name:    "episodes",
		Aliases: []string{"episode", "ep"},
		Usage:   "manage Spotify video episodes",
		Commands: []*cli.Command{
			spotifyVideoEpisodeCreateCmd,
			spotifyVideoEpisodeGetCmd,
			spotifyVideoEpisodeListCmd,
			spotifyVideoEpisodeUpdateCmd,
			spotifyVideoEpisodeDeleteCmd,
		},
	}

	spotifyVideoEpisodeCreateCmd = &cli.Command{
		Name:      "create",
		Usage:     "create a Spotify video episode",
		ArgsUsage: "[input.json]",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  "input",
				Usage: "read input from JSON file (or pass JSON via stdin)",
			},
		},
		Action: spotifyVideoEpisodeCreate,
	}

	spotifyVideoEpisodeGetCmd = &cli.Command{
		Name:      "get",
		Usage:     "get a Spotify video episode",
		ArgsUsage: "<episode_id>",
		Action:    spotifyVideoEpisodeGet,
	}

	spotifyVideoEpisodeListCmd = &cli.Command{
		Name:      "list",
		Usage:     "list Spotify video episodes",
		ArgsUsage: "<show_id>",
		Action:    spotifyVideoEpisodeList,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  "updated_since",
				Usage: "only episodes updated since this date (ISO8601 format)",
			},
			&cli.IntFlag{
				Name:  "page",
				Usage: "page number for pagination",
			},
			&cli.IntFlag{
				Name:  "per_page",
				Usage: "items per page (max 500)",
			},
		},
	}

	spotifyVideoEpisodeUpdateCmd = &cli.Command{
		Name:      "update",
		Usage:     "update a Spotify video episode",
		ArgsUsage: "<episode_id> [input.json]",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  "input",
				Usage: "read input from JSON file (or pass JSON via stdin)",
			},
		},
		Action: spotifyVideoEpisodeUpdate,
	}

	spotifyVideoEpisodeDeleteCmd = &cli.Command{
		Name:      "delete",
		Usage:     "delete a Spotify video episode",
		ArgsUsage: "<episode_id>",
		Action:    spotifyVideoEpisodeDelete,
	}
)

func spotifyVideoShowCreate(ctx context.Context, cmd *cli.Command) error {
	instanceID, err := requireInstance()
	if err != nil {
		return err
	}

	var data []byte
	if cmd.IsSet("input") {
		data, err = os.ReadFile(cmd.String("input"))
		if err != nil {
			return fmt.Errorf("failed to read input file: %w", err)
		}
	} else if cmd.Args().First() != "" {
		data, err = os.ReadFile(cmd.Args().First())
		if err != nil {
			return fmt.Errorf("failed to read input file: %w", err)
		}
	} else {
		data, err = readInputStdin()
		if err != nil {
			return err
		}
	}

	params := atomic.IntegrationProxyInput{
		InstanceID:  instanceID,
		Provider:    "spotify",
		ProxyMethod: atomic.SpotifyVideoShowCreate,
		Parameters:  data,
	}

	result, err := callIntegrationProxy(ctx, &params)
	if err != nil {
		return err
	}

	PrintResult(cmd, []interface{}{result}, WithSingleValue(true))
	return nil
}

func spotifyVideoShowGet(ctx context.Context, cmd *cli.Command) error {
	instanceID, err := requireInstance()
	if err != nil {
		return err
	}

	if cmd.NArg() < 1 {
		return fmt.Errorf("show_id is required")
	}

	showID := cmd.Args().Get(0)

	input := atomic.SpotifyVideoShowGetInput{
		ShowID: showID,
	}

	data, err := json.Marshal(input)
	if err != nil {
		return fmt.Errorf("failed to marshal input: %w", err)
	}

	params := atomic.IntegrationProxyInput{
		InstanceID:  instanceID,
		Provider:    "spotify",
		ProxyMethod: atomic.SpotifyVideoShowGet,
		Parameters:  data,
	}

	result, err := callIntegrationProxy(ctx, &params)
	if err != nil {
		return err
	}

	PrintResult(cmd, []interface{}{result}, WithSingleValue(true))
	return nil
}

func spotifyVideoShowList(ctx context.Context, cmd *cli.Command) error {
	instanceID, err := requireInstance()
	if err != nil {
		return err
	}

	input := atomic.SpotifyVideoShowListInput{}

	if cmd.IsSet("updated_since") {
		updatedSince := cmd.String("updated_since")
		input.UpdatedSince = &updatedSince
	}

	data, err := json.Marshal(input)
	if err != nil {
		return fmt.Errorf("failed to marshal input: %w", err)
	}

	params := atomic.IntegrationProxyInput{
		InstanceID:  instanceID,
		Provider:    "spotify",
		ProxyMethod: atomic.SpotifyVideoShowList,
		Parameters:  data,
	}

	result, err := callIntegrationProxy(ctx, &params)
	if err != nil {
		return err
	}

	if shows, ok := result.([]atomic.SpotifyVideoShow); ok {
		results := make([]interface{}, len(shows))
		for i, show := range shows {
			results[i] = show
		}
		PrintResult(cmd, results)
		return nil
	}

	PrintResult(cmd, []interface{}{result})
	return nil
}

func spotifyVideoShowUpdate(ctx context.Context, cmd *cli.Command) error {
	instanceID, err := requireInstance()
	if err != nil {
		return err
	}

	if cmd.NArg() < 1 {
		return fmt.Errorf("show_id is required")
	}

	showID := cmd.Args().Get(0)

	var data []byte
	if cmd.IsSet("input") {
		data, err = os.ReadFile(cmd.String("input"))
		if err != nil {
			return fmt.Errorf("failed to read input file: %w", err)
		}
	} else if cmd.NArg() > 1 {
		data, err = os.ReadFile(cmd.Args().Get(1))
		if err != nil {
			return fmt.Errorf("failed to read input file: %w", err)
		}
	} else {
		data, err = readInputStdin()
		if err != nil {
			return err
		}
	}

	var updateData map[string]interface{}
	if err := json.Unmarshal(data, &updateData); err != nil {
		return fmt.Errorf("failed to unmarshal input: %w", err)
	}
	updateData["show_id"] = showID
	data, err = json.Marshal(updateData)
	if err != nil {
		return fmt.Errorf("failed to marshal input: %w", err)
	}

	params := atomic.IntegrationProxyInput{
		InstanceID:  instanceID,
		Provider:    "spotify",
		ProxyMethod: atomic.SpotifyVideoShowUpdate,
		Parameters:  data,
	}

	result, err := callIntegrationProxy(ctx, &params)
	if err != nil {
		return err
	}

	PrintResult(cmd, []interface{}{result}, WithSingleValue(true))
	return nil
}

func spotifyVideoShowDelete(ctx context.Context, cmd *cli.Command) error {
	instanceID, err := requireInstance()
	if err != nil {
		return err
	}

	if cmd.NArg() < 1 {
		return fmt.Errorf("show_id is required")
	}

	showID := cmd.Args().Get(0)

	input := atomic.SpotifyVideoShowDeleteInput{
		ShowID: showID,
	}

	data, err := json.Marshal(input)
	if err != nil {
		return fmt.Errorf("failed to marshal input: %w", err)
	}

	params := atomic.IntegrationProxyInput{
		InstanceID:  instanceID,
		Provider:    "spotify",
		ProxyMethod: atomic.SpotifyVideoShowDelete,
		Parameters:  data,
	}

	result, err := callIntegrationProxy(ctx, &params)
	if err != nil {
		return err
	}

	PrintResult(cmd, []interface{}{result}, WithSingleValue(true))
	return nil
}

func spotifyVideoEpisodeCreate(ctx context.Context, cmd *cli.Command) error {
	instanceID, err := requireInstance()
	if err != nil {
		return err
	}

	var data []byte
	if cmd.IsSet("input") {
		data, err = os.ReadFile(cmd.String("input"))
		if err != nil {
			return fmt.Errorf("failed to read input file: %w", err)
		}
	} else if cmd.Args().First() != "" {
		data, err = os.ReadFile(cmd.Args().First())
		if err != nil {
			return fmt.Errorf("failed to read input file: %w", err)
		}
	} else {
		data, err = readInputStdin()
		if err != nil {
			return err
		}
	}

	params := atomic.IntegrationProxyInput{
		InstanceID:  instanceID,
		Provider:    "spotify",
		ProxyMethod: atomic.SpotifyVideoEpisodeCreate,
		Parameters:  data,
	}

	result, err := callIntegrationProxy(ctx, &params)
	if err != nil {
		return err
	}

	PrintResult(cmd, []interface{}{result}, WithSingleValue(true))
	return nil
}

func spotifyVideoEpisodeGet(ctx context.Context, cmd *cli.Command) error {
	instanceID, err := requireInstance()
	if err != nil {
		return err
	}

	if cmd.NArg() < 1 {
		return fmt.Errorf("episode_id is required")
	}

	episodeID := cmd.Args().Get(0)

	input := atomic.SpotifyVideoEpisodeGetInput{
		EpisodeID: episodeID,
	}

	data, err := json.Marshal(input)
	if err != nil {
		return fmt.Errorf("failed to marshal input: %w", err)
	}

	params := atomic.IntegrationProxyInput{
		InstanceID:  instanceID,
		Provider:    "spotify",
		ProxyMethod: atomic.SpotifyVideoEpisodeGet,
		Parameters:  data,
	}

	result, err := callIntegrationProxy(ctx, &params)
	if err != nil {
		return err
	}

	PrintResult(cmd, []interface{}{result}, WithSingleValue(true))
	return nil
}

func spotifyVideoEpisodeList(ctx context.Context, cmd *cli.Command) error {
	instanceID, err := requireInstance()
	if err != nil {
		return err
	}

	if cmd.NArg() < 1 {
		return fmt.Errorf("show_id is required")
	}

	showID := cmd.Args().Get(0)

	input := atomic.SpotifyVideoEpisodeListInput{
		ShowID: showID,
	}

	if cmd.IsSet("updated_since") {
		updatedSince := cmd.String("updated_since")
		input.UpdatedSince = &updatedSince
	}
	if cmd.IsSet("page") {
		page := cmd.Int("page")
		input.Page = &page
	}
	if cmd.IsSet("per_page") {
		perPage := cmd.Int("per_page")
		input.PerPage = &perPage
	}

	data, err := json.Marshal(input)
	if err != nil {
		return fmt.Errorf("failed to marshal input: %w", err)
	}

	params := atomic.IntegrationProxyInput{
		InstanceID:  instanceID,
		Provider:    "spotify",
		ProxyMethod: atomic.SpotifyVideoEpisodeList,
		Parameters:  data,
	}

	result, err := callIntegrationProxy(ctx, &params)
	if err != nil {
		return err
	}

	if episodes, ok := result.([]atomic.SpotifyVideoEpisode); ok {
		results := make([]interface{}, len(episodes))
		for i, episode := range episodes {
			results[i] = episode
		}
		PrintResult(cmd, results)
		return nil
	}

	PrintResult(cmd, []interface{}{result})
	return nil
}

func spotifyVideoEpisodeUpdate(ctx context.Context, cmd *cli.Command) error {
	instanceID, err := requireInstance()
	if err != nil {
		return err
	}

	if cmd.NArg() < 1 {
		return fmt.Errorf("episode_id is required")
	}

	episodeID := cmd.Args().Get(0)

	var data []byte
	if cmd.IsSet("input") {
		data, err = os.ReadFile(cmd.String("input"))
		if err != nil {
			return fmt.Errorf("failed to read input file: %w", err)
		}
	} else if cmd.NArg() > 1 {
		data, err = os.ReadFile(cmd.Args().Get(1))
		if err != nil {
			return fmt.Errorf("failed to read input file: %w", err)
		}
	} else {
		data, err = readInputStdin()
		if err != nil {
			return err
		}
	}

	var updateData map[string]interface{}
	if err := json.Unmarshal(data, &updateData); err != nil {
		return fmt.Errorf("failed to unmarshal input: %w", err)
	}
	updateData["episode_id"] = episodeID
	data, err = json.Marshal(updateData)
	if err != nil {
		return fmt.Errorf("failed to marshal input: %w", err)
	}

	params := atomic.IntegrationProxyInput{
		InstanceID:  instanceID,
		Provider:    "spotify",
		ProxyMethod: atomic.SpotifyVideoEpisodeUpdate,
		Parameters:  data,
	}

	result, err := callIntegrationProxy(ctx, &params)
	if err != nil {
		return err
	}

	PrintResult(cmd, []interface{}{result}, WithSingleValue(true))
	return nil
}

func spotifyVideoEpisodeDelete(ctx context.Context, cmd *cli.Command) error {
	instanceID, err := requireInstance()
	if err != nil {
		return err
	}

	if cmd.NArg() < 1 {
		return fmt.Errorf("episode_id is required")
	}

	episodeID := cmd.Args().Get(0)

	input := atomic.SpotifyVideoEpisodeDeleteInput{
		EpisodeID: episodeID,
	}

	data, err := json.Marshal(input)
	if err != nil {
		return fmt.Errorf("failed to marshal input: %w", err)
	}

	params := atomic.IntegrationProxyInput{
		InstanceID:  instanceID,
		Provider:    "spotify",
		ProxyMethod: atomic.SpotifyVideoEpisodeDelete,
		Parameters:  data,
	}

	result, err := callIntegrationProxy(ctx, &params)
	if err != nil {
		return err
	}

	PrintResult(cmd, []interface{}{result}, WithSingleValue(true))
	return nil
}
