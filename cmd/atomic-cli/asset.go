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
	"io"
	"mime"
	"net/http"
	"os"
	"path/filepath"

	"github.com/apex/log"
	"github.com/libatomic/atomic/pkg/atomic"
	"github.com/libatomic/atomic/pkg/helpers"
	"github.com/urfave/cli/v3"
)

var (
	assetCreateFlags = []cli.Flag{
		&cli.StringFlag{
			Name:  "description",
			Usage: "set the description",
		},
		&cli.StringFlag{
			Name:  "mime_type",
			Usage: "set the mime type",
		},
		&cli.StringFlag{
			Name:  "type",
			Usage: "set the type",
			Value: string(atomic.AssetTypeMedia),
		},
		&cli.BoolFlag{
			Name:  "public",
			Usage: "set the public flag",
		},
		&cli.StringFlag{
			Name:  "expires_at",
			Usage: "set the expires at",
		},
		&cli.StringFlag{
			Name:  "metadata",
			Usage: "set the metadata from a JSON file",
		},
		&cli.StringSliceFlag{
			Name:  "categories",
			Usage: "category ids to add to the asset",
		},
	}

	assetCmd = &cli.Command{
		Name:    "asset",
		Aliases: []string{"assets", "a"},
		Usage:   "manage assets",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  "asset_volume",
				Usage: "uri of the asset volume",
			},
		},
		Commands: []*cli.Command{
			{
				Name:      "create",
				Usage:     "create a new asset",
				ArgsUsage: "<filename>",
				Flags:     assetCreateFlags,
				Action:    assetCreate,
			},
		},
		Before: func(ctx context.Context, cmd *cli.Command) (context.Context, error) {
			if a, ok := backend.(*atomic.Atomic); ok {
				if !cmd.IsSet("asset_volume") {
					return nil, fmt.Errorf("asset volume uri is required")
				}

				vol, err := helpers.VolumeFromURI(cmd.String("asset_volume"))
				if err != nil {
					return nil, fmt.Errorf("failed to get asset volume: %w", err)
				}

				a.SetAssetVolume(vol)

				log.Infof("using asset volume %s", cmd.String("asset_volume"))
			}
			return ctx, nil
		},
	}
)

func assetCreate(ctx context.Context, cmd *cli.Command) error {
	var input atomic.AssetCreateInput

	if err := BindFlagsFromContext(cmd, &input, "description", "mime_type", "type", "public", "expires_at", "categories"); err != nil {
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

	fd, err := os.Open(cmd.Args().First())
	if err != nil {
		return fmt.Errorf("failed to open asset file: %w", err)
	}
	defer fd.Close()

	input.Filename = filepath.Base(cmd.Args().First())

	bytes, err := io.ReadAll(fd)
	if err != nil {
		return fmt.Errorf("failed to read asset file: %w", err)
	}

	// attempt to detect the mime type from the file content
	mimeType := http.DetectContentType(bytes)
	if mimeType == "application/octet-stream" {
		// fallback to the file extension if the mime type is unknown
		if extType := mime.TypeByExtension(filepath.Ext(cmd.Args().First())); extType != "" {
			mimeType = extType
		}
	}

	input.MimeType = mimeType

	fd.Seek(0, io.SeekStart)

	input.Size = int64(len(bytes))

	input.Payload = fd

	asset, err := backend.AssetCreate(ctx, &input)
	if err != nil {
		return err
	}

	PrintResult(cmd, []*atomic.Asset{asset}, WithFields("id", "filename", "mime_type", "type", "public", "expires_at", "metadata", "categories"))

	return nil
}
