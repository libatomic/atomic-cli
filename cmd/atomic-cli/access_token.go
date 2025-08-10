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
	"strings"

	"github.com/libatomic/atomic/pkg/atomic"
	"github.com/libatomic/atomic/pkg/oauth"
	"github.com/urfave/cli/v3"
)

var (
	accessTokenCmd = &cli.Command{
		Name:    "access-token",
		Aliases: []string{"token"},
		Usage:   "manage access tokens",
		Commands: []*cli.Command{
			{
				Name:  "create",
				Usage: "create an access token",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:  "application_id",
						Usage: "specify the application id",
					},
					&cli.StringFlag{
						Name:  "user_id",
						Usage: "specify the user id",
					},
					&cli.StringFlag{
						Name:  "partner_id",
						Usage: "specify the partner id",
					},
					&cli.StringSliceFlag{
						Name:  "scope",
						Usage: "specify the scope",
						Value: []string{"openid", "profile"},
					},
					&cli.StringFlag{
						Name:  "type",
						Usage: "specify the type",
						Value: "access",
					},
					&cli.TimestampFlag{
						Name:  "expires_at",
						Usage: "specify the expires at",
					},
					&cli.StringFlag{
						Name:  "redirect_uri",
						Usage: "specify the redirect uri",
					},
					&cli.BoolFlag{
						Name:  "force",
						Usage: "specify if the token should be force created",
					},
					&cli.BoolFlag{
						Name:  "stateless",
						Usage: "specify if the token should be stateless",
					},
					&cli.BoolFlag{
						Name:  "use_client_id",
						Usage: "specify if the token should be created using the client id",
					},
					&cli.StringFlag{
						Name:  "additional_claims",
						Usage: "specify additional claims from a json file",
					},
				},
				Action: accessTokenCreate,
			},
		},
	}
)

func accessTokenCreate(ctx context.Context, cmd *cli.Command) error {
	var v atomic.AccessTokenCreateInput

	if err := BindFlagsFromContext(cmd, &v); err != nil {
		return err
	}

	if cmd.IsSet("additional_claims") {
		data, err := os.ReadFile(cmd.String("additional_claims"))
		if err != nil {
			return err
		}

		var claims oauth.MapClaims
		if err := json.Unmarshal(data, &claims); err != nil {
			return err
		}

		v.AdditionalClaims = claims
	}

	token, err := backend.AccessTokenCreate(ctx, &v)
	if err != nil {
		return err
	}

	PrintResult(
		cmd,
		[]*atomic.AccessToken{token},
		WithFields("id", "created_at", "type", "owner_id", "scope", "expires_at"),
		WithVirtualField("owner_id", func(value any) string {
			token := value.(atomic.AccessToken)
			if token.UserID.Valid() {
				return token.UserID.String()
			} else if token.ApplicationID.Valid() {
				return token.ApplicationID.String()
			} else if token.PartnerID.Valid() {
				return token.PartnerID.String()
			}
			return ""
		}),
		WithVirtualField("type", func(value any) string {
			token := value.(atomic.AccessToken)
			t := string(token.Type)
			if token.UserID.Valid() {
				t = "user"
			} else if token.ApplicationID.Valid() {
				t = "application"
			} else if token.PartnerID.Valid() {
				t = "partner"
			}
			return fmt.Sprintf("%s (%s)", token.Type, t)
		}),
		WithVirtualField("scope", func(value any) string {
			token := value.(atomic.AccessToken)
			return strings.Join(token.Claims.Scope(), ",")
		}),
	)

	return nil
}
