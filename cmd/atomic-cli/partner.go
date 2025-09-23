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
	"github.com/libatomic/atomic/pkg/ptr"
	"github.com/urfave/cli/v3"
)

var (
	partnerCreateFlags = []cli.Flag{
		&cli.BoolFlag{
			Name:  "file",
			Usage: "set the partner input from a JSON file",
		},
		&cli.StringFlag{
			Name:  "description",
			Usage: "set the partner description",
		},
		&cli.StringFlag{
			Name:  "support_contact",
			Usage: "set the partner support contact",
		},
		&cli.StringFlag{
			Name:  "metadata",
			Usage: "set the partner metadata from a JSON file",
		},
		&cli.StringSliceFlag{
			Name:  "roles",
			Usage: "set the partner roles (can be specified multiple times, e.g., --roles admin --roles member)",
			Value: []string{atomic.RoleAdmin},
		},
		&cli.StringSliceFlag{
			Name:  "permissions",
			Usage: "set the partner permissions (can be specified multiple times, e.g., --permissions read --permissions write)",
		},
	}

	partnerCmd = &cli.Command{
		Name:    "partner",
		Aliases: []string{"partners"},
		Usage:   "manage partners",
		Commands: []*cli.Command{
			{
				Name:      "create",
				Usage:     "create a new partner",
				ArgsUsage: "<partner name>",
				Description: `Create a new partner with the specified name and optional flags.

Examples:
  # Create a partner with default admin role
  atomic-cli partner create "My Partner"

  # Create a partner with specific roles and permissions
  atomic-cli partner create "API Partner" --roles admin --roles member --permissions read --permissions write

  # Create a partner from JSON file
  atomic-cli partner create --file partner.json

  # Create a partner with description and support contact
  atomic-cli partner create "Support Partner" --description "Customer support partner" --support_contact "support@example.com"`,
				Flags:  partnerCreateFlags,
				Action: partnerCreate,
			},
			{
				Name:      "update",
				Usage:     "update a partner",
				ArgsUsage: "<partner id>",
				Flags:     partnerCreateFlags,
				Action:    partnerUpdate,
			},
			{
				Name:      "delete",
				Usage:     "delete a partner",
				ArgsUsage: "<partner id>",
				Action:    partnerDelete,
			},
			{
				Name:      "get",
				Usage:     "get a partner",
				ArgsUsage: "<partner id>",
				Flags: []cli.Flag{
					&cli.BoolFlag{
						Name:    "credentials",
						Aliases: []string{"c"},
						Value:   true,
						Usage:   "include credentials",
					},
					&cli.BoolFlag{
						Name:    "tokens",
						Aliases: []string{"t"},
						Value:   true,
						Usage:   "include tokens",
					},
				},
				Action: partnerGet,
			},
			{
				Name:   "list",
				Usage:  "list partners",
				Action: partnerList,
			},
			{
				Name:    "credential",
				Aliases: []string{"credentials", "creds"},
				Usage:   "manage partner credentials",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:  "partner_id",
						Usage: "set the partner id",
					},
				},
				Commands: []*cli.Command{
					{
						Name:      "create",
						Usage:     "create a new partner credential",
						ArgsUsage: "<partner id>",
						Flags: []cli.Flag{
							&cli.StringSliceFlag{
								Name:  "permissions",
								Usage: "set the partner permissions (can be specified multiple times, e.g., --permissions read --permissions write)",
							},
							&cli.StringSliceFlag{
								Name:  "roles",
								Usage: "set the partner roles (can be specified multiple times, e.g., --roles admin --roles member)",
							},
							&cli.StringFlag{
								Name:  "instance_id",
								Usage: "set the instance id",
							},
							&cli.TimestampFlag{
								Name:  "expires_at",
								Usage: "set the credential expires at",
							},
						},
						Action: partnerCredentialCreate,
					},
					{
						Name:      "get",
						Usage:     "get a partner credential",
						ArgsUsage: "<client id>",
						Action:    partnerCredentialGet,
					},
					{
						Name:      "revoke",
						Aliases:   []string{"delete"},
						Usage:     "revoke a partner credential",
						ArgsUsage: "<client id>",
						Action:    partnerCredentialDelete,
					},
				},
			},
			{
				Name:  "token",
				Usage: "manage partner tokens",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:  "partner_id",
						Usage: "set the partner id",
					},
				},
				Commands: []*cli.Command{
					{
						Name:      "create",
						Usage:     "create a new partner token",
						ArgsUsage: "<partner id>",
						Flags: []cli.Flag{
							&cli.StringFlag{
								Name:  "instance_id",
								Usage: "set the instance id",
							},
							&cli.TimestampFlag{
								Name:  "expires_at",
								Usage: "set the token expires at",
							},
							&cli.StringSliceFlag{
								Name:  "permissions",
								Usage: "set the partner permissions (can be specified multiple times, e.g., --permissions read --permissions write)",
							},
							&cli.StringSliceFlag{
								Name:  "roles",
								Usage: "set the partner roles (can be specified multiple times, e.g., --roles admin --roles member)",
							},
						},
						Action: partnerTokenCreate,
					},
					{
						Name:      "get",
						Usage:     "get a partner token",
						ArgsUsage: "<token id>",
						Action:    partnerTokenGet,
					},
					{
						Name:      "revoke",
						Aliases:   []string{"delete"},
						Usage:     "revoke a partner token",
						ArgsUsage: "<token id>",
						Action:    partnerTokenRevoke,
					},
				},
			},
		},
		Before: func(ctx context.Context, cmd *cli.Command) (context.Context, error) {
			var ok bool

			partners, ok = backend.(atomic.PartnerBackend)
			if !ok {
				return nil, fmt.Errorf("backend does not support partner operations")
			}

			return ctx, nil
		},
	}

	partners atomic.PartnerBackend
)

func partnerCreate(ctx context.Context, cmd *cli.Command) error {
	var input atomic.PartnerCreateInput

	if cmd.IsSet("file") && cmd.Bool("file") {
		content, err := os.ReadFile(cmd.Args().First())
		if err != nil {
			return fmt.Errorf("failed to read user create input file: %w", err)
		}

		if err := json.Unmarshal(content, &input); err != nil {
			return fmt.Errorf("failed to unmarshal user create input: %w", err)
		}
	} else if cmd.Args().First() != "" {
		input.Name = cmd.Args().First()
	}

	if err := BindFlagsFromContext(cmd, &input, "description", "support_contact"); err != nil {
		return err
	}

	if cmd.IsSet("metadata") {
		content, err := os.ReadFile(cmd.Args().First())
		if err != nil {
			return fmt.Errorf("failed to read partner create input file: %w", err)
		}

		if err := json.Unmarshal(content, &input.Metadata); err != nil {
			return fmt.Errorf("failed to unmarshal partner create input: %w", err)
		}
	}

	partner, err := partners.PartnerCreate(ctx, &input)
	if err != nil {
		return err
	}

	PrintResult(cmd, []*atomic.Partner{partner}, WithFields("id", "name", "description", "support_contact", "roles", "permissions", "metadata"),
		WithVirtualField("id", func(v any) string {
			return v.(atomic.Partner).UUID.String()
		}))

	return nil
}

func partnerUpdate(ctx context.Context, cmd *cli.Command) error {
	var input atomic.PartnerUpdateInput

	if cmd.IsSet("file") && cmd.Bool("file") {
		content, err := os.ReadFile(cmd.Args().First())
		if err != nil {
			return fmt.Errorf("failed to read partner update input file: %w", err)
		}

		if err := json.Unmarshal(content, &input); err != nil {
			return fmt.Errorf("failed to unmarshal partner update input: %w", err)
		}
	}

	id, err := atomic.ParseID(cmd.Args().First())
	if err != nil {
		return fmt.Errorf("failed to parse partner id: %w", err)
	}

	input.PartnerID = id

	if err := BindFlagsFromContext(cmd, &input, "description", "support_contact"); err != nil {
		return err
	}

	if cmd.IsSet("metadata") {
		content, err := os.ReadFile(cmd.Args().First())
		if err != nil {
			return fmt.Errorf("failed to read partner create input file: %w", err)
		}

		if err := json.Unmarshal(content, &input.Metadata); err != nil {
			return fmt.Errorf("failed to unmarshal partner create input: %w", err)
		}
	}

	partner, err := partners.PartnerUpdate(ctx, &input)
	if err != nil {
		return err
	}

	PrintResult(cmd, []*atomic.Partner{partner}, WithFields("id", "name", "description", "support_contact", "roles", "permissions", "metadata"),
		WithVirtualField("id", func(v any) string {
			return v.(atomic.Partner).UUID.String()
		}))

	return nil
}

func partnerDelete(ctx context.Context, cmd *cli.Command) error {
	var input atomic.PartnerDeleteInput

	id, err := atomic.ParseID(cmd.Args().First())
	if err != nil {
		return fmt.Errorf("failed to parse partner id: %w", err)
	}

	input.PartnerID = id

	if err := partners.PartnerDelete(ctx, &input); err != nil {
		return err
	}

	fmt.Println("partner deleted")

	return nil
}

func partnerGet(ctx context.Context, cmd *cli.Command) error {
	var input atomic.PartnerGetInput

	id, err := atomic.ParseID(cmd.Args().First())
	if err != nil {
		return fmt.Errorf("failed to parse partner id: %w", err)
	}

	if cmd.Bool("credentials") {
		input.Expand = append(input.Expand, "credentials")
	}

	if cmd.Bool("tokens") {
		input.Expand = append(input.Expand, "access_tokens")
	}

	input.PartnerID = &id

	partner, err := partners.PartnerGet(ctx, &input)
	if err != nil {
		return err
	}

	PrintResult(cmd, []*atomic.Partner{partner}, WithFields("id", "name", "description", "support_contact", "roles", "permissions", "metadata"),
		WithVirtualField("id", func(v any) string {
			return v.(atomic.Partner).UUID.String()
		}))

	if cmd.Bool("credentials") {
		fmt.Println("credentials:")
		PrintResult(cmd, partner.Credentials, WithFields("client_id", "client_secret", "permissions", "roles", "instance_id", "expires_at"),
			WithVirtualField("client_id", func(v any) string {
				return v.(atomic.PartnerCredential).ClientIDVal.String()
			}))
	}

	if cmd.Bool("tokens") {
		fmt.Println("tokens:")
		PrintResult(cmd, partner.AccessTokens, WithFields("id", "permissions", "roles", "instance_id", "expires_at"),
			WithVirtualField("id", func(v any) string {
				return v.(atomic.PartnerAccessToken).UUID.String()
			}),
			WithVirtualField("permissions", func(v any) string {
				token := v.(atomic.PartnerAccessToken)
				return strings.Join(token.Claims.Scope(), " ")
			}),
			WithVirtualField("roles", func(v any) string {
				token := v.(atomic.PartnerAccessToken)
				roles, ok := token.Claims.Get("roles").(string)
				if !ok {
					return ""
				}
				return roles
			}))
	}
	return nil
}

func partnerList(ctx context.Context, cmd *cli.Command) error {
	var input atomic.PartnerListInput

	partners, err := partners.PartnerList(ctx, &input)
	if err != nil {
		return err
	}

	PrintResult(cmd, partners, WithFields("id", "name", "description", "support_contact", "roles", "permissions", "metadata"),
		WithVirtualField("id", func(v any) string {
			return v.(atomic.Partner).UUID.String()
		}))

	return nil
}

func partnerCredentialCreate(ctx context.Context, cmd *cli.Command) error {
	var input atomic.PartnerCredentialCreateInput

	partnerID, err := atomic.ParseID(cmd.Args().First())
	if err != nil {
		return fmt.Errorf("failed to parse partner id: %w", err)
	}

	input.PartnerID = partnerID

	if cmd.IsSet("instance_id") {
		instanceID, err := atomic.ParseID(cmd.String("instance_id"))
		if err != nil {
			return fmt.Errorf("failed to parse instance id: %w", err)
		}
		input.InstanceID = &instanceID
	}

	if err := BindFlagsFromContext(cmd, &input, "instance_id"); err != nil {
		return err
	}

	cred, err := partners.PartnerCredentialCreate(ctx, &input)
	if err != nil {
		return err
	}

	PrintResult(cmd, []*atomic.PartnerCredential{cred}, WithFields("client_id", "client_secret", "permissions", "roles", "instance_id", "expires_at"),
		WithVirtualField("client_id", func(v any) string {
			return v.(atomic.PartnerCredential).ClientIDVal.String()
		}))

	return nil
}

func partnerCredentialGet(ctx context.Context, cmd *cli.Command) error {
	var input atomic.PartnerCredentialGetInput

	partnerID, err := atomic.ParseID(cmd.String("partner_id"))
	if err != nil {
		return fmt.Errorf("failed to parse partner id: %w", err)
	}

	input.PartnerID = &partnerID

	clientID, err := atomic.ParseID(cmd.Args().First())
	if err != nil {
		return fmt.Errorf("failed to parse client id: %w", err)
	}

	input.ClientID = ptr.String(clientID.String())

	cred, err := partners.PartnerCredentialGet(ctx, &input)
	if err != nil {
		return err
	}

	PrintResult(cmd, []*atomic.PartnerCredential{cred}, WithFields("client_id", "client_secret", "permissions", "roles", "instance_id", "expires_at"),
		WithVirtualField("client_id", func(v any) string {
			return v.(atomic.PartnerCredential).ClientIDVal.String()
		}))

	return nil
}

func partnerCredentialDelete(ctx context.Context, cmd *cli.Command) error {
	var input atomic.PartnerCredentialDeleteInput

	partnerID, err := atomic.ParseID(cmd.String("partner_id"))
	if err != nil {
		return fmt.Errorf("failed to parse partner id: %w", err)
	}

	clientID, err := atomic.ParseID(cmd.Args().First())
	if err != nil {
		return fmt.Errorf("failed to parse client id: %w", err)
	}

	input.PartnerID = &partnerID
	input.ClientID = ptr.String(clientID.String())

	if err := partners.PartnerCredentialDelete(ctx, &input); err != nil {
		return err
	}

	fmt.Println("partner credential deleted")

	return nil
}

func partnerTokenCreate(ctx context.Context, cmd *cli.Command) error {
	var input atomic.PartnerTokenCreateInput

	partnerID, err := atomic.ParseID(cmd.String("partner_id"))
	if err != nil {
		return fmt.Errorf("failed to parse partner id: %w", err)
	}

	input.PartnerID = partnerID

	if err := BindFlagsFromContext(cmd, &input, "instance_id"); err != nil {
		return err
	}

	token, err := partners.PartnerTokenCreate(ctx, &input)
	if err != nil {
		return err
	}

	PrintResult(cmd, []*atomic.PartnerAccessToken{token}, WithFields("id", "permissions", "roles", "instance_id", "expires_at"),
		WithVirtualField("id", func(v any) string {
			return v.(atomic.PartnerAccessToken).UUID.String()
		}),
		WithVirtualField("permissions", func(v any) string {
			token := v.(atomic.PartnerAccessToken)
			return strings.Join(token.Claims.Scope(), " ")
		}),
		WithVirtualField("roles", func(v any) string {
			token := v.(atomic.PartnerAccessToken)
			roles, ok := token.Claims.Get("roles").(string)
			if !ok {
				return ""
			}
			return roles
		}))

	return nil
}

func partnerTokenGet(ctx context.Context, cmd *cli.Command) error {
	var input atomic.PartnerTokenGetInput

	partnerID, err := atomic.ParseID(cmd.String("partner_id"))
	if err != nil {
		return fmt.Errorf("failed to parse partner id: %w", err)
	}

	input.PartnerID = &partnerID

	tokenID, err := atomic.ParseID(cmd.Args().First())
	if err != nil {
		return fmt.Errorf("failed to parse token id: %w", err)
	}

	input.TokenID = tokenID

	token, err := partners.PartnerTokenGet(ctx, &input)
	if err != nil {
		return err
	}

	PrintResult(cmd, []*atomic.PartnerAccessToken{token}, WithFields("id", "permissions", "roles", "instance_id", "expires_at"),
		WithVirtualField("id", func(v any) string {
			return v.(atomic.PartnerAccessToken).UUID.String()
		}),
		WithVirtualField("permissions", func(v any) string {
			token := v.(atomic.PartnerAccessToken)
			return strings.Join(token.Claims.Scope(), " ")
		}),
		WithVirtualField("roles", func(v any) string {
			token := v.(atomic.PartnerAccessToken)
			roles, ok := token.Claims.Get("roles").(string)
			if !ok {
				return ""
			}
			return roles
		}))

	return nil
}

func partnerTokenRevoke(ctx context.Context, cmd *cli.Command) error {
	var input atomic.PartnerTokenRevokeInput

	partnerID, err := atomic.ParseID(cmd.String("partner_id"))
	if err != nil {
		return fmt.Errorf("failed to parse partner id: %w", err)
	}

	tokenID, err := atomic.ParseID(cmd.Args().First())
	if err != nil {
		return fmt.Errorf("failed to parse token id: %w", err)
	}

	input.PartnerID = &partnerID
	input.TokenID = tokenID

	if err := partners.PartnerTokenRevoke(ctx, &input); err != nil {
		return err
	}

	fmt.Println("partner token deleted")

	return nil
}
