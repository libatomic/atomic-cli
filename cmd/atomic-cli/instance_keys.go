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
	"strings"
	"time"

	"github.com/libatomic/atomic/v2/pkg/atomic"
	"github.com/urfave/cli/v3"
)

var (
	instKeysFields = []string{"kind", "key_id", "algorithm", "status", "expires_at", "created_at", "source", "created_by", "reason"}

	instKeysKindFlag = &cli.StringFlag{
		Name:  "kind",
		Usage: "which key: token (signs bearers, link tokens and webhook signatures) or session (seals session cookies)",
		Value: string(atomic.InstanceKeyKindToken),
	}

	instKeysReasonFlag = &cli.StringFlag{
		Name:  "reason",
		Usage: "why, for the key's audit trail",
	}

	instKeysCmd = &cli.Command{
		Name:      "keys",
		Usage:     "an instance's signing keys: list, rotate, revert and retire (instance:keys scope)",
		ArgsUsage: "keys <command> [instance id or name]",
		Description: "Every instance signs with a token key and seals its session cookies with a session key. A rotation " +
			"makes a new current key and gives the one it replaces a grace period, during which it still verifies " +
			"what it signed; a revert undoes the last rotation the same way, and a retire ends a grace period early. " +
			"The instance defaults to -i; the changes reach every node at once.",
		Commands: []*cli.Command{
			{
				Name:      "list",
				Usage:     "list the token and session keys (never the material)",
				ArgsUsage: "list [instance id or name]",
				Action:    instKeysList,
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:  "kind",
						Usage: "only token or session keys",
					},
				},
			},
			{
				Name:      "rotate",
				Usage:     "replace the current key, keeping the old one for a grace period",
				ArgsUsage: "rotate [instance id or name]",
				Description: "Generates a new key and makes it current; everything new is signed or sealed with it under its " +
					"own key id. The key it replaces keeps verifying until the grace period ends. A session rotation on an " +
					"instance still using the built-in default secret keeps that secret good for the grace period too, so " +
					"the cookies already out survive.",
				Action: instKeysRotate,
				Flags: []cli.Flag{
					instKeysKindFlag,
					&cli.StringFlag{
						Name:  "alg",
						Usage: "the new token algorithm: ES256 or HS256 (RS256 only verifies now); ignored for session keys",
						Value: "ES256",
					},
					&cli.StringFlag{
						Name:  "grace",
						Usage: "how long the replaced key keeps verifying, e.g. 30d, 90d or 720h (up to 365d); 0 ends it at once",
						Value: "30d",
					},
					instKeysReasonFlag,
				},
			},
			{
				Name:      "revert",
				Usage:     "undo the last rotation: the replaced key signs again and the new one gets the grace period",
				ArgsUsage: "revert [instance id or name]",
				Description: "Only a key still in its grace period can come back; once it has expired nothing it signed is " +
					"valid any more, and a fresh rotation is the right move. A session key reverted off a rotation from the " +
					"built-in default secret goes back to sealing with it.",
				Action: instKeysRevert,
				Flags: []cli.Flag{
					instKeysKindFlag,
					&cli.StringFlag{
						Name:  "grace",
						Usage: "how long the reverted key keeps verifying, e.g. 7d or 30d (up to 365d); 0 ends it at once",
						Value: "30d",
					},
					instKeysReasonFlag,
				},
			},
			{
				Name:        "retire",
				Usage:       "end a previous key's grace period now",
				ArgsUsage:   "retire <key id> [instance id or name]",
				Description: "Nothing the key signed verifies after this. The current key cannot be retired; rotate it instead.",
				Action:      instKeysRetire,
				Flags: []cli.Flag{
					instKeysReasonFlag,
				},
			},
		},
	}
)

// instKeysInstance is the instance named by the positional argument at
// position n, or the one -i selected.
func instKeysInstance(ctx context.Context, cmd *cli.Command, n int) (*atomic.Instance, error) {
	if arg := cmd.Args().Get(n); arg != "" {
		return resolveInstanceArg(ctx, arg)
	}

	if inst != nil {
		return inst, nil
	}

	return nil, fmt.Errorf("an instance is required: pass its id or name, or set -i")
}

// instKeysKind reads --kind as a key kind.
func instKeysKind(cmd *cli.Command) (atomic.InstanceKeyKind, error) {
	kind := atomic.InstanceKeyKind(strings.ToLower(strings.TrimSpace(cmd.String("kind"))))

	switch kind {
	case "", atomic.InstanceKeyKindToken, atomic.InstanceKeyKindSession:
		return kind, nil
	}

	return "", fmt.Errorf("--kind must be token or session, not %q", kind)
}

// instKeysGrace reads --grace; zero becomes the immediate retire the API
// spells as a negative grace.
func instKeysGrace(cmd *cli.Command) (time.Duration, error) {
	grace, err := parseGrace(cmd.String("grace"))
	if err != nil {
		return 0, err
	}

	if grace <= 0 {
		return -time.Second, nil
	}

	if grace > atomic.MaxInstanceKeyGrace {
		return 0, fmt.Errorf("--grace must be at most %dd", int(atomic.MaxInstanceKeyGrace.Hours()/24))
	}

	return grace, nil
}

func instKeysPrint(cmd *cli.Command, keys []*atomic.InstanceKey) {
	now := time.Now()

	PrintResult(cmd, keys,
		WithFields(instKeysFields...),
		WithVirtualField("status", func(v any) string {
			k, ok := v.(atomic.InstanceKey)
			if !ok {
				return ""
			}

			switch {
			case k.Current():
				if k.Deprecated() {
					return "current (deprecated)"
				}

				return "current"
			case k.Valid(now):
				return "grace"
			default:
				return "expired"
			}
		}),
		WithFieldFormatter("expires_at", func(v any) string {
			if t, ok := v.(time.Time); ok && !t.IsZero() {
				return t.Format(time.RFC3339)
			}

			return ""
		}),
		WithFieldFormatter("created_at", func(v any) string {
			if t, ok := v.(time.Time); ok {
				return t.Format(time.RFC3339)
			}

			return ""
		}),
	)
}

func instKeysList(ctx context.Context, cmd *cli.Command) error {
	target, err := instKeysInstance(ctx, cmd, 0)
	if err != nil {
		return err
	}

	kind, err := instKeysKind(cmd)
	if err != nil {
		return err
	}

	keys, err := backend.InstanceKeyList(ctx, &atomic.InstanceKeyListInput{InstanceID: target.UUID, Kind: kind})
	if err != nil {
		return err
	}

	instKeysPrint(cmd, keys)

	return nil
}

func instKeysRotate(ctx context.Context, cmd *cli.Command) error {
	target, err := instKeysInstance(ctx, cmd, 0)
	if err != nil {
		return err
	}

	kind, err := instKeysKind(cmd)
	if err != nil {
		return err
	}

	grace, err := instKeysGrace(cmd)
	if err != nil {
		return err
	}

	in := &atomic.InstanceKeyRotateInput{
		InstanceID: target.UUID,
		Kind:       kind,
		Grace:      grace,
		Reason:     cmd.String("reason"),
	}

	if kind == atomic.InstanceKeyKindToken {
		in.Algorithm = strings.ToUpper(strings.TrimSpace(cmd.String("alg")))
	}

	key, err := backend.InstanceKeyRotate(ctx, in)
	if err != nil {
		return err
	}

	instKeysPrint(cmd, []*atomic.InstanceKey{key})

	return nil
}

func instKeysRevert(ctx context.Context, cmd *cli.Command) error {
	target, err := instKeysInstance(ctx, cmd, 0)
	if err != nil {
		return err
	}

	kind, err := instKeysKind(cmd)
	if err != nil {
		return err
	}

	grace, err := instKeysGrace(cmd)
	if err != nil {
		return err
	}

	key, err := backend.InstanceKeyRevert(ctx, &atomic.InstanceKeyRevertInput{
		InstanceID: target.UUID,
		Kind:       kind,
		Grace:      grace,
		Reason:     cmd.String("reason"),
	})
	if err != nil {
		return err
	}

	instKeysPrint(cmd, []*atomic.InstanceKey{key})

	return nil
}

func instKeysRetire(ctx context.Context, cmd *cli.Command) error {
	keyID := strings.TrimSpace(cmd.Args().Get(0))
	if keyID == "" {
		return fmt.Errorf("a key id is required")
	}

	target, err := instKeysInstance(ctx, cmd, 1)
	if err != nil {
		return err
	}

	key, err := backend.InstanceKeyRetire(ctx, &atomic.InstanceKeyRetireInput{
		InstanceID: target.UUID,
		KeyID:      keyID,
		Reason:     cmd.String("reason"),
	})
	if err != nil {
		return err
	}

	instKeysPrint(cmd, []*atomic.InstanceKey{key})

	return nil
}
