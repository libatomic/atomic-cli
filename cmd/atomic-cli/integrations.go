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
	"bufio"
	"context"
	"fmt"
	"os"

	"github.com/libatomic/atomic/pkg/atomic"
	"github.com/urfave/cli/v3"
)

var (
	integrationsCmd = &cli.Command{
		Name:    "integrations",
		Aliases: []string{"integration", "int"},
		Usage:   "manage integrations",
		Commands: []*cli.Command{
			spotifyCmd,
		},
	}
)

func readInputStdin() ([]byte, error) {
	scanner := bufio.NewScanner(os.Stdin)
	var data []byte
	for scanner.Scan() {
		data = append(data, scanner.Bytes()...)
		data = append(data, '\n')
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to read from stdin: %w", err)
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("no input provided")
	}
	return data, nil
}

func callIntegrationProxy(ctx context.Context, params *atomic.IntegrationProxyInput) (interface{}, error) {
	if a, ok := backend.(*atomic.Atomic); ok {
		return a.IntegrationProxy(ctx, params)
	}

	return nil, fmt.Errorf("integration proxy not yet supported via API client, use --db_source for direct database access")
}

func requireInstance() (atomic.ID, error) {
	if inst == nil {
		return atomic.IDZero, fmt.Errorf("instance is required; set --instance_id or configure a default instance")
	}
	return inst.UUID, nil
}
