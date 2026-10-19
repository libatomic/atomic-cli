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
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/urfave/cli/v3"
)

// jsonInputUsage documents the accepted forms for JSON-valued flags.
const jsonInputUsage = " (inline JSON, @path, or a file path)"

// readJSONInput decodes a flag value that may be inline JSON, a path
// prefixed with @, or a bare file path. Agents tend to pass inline JSON;
// humans tend to pass paths. Both work.
func readJSONInput(flag, value string, target any) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return fmt.Errorf("--%s: empty value", flag)
	}

	var data []byte
	switch {
	case strings.HasPrefix(value, "{") || strings.HasPrefix(value, "["):
		data = []byte(value)
	default:
		path := strings.TrimPrefix(value, "@")
		b, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("--%s: read %s: %w (pass inline JSON, @path, or a file path)", flag, path, err)
		}
		data = b
	}

	if err := json.Unmarshal(data, target); err != nil {
		return fmt.Errorf("--%s: invalid JSON: %w", flag, err)
	}
	return nil
}

// readJSONFlag applies readJSONInput for a flag when it is set.
func readJSONFlag(cmd *cli.Command, flag string, target any) error {
	if !cmd.IsSet(flag) {
		return nil
	}
	return readJSONInput(flag, cmd.String(flag), target)
}
