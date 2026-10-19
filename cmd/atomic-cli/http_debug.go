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
	"net/http"
	"net/http/httputil"
	"os"
	"regexp"
	"strings"
)

type (
	// debugTransport dumps every API request and response to stderr with
	// credentials redacted. Enabled by --verbose.
	debugTransport struct {
		base http.RoundTripper
	}
)

var (
	authHeaderRE = regexp.MustCompile(`(?mi)^(Authorization|Cookie|Set-Cookie):.*$`)
	secretBodyRE = regexp.MustCompile(`(client_secret|password|access_token|refresh_token)(=|":\s*")[^&"\s]+`)
)

func (t debugTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if dump, err := httputil.DumpRequestOut(req, true); err == nil {
		os.Stderr.WriteString(">>> " + redactDump(dump) + "\n")
	}

	base := t.base
	if base == nil {
		base = http.DefaultTransport
	}
	resp, err := base.RoundTrip(req)
	if err != nil {
		os.Stderr.WriteString("<<< transport error: " + err.Error() + "\n")
		return nil, err
	}

	if dump, err := httputil.DumpResponse(resp, true); err == nil {
		os.Stderr.WriteString("<<< " + redactDump(dump) + "\n")
	}
	return resp, nil
}

func redactDump(dump []byte) string {
	s := authHeaderRE.ReplaceAllString(string(dump), "$1: ***")
	s = secretBodyRE.ReplaceAllString(s, "${1}${2}***")
	return strings.TrimRight(s, "\r\n")
}
