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
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSaveCredentialsPreservesOthersAndStripsClientCreds(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "credentials")

	// seed: a default profile with client creds and a second profile
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	seed := "[default]\nhost = \"old.example.com\"\nclient_id = \"id\"\nclient_secret = \"secret\"\nout_format = \"json\"\n\n[staging]\nhost = \"staging.example.com\"\naccess_token = \"tok\"\n"
	if err := os.WriteFile(path, []byte(seed), 0o600); err != nil {
		t.Fatal(err)
	}

	removed, err := saveCredentials(path, "default", map[string]string{
		"host":         "new.example.com",
		"access_token": "CfWBScAgZmUzpjfnFb6t2",
		"login":        "ada@example.com",
	}, []string{"client_id", "client_secret"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(removed, ",") != "client_id,client_secret" {
		t.Fatalf("removed = %v", removed)
	}

	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %o, want 600", fi.Mode().Perm())
	}

	cf := loadCredentials(path)
	if v, _ := cf.Lookup("default", "host"); v != "new.example.com" {
		t.Fatalf("host = %q", v)
	}
	if v, _ := cf.Lookup("default", "out_format"); v != "json" {
		t.Fatalf("out_format lost: %q", v)
	}
	if _, ok := cf.Lookup("default", "client_secret"); ok {
		t.Fatal("client_secret still present")
	}
	if v, _ := cf.Lookup("staging", "access_token"); v != "tok" {
		t.Fatalf("other profile damaged: %q", v)
	}
	if got := cf.Profiles(); strings.Join(got, ",") != "default,staging" {
		t.Fatalf("profiles not sorted: %v", got)
	}

	// logout path: unset token fields, keep host
	if _, err := saveCredentials(path, "default", nil, []string{"access_token", "login"}); err != nil {
		t.Fatal(err)
	}
	cf = loadCredentials(path)
	if _, ok := cf.Lookup("default", "access_token"); ok {
		t.Fatal("access_token still present after logout")
	}
	if v, _ := cf.Lookup("default", "host"); v != "new.example.com" {
		t.Fatalf("host lost on logout: %q", v)
	}
}

func TestSaveCredentialsCreatesFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".atomic", "credentials")
	if _, err := saveCredentials(path, "default", map[string]string{"host": "h", "access_token": "t"}, nil); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "[default]") || !strings.Contains(string(data), "access_token = \"t\"") {
		t.Fatalf("unexpected contents:\n%s", data)
	}
}

func TestNormalizeHost(t *testing.T) {
	cases := map[string]string{
		"stratechery.passport.online":            "stratechery.passport.online",
		"https://Stratechery.Passport.Online/":   "stratechery.passport.online",
		"http://beets.rob.modelrocket.io/admin/": "beets.rob.modelrocket.io",
		"  host.example.com?x=1 ":                "host.example.com",
	}
	for in, want := range cases {
		if got := normalizeHost(in); got != want {
			t.Errorf("normalizeHost(%q) = %q, want %q", in, got, want)
		}
	}
}
