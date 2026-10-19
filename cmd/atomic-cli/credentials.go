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
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"

	"github.com/BurntSushi/toml"
	"github.com/apex/log"
	"gopkg.in/yaml.v2"
)

// credentialsFile is a parsed view of ~/.atomic/credentials.
// Both YAML and TOML are accepted; whichever parser succeeds wins.
type credentialsFile struct {
	profiles map[string]map[string]string
	path     string
	loaded   bool
	// parseErrors collected from each attempted parser; only logged when the
	// file exists, has content, and neither parser produced a usable result
	parseErrors []string
}

var (
	credsCache  = map[string]*credentialsFile{}
	credsCacheM sync.Mutex
)

// loadCredentials reads and parses the credentials file at the given path.
// Results are cached per-path so callers can invoke this from every flag
// source without re-reading the file.
func loadCredentials(path string) *credentialsFile {
	credsCacheM.Lock()
	defer credsCacheM.Unlock()

	if cf, ok := credsCache[path]; ok {
		return cf
	}

	cf := &credentialsFile{path: path, profiles: map[string]map[string]string{}}
	credsCache[path] = cf

	data, err := os.ReadFile(path)
	if err != nil {
		// missing/unreadable: leave empty so all lookups simply return ""
		// (only complain if it's not just a missing file)
		if !os.IsNotExist(err) {
			log.Warnf("credentials: failed to read %s: %s", path, err)
		}
		return cf
	}
	if len(data) == 0 {
		return cf
	}

	// Try TOML first (atomic-cli's default format). If parse fails, try YAML.
	parsed, tomlErr := tryParse(data, toml.Unmarshal)
	if tomlErr == nil && len(parsed) > 0 {
		cf.profiles = parsed
		cf.loaded = true
		return cf
	}
	if tomlErr != nil {
		cf.parseErrors = append(cf.parseErrors, fmt.Sprintf("toml: %s", tomlErr))
	}

	parsed, yamlErr := tryParse(data, yaml.Unmarshal)
	if yamlErr == nil && len(parsed) > 0 {
		cf.profiles = parsed
		cf.loaded = true
		return cf
	}
	if yamlErr != nil {
		cf.parseErrors = append(cf.parseErrors, fmt.Sprintf("yaml: %s", yamlErr))
	}

	// neither parser produced anything — surface the errors so the user knows
	// their credentials file is broken instead of silently falling back to
	// the default API host
	log.Warnf("credentials: %s could not be parsed; falling back to defaults", path)
	for _, e := range cf.parseErrors {
		log.Warnf("credentials: %s", e)
	}
	log.Warnf("credentials: run `atomic-cli login <instance>` to recreate it")

	return cf
}

// tryParse runs the unmarshaler and returns the normalized profiles. An empty
// result with a nil error means the file parsed but didn't contain any
// profile-shaped sections (so the caller may want to try the next parser).
func tryParse(data []byte, unmarshaler func([]byte, any) error) (map[string]map[string]string, error) {
	parsed, ok := parseCredentialsBytes(data, unmarshaler)
	if !ok {
		// parseCredentialsBytes returns false either when unmarshal failed or
		// when there were no profile sections; re-run the unmarshaler to
		// distinguish so we can report a real parse error
		var probe map[string]any
		if err := unmarshaler(data, &probe); err != nil {
			var probeAny map[any]any
			if err2 := unmarshaler(data, &probeAny); err2 != nil {
				return nil, err
			}
		}
		return nil, nil
	}
	return parsed, nil
}

// parseCredentialsBytes runs an unmarshaler and normalizes the resulting tree
// into map[profile]map[field]string. Returns false when the file does not
// look like a profile-shaped document.
func parseCredentialsBytes(data []byte, unmarshaler func([]byte, any) error) (map[string]map[string]string, bool) {
	var raw map[string]any
	if err := unmarshaler(data, &raw); err != nil {
		// gopkg.in/yaml.v2 may produce map[interface{}]interface{} at the top
		// level — try that shape too.
		var rawAny map[any]any
		if err2 := unmarshaler(data, &rawAny); err2 != nil {
			return nil, false
		}
		raw = make(map[string]any, len(rawAny))
		for k, v := range rawAny {
			if ks, ok := k.(string); ok {
				raw[ks] = v
			}
		}
	}

	out := make(map[string]map[string]string, len(raw))
	for k, v := range raw {
		fields, ok := normalizeProfileFields(v)
		if !ok {
			// not a profile-shaped value (e.g. top-level scalar) — skip
			continue
		}
		out[k] = fields
	}
	if len(out) == 0 {
		return nil, false
	}
	return out, true
}

// normalizeProfileFields converts whatever the YAML/TOML decoder returned
// for a profile section into map[field]string.
func normalizeProfileFields(raw any) (map[string]string, bool) {
	switch v := raw.(type) {
	case map[string]any:
		out := make(map[string]string, len(v))
		for k, val := range v {
			out[k] = fmt.Sprintf("%v", val)
		}
		return out, true
	case map[any]any:
		out := make(map[string]string, len(v))
		for k, val := range v {
			ks, ok := k.(string)
			if !ok {
				continue
			}
			out[ks] = fmt.Sprintf("%v", val)
		}
		return out, true
	}
	return nil, false
}

// Lookup returns the named field for the named profile, or "" + false when
// either the profile or field is missing.
func (c *credentialsFile) Lookup(profile, field string) (string, bool) {
	if c == nil || c.profiles == nil {
		return "", false
	}
	fields, ok := c.profiles[profile]
	if !ok {
		return "", false
	}
	v, ok := fields[field]
	return v, ok
}

// Profiles returns the list of profile names known in the file (sorted).
func (c *credentialsFile) Profiles() []string {
	if c == nil || c.profiles == nil {
		return nil
	}
	names := make([]string, 0, len(c.profiles))
	for k := range c.profiles {
		names = append(names, k)
	}
	sort.Strings(names)
	return names
}

// saveCredentials updates one profile in the credentials file: fields in
// set are written, fields in unset are removed, everything else (other
// fields, other profiles) is preserved. The file is written as TOML with
// mode 0600 via a temp file and rename, and the in-memory cache for the
// path is dropped. It returns the names of unset fields that were present.
func saveCredentials(path, prof string, set map[string]string, unset []string) ([]string, error) {
	profiles := map[string]map[string]string{}
	if existing := loadCredentials(path); existing != nil {
		for name, fields := range existing.profiles {
			cp := make(map[string]string, len(fields))
			for k, v := range fields {
				cp[k] = v
			}
			profiles[name] = cp
		}
	}

	fields := profiles[prof]
	if fields == nil {
		fields = map[string]string{}
		profiles[prof] = fields
	}

	var removed []string
	for _, k := range unset {
		if _, ok := fields[k]; ok {
			removed = append(removed, k)
			delete(fields, k)
		}
	}
	for k, v := range set {
		fields[k] = v
	}
	if len(fields) == 0 {
		delete(profiles, prof)
	}

	var buf bytes.Buffer
	buf.WriteString("# Managed by atomic-cli. Run `atomic-cli login <instance>` to sign in.\n\n")
	if err := toml.NewEncoder(&buf).Encode(profiles); err != nil {
		return nil, fmt.Errorf("encode credentials: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create %s: %w", filepath.Dir(path), err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, buf.Bytes(), 0o600); err != nil {
		return nil, fmt.Errorf("write %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return nil, fmt.Errorf("replace %s: %w", path, err)
	}
	_ = os.Chmod(path, 0o600)

	credsCacheM.Lock()
	delete(credsCache, path)
	credsCacheM.Unlock()

	sort.Strings(removed)
	return removed, nil
}
