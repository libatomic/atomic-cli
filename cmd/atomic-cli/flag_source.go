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
	"fmt"

	"github.com/BurntSushi/toml"
	altsrc "github.com/urfave/cli-altsrc/v3"
	"gopkg.in/yaml.v2"
)

type (
	DynamicKeySource struct {
		key     func() string
		desc    string
		sourcer altsrc.Sourcer
		um      func([]byte, any) error
	}
)

func NewDynamicKeySource(f func([]byte, any) error, desc string, key func() string, uriSrc altsrc.Sourcer) *DynamicKeySource {
	return &DynamicKeySource{
		key:     key,
		desc:    desc,
		sourcer: uriSrc,
		um:      f,
	}
}

func (d *DynamicKeySource) Lookup() (string, bool) {
	maafsc := altsrc.NewMapAnyAnyURISourceCache(d.sourcer.SourceURI(), d.um)
	if v, ok := altsrc.NestedVal(d.key(), maafsc.Get()); ok {
		return fmt.Sprintf("%[1]v", v), ok
	}

	return "", false
}

func (d *DynamicKeySource) String() string {
	return fmt.Sprintf("%s file %[2]q at key %[3]q", d.desc, d.sourcer.SourceURI(), d.key())
}

func (d *DynamicKeySource) GoString() string {
	return fmt.Sprintf("%sValueSource{file:%[2]q,keyPath:%[3]q}", d.desc, d.sourcer.SourceURI(), d.key())
}

func TOML(key func() string, source altsrc.Sourcer) *DynamicKeySource {
	return NewDynamicKeySource(toml.Unmarshal, "toml", key, source)
}

func YAML(key func() string, source altsrc.Sourcer) *DynamicKeySource {
	return NewDynamicKeySource(yaml.Unmarshal, "yaml", key, source)
}

// CredentialsSource looks up <profile>.<field> in the cli credentials file.
// It uses the loadCredentials cache so the file is parsed exactly once per
// path regardless of how many flags reference it. Both YAML and TOML are
// supported transparently.
type CredentialsSource struct {
	pathFn    func() string
	profileFn func() string
	field     string
}

func NewCredentialsSource(field string, pathFn, profileFn func() string) *CredentialsSource {
	return &CredentialsSource{
		pathFn:    pathFn,
		profileFn: profileFn,
		field:     field,
	}
}

func (c *CredentialsSource) Lookup() (string, bool) {
	cf := loadCredentials(c.pathFn())
	return cf.Lookup(c.profileFn(), c.field)
}

func (c *CredentialsSource) String() string {
	return fmt.Sprintf("credentials file %q profile %q field %q", c.pathFn(), c.profileFn(), c.field)
}

func (c *CredentialsSource) GoString() string {
	return fmt.Sprintf("CredentialsSource{file:%q,profile:%q,field:%q}", c.pathFn(), c.profileFn(), c.field)
}
