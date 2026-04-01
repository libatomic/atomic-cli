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
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	bolt "go.etcd.io/bbolt"
)

var (
	idmapBucket   = []byte("idmap")
	cardmapBucket = []byte("cardmap")
)

// idMapStore is a persistent key-value store backed by bbolt for tracking
// old ID → new ID mappings during stripe import. Each type gets its own
// file (e.g. customers.map.db) keeping the import state file small.
//
// Values in the idmap bucket are stored as "newID\x00hash" where hash is
// the SHA-256 hex digest of the source JSONL record. This allows the import
// to detect when a record has changed and only update it if needed.
type idMapStore struct {
	db *bolt.DB
}

// openIDMapStore opens or creates a bbolt database at path.
func openIDMapStore(path string) (*idMapStore, error) {
	db, err := bolt.Open(path, 0600, &bolt.Options{NoSync: true})
	if err != nil {
		return nil, fmt.Errorf("failed to open id map store %s: %w", path, err)
	}

	err = db.Update(func(tx *bolt.Tx) error {
		if _, err := tx.CreateBucketIfNotExists(idmapBucket); err != nil {
			return err
		}
		if _, err := tx.CreateBucketIfNotExists(cardmapBucket); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to initialize id map store: %w", err)
	}

	return &idMapStore{db: db}, nil
}

// Put stores an old→new ID mapping with the source record hash.
func (s *idMapStore) Put(oldID, newID, hash string) error {
	val := newID + "\x00" + hash
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(idmapBucket).Put([]byte(oldID), []byte(val))
	})
}

// Get retrieves the new ID and source hash for an old ID.
// Returns ("", "", false) if not found.
func (s *idMapStore) Get(oldID string) (newID string, hash string, found bool) {
	s.db.View(func(tx *bolt.Tx) error {
		v := tx.Bucket(idmapBucket).Get([]byte(oldID))
		if v != nil {
			found = true
			parts := bytes.SplitN(v, []byte{0}, 2)
			newID = string(parts[0])
			if len(parts) > 1 {
				hash = string(parts[1])
			}
		}
		return nil
	})
	return
}

// Has returns true if the old ID exists in the store.
func (s *idMapStore) Has(oldID string) bool {
	_, _, found := s.Get(oldID)
	return found
}

// Changed returns true if the old ID exists but its stored hash differs
// from the provided hash. Returns false if the ID is not in the store.
func (s *idMapStore) Changed(oldID, currentHash string) bool {
	_, storedHash, found := s.Get(oldID)
	if !found {
		return false
	}
	return storedHash != currentHash
}

// PutCard stores a customer→payment method mapping.
func (s *idMapStore) PutCard(customerID, pmID string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(cardmapBucket).Put([]byte(customerID), []byte(pmID))
	})
}

// GetCard retrieves the payment method ID for a customer.
func (s *idMapStore) GetCard(customerID string) (string, bool) {
	var val string
	var found bool
	s.db.View(func(tx *bolt.Tx) error {
		v := tx.Bucket(cardmapBucket).Get([]byte(customerID))
		if v != nil {
			val = string(v)
			found = true
		}
		return nil
	})
	return val, found
}

// Count returns the number of entries in the ID map.
func (s *idMapStore) Count() int {
	var count int
	s.db.View(func(tx *bolt.Tx) error {
		count = tx.Bucket(idmapBucket).Stats().KeyN
		return nil
	})
	return count
}

// CardCount returns the number of entries in the card map.
func (s *idMapStore) CardCount() int {
	var count int
	s.db.View(func(tx *bolt.Tx) error {
		count = tx.Bucket(cardmapBucket).Stats().KeyN
		return nil
	})
	return count
}

// Sync forces a sync of the database to disk.
func (s *idMapStore) Sync() error {
	return s.db.Sync()
}

// Close syncs and closes the database.
func (s *idMapStore) Close() error {
	if err := s.db.Sync(); err != nil {
		s.db.Close()
		return err
	}
	return s.db.Close()
}

// recordHash computes a SHA-256 hex digest of a record's canonical JSON representation.
// Go's json.Marshal produces deterministic output for structs (field declaration order)
// and sorts map keys lexicographically, so this is stable across runs.
func recordHash(v any) string {
	data, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}
