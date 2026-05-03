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
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/gob"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/lensesio/tableprinter"
	"github.com/libatomic/atomic/pkg/atomic"
	"github.com/libatomic/atomic/pkg/oauth"
	"github.com/libatomic/atomic/pkg/ptr"
	"github.com/urfave/cli/v3"
)

const (
	defaultSessionCookieName = "_atomic_session"
)

var (
	sessionCmd = &cli.Command{
		Name:  "session",
		Usage: "session diagnostics",
		Commands: []*cli.Command{
			sessionDecodeCmd,
			sessionCookieCmd,
		},
	}

	sessionCookieCmd = &cli.Command{
		Name:      "cookie",
		Usage:     "decode an atomic session cookie (gorilla/sessions format) and print its structure",
		ArgsUsage: "<cookie-value>",
		Description: "Atomic uses gorilla/sessions which produces a cookie of the form " +
			"<date>|<value>|<mac> (optionally wrapped in an outer base64 layer). This command " +
			"decodes that envelope and surfaces the timestamp, value structure, and HMAC. The " +
			"value itself is encrypted with the instance's block cipher key — if --hash-key " +
			"and --block-key are provided, the inner session payload is decrypted and printed; " +
			"otherwise just the envelope is shown. Reads from stdin when no value is given.",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  "session-key",
				Usage: "raw session key (the same string atomic stores in instance.session_key); sha512'd to derive the hash + block keys. when --instance_id is set this defaults to the instance's session_key automatically",
			},
			&cli.StringFlag{
				Name:  "hash-key",
				Usage: "explicit hash key (base64 or hex); overrides --session-key derivation",
			},
			&cli.StringFlag{
				Name:  "block-key",
				Usage: "explicit block key (base64 or hex); overrides --session-key derivation",
			},
			&cli.StringFlag{
				Name:  "name",
				Usage: "cookie name used for MAC verification; defaults to the instance's session_cookie when --instance_id is set, else _atomic_session",
				Value: defaultSessionCookieName,
			},
			&cli.BoolFlag{
				Name:  "session",
				Usage: "include the decoded session values block in the report. when none of --session/--user/--application are set, all three are included (default).",
			},
			&cli.BoolFlag{
				Name:  "user",
				Usage: "include the resolved user block (id, login, roles, ...). same default behavior as --session.",
			},
			&cli.BoolFlag{
				Name:  "application",
				Usage: "include the resolved application block (id, name, client_id, ...). same default behavior as --session.",
			},
		},
		Action: sessionCookieAction,
	}

	sessionDecodeCmd = &cli.Command{
		Name:      "decode",
		Usage:     "decode a browser HAR file: client info, atomic session cookie, and a request/response report with simple diagnostics",
		ArgsUsage: "<file.har>",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  "cookie-name",
				Usage: "atomic session cookie name (instance can override; default: _atomic_session). When --instance_id is set, this is auto-detected from the instance's session_cookie field.",
				Value: defaultSessionCookieName,
			},
			&cli.StringFlag{
				Name:  "host",
				Usage: "filter requests to this host (default: auto-detected from the session cookie's domain or the instance host)",
			},
			&cli.IntFlag{
				Name:  "max-body",
				Usage: "max bytes of error response body to print per failing request",
				Value: 600,
			},
			&cli.BoolFlag{
				Name:  "all",
				Usage: "disable the host filter and include every request in the report (default: only requests to the instance host are shown)",
			},
			&cli.BoolFlag{
				Name:  "markdown",
				Usage: "render the report as Markdown (set --markdown=false for the plain-text format)",
				Value: true,
			},
			&cli.StringFlag{
				Name:    "out",
				Aliases: []string{"O"},
				Usage:   "write the report to a file instead of stdout",
			},
		},
		Action: sessionDecodeAction,
	}
)

// harFile is a partial schema for the HTTP Archive 1.2 format. Only the
// fields used by the decoder are listed.
type (
	harFile struct {
		Log harLog `json:"log"`
	}

	harLog struct {
		Version string     `json:"version"`
		Creator harCreator `json:"creator"`
		Browser harCreator `json:"browser"`
		Pages   []harPage  `json:"pages"`
		Entries []harEntry `json:"entries"`
	}

	harCreator struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	}

	harPage struct {
		StartedDateTime string `json:"startedDateTime"`
		ID              string `json:"id"`
		Title           string `json:"title"`
	}

	harEntry struct {
		StartedDateTime string      `json:"startedDateTime"`
		Time            float64     `json:"time"`
		Request         harRequest  `json:"request"`
		Response        harResponse `json:"response"`
		ServerIPAddress string      `json:"serverIPAddress"`
		Connection      string      `json:"connection"`
	}

	harRequest struct {
		Method      string       `json:"method"`
		URL         string       `json:"url"`
		HTTPVersion string       `json:"httpVersion"`
		Headers     []harHeader  `json:"headers"`
		Cookies     []harCookie  `json:"cookies"`
		QueryString []harHeader  `json:"queryString"`
		PostData    *harPostData `json:"postData,omitempty"`
	}

	harPostData struct {
		MimeType string      `json:"mimeType"`
		Text     string      `json:"text"`
		Params   []harHeader `json:"params,omitempty"`
	}

	harResponse struct {
		Status      int         `json:"status"`
		StatusText  string      `json:"statusText"`
		HTTPVersion string      `json:"httpVersion"`
		Headers     []harHeader `json:"headers"`
		Cookies     []harCookie `json:"cookies"`
		Content     harContent  `json:"content"`
	}

	harHeader struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	}

	harCookie struct {
		Name     string `json:"name"`
		Value    string `json:"value"`
		Path     string `json:"path"`
		Domain   string `json:"domain"`
		Expires  string `json:"expires"`
		HTTPOnly bool   `json:"httpOnly"`
		Secure   bool   `json:"secure"`
	}

	harContent struct {
		Size     int64  `json:"size"`
		MimeType string `json:"mimeType"`
		Text     string `json:"text"`
		Encoding string `json:"encoding"`
	}
)

func sessionDecodeAction(ctx context.Context, cmd *cli.Command) error {
	if cmd.NArg() < 1 {
		return fmt.Errorf("har file path is required")
	}
	path := cmd.Args().First()

	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read har file: %w", err)
	}

	var har harFile
	if err := json.Unmarshal(data, &har); err != nil {
		return fmt.Errorf("failed to parse har file: %w", err)
	}

	cookieName := cmd.String("cookie-name")
	// when --instance_id is set, the atomic instance may override the cookie
	// name via SessionCookieVal — pull it through so the decoder picks the
	// right cookie automatically
	if !cmd.IsSet("cookie-name") && inst != nil && inst.SessionCookieVal != "" {
		cookieName = inst.SessionCookieVal
	}

	showAll := cmd.Bool("all")

	hostFilter := cmd.String("host")
	if hostFilter == "" && !showAll {
		hostFilter = autoDetectHost(har, cookieName)
		// fall back to the global --host (the instance API host) so requests
		// to that endpoint get filtered in even when no Set-Cookie is in the
		// HAR (e.g. trace started after the session was already established)
		if hostFilter == "" {
			if h := mainCmd.String("host"); h != "" {
				hostFilter = stripHostScheme(h)
			}
		}
	}
	if showAll {
		hostFilter = "" // --all disables host filtering entirely
	}
	maxBody := int(cmd.Int("max-body"))
	markdown := cmd.Bool("markdown")

	out := os.Stdout
	if outPath := cmd.String("out"); outPath != "" {
		f, err := os.Create(outPath)
		if err != nil {
			return fmt.Errorf("failed to create %s: %w", outPath, err)
		}
		defer f.Close()
		out = f
	}

	if markdown {
		renderMarkdownReport(out, path, har, cookieName, hostFilter, maxBody, showAll)
	} else {
		renderTextReport(out, path, har, cookieName, hostFilter, maxBody, showAll)
	}
	return nil
}

func sessionCookieAction(ctx context.Context, cmd *cli.Command) error {
	var raw string
	if cmd.NArg() >= 1 {
		raw = cmd.Args().First()
	} else {
		buf, err := io.ReadAll(os.Stdin)
		if err != nil {
			return fmt.Errorf("failed to read cookie value from stdin: %w", err)
		}
		raw = strings.TrimSpace(string(buf))
	}
	if raw == "" {
		return fmt.Errorf("cookie value is required (pass as arg or pipe to stdin)")
	}

	// tolerate "name=value" form (e.g. directly pasted Cookie: header chunk)
	if eq := strings.IndexByte(raw, '='); eq > 0 {
		candidate := strings.TrimSpace(raw[eq+1:])
		// only strip the leading "name=" if what follows still looks like a
		// cookie value — JWT (two dots) or gorilla envelope (two pipes) or
		// a long base64-ish blob.
		if strings.Count(candidate, ".") == 2 ||
			strings.Count(candidate, "|") >= 2 ||
			(len(candidate) > 32 && !strings.ContainsAny(candidate, " \t")) {
			raw = candidate
		}
	}
	if dec, err := url.QueryUnescape(raw); err == nil {
		raw = dec
	}

	cookieName := cmd.String("name")
	if !cmd.IsSet("name") && inst != nil && inst.SessionCookieVal != "" {
		cookieName = inst.SessionCookieVal
	}

	// Try JWT first (some atomic surfaces issue JWT-shaped cookies).
	if header, claims, ok := parseJWTUnverified(raw); ok {
		out := map[string]any{
			"format": "jwt",
			"header": header,
			"claims": claims,
		}
		pretty, err := json.MarshalIndent(out, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(pretty))
		return nil
	}

	// Otherwise decode as gorilla/sessions envelope.
	env, err := decodeGorillaCookie(raw)
	if err != nil {
		return fmt.Errorf("cookie is neither a JWT nor a gorilla/sessions cookie: %w", err)
	}

	out := map[string]any{
		"format":            "gorilla/sessions",
		"cookie_name":       cookieName,
		"timestamp":         env.timestamp,
		"timestamp_human":   env.timestampHuman,
		"value_decoded_len": env.valueLen,
		"mac_base64":        env.macB64,
		"mac_len_bytes":     env.macLen,
	}

	// derive hash + block keys, in priority order:
	//   1. explicit --hash-key / --block-key flags
	//   2. --session-key flag (sha512 → 32+32)
	//   3. instance's session_key (when -i is set)
	//   4. atomic's compiled-in default keys
	hashKey, blockKey, keySource := resolveSessionKeys(cmd)
	if keySource != "" {
		out["key_source"] = keySource
	}

	// Section selection: when none of --session/--user/--application are
	// set the report includes all three; otherwise only the requested
	// blocks are returned. The cookie envelope is always included as it
	// contains the metadata that identifies the cookie itself.
	wantSession := cmd.Bool("session")
	wantUser := cmd.Bool("user")
	wantApp := cmd.Bool("application")
	if !wantSession && !wantUser && !wantApp {
		wantSession, wantUser, wantApp = true, true, true
	}

	macOK := false
	if hashKey != nil {
		macOK = env.verifyMAC(cookieName, hashKey)
		out["mac_verified"] = macOK
	}
	if blockKey != nil {
		// only attempt to decrypt + decode when the MAC verifies — otherwise
		// the keys are wrong (or the cookie was issued by a different
		// instance) and the gob "decode" would just be garbled bytes.
		if !macOK && hashKey != nil {
			out["values_skipped"] = "MAC did not verify; the session key in use does not match the issuer of this cookie"
		} else {
			plaintext, perr := env.decryptValue(blockKey)
			if perr != nil {
				out["decrypt_error"] = perr.Error()
			} else {
				values, derr := decodeSessionValues(plaintext)
				if derr != nil {
					out["decode_error"] = derr.Error()
					out["value_plaintext_hex"] = fmt.Sprintf("%x", plaintext)
				} else {
					rendered := renderSessionValues(values)
					if wantSession {
						out["values"] = rendered
					}
					// when -i is set, we have a backend client and the
					// instance UUID; resolve subject → user and
					// client_id → application so the report shows the
					// real principal/app rather than just opaque ids.
					if inst != nil && backend != nil {
						if wantUser {
							if u := lookupSessionUser(ctx, rendered); u != nil {
								out["user"] = u
							}
						}
						if wantApp {
							if app := lookupSessionApplication(ctx, rendered); app != nil {
								out["application"] = app
							}
						}
					}
				}
			}
		}
	}

	switch cmd.String("out-format") {
	case "json":
		b, err := json.Marshal(out)
		if err != nil {
			return err
		}
		fmt.Println(string(b))
	case "json-pretty", "jsonl", "ndjson":
		b, err := json.MarshalIndent(out, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(b))
	default:
		renderSessionCookieTables(os.Stdout, out)
	}
	return nil
}

// renderSessionCookieTables prints a clean per-section terminal table
// view of the decoded session cookie using lensesio/tableprinter (same
// renderer the rest of the cli uses). Inline error/skip notes appear
// between sections so they're impossible to miss. The global -o json /
// json-pretty flags still emit JSON for tooling.
func renderSessionCookieTables(w *os.File, out map[string]any) {
	// Cookie envelope — fixed column order so the most-relevant fields
	// (format, timestamp, mac state) sort to the top instead of being
	// alphabetized with low-signal entries.
	envelope := [][2]string{}
	add := func(k string) {
		if v, ok := out[k]; ok && v != nil && fmt.Sprintf("%v", v) != "" {
			envelope = append(envelope, [2]string{k, fmt.Sprintf("%v", v)})
		}
	}
	for _, k := range []string{
		"format", "cookie_name", "timestamp", "timestamp_human",
		"value_decoded_len", "mac_len_bytes", "mac_base64", "key_source",
	} {
		add(k)
	}
	if v, ok := out["mac_verified"]; ok {
		envelope = append(envelope, [2]string{"mac_verified", fmt.Sprintf("%v", v)})
	}

	fmt.Fprintln(w, "Cookie envelope")
	printKVTable(w, envelope)

	// Skip / error notes between sections.
	for _, k := range []string{"values_skipped", "decrypt_error", "decode_error", "hash_key_error", "block_key_error"} {
		if v, ok := out[k]; ok && v != "" {
			fmt.Fprintf(w, "\n%s: %v\n", k, v)
		}
	}

	if values, ok := out["values"].(map[string]any); ok && len(values) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "Session values")
		printKVTable(w, sortedKVRows(values))
	}

	if user, ok := out["user"].(map[string]any); ok && len(user) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "User")
		printKVTable(w, sortedKVRows(user))
	}

	if app, ok := out["application"].(map[string]any); ok && len(app) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "Application")
		printKVTable(w, sortedKVRows(app))
	}
}

// sortedKVRows turns a flat map[string]any into [field, value] rows in
// alphabetical order. Composite values (slices, nested maps) are JSON-
// encoded so they fit in a single cell.
func sortedKVRows(m map[string]any) [][2]string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	rows := make([][2]string, 0, len(keys))
	for _, k := range keys {
		var cell string
		switch x := m[k].(type) {
		case nil:
			cell = ""
		case string:
			cell = x
		case []any, map[string]any, oauth.Permissions, []string:
			b, err := json.Marshal(x)
			if err != nil {
				cell = fmt.Sprintf("%v", x)
			} else {
				cell = string(b)
			}
		default:
			cell = fmt.Sprintf("%v", x)
		}
		rows = append(rows, [2]string{k, cell})
	}
	return rows
}

// printKVTable renders a 2-column table (FIELD | VALUE) with the same
// borders/style the rest of the cli uses for consistency.
func printKVTable(w *os.File, rows [][2]string) {
	if len(rows) == 0 {
		return
	}
	stringRows := make([][]string, len(rows))
	for i, r := range rows {
		stringRows[i] = []string{r[0], r[1]}
	}
	p := tableprinter.New(w)
	p.BorderTop = true
	p.BorderBottom = true
	p.BorderLeft = true
	p.BorderRight = true
	p.ColumnSeparator = "|"
	p.HeaderAlignment = tableprinter.AlignCenter
	p.RowLine = true
	p.Render([]string{"FIELD", "VALUE"}, stringRows, nil, true)
}

// resolveSessionKeys produces the (hash, block) key pair used to decode an
// atomic session cookie, mirroring the way oauth/cookiestore.go resolves
// them at runtime: explicit flags > --session-key string > instance's
// SessionKeyVal > the compiled-in defaults. The returned source string is
// included in the report so callers can tell which path was taken.
func resolveSessionKeys(cmd *cli.Command) (hash, block []byte, source string) {
	if hk := cmd.String("hash-key"); hk != "" {
		if k, err := loadKeyMaterial(hk); err == nil {
			hash = k
			source = "explicit --hash-key/--block-key"
		}
	}
	if bk := cmd.String("block-key"); bk != "" {
		if k, err := loadKeyMaterial(bk); err == nil {
			block = k
			source = "explicit --hash-key/--block-key"
		}
	}
	if hash != nil && block != nil {
		return
	}

	deriveFrom := func(key, src string) {
		sha := sha512.Sum512([]byte(key))
		if hash == nil {
			hash = sha[0:32]
		}
		if block == nil {
			block = sha[32:64]
		}
		if source == "" {
			source = src
		}
	}

	if sk := cmd.String("session-key"); sk != "" {
		deriveFrom(sk, "--session-key")
	}
	if (hash == nil || block == nil) && inst != nil && inst.SessionKeyVal != nil && *inst.SessionKeyVal != "" {
		deriveFrom(*inst.SessionKeyVal, fmt.Sprintf("instance %s session_key", inst.UUID))
	}
	if hash == nil || block == nil {
		// Final fallback mirrors the runtime path in pkg/oauth/cookiestore.go:
		// the instance's SessionKey() returns atomic.DefaultSessionKey when
		// SessionKeyVal is nil, and the cookie store sha512s that string to
		// derive both keys. So a cookie issued for an instance with no
		// configured session_key is decodable with sha512(DefaultSessionKey).
		deriveFrom(atomic.DefaultSessionKey, "atomic.DefaultSessionKey")
	}
	return
}

// decodeSessionValues gob-decodes the plaintext payload of an atomic
// session cookie. gorilla/sessions stores Session.Values as
// map[interface{}]interface{}, so the gob stream produced by the
// CookieStore's GobEncoder serializes that shape; the registered types
// below cover the values atomic puts in (strings + int64 timestamps +
// oauth.Permissions for scope).
func decodeSessionValues(plaintext []byte) (map[any]any, error) {
	out := make(map[any]any)
	dec := gob.NewDecoder(bytes.NewReader(plaintext))
	if err := dec.Decode(&out); err != nil {
		return nil, err
	}
	return out, nil
}

// renderSessionValues turns the map[any]any from gob into a friendlier
// shape: string keys, with timestamp claims rendered as RFC3339 alongside
// the original unix-seconds value.
func renderSessionValues(in map[any]any) map[string]any {
	out := make(map[string]any, len(in))
	for k, v := range in {
		key := fmt.Sprintf("%v", k)
		out[key] = v
		// auto-render the well-known timestamp keys for readability
		switch key {
		case "created_at", "expires_at":
			if ts, ok := toUnix(v); ok {
				out[key+"_human"] = time.Unix(ts, 0).UTC().Format(time.RFC3339)
			}
		}
	}
	return out
}

// lookupSessionUser resolves the user behind a decoded session by its
// stored "subject" (a UUID-string the cookie carries through Principal.
// Subject()). Falls back to the "login" claim if a subject lookup fails.
// Uses UserList with filters because atomic-go's UserGet only supports
// path-based lookup by UserID — and the session stores SubjectVal, not
// the UUID. Returns nil on any miss (failures are diagnostic-only).
func lookupSessionUser(ctx context.Context, values map[string]any) map[string]any {
	subject, _ := values["subject"].(string)
	login, _ := values["login"].(string)

	var u *atomic.User
	if subject != "" {
		users, _ := backend.UserList(ctx, &atomic.UserListInput{
			InstanceID: &inst.UUID,
			Subject:    &subject,
			Limit:      ptr.Uint64(1),
		})
		if len(users) > 0 {
			u = users[0]
		}
	}
	if u == nil && login != "" {
		users, _ := backend.UserList(ctx, &atomic.UserListInput{
			InstanceID: &inst.UUID,
			Login:      &login,
			Limit:      ptr.Uint64(1),
		})
		if len(users) > 0 {
			u = users[0]
		}
	}
	if u == nil {
		return nil
	}

	out := map[string]any{
		"id":      u.UUID.String(),
		"login":   u.LoginVal,
		"subject": u.SubjectVal.UUID().String(),
		"roles":   u.RolesVal,
	}
	if u.ProfileVal != nil {
		if u.ProfileVal.Name != "" {
			out["name"] = u.ProfileVal.Name
		}
		if u.ProfileVal.EmailClaim != nil && u.ProfileVal.EmailClaim.Email != nil {
			out["email"] = *u.ProfileVal.EmailClaim.Email
		}
	}
	return out
}

// lookupSessionApplication resolves the OAuth client (atomic Application)
// that issued the session by its client_id. atomic-go's ApplicationGet
// only supports path-based lookup by ApplicationID (not client_id), so
// we list all apps in the instance and match locally. Reasonable for a
// diagnostic command — instances rarely have hundreds of apps.
func lookupSessionApplication(ctx context.Context, values map[string]any) map[string]any {
	clientID, _ := values["client_id"].(string)
	if clientID == "" {
		return nil
	}
	apps, err := backend.ApplicationList(ctx, &atomic.ApplicationListInput{
		InstanceID: inst.UUID,
	})
	if err != nil {
		return nil
	}
	var app *atomic.Application
	for _, a := range apps {
		if a.ClientIDVal == clientID {
			app = a
			break
		}
	}
	if app == nil {
		return nil
	}
	out := map[string]any{
		"id":          app.UUID.String(),
		"name":        app.Name,
		"client_id":   app.ClientIDVal,
		"description": app.Description,
	}
	if len(app.PermissionsVal) > 0 {
		out["permissions"] = app.PermissionsVal
	}
	if len(app.Grants) > 0 {
		out["allowed_grants"] = app.Grants
	}
	return out
}

func toUnix(v any) (int64, bool) {
	switch x := v.(type) {
	case int64:
		return x, true
	case int:
		return int64(x), true
	case float64:
		return int64(x), true
	}
	return 0, false
}

// gorillaEnvelope captures the parsed shape of a gorilla/sessions cookie:
// <date>|<base64(encrypted-value)>|<base64(mac)>, optionally wrapped in
// an outer base64 layer. We surface enough of the structure that the
// caller can spot anomalies (missing timestamp, suspiciously short MAC,
// etc.) without holding the signing key.
type gorillaEnvelope struct {
	innerBytes     []byte // the bytes that the MAC is computed over: name|date|value
	timestamp      int64
	timestampHuman string

	value    []byte // raw bytes of the inner value segment (still base64-encoded inside)
	valueB64 string
	valueLen int

	mac    []byte
	macB64 string
	macLen int
}

func decodeGorillaCookie(s string) (*gorillaEnvelope, error) {
	// gorilla outputs base64-URL-encoded bytes whose plaintext is
	// "date|value|mac". Some intermediaries (or hand-pasted samples) end
	// up with the inner format directly visible — try both.
	candidate := s
	if !strings.Contains(s, "|") {
		decoded, err := base64URLDecode(s)
		if err != nil {
			return nil, fmt.Errorf("base64 decode failed: %w", err)
		}
		candidate = string(decoded)
	}

	parts := strings.SplitN(candidate, "|", 3)
	if len(parts) != 3 {
		return nil, fmt.Errorf("expected 3 pipe-separated segments (date|value|mac), got %d", len(parts))
	}

	ts, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return nil, fmt.Errorf("first segment is not a unix timestamp: %q", parts[0])
	}

	// parts[1] is base64-encoded ciphertext; decode it for the eventual
	// AES-CTR step but also keep the base64 form for display.
	value, err := base64URLDecode(parts[1])
	if err != nil {
		value = []byte(parts[1])
	}
	// parts[2] is the RAW HMAC bytes (gorilla appends them directly after
	// the trailing pipe before the outer base64 encode). Re-base64 them
	// for display so the JSON output stays printable.
	macRaw := []byte(parts[2])

	// the bytes the MAC is computed over (before the trailing pipe got
	// stripped during encode): "<date>|<value-as-base64>"
	innerBytes := []byte(parts[0] + "|" + parts[1])

	return &gorillaEnvelope{
		innerBytes:     innerBytes,
		timestamp:      ts,
		timestampHuman: time.Unix(ts, 0).UTC().Format(time.RFC3339),
		value:          value,
		valueB64:       parts[1],
		valueLen:       len(value),
		mac:            macRaw,
		macB64:         base64.URLEncoding.EncodeToString(macRaw),
		macLen:         len(macRaw),
	}, nil
}

// verifyMAC reports whether the cookie's MAC matches the expected HMAC of
// "<name>|<date>|<value>" under the supplied hash key. Returns true only
// on full match. Mirrors gorilla/securecookie's createMac/verifyMac.
func (env *gorillaEnvelope) verifyMAC(name string, key []byte) bool {
	prefix := []byte(name + "|")
	msg := append(prefix, env.innerBytes...)
	h := hmac.New(sha256.New, key)
	h.Write(msg)
	expected := h.Sum(nil)
	return hmac.Equal(expected, env.mac)
}

// decryptValue decrypts the inner value using AES-CTR (the cipher
// gorilla/securecookie uses by default). The first aes.BlockSize bytes of
// env.value are the IV; the rest is the ciphertext.
func (env *gorillaEnvelope) decryptValue(key []byte) ([]byte, error) {
	if len(env.value) < aes.BlockSize {
		return nil, fmt.Errorf("encrypted value too short (%d bytes)", len(env.value))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes.NewCipher: %w", err)
	}
	iv := env.value[:aes.BlockSize]
	ct := env.value[aes.BlockSize:]
	pt := make([]byte, len(ct))
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(pt, ct)
	return pt, nil
}

// loadKeyMaterial accepts a key in one of three forms: base64 (URL or
// std), hex, or raw bytes already at the expected length. Mirrors how
// atomic / gorilla typically pass keys through env vars.
func loadKeyMaterial(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, fmt.Errorf("empty key")
	}
	if b, err := base64.StdEncoding.DecodeString(s); err == nil && len(b) >= 16 {
		return b, nil
	}
	if b, err := base64.URLEncoding.DecodeString(s); err == nil && len(b) >= 16 {
		return b, nil
	}
	if b, err := base64.RawStdEncoding.DecodeString(s); err == nil && len(b) >= 16 {
		return b, nil
	}
	if b, err := base64.RawURLEncoding.DecodeString(s); err == nil && len(b) >= 16 {
		return b, nil
	}
	if hx, err := hex.DecodeString(s); err == nil && len(hx) >= 16 {
		return hx, nil
	}
	if len(s) >= 16 {
		return []byte(s), nil
	}
	return nil, fmt.Errorf("could not decode key (need base64/hex/raw bytes, got %d chars)", len(s))
}

// note: gorilla/sessions encodes Session.Values (map[interface{}]interface{})
// with gob, so every concrete type stored in the map must be gob-registered
// somewhere in the import graph before decode. Atomic's pkg/oauth init()
// already registers oauth.Permissions (under its legacy internal/pkg path);
// importing the package pulls in that registration. If new types ever land
// in Session.Values, register them in pkg/oauth alongside Permissions so
// both the server and this decoder pick them up.
var _ = oauth.Permissions{}

// renderTextReport is the original plain-text layout, retained when the
// caller passes --markdown=false.
func renderTextReport(w *os.File, path string, har harFile, cookieName, hostFilter string, maxBody int, showAll bool) {
	fmt.Fprintf(w, "HAR file: %s\n", path)
	if har.Log.Version != "" {
		fmt.Fprintf(w, "  version: %s\n", har.Log.Version)
	}
	if har.Log.Creator.Name != "" {
		fmt.Fprintf(w, "  creator: %s %s\n", har.Log.Creator.Name, har.Log.Creator.Version)
	}
	if har.Log.Browser.Name != "" {
		fmt.Fprintf(w, "  browser: %s %s\n", har.Log.Browser.Name, har.Log.Browser.Version)
	}

	clientReport(w, har)
	cookieReport(w, har, cookieName)
	requestReport(w, har, hostFilter, maxBody, showAll)
}

// clientReport prints high-level info about the browser/client that produced
// the HAR: user-agent (taken from the most-seen request), referer, accept-
// language, the page list, the time range covered, and the unique remote
// IPs encountered.
func clientReport(w *os.File, har harFile) {
	if len(har.Log.Entries) == 0 {
		return
	}

	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Client")

	userAgents := tallyHeader(har.Log.Entries, "user-agent")
	if len(userAgents) > 0 {
		ua, count := topTally(userAgents)
		fmt.Fprintf(w, "  user-agent: %s\n", ua)
		if len(userAgents) > 1 {
			fmt.Fprintf(w, "    (%d distinct user-agents seen; primary used by %d requests)\n", len(userAgents), count)
		}
	}

	if accept := topHeader(har.Log.Entries, "accept-language"); accept != "" {
		fmt.Fprintf(w, "  accept-language: %s\n", accept)
	}
	if referer := topHeader(har.Log.Entries, "referer"); referer != "" {
		fmt.Fprintf(w, "  referer: %s\n", referer)
	}
	if origin := topHeader(har.Log.Entries, "origin"); origin != "" {
		fmt.Fprintf(w, "  origin: %s\n", origin)
	}

	ips := uniqueServerIPs(har.Log.Entries)
	if len(ips) > 0 {
		fmt.Fprintf(w, "  server ip(s): %s\n", strings.Join(ips, ", "))
	}

	first, last := timeRange(har.Log.Entries)
	if !first.IsZero() {
		fmt.Fprintf(w, "  time range: %s → %s (%s, %d entries)\n",
			first.UTC().Format(time.RFC3339), last.UTC().Format(time.RFC3339),
			last.Sub(first).Round(time.Millisecond), len(har.Log.Entries))
	}

	hosts := uniqueHosts(har.Log.Entries)
	if len(hosts) > 0 {
		fmt.Fprintf(w, "  hosts touched: %s\n", strings.Join(hosts, ", "))
	}

	if len(har.Log.Pages) > 0 {
		fmt.Fprintln(w, "  pages:")
		for _, p := range har.Log.Pages {
			fmt.Fprintf(w, "    - %s (%s)\n", p.Title, p.StartedDateTime)
		}
	}
}

// cookieReport finds the atomic session cookie (cookieName) in any of the
// HAR entries (request or set-cookie response) and prints what we can learn
// from it: cookie attributes (domain, path, secure, etc.) and a JWT decode
// of the cookie value when the value is JWT-shaped. Without the session
// signing key the JWT signature can't be verified, so we use the unverified
// parser purely to surface header + claims for inspection.
func cookieReport(w *os.File, har harFile, cookieName string) {
	fmt.Fprintln(w, "")
	fmt.Fprintf(w, "Session cookie: %s\n", cookieName)

	cookieValue, attrs, source := findCookie(har, cookieName)
	if cookieValue == "" {
		fmt.Fprintln(w, "  (not found in any request or set-cookie response)")
		return
	}

	fmt.Fprintf(w, "  source: %s\n", source)
	if attrs != nil {
		if attrs.Domain != "" {
			fmt.Fprintf(w, "  domain: %s\n", attrs.Domain)
		}
		if attrs.Path != "" {
			fmt.Fprintf(w, "  path: %s\n", attrs.Path)
		}
		if attrs.Expires != "" {
			fmt.Fprintf(w, "  expires: %s\n", attrs.Expires)
		}
		fmt.Fprintf(w, "  http-only: %v, secure: %v\n", attrs.HTTPOnly, attrs.Secure)
	}
	fmt.Fprintf(w, "  raw length: %d bytes\n", len(cookieValue))

	header, claims, ok := parseJWTUnverified(cookieValue)
	if !ok {
		fmt.Fprintln(w, "  value: (not JWT-shaped — likely gorilla/securecookie encoded; full decode requires the session signing key)")
		return
	}

	fmt.Fprintln(w, "  jwt header:")
		printIndentedJSON(w, "    ", header)
	fmt.Fprintln(w, "  jwt claims:")
		printIndentedJSON(w, "    ", claims)

	// surface common claim derivatives in a quick-glance form
	if expVal, ok := claims["exp"]; ok {
		if t, ok := claimToTime(expVal); ok {
			rel := time.Until(t).Round(time.Second)
			when := "expired"
			if rel > 0 {
				when = "expires in " + rel.String()
			}
			fmt.Fprintf(w, "  expiry: %s (%s)\n", t.UTC().Format(time.RFC3339), when)
		}
	}
	if iatVal, ok := claims["iat"]; ok {
		if t, ok := claimToTime(iatVal); ok {
			fmt.Fprintf(w, "  issued at: %s (%s ago)\n", t.UTC().Format(time.RFC3339), time.Since(t).Round(time.Second))
		}
	}
	if sub, ok := claims["sub"].(string); ok && sub != "" {
		fmt.Fprintf(w, "  subject: %s\n", sub)
	}
	if aud, ok := claims["aud"]; ok {
		fmt.Fprintf(w, "  audience: %v\n", aud)
	}
}

// requestReport walks the HAR entries (optionally restricted to hostFilter),
// emits a per-request line for failing/notable requests, and ends with a
// status-class summary plus a simple diagnosis.
func requestReport(w *os.File, har harFile, hostFilter string, maxBody int, showAll bool) {
	fmt.Fprintln(w, "")
	if hostFilter != "" {
		fmt.Fprintf(w, "Requests (filtered to host: %s)\n", hostFilter)
	} else {
		fmt.Fprintln(w, "Requests")
	}

	classes := map[string]*statusBucket{
		"2xx": {},
		"3xx": {},
		"4xx": {},
		"5xx": {},
		"0":   {}, // no response (connection failed / aborted)
	}

	matched := 0
	for _, e := range har.Log.Entries {
		host := requestHost(e.Request.URL)
		if hostFilter != "" && host != hostFilter {
			continue
		}
		matched++

		class := statusClass(e.Response.Status)
		b := classes[class]
		if b == nil {
			b = &statusBucket{}
			classes[class] = b
		}
		b.count++
		if len(b.urls) < 3 {
			b.urls = append(b.urls, briefURL(e.Request.URL))
		}

		// render individual entry: always for non-success, only on --all for 2xx/3xx
		if !showAll && (class == "2xx" || class == "3xx") {
			continue
		}

		fmt.Fprintf(w, "  [%s] %d %s %s\n", e.StartedDateTime, e.Response.Status, e.Request.Method, e.Request.URL)
		if e.Response.StatusText != "" && e.Response.Status >= 400 {
			fmt.Fprintf(w, "    statusText: %s\n", e.Response.StatusText)
		}
		if e.Response.Status >= 400 || e.Response.Status == 0 {
			body := truncateBody(e.Response.Content.Text, maxBody)
			if body != "" {
				fmt.Fprintf(w, "    body: %s\n", body)
			}
			if reason := errorHint(e.Response.Status); reason != "" {
				fmt.Fprintf(w, "    hint: %s\n", reason)
			}
		}
	}

	if matched == 0 {
		fmt.Fprintln(w, "  (no requests matched the host filter)")
		return
	}

	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Summary")
	for _, k := range []string{"2xx", "3xx", "4xx", "5xx", "0"} {
		b := classes[k]
		if b == nil || b.count == 0 {
			continue
		}
		fmt.Fprintf(w, "  %s: %d\n", k, b.count)
	}
	fmt.Fprintf(w, "  total: %d\n", matched)

	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Diagnosis")
	for _, line := range diagnose(classes, matched) {
		fmt.Fprintf(w, "  - %s\n", line)
	}
}

// statusBucket holds a request count and a few sample URLs for a status
// class. Used by requestReport / diagnose to summarize HAR entries.
type statusBucket struct {
	count int
	urls  []string
}

// diagnose translates the status-class counts into a small set of plain-
// language hints: server-side instability vs auth failures vs misuse, etc.
func diagnose(classes map[string]*statusBucket, total int) []string {
	get := func(k string) *statusBucket {
		v, ok := classes[k]
		if !ok || v == nil {
			return nil
		}
		return v
	}

	var notes []string

	if v := get("5xx"); v != nil && v.count > 0 {
		notes = append(notes, fmt.Sprintf("%d server-side error response(s) (5xx) — investigate the API service / upstream dependencies (see %s)", v.count, joinSamples(v.urls)))
	}
	if v := get("0"); v != nil && v.count > 0 {
		notes = append(notes, fmt.Sprintf("%d request(s) with no response — likely network failure, CORS preflight, or aborted client-side", v.count))
	}

	if v := get("4xx"); v != nil && v.count > 0 {
		// distinguish auth from generic 4xx via the URLs we sampled
		notes = append(notes, fmt.Sprintf("%d client error response(s) (4xx) — check authentication, request shape, or path", v.count))
	}

	if v := get("2xx"); v != nil && v.count > 0 && total == v.count {
		notes = append(notes, "all requests succeeded — no API-level issue is visible in this HAR")
	}

	if len(notes) == 0 {
		notes = append(notes, "no notable failures detected")
	}
	return notes
}

func errorHint(status int) string {
	switch {
	case status == 0:
		return "no response — connection failure, CORS preflight, or aborted before the server replied"
	case status == 401:
		return "unauthenticated — session cookie missing/expired or access_token rejected"
	case status == 403:
		return "forbidden — caller authenticated but lacks permission for this resource"
	case status == 404:
		return "not found — wrong path or the resource doesn't exist in this instance"
	case status == 409:
		return "conflict — duplicate or concurrent-modification"
	case status == 422 || status == 400:
		return "bad request — validation/shape problem in the request body or query"
	case status == 429:
		return "rate limited — back off and retry"
	case status >= 500 && status < 600:
		return "server error — investigate the api logs for this entry's timestamp"
	}
	return ""
}

// findCookie searches HAR entries for the named cookie, preferring response
// Set-Cookie (which gives us the attributes) over request cookies. Returns
// the value, attributes when available, and a human-readable source label.
func findCookie(har harFile, name string) (string, *harCookie, string) {
	// prefer response set-cookie (has attributes)
	for _, e := range har.Log.Entries {
		for _, c := range e.Response.Cookies {
			if c.Name == name {
				cc := c
				return c.Value, &cc, fmt.Sprintf("Set-Cookie on %s %s", e.Request.Method, briefURL(e.Request.URL))
			}
		}
	}
	// fall back to request Cookie header
	for _, e := range har.Log.Entries {
		for _, c := range e.Request.Cookies {
			if c.Name == name {
				cc := c
				return c.Value, &cc, fmt.Sprintf("Cookie header on %s %s", e.Request.Method, briefURL(e.Request.URL))
			}
		}
		// some browsers don't populate request.cookies but include the raw
		// header — try parsing the Cookie: header too
		for _, h := range e.Request.Headers {
			if strings.EqualFold(h.Name, "cookie") {
				if v := cookieFromRawHeader(h.Value, name); v != "" {
					return v, nil, fmt.Sprintf("Cookie: header on %s %s", e.Request.Method, briefURL(e.Request.URL))
				}
			}
		}
	}
	return "", nil, ""
}

// cookieFromRawHeader returns the first matching cookie value from a raw
// Cookie: header string of the form "a=1; b=2".
func cookieFromRawHeader(header, name string) string {
	for _, p := range strings.Split(header, ";") {
		p = strings.TrimSpace(p)
		eq := strings.IndexByte(p, '=')
		if eq < 0 {
			continue
		}
		if p[:eq] == name {
			return p[eq+1:]
		}
	}
	return ""
}

// parseJWTUnverified splits a JWT into its header/claims and base64url-
// decodes them. Returns ok=false when the value doesn't have the 3-segment
// shape or the segments don't decode to JSON. Signature verification is
// intentionally skipped — without the session signing key we couldn't
// verify anyway, and the caller just wants to inspect the claims.
func parseJWTUnverified(token string) (header, claims map[string]any, ok bool) {
	// JWTs are URL-encoded sometimes; tolerate both.
	if dec, err := url.QueryUnescape(token); err == nil {
		token = dec
	}

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, nil, false
	}

	hb, err := base64URLDecode(parts[0])
	if err != nil {
		return nil, nil, false
	}
	if err := json.Unmarshal(hb, &header); err != nil {
		return nil, nil, false
	}

	cb, err := base64URLDecode(parts[1])
	if err != nil {
		return nil, nil, false
	}
	if err := json.Unmarshal(cb, &claims); err != nil {
		return nil, nil, false
	}

	return header, claims, true
}

func base64URLDecode(s string) ([]byte, error) {
	// JWTs use unpadded base64url
	if pad := len(s) % 4; pad != 0 {
		s += strings.Repeat("=", 4-pad)
	}
	return base64.URLEncoding.DecodeString(s)
}

func claimToTime(v any) (time.Time, bool) {
	switch x := v.(type) {
	case float64:
		return time.Unix(int64(x), 0), true
	case int64:
		return time.Unix(x, 0), true
	case json.Number:
		n, err := x.Int64()
		if err == nil {
			return time.Unix(n, 0), true
		}
	}
	return time.Time{}, false
}

func printIndentedJSON(w *os.File, indent string, v any) {
	out, err := json.MarshalIndent(v, indent, "  ")
	if err != nil {
		fmt.Fprintf(w, "%s%v\n", indent, v)
		return
	}
	fmt.Fprintf(w, "%s%s\n", indent, string(out))
}

func tallyHeader(entries []harEntry, name string) map[string]int {
	out := map[string]int{}
	for _, e := range entries {
		v := getHeader(e.Request.Headers, name)
		if v == "" {
			continue
		}
		out[v]++
	}
	return out
}

func topTally(t map[string]int) (string, int) {
	type pair struct {
		v string
		c int
	}
	pairs := make([]pair, 0, len(t))
	for v, c := range t {
		pairs = append(pairs, pair{v, c})
	}
	sort.Slice(pairs, func(i, j int) bool { return pairs[i].c > pairs[j].c })
	if len(pairs) == 0 {
		return "", 0
	}
	return pairs[0].v, pairs[0].c
}

func topHeader(entries []harEntry, name string) string {
	t := tallyHeader(entries, name)
	v, _ := topTally(t)
	return v
}

func getHeader(headers []harHeader, name string) string {
	for _, h := range headers {
		if strings.EqualFold(h.Name, name) {
			return h.Value
		}
	}
	return ""
}

func uniqueServerIPs(entries []harEntry) []string {
	seen := map[string]bool{}
	var ips []string
	for _, e := range entries {
		if e.ServerIPAddress == "" {
			continue
		}
		if !seen[e.ServerIPAddress] {
			seen[e.ServerIPAddress] = true
			ips = append(ips, e.ServerIPAddress)
		}
	}
	sort.Strings(ips)
	return ips
}

func uniqueHosts(entries []harEntry) []string {
	seen := map[string]bool{}
	var hosts []string
	for _, e := range entries {
		h := requestHost(e.Request.URL)
		if h == "" || seen[h] {
			continue
		}
		seen[h] = true
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)
	return hosts
}

func timeRange(entries []harEntry) (first, last time.Time) {
	for _, e := range entries {
		t, err := time.Parse(time.RFC3339Nano, e.StartedDateTime)
		if err != nil {
			t, err = time.Parse(time.RFC3339, e.StartedDateTime)
		}
		if err != nil {
			continue
		}
		if first.IsZero() || t.Before(first) {
			first = t
		}
		if t.After(last) {
			last = t
		}
	}
	return
}

func requestHost(u string) string {
	parsed, err := url.Parse(u)
	if err != nil {
		return ""
	}
	return parsed.Host
}

func briefURL(u string) string {
	parsed, err := url.Parse(u)
	if err != nil {
		return u
	}
	if parsed.RawQuery != "" {
		return parsed.Path + "?…"
	}
	return parsed.Path
}

func statusClass(status int) string {
	switch {
	case status == 0:
		return "0"
	case status < 300:
		return "2xx"
	case status < 400:
		return "3xx"
	case status < 500:
		return "4xx"
	default:
		return "5xx"
	}
}

func truncateBody(s string, max int) string {
	s = strings.TrimSpace(s)
	if max <= 0 || len(s) <= max {
		return s
	}
	return s[:max] + "…"
}

func joinSamples(urls []string) string {
	if len(urls) == 0 {
		return ""
	}
	return strings.Join(urls, ", ")
}

// autoDetectHost tries to identify the atomic API host from the HAR. First
// checks any Set-Cookie response carrying the named session cookie; if no
// hit, falls back to atomic-go's DefaultAPIHost when that host appears in
// the HAR. Returns "" when nothing reasonable can be guessed.
func autoDetectHost(har harFile, cookieName string) string {
	for _, e := range har.Log.Entries {
		for _, c := range e.Response.Cookies {
			if c.Name == cookieName {
				return requestHost(e.Request.URL)
			}
		}
	}
	// fallback: any host that received the cookie in the request
	for _, e := range har.Log.Entries {
		for _, c := range e.Request.Cookies {
			if c.Name == cookieName {
				return requestHost(e.Request.URL)
			}
		}
	}
	return ""
}

// reference atomic.Instance to keep the import in case session_cookie
// detection above is not exercised in some build path
var _ = atomic.Instance{}

// classifyRequest tags a HAR entry by the surface it's hitting:
//
//	"oauth"  — /oauth/*, /.well-known/*, well-known auth endpoints
//	"api"    — atomic REST surface (/api/<version>/...)
//	"app"    — instance app paths like /member, /admin (HTML / static)
//	"other"  — everything else (third-party assets, telemetry, etc.)
//
// Used by the request summary so the reader can see at a glance which
// calls are authentication-flow vs business-logic vs app shell vs noise.
func classifyRequest(u string) string {
	parsed, err := url.Parse(u)
	if err != nil || parsed.Path == "" {
		return "other"
	}
	p := strings.ToLower(parsed.Path)
	switch {
	case strings.HasPrefix(p, "/oauth/"),
		strings.HasPrefix(p, "/.well-known/"),
		strings.HasSuffix(p, "/jwks.json"),
		strings.HasSuffix(p, "/openid-configuration"):
		return "oauth"
	case strings.HasPrefix(p, "/api/"):
		return "api"
	case strings.HasPrefix(p, "/member"),
		strings.HasPrefix(p, "/admin"),
		strings.HasPrefix(p, "/auth/"),
		strings.HasPrefix(p, "/login"),
		strings.HasPrefix(p, "/logout"):
		return "app"
	}
	return "other"
}

// resolveBackendMethod returns the atomic-side method name a request maps
// to (for the "method" column of the request summary). Returns "" for
// classifications that don't have a meaningful internal mapping.
//
// API mapping mirrors atomic-go's path conventions:
//
//	GET    /api/<v>/<resource>            → atomic.<Resource>List
//	GET    /api/<v>/<resource>/<id>       → atomic.<Resource>Get
//	POST   /api/<v>/<resource>            → atomic.<Resource>Create
//	PUT    /api/<v>/<resource>/<id>       → atomic.<Resource>Update
//	PATCH  /api/<v>/<resource>/<id>       → atomic.<Resource>Update
//	DELETE /api/<v>/<resource>/<id>       → atomic.<Resource>Delete
//
// Sub-resource paths (e.g. /api/v/<resource>/<id>/<verb>) get a best-
// effort name combining the parent resource and the verb.
func resolveBackendMethod(method, u string) string {
	parsed, err := url.Parse(u)
	if err != nil {
		return ""
	}
	p := parsed.Path
	switch classifyRequest(u) {
	case "oauth":
		return resolveOAuthMethod(p)
	case "api":
		return resolveAPIMethod(method, p)
	}
	return ""
}

func resolveOAuthMethod(path string) string {
	switch {
	case strings.HasSuffix(path, "/.well-known/openid-configuration"),
		path == "/.well-known/openid-configuration":
		return "oauth.OpenIDConfiguration"
	case strings.HasSuffix(path, "/jwks.json"):
		return "oauth.JWKS"
	case strings.HasSuffix(path, "/authorize"):
		return "oauth.Authorize"
	case strings.HasSuffix(path, "/token"):
		return "oauth.Token"
	case strings.HasSuffix(path, "/userinfo"):
		return "oauth.UserInfo"
	case strings.HasSuffix(path, "/login"):
		return "oauth.Login"
	case strings.HasSuffix(path, "/logout"):
		return "oauth.Logout"
	case strings.HasSuffix(path, "/revoke"):
		return "oauth.Revoke"
	case strings.HasSuffix(path, "/introspect"):
		return "oauth.Introspect"
	}
	return ""
}

func resolveAPIMethod(method, path string) string {
	// Locate the resource segment(s) by walking the path looking for an
	// "api" segment optionally followed by a version segment. This handles
	// "/api/1.0.0/instances", "/api/v1/instances", and "/api/instances"
	// equally well, plus deployments where the api is mounted under a
	// gateway prefix like "/passport/api/1.0.0/instances".
	parts := strings.Split(strings.Trim(path, "/"), "/")
	apiIdx := -1
	for i, seg := range parts {
		if seg == "api" {
			apiIdx = i
			break
		}
	}
	if apiIdx < 0 {
		return ""
	}
	parts = parts[apiIdx+1:]
	if len(parts) > 0 && looksLikeVersion(parts[0]) {
		parts = parts[1:]
	}
	if len(parts) == 0 {
		return ""
	}

	resource := titleCase(singularize(parts[0]))
	if resource == "" {
		return ""
	}

	hasID := len(parts) >= 2 && parts[1] != ""
	hasSub := len(parts) >= 3 && parts[2] != ""

	if hasSub {
		sub := titleCase(strings.ReplaceAll(parts[2], "-", ""))
		return "atomic." + resource + sub
	}

	verb := ""
	switch strings.ToUpper(method) {
	case "GET":
		if hasID {
			verb = "Get"
		} else {
			verb = "List"
		}
	case "POST":
		verb = "Create"
	case "PUT", "PATCH":
		verb = "Update"
	case "DELETE":
		verb = "Delete"
	default:
		verb = titleCase(strings.ToLower(method))
	}
	return "atomic." + resource + verb
}

// looksLikeVersion matches "1.0.0", "v1", "v2.1" — keeps the second
// resolveAPIMethod check loose so atomic's "/api/1.0.0/" and any future
// "/api/v2/..." style both work.
func looksLikeVersion(s string) bool {
	if s == "" {
		return false
	}
	if s[0] == 'v' || s[0] == 'V' {
		s = s[1:]
	}
	if s == "" {
		return false
	}
	for _, r := range s {
		if !(r == '.' || (r >= '0' && r <= '9')) {
			return false
		}
	}
	return true
}

// singularize handles the small set of plural→singular shapes atomic uses
// for API resources. Falls back to dropping a trailing 's' when present.
func singularize(s string) string {
	switch s {
	case "categories":
		return "category"
	case "audiences":
		return "audience"
	case "addresses":
		return "address"
	}
	if strings.HasSuffix(s, "ies") {
		return s[:len(s)-3] + "y"
	}
	if strings.HasSuffix(s, "s") {
		return s[:len(s)-1]
	}
	return s
}

func titleCase(s string) string {
	if s == "" {
		return ""
	}
	// strip trailing format suffix and IDs that obviously aren't a verb
	if i := strings.IndexByte(s, '.'); i > 0 {
		s = s[:i]
	}
	parts := strings.FieldsFunc(s, func(r rune) bool { return r == '_' || r == '-' })
	for i, p := range parts {
		if p == "" {
			continue
		}
		parts[i] = strings.ToUpper(p[:1]) + p[1:]
	}
	return strings.Join(parts, "")
}

// renderMarkdownReport emits the HAR analysis as Markdown: # / ## headings,
// pipe-tables for the client/summary/request detail blocks, and fenced JSON
// blocks for the JWT decode. Same data as the text mode; just formatted for
// pasting into a ticket / wiki / PR description.
func renderMarkdownReport(w *os.File, path string, har harFile, cookieName, hostFilter string, maxBody int, showAll bool) {
	fmt.Fprintf(w, "# Session decode: %s\n\n", path)
	if har.Log.Version != "" || har.Log.Creator.Name != "" || har.Log.Browser.Name != "" {
		fmt.Fprintln(w, "| field | value |")
		fmt.Fprintln(w, "|---|---|")
		if har.Log.Version != "" {
			fmt.Fprintf(w, "| HAR version | %s |\n", har.Log.Version)
		}
		if har.Log.Creator.Name != "" {
			fmt.Fprintf(w, "| creator | %s %s |\n", mdEscape(har.Log.Creator.Name), mdEscape(har.Log.Creator.Version))
		}
		if har.Log.Browser.Name != "" {
			fmt.Fprintf(w, "| browser | %s %s |\n", mdEscape(har.Log.Browser.Name), mdEscape(har.Log.Browser.Version))
		}
		fmt.Fprintln(w)
	}

	mdClientReport(w, har)
	mdCookieReport(w, har, cookieName)
	mdRequestReport(w, har, hostFilter, maxBody, showAll)
}

func mdClientReport(w *os.File, har harFile) {
	if len(har.Log.Entries) == 0 {
		return
	}
	fmt.Fprintln(w, "## Client")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "| field | value |")
	fmt.Fprintln(w, "|---|---|")

	if uas := tallyHeader(har.Log.Entries, "user-agent"); len(uas) > 0 {
		ua, count := topTally(uas)
		extra := ""
		if len(uas) > 1 {
			extra = fmt.Sprintf(" *(primary, used by %d of %d distinct UAs)*", count, len(uas))
		}
		fmt.Fprintf(w, "| user-agent | `%s`%s |\n", mdEscapeCode(ua), extra)
	}
	if v := topHeader(har.Log.Entries, "accept-language"); v != "" {
		fmt.Fprintf(w, "| accept-language | %s |\n", mdEscape(v))
	}
	if v := topHeader(har.Log.Entries, "referer"); v != "" {
		fmt.Fprintf(w, "| referer | %s |\n", mdEscape(v))
	}
	if v := topHeader(har.Log.Entries, "origin"); v != "" {
		fmt.Fprintf(w, "| origin | %s |\n", mdEscape(v))
	}
	if ips := uniqueServerIPs(har.Log.Entries); len(ips) > 0 {
		fmt.Fprintf(w, "| server ip(s) | %s |\n", mdEscape(strings.Join(ips, ", ")))
	}
	if first, last := timeRange(har.Log.Entries); !first.IsZero() {
		fmt.Fprintf(w, "| time range | %s → %s (%s, %d entries) |\n",
			first.UTC().Format(time.RFC3339), last.UTC().Format(time.RFC3339),
			last.Sub(first).Round(time.Millisecond), len(har.Log.Entries))
	}
	if hosts := uniqueHosts(har.Log.Entries); len(hosts) > 0 {
		fmt.Fprintf(w, "| hosts touched | %s |\n", mdEscape(strings.Join(hosts, ", ")))
	}
	fmt.Fprintln(w)

	if len(har.Log.Pages) > 0 {
		fmt.Fprintln(w, "**Pages:**")
		fmt.Fprintln(w)
		for _, p := range har.Log.Pages {
			fmt.Fprintf(w, "- %s *(%s)*\n", mdEscape(p.Title), p.StartedDateTime)
		}
		fmt.Fprintln(w)
	}
}

func mdCookieReport(w *os.File, har harFile, cookieName string) {
	fmt.Fprintf(w, "## Session cookie: `%s`\n\n", cookieName)
	cookieValue, attrs, source := findCookie(har, cookieName)
	if cookieValue == "" {
		fmt.Fprintln(w, "_not found in any request or set-cookie response_")
		fmt.Fprintln(w)
		return
	}

	fmt.Fprintln(w, "| field | value |")
	fmt.Fprintln(w, "|---|---|")
	fmt.Fprintf(w, "| source | %s |\n", mdEscape(source))
	fmt.Fprintf(w, "| raw length | %d bytes |\n", len(cookieValue))
	if attrs != nil {
		if attrs.Domain != "" {
			fmt.Fprintf(w, "| domain | %s |\n", mdEscape(attrs.Domain))
		}
		if attrs.Path != "" {
			fmt.Fprintf(w, "| path | %s |\n", mdEscape(attrs.Path))
		}
		if attrs.Expires != "" {
			fmt.Fprintf(w, "| expires | %s |\n", mdEscape(attrs.Expires))
		}
		fmt.Fprintf(w, "| http-only | %v |\n", attrs.HTTPOnly)
		fmt.Fprintf(w, "| secure | %v |\n", attrs.Secure)
	}
	fmt.Fprintln(w)

	header, claims, ok := parseJWTUnverified(cookieValue)
	if !ok {
		fmt.Fprintln(w, "_value is not JWT-shaped — likely gorilla/securecookie encoded; full decode requires the session signing key._")
		fmt.Fprintln(w)
		return
	}

	fmt.Fprintln(w, "**JWT header**")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "```json")
	mdEmitJSON(w, header)
	fmt.Fprintln(w, "```")
	fmt.Fprintln(w)

	fmt.Fprintln(w, "**JWT claims**")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "```json")
	mdEmitJSON(w, claims)
	fmt.Fprintln(w, "```")
	fmt.Fprintln(w)

	rows := [][2]string{}
	if expVal, ok := claims["exp"]; ok {
		if t, ok := claimToTime(expVal); ok {
			rel := time.Until(t).Round(time.Second)
			when := "expired"
			if rel > 0 {
				when = "expires in " + rel.String()
			}
			rows = append(rows, [2]string{"expiry", fmt.Sprintf("%s (%s)", t.UTC().Format(time.RFC3339), when)})
		}
	}
	if iatVal, ok := claims["iat"]; ok {
		if t, ok := claimToTime(iatVal); ok {
			rows = append(rows, [2]string{"issued at", fmt.Sprintf("%s (%s ago)", t.UTC().Format(time.RFC3339), time.Since(t).Round(time.Second))})
		}
	}
	if sub, ok := claims["sub"].(string); ok && sub != "" {
		rows = append(rows, [2]string{"subject", sub})
	}
	if aud, ok := claims["aud"]; ok {
		rows = append(rows, [2]string{"audience", fmt.Sprintf("%v", aud)})
	}
	if len(rows) > 0 {
		fmt.Fprintln(w, "| field | value |")
		fmt.Fprintln(w, "|---|---|")
		for _, r := range rows {
			fmt.Fprintf(w, "| %s | %s |\n", r[0], mdEscape(r[1]))
		}
		fmt.Fprintln(w)
	}
}

func mdRequestReport(w *os.File, har harFile, hostFilter string, maxBody int, _ bool) {
	if hostFilter != "" {
		fmt.Fprintf(w, "## Requests *(filtered to host: `%s`)*\n\n", hostFilter)
	} else {
		fmt.Fprintln(w, "## Requests")
		fmt.Fprintln(w)
	}

	classes := map[string]*statusBucket{
		"2xx": {}, "3xx": {}, "4xx": {}, "5xx": {}, "0": {},
	}

	matches := make([]harEntry, 0, len(har.Log.Entries))
	for _, e := range har.Log.Entries {
		host := requestHost(e.Request.URL)
		if hostFilter != "" && host != hostFilter {
			continue
		}
		matches = append(matches, e)

		class := statusClass(e.Response.Status)
		b := classes[class]
		if b == nil {
			b = &statusBucket{}
			classes[class] = b
		}
		b.count++
		if len(b.urls) < 3 {
			b.urls = append(b.urls, briefURL(e.Request.URL))
		}
	}
	matched := len(matches)

	if matched == 0 {
		fmt.Fprintln(w, "_no requests matched the host filter_")
		fmt.Fprintln(w)
		return
	}

	// === Request summary (one row per request, no body/headers) ===
	fmt.Fprintln(w, "### Request summary")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "| # | time | host | type | endpoint | status | backend method |")
	fmt.Fprintln(w, "|---:|---|---|---|---|---:|---|")
	for i, e := range matches {
		statusCell := fmt.Sprintf("%d", e.Response.Status)
		if e.Response.Status == 0 {
			statusCell = "—"
		}
		path := pathOnly(e.Request.URL)
		methodName := resolveBackendMethod(e.Request.Method, e.Request.URL)
		methodCell := ""
		if methodName != "" {
			methodCell = "`" + methodName + "`"
		}
		// endpoint combines HTTP method + path so the summary fits in a
		// reasonable terminal/preview width without a separate column.
		endpoint := fmt.Sprintf("`%s %s`", e.Request.Method, mdEscapeCode(path))
		fmt.Fprintf(w, "| %d | %s | %s | %s | %s | %s | %s |\n",
			i+1,
			shortTime(e.StartedDateTime),
			mdEscape(requestHost(e.Request.URL)),
			classifyRequest(e.Request.URL),
			endpoint,
			statusCell,
			methodCell,
		)
	}
	fmt.Fprintln(w)

	// === Request detail — drills into every entry the summary lists. The
	// host-filter / --all behavior already happened upstream when we built
	// `matches`, so detail and summary are always in sync.
	fmt.Fprintln(w, "### Request detail")
	fmt.Fprintln(w)
	for i, e := range matches {
		mdRenderRequestDetail(w, i+1, e, maxBody)
	}

	// === Summary by status class ===
	fmt.Fprintln(w, "### Summary")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "| status class | count |")
	fmt.Fprintln(w, "|---|---:|")
	for _, k := range []string{"2xx", "3xx", "4xx", "5xx", "0"} {
		b := classes[k]
		if b == nil || b.count == 0 {
			continue
		}
		fmt.Fprintf(w, "| %s | %d |\n", k, b.count)
	}
	fmt.Fprintf(w, "| **total** | **%d** |\n", matched)
	fmt.Fprintln(w)

	// === Diagnosis ===
	fmt.Fprintln(w, "### Diagnosis")
	fmt.Fprintln(w)
	for _, line := range diagnose(classes, matched) {
		fmt.Fprintf(w, "- %s\n", line)
	}
	fmt.Fprintln(w)
}

// mdRenderRequestDetail prints one request's full picture: timestamp,
// method+path, optional query-param table, request body (pretty when
// JSON), response status + body (pretty when JSON), and a hint when the
// status indicates a known failure mode.
func mdRenderRequestDetail(w *os.File, idx int, e harEntry, maxBody int) {
	parsed, _ := url.Parse(e.Request.URL)
	path := ""
	host := ""
	if parsed != nil {
		path = parsed.Path
		host = parsed.Host
	}
	if path == "" {
		path = e.Request.URL
	}

	// Show the backend method right in the heading for oauth/api calls so
	// the reader can map a row to its atomic-side handler at a glance.
	backendMethod := resolveBackendMethod(e.Request.Method, e.Request.URL)
	heading := fmt.Sprintf("#### %d. `%s %s`", idx, e.Request.Method, path)
	if backendMethod != "" {
		heading += fmt.Sprintf(" → `%s`", backendMethod)
	}
	fmt.Fprintln(w, heading)
	fmt.Fprintln(w)

	// Per-request meta table — keeps the most-used fields close to the
	// top so the reader doesn't have to scan the whole block to spot the
	// status / type / backend method.
	fmt.Fprintln(w, "| field | value |")
	fmt.Fprintln(w, "|---|---|")
	fmt.Fprintf(w, "| time | %s |\n", e.StartedDateTime)
	if host != "" {
		fmt.Fprintf(w, "| host | %s |\n", mdEscape(host))
	}
	kind := classifyRequest(e.Request.URL)
	fmt.Fprintf(w, "| type | %s |\n", kind)
	if backendMethod != "" {
		switch kind {
		case "oauth":
			fmt.Fprintf(w, "| oauth method | `%s` |\n", backendMethod)
		case "api":
			fmt.Fprintf(w, "| atomic method | `%s` |\n", backendMethod)
		default:
			fmt.Fprintf(w, "| backend method | `%s` |\n", backendMethod)
		}
	}
	statusCell := fmt.Sprintf("%d %s", e.Response.Status, e.Response.StatusText)
	if e.Response.Status == 0 {
		statusCell = "— (no response)"
	}
	fmt.Fprintf(w, "| status | %s |\n", mdEscape(strings.TrimSpace(statusCell)))
	fmt.Fprintf(w, "| duration | %.0fms |\n", e.Time)
	fmt.Fprintln(w)

	// Query params — render only when present, as a small kv table.
	if parsed != nil && parsed.RawQuery != "" {
		fmt.Fprintln(w, "**Query parameters**")
		fmt.Fprintln(w)
		fmt.Fprintln(w, "| name | value |")
		fmt.Fprintln(w, "|---|---|")
		// preserve original order from the HAR queryString block when
		// available; fall back to url.ParseQuery (alphabetical).
		if len(e.Request.QueryString) > 0 {
			for _, q := range e.Request.QueryString {
				fmt.Fprintf(w, "| `%s` | `%s` |\n", mdEscapeCode(q.Name), mdEscapeCode(q.Value))
			}
		} else if vals, err := url.ParseQuery(parsed.RawQuery); err == nil {
			keys := make([]string, 0, len(vals))
			for k := range vals {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				for _, v := range vals[k] {
					fmt.Fprintf(w, "| `%s` | `%s` |\n", mdEscapeCode(k), mdEscapeCode(v))
				}
			}
		}
		fmt.Fprintln(w)
	}

	// Request body — present on POST/PUT/PATCH; pretty when JSON.
	if reqBody := requestBodyText(e); reqBody != "" {
		fmt.Fprintln(w, "**Request body**")
		fmt.Fprintln(w)
		emitFencedBody(w, reqBody, maxBody)
	}

	// Response body — pretty when JSON, raw otherwise.
	if respBody := strings.TrimSpace(e.Response.Content.Text); respBody != "" {
		fmt.Fprintln(w, "**Response body**")
		fmt.Fprintln(w)
		emitFencedBody(w, respBody, maxBody)
	}

	// Hint for known failure modes.
	if hint := errorHint(e.Response.Status); hint != "" {
		fmt.Fprintf(w, "**Hint:** %s\n\n", hint)
	}
}

// stripHostScheme normalizes a value like "https://api.example.com:443/foo"
// down to the bare "host[:port]" form harEntry.Request.URL parses to, so a
// global --host flag value compares correctly against requestHost(...).
func stripHostScheme(h string) string {
	h = strings.TrimSpace(h)
	if h == "" {
		return ""
	}
	if !strings.Contains(h, "://") {
		// allow bare "host[:port]" or "host[:port]/path" forms
		if i := strings.IndexByte(h, '/'); i >= 0 {
			h = h[:i]
		}
		return h
	}
	u, err := url.Parse(h)
	if err != nil || u.Host == "" {
		return h
	}
	return u.Host
}

// shortTime extracts the HH:MM:SS portion of an RFC3339 timestamp; falls
// back to the input when parsing fails so the column never goes blank.
func shortTime(s string) string {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		t, err = time.Parse(time.RFC3339, s)
	}
	if err != nil {
		return s
	}
	return t.UTC().Format("15:04:05")
}

// mdEscape escapes pipe characters so cell content doesn't break the table
// layout; the rest of GFM's special chars are left alone for readability.
func mdEscape(s string) string {
	return strings.ReplaceAll(s, "|", `\|`)
}

// mdEscapeCode escapes a value going inside a `…` span — backticks need to
// be replaced with a unicode lookalike (or the span breaks). Pipes still
// need escaping for the surrounding table cell.
func mdEscapeCode(s string) string {
	s = strings.ReplaceAll(s, "`", "ʼ")
	return strings.ReplaceAll(s, "|", `\|`)
}

// pathOnly returns the URL's path with no query string. Used by the
// request summary so paths fit cleanly in a table cell.
func pathOnly(u string) string {
	parsed, err := url.Parse(u)
	if err != nil || parsed.Path == "" {
		return u
	}
	return parsed.Path
}

// requestBodyText returns the request body text from a HAR entry's
// postData block, or "" when there's no body (GETs, etc.) or the body
// wasn't captured.
func requestBodyText(e harEntry) string {
	if e.Request.PostData == nil {
		return ""
	}
	return e.Request.PostData.Text
}

// emitFencedBody writes a body to the report. JSON bodies are reformatted
// with json.Indent for readability; everything else is fenced as-is.
// Truncates to maxBody bytes so a runaway response can't blow up the
// report.
func emitFencedBody(w *os.File, body string, maxBody int) {
	body = strings.TrimSpace(body)
	if body == "" {
		return
	}
	if maxBody > 0 && len(body) > maxBody {
		body = body[:maxBody] + "\n…(truncated)"
	}

	// detect JSON shape; pretty-print if so.
	trimmed := strings.TrimSpace(body)
	if (strings.HasPrefix(trimmed, "{") && strings.HasSuffix(trimmed, "}")) ||
		(strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]")) {
		var v any
		if err := json.Unmarshal([]byte(trimmed), &v); err == nil {
			pretty, err := json.MarshalIndent(v, "", "  ")
			if err == nil {
				fmt.Fprintln(w, "```json")
				fmt.Fprintln(w, string(pretty))
				fmt.Fprintln(w, "```")
				fmt.Fprintln(w)
				return
			}
		}
	}

	fmt.Fprintln(w, "```")
	fmt.Fprintln(w, body)
	fmt.Fprintln(w, "```")
	fmt.Fprintln(w)
}

func mdEmitJSON(w *os.File, v any) {
	out, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		fmt.Fprintf(w, "%v\n", v)
		return
	}
	fmt.Fprintln(w, string(out))
}
