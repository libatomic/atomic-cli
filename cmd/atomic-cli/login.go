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
	"bufio"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	client "github.com/libatomic/atomic-go/v2"
	"github.com/libatomic/atomic/v2/pkg/atomic"
	"github.com/urfave/cli/v3"
	"golang.org/x/term"
)

type (
	// instanceConfig is the subset of /.well-known/config.json the login
	// flow needs.
	instanceConfig struct {
		Aud struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"aud"`
		AdminBasePath    string `json:"admin_basepath"`
		CLITokenLifetime int64  `json:"cli_token_lifetime"`
	}

	// principal is the subset of /oauth/userPrincipal the login flow needs.
	principal struct {
		ID      string   `json:"id"`
		Login   string   `json:"login"`
		Roles   []string `json:"roles"`
		Profile struct {
			Email string `json:"email"`
		} `json:"profile"`
	}

	// whoamiInfo is the output of `atomic-cli whoami`.
	whoamiInfo struct {
		Host       string `json:"host"`
		InstanceID string `json:"instance_id,omitempty"`
		Login      string `json:"login,omitempty"`
		UserID     string `json:"user_id,omitempty"`
		Auth       string `json:"auth"`
		TokenID    string `json:"token_id,omitempty"`
		ExpiresAt  string `json:"expires_at,omitempty"`
		ExpiresIn  string `json:"expires_in,omitempty"`
		Deprecated bool   `json:"deprecated_client_credentials,omitempty"`
	}
)

const (
	// credential file fields written by login
	credHost       = "host"
	credInstanceID = "instance_id"
	credToken      = "access_token"
	credTokenID    = "token_id"
	credExpiresAt  = "expires_at"
	credLogin      = "login"
	credUserID     = "user_id"
	credClientID   = "client_id"
	credSecret     = "client_secret"

	cliAuthorizePath = "/cli/authorize"
	loginHTTPTimeout = 15 * time.Second
)

var (
	loginCmd = &cli.Command{
		Name:      "login",
		Usage:     "sign in to an instance through the admin app and store a personal token (replaces client credentials)",
		ArgsUsage: "<instance>",
		Metadata:  localMeta(),
		Flags: []cli.Flag{
			&cli.BoolFlag{
				Name:  "no-browser",
				Usage: "print the authorization URL without trying to open a browser",
			},
		},
		Action: loginAction,
	}

	logoutCmd = &cli.Command{
		Name:     "logout",
		Usage:    "revoke the stored token and forget it",
		Metadata: localMeta(),
		Action:   logoutAction,
	}

	whoamiCmd = &cli.Command{
		Name:     "whoami",
		Usage:    "show which instance and account the CLI is using and when the token expires",
		Metadata: readOnlyLocalMeta(),
		Action:   whoamiAction,
	}
)

func loginAction(ctx context.Context, cmd *cli.Command) error {
	host := normalizeHost(cmd.Args().First())
	if host == "" {
		return errors.New("usage: atomic-cli login <instance>, e.g. atomic-cli login stratechery.passport.online")
	}

	cfg, err := fetchInstanceConfig(ctx, host)
	if err != nil {
		return fmt.Errorf("%s does not look like a Passport instance: %w", host, err)
	}
	if cfg.CLITokenLifetime == 0 {
		return fmt.Errorf("%s does not support CLI login yet (its server predates PSPT-780); ask the operator to upgrade", host)
	}

	state, err := randomState()
	if err != nil {
		return err
	}

	device, _ := os.Hostname()
	base := strings.TrimSuffix(cfg.AdminBasePath, "/")
	if base == "" {
		base = "/admin"
	}
	authURL := fmt.Sprintf("https://%s%s%s?%s", host, base, cliAuthorizePath, url.Values{
		"state":  {state},
		"device": {device},
		"v":      {Version},
	}.Encode())

	fmt.Fprintf(os.Stderr, "Open this URL in your browser to authorize atomic-cli on %s:\n\n  %s\n\n", host, authURL)
	if !cmd.Bool("no-browser") && interactive() {
		if err := openBrowser(authURL); err == nil {
			fmt.Fprintln(os.Stderr, "(a browser window should have opened)")
		}
	}

	token, err := readSecret("Paste the token shown in the browser: ")
	if err != nil {
		return err
	}
	if token == "" {
		return errors.New("no token entered")
	}

	api := client.New(client.WithHost(host), client.WithToken(token))

	who, err := fetchPrincipal(ctx, host, token)
	if err != nil {
		return fmt.Errorf("the token was not accepted by %s: %w", host, err)
	}
	if !contains(who.Roles, "admin") {
		return fmt.Errorf("%s is signed in as %s, which is not an administrator on %s", "the token", who.Login, host)
	}

	tokenID, err := atomic.ParseID(token)
	if err != nil {
		return errors.New("that does not look like a token issued by the authorization page (expected a stored token id)")
	}
	instID, err := atomic.ParseID(cfg.Aud.ID)
	if err != nil {
		return fmt.Errorf("instance id from config: %w", err)
	}

	rec, err := api.AccessTokenGet(ctx, &atomic.AccessTokenGetInput{
		InstanceID:    &instID,
		AccessTokenID: &tokenID,
	})
	if err != nil {
		return fmt.Errorf("could not read the token back from %s: %w", host, err)
	}
	if nonce, _ := rec.Claims["nonce"].(string); nonce != state {
		return errors.New("the token was not created for this login attempt (nonce mismatch); run login again and paste the token from the page it opens")
	}
	if rec.Type != "cli" {
		return fmt.Errorf("token type is %q, expected cli", rec.Type)
	}

	set := map[string]string{
		credHost:       host,
		credInstanceID: cfg.Aud.Name,
		credToken:      token,
		credTokenID:    tokenID.String(),
		credLogin:      firstNonEmpty(who.Profile.Email, who.Login),
		credUserID:     who.ID,
	}
	if rec.ExpiresAtVal != nil {
		set[credExpiresAt] = rec.ExpiresAtVal.UTC().Format(time.RFC3339)
	}

	removed, err := saveCredentials(creds, profile, set, []string{credClientID, credSecret})
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "Logged in to %s as %s.", host, set[credLogin])
	if rec.ExpiresAtVal != nil {
		fmt.Fprintf(os.Stderr, " Token expires %s (%s).", rec.ExpiresAtVal.Local().Format("2006-01-02"), humanDuration(time.Until(*rec.ExpiresAtVal)))
	}
	fmt.Fprintln(os.Stderr)
	if len(removed) > 0 {
		fmt.Fprintf(os.Stderr, "Removed deprecated %s from the %s profile in %s.\n", strings.Join(removed, " and "), profile, creds)
	}
	return nil
}

func logoutAction(ctx context.Context, cmd *cli.Command) error {
	cf := loadCredentials(creds)
	token, hasToken := cf.Lookup(profile, credToken)
	host, _ := cf.Lookup(profile, credHost)
	userID, _ := cf.Lookup(profile, credUserID)
	tokenID, _ := cf.Lookup(profile, credTokenID)

	if hasToken && host != "" && userID != "" && tokenID != "" {
		uid, err1 := atomic.ParseID(userID)
		tid, err2 := atomic.ParseID(tokenID)
		if err1 == nil && err2 == nil {
			api := client.New(client.WithHost(host), client.WithToken(token))
			if err := api.UserTokenRevoke(ctx, &atomic.AccessTokenRevokeInput{UserID: &uid, AccessTokenID: tid}); err != nil {
				fmt.Fprintf(os.Stderr, "warning: could not revoke the token on %s (%v); it will expire on its own\n", host, err)
			} else {
				fmt.Fprintf(os.Stderr, "Revoked token on %s (nodes may honour it for up to an hour).\n", host)
			}
		}
	}

	_, err := saveCredentials(creds, profile, nil, []string{credToken, credTokenID, credExpiresAt, credLogin, credUserID})
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "Logged out of profile %s.\n", profile)
	return nil
}

func whoamiAction(ctx context.Context, cmd *cli.Command) error {
	info := currentAuth()
	PrintResult(cmd, []whoamiInfo{info}, WithSingleValue(true), WithFields("host", "instance_id", "login", "auth", "expires_at", "expires_in"))
	return nil
}

// currentAuth summarizes how the active profile authenticates. It never
// returns secret values.
func currentAuth() whoamiInfo {
	cf := loadCredentials(creds)
	info := whoamiInfo{Auth: "none"}

	info.Host, _ = cf.Lookup(profile, credHost)
	if h := os.Getenv("PASSPORT_API_HOST"); h != "" {
		info.Host = h
	}
	info.InstanceID, _ = cf.Lookup(profile, credInstanceID)
	info.Login, _ = cf.Lookup(profile, credLogin)
	info.UserID, _ = cf.Lookup(profile, credUserID)
	info.TokenID, _ = cf.Lookup(profile, credTokenID)

	_, fileID := cf.Lookup(profile, credClientID)
	_, fileSecret := cf.Lookup(profile, credSecret)
	_, fileToken := cf.Lookup(profile, credToken)

	switch {
	case os.Getenv("PASSPORT_ACCESS_TOKEN") != "":
		info.Auth = "access token (environment)"
	case fileToken && info.TokenID != "":
		info.Auth = "cli token (atomic-cli login)"
	case fileToken:
		info.Auth = "access token (credentials file)"
	case os.Getenv("PASSPORT_CLIENT_ID") != "" && os.Getenv("PASSPORT_CLIENT_SECRET") != "":
		info.Auth = "client credentials (environment, deprecated)"
		info.Deprecated = true
	case fileID && fileSecret:
		info.Auth = "client credentials (credentials file, deprecated)"
		info.Deprecated = true
	}

	if exp, ok := cf.Lookup(profile, credExpiresAt); ok {
		info.ExpiresAt = exp
		if t, err := time.Parse(time.RFC3339, exp); err == nil {
			if d := time.Until(t); d > 0 {
				info.ExpiresIn = humanDuration(d)
			} else {
				info.ExpiresIn = "expired"
			}
		}
	}
	return info
}

// fetchInstanceConfig reads the public instance config.
func fetchInstanceConfig(ctx context.Context, host string) (*instanceConfig, error) {
	u := fmt.Sprintf("https://%s/api/1.0.0/.well-known/config.json?instance_name=%s", host, url.QueryEscape(host))
	var cfg instanceConfig
	if err := getJSON(ctx, u, "", &cfg); err != nil {
		return nil, err
	}
	if cfg.Aud.Name == "" {
		return nil, errors.New("no instance in config response")
	}
	return &cfg, nil
}

// fetchPrincipal resolves the user behind a bearer token.
func fetchPrincipal(ctx context.Context, host, token string) (*principal, error) {
	var who principal
	if err := getJSON(ctx, fmt.Sprintf("https://%s/oauth/userPrincipal", host), token, &who); err != nil {
		return nil, err
	}
	if who.ID == "" {
		return nil, errors.New("empty principal")
	}
	return &who, nil
}

func getJSON(ctx context.Context, u, bearer string, out any) error {
	ctx, cancel := context.WithTimeout(ctx, loginHTTPTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		var apiErr client.Error
		_ = json.NewDecoder(resp.Body).Decode(&apiErr)
		apiErr.Status = resp.Status
		return apiErr
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// readSecret prompts on stderr and reads a line without echo. Without a
// terminal (pipes, agents) it reads one line from stdin instead.
func readSecret(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	if term.IsTerminal(int(os.Stdin.Fd())) {
		b, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(b)), nil
	}
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && line == "" {
		return "", err
	}
	return strings.TrimSpace(line), nil
}

// openBrowser launches the platform's default browser. Failure is not fatal;
// the caller has already printed the URL.
func openBrowser(u string) error {
	var c *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		c = exec.Command("open", u)
	case "windows":
		c = exec.Command("rundll32", "url.dll,FileProtocolHandler", u)
	default:
		c = exec.Command("xdg-open", u)
	}
	return c.Start()
}

func randomState() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func normalizeHost(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "https://")
	s = strings.TrimPrefix(s, "http://")
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	return strings.ToLower(s)
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func humanDuration(d time.Duration) string {
	switch {
	case d >= 48*time.Hour:
		return fmt.Sprintf("%d days", int(d.Hours()/24))
	case d >= 2*time.Hour:
		return fmt.Sprintf("%d hours", int(d.Hours()))
	default:
		return fmt.Sprintf("%d minutes", int(d.Minutes()))
	}
}
