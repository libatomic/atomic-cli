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
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	"strings"

	"github.com/stripe/stripe-go/v79"
	"github.com/stripe/stripe-go/v79/account"
	"github.com/urfave/cli/v3"
	"golang.ngrok.com/ngrok/v2"
	"gopkg.in/yaml.v2"
)

const (
	stripeConnectAuthorizeURL = "https://connect.stripe.com/oauth/authorize"
	stripeConnectTokenURL     = "https://connect.stripe.com/oauth/token"
)

type (
	connectResult struct {
		AccountID      string `json:"account_id"`
		AccountName    string `json:"account_name"`
		Livemode       bool   `json:"livemode"`
		PublishableKey string `json:"publishable_key"`
		SecretKey      string `json:"secret_key"`
		RefreshToken   string `json:"refresh_token"`
		Scope          string `json:"scope"`
	}

	stripeTokenResponse struct {
		AccessToken          string `json:"access_token"`
		Livemode             bool   `json:"livemode"`
		RefreshToken         string `json:"refresh_token"`
		Scope                string `json:"scope"`
		StripePublishableKey string `json:"stripe_publishable_key"`
		StripeUserID         string `json:"stripe_user_id"`
		TokenType            string `json:"token_type"`
	}
)

var (
	stripeConnectCmd = &cli.Command{
		Name:   "connect",
		Usage:  "connect a stripe account via OAuth",
		Action: stripeConnect,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     "client-id",
				Usage:    "stripe connect client id",
				Sources:  cli.NewValueSourceChain(cli.EnvVar("STRIPE_CLIENT_ID")),
				Required: true,
			},
			&cli.StringFlag{
				Name:    "output",
				Aliases: []string{"o"},
				Usage:   "directory to save the credentials file",
				Value:   ".",
			},
			&cli.BoolFlag{
				Name:  "ngrok",
				Usage: "use ngrok to create a public tunnel for the OAuth callback",
			},
			&cli.StringFlag{
				Name:    "ngrok-authtoken",
				Usage:   "ngrok auth token (overrides config file and $NGROK_AUTHTOKEN)",
				Sources: cli.NewValueSourceChain(cli.EnvVar("NGROK_AUTHTOKEN")),
			},
			&cli.StringFlag{
				Name:  "ngrok-config",
				Usage: "path to ngrok config file",
				Value: defaultNgrokConfigPath(),
			},
		},
	}
)

func stripeConnect(ctx context.Context, cmd *cli.Command) error {
	secretKey := stripe.Key // set by the stripe parent command's Before hook
	clientID := cmd.String("client-id")
	liveMode := !strings.HasPrefix(secretKey, "sk_test_")

	var listener net.Listener
	var callbackURL string

	useNgrok := cmd.Bool("ngrok") || cmd.IsSet("ngrok-authtoken") || cmd.IsSet("ngrok-config")

	if useNgrok {
		token := cmd.String("ngrok-authtoken")
		if token == "" {
			var err error
			token, err = readNgrokAuthtoken(cmd.String("ngrok-config"))
			if err != nil {
				return fmt.Errorf("failed to read ngrok config: %w", err)
			}
			if token == "" {
				return fmt.Errorf("ngrok authtoken not found; set --ngrok-authtoken, $NGROK_AUTHTOKEN, or configure it in %s", cmd.String("ngrok-config"))
			}
		}

		agent, err := ngrok.NewAgent(ngrok.WithAuthtoken(token))
		if err != nil {
			return fmt.Errorf("failed to create ngrok agent: %w", err)
		}

		ep, err := agent.Listen(ctx)
		if err != nil {
			return fmt.Errorf("failed to create ngrok tunnel: %w", err)
		}
		defer ep.Close()

		listener = ep
		callbackURL = ep.URL().String()

		fmt.Fprintf(os.Stderr, "ngrok tunnel created: %s\n", callbackURL)
	} else {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return fmt.Errorf("failed to start local listener: %w", err)
		}
		defer ln.Close()

		listener = ln
		callbackURL = fmt.Sprintf("http://127.0.0.1:%d", ln.Addr().(*net.TCPAddr).Port)

		fmt.Fprintf(os.Stderr, "listening on %s\n", callbackURL)
		fmt.Fprintf(os.Stderr, "note: you must proxy this address to a public URL for the stripe callback to work\n")
	}

	fmt.Fprintf(os.Stderr, "\nensure this URI is in your Stripe Dashboard under Connect > Settings > Redirects:\n  %s\n\n", callbackURL)

	// build the stripe connect authorize URL
	authorizeURL, _ := url.Parse(stripeConnectAuthorizeURL)
	q := authorizeURL.Query()
	q.Set("response_type", "code")
	q.Set("client_id", clientID)
	q.Set("scope", "read_write")
	q.Set("redirect_uri", callbackURL)
	authorizeURL.RawQuery = q.Encode()

	fmt.Fprintf(os.Stderr, "\nopen this URL in your browser to connect a stripe account:\n\n")
	fmt.Fprintf(os.Stderr, "  %s\n\n", authorizeURL.String())
	fmt.Fprintf(os.Stderr, "waiting for callback...\n")

	// handle the callback
	resultCh := make(chan *connectResult, 1)
	errCh := make(chan error, 1)

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		code := r.URL.Query().Get("code")
		if code == "" {
			errDesc := r.URL.Query().Get("error_description")
			if errDesc == "" {
				errDesc = r.URL.Query().Get("error")
			}
			if errDesc == "" {
				errDesc = "no authorization code received"
			}
			errCh <- fmt.Errorf("stripe connect failed: %s", errDesc)
			fmt.Fprintf(w, "Error: %s\nYou can close this window.", errDesc)
			return
		}

		result, err := exchangeStripeCode(code, secretKey, liveMode)
		if err != nil {
			errCh <- err
			fmt.Fprintf(w, "Error: %s\nYou can close this window.", err.Error())
			return
		}

		resultCh <- result
		fmt.Fprintf(w, "Stripe account %s (%s) connected successfully!\nYou can close this window.", result.AccountID, result.AccountName)
	})

	server := &http.Server{Handler: mux}

	go func() {
		if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
			errCh <- fmt.Errorf("server error: %w", err)
		}
	}()

	var result *connectResult

	select {
	case result = <-resultCh:
	case err := <-errCh:
		server.Shutdown(ctx)
		return err
	case <-ctx.Done():
		server.Shutdown(ctx)
		return ctx.Err()
	}

	server.Shutdown(ctx)

	// save credentials to file
	accountID := strings.TrimPrefix(result.AccountID, "acct_")
	outPath := filepath.Join(cmd.String("output"), fmt.Sprintf("stripe-connect-%s.json", accountID))

	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal credentials: %w", err)
	}

	if err := os.WriteFile(outPath, append(data, '\n'), 0600); err != nil {
		return fmt.Errorf("failed to write credentials file: %w", err)
	}

	// display the result
	fmt.Fprintf(os.Stderr, "\nstripe account connected successfully\n")
	fmt.Fprintf(os.Stderr, "credentials saved to %s\n\n", outPath)

	PrintResult(cmd, []*connectResult{result},
		WithFields("account_id", "account_name", "livemode", "publishable_key", "secret_key", "scope"),
	)

	return nil
}

func exchangeStripeCode(code, secretKey string, liveMode bool) (*connectResult, error) {
	args := url.Values{}
	args.Set("code", code)
	args.Set("grant_type", "authorization_code")

	req, err := http.NewRequest(http.MethodPost, stripeConnectTokenURL, strings.NewReader(args.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create token request: %w", err)
	}

	req.SetBasicAuth(secretKey, "")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange code: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read token response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		var errResp struct {
			Error            string `json:"error"`
			ErrorDescription string `json:"error_description"`
		}
		json.Unmarshal(body, &errResp)
		if errResp.ErrorDescription != "" {
			return nil, fmt.Errorf("stripe token exchange failed: %s", errResp.ErrorDescription)
		}
		return nil, fmt.Errorf("stripe token exchange failed: %s", string(body))
	}

	var tokenResp stripeTokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("failed to parse token response: %w", err)
	}

	if tokenResp.Livemode != liveMode {
		return nil, fmt.Errorf("livemode mismatch: expected %v, got %v", liveMode, tokenResp.Livemode)
	}

	// fetch account details
	stripe.Key = tokenResp.AccessToken
	acct, err := account.GetByID(tokenResp.StripeUserID, &stripe.AccountParams{})
	if err != nil {
		return nil, fmt.Errorf("failed to get account details: %w", err)
	}

	accountName := ""
	if acct.Settings != nil && acct.Settings.Dashboard != nil {
		accountName = acct.Settings.Dashboard.DisplayName
	}

	return &connectResult{
		AccountID:      tokenResp.StripeUserID,
		AccountName:    accountName,
		Livemode:       tokenResp.Livemode,
		PublishableKey: tokenResp.StripePublishableKey,
		SecretKey:      tokenResp.AccessToken,
		RefreshToken:   tokenResp.RefreshToken,
		Scope:          tokenResp.Scope,
	}, nil
}

func defaultNgrokConfigPath() string {
	usr, err := user.Current()
	if err != nil {
		return ""
	}
	return filepath.Join(usr.HomeDir, ".ngrok2", "ngrok.yml")
}

func readNgrokAuthtoken(configPath string) (string, error) {
	if configPath == "" {
		return "", nil
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}

	var cfg struct {
		Authtoken string `yaml:"authtoken"`
		Agent     struct {
			Authtoken string `yaml:"authtoken"`
		} `yaml:"agent"`
	}

	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return "", fmt.Errorf("failed to parse ngrok config: %w", err)
	}

	// v3 config uses agent.authtoken, v2 uses top-level authtoken
	if cfg.Agent.Authtoken != "" {
		return cfg.Agent.Authtoken, nil
	}

	return cfg.Authtoken, nil
}
