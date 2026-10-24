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
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/stripe/stripe-go/v79"
	"github.com/stripe/stripe-go/v79/customer"
	"github.com/stripe/stripe-go/v79/event"
	"github.com/stripe/stripe-go/v79/subscription"
	"github.com/urfave/cli/v3"
)

// Fixture pulling takes a scenario's events from the Stripe events API
// (which keeps 30 days of history with the same payloads webhooks carry,
// previous_attributes included) and writes them in the layout the atomic
// state-machine replay tests read:
//
//	<output>/<name>/scenario.json      pull metadata and the Passport seed
//	<output>/<name>/NNN_<type>.json     one event per file, in created order
//	<output>/<name>/expect.json         per-step expectations, filled in by hand
//
// No listener, tunnel or dashboard endpoint is needed: run the scenario in a
// sandbox however is convenient, then pull it by customer or subscription.
// A JSONL file written by `atomic-cli stripe webhook --log-only` converts the
// same way with --from-jsonl.

type (
	fixtureScenario struct {
		Name         string            `json:"name"`
		Source       string            `json:"source"`
		Account      string            `json:"account,omitempty"`
		APIVersion   string            `json:"api_version,omitempty"`
		PulledAt     time.Time         `json:"pulled_at"`
		Customer     string            `json:"customer,omitempty"`
		Subscription string            `json:"subscription,omitempty"`
		Since        *time.Time        `json:"since,omitempty"`
		Until        *time.Time        `json:"until,omitempty"`
		Seed         fixtureSeed       `json:"seed"`
		Events       []fixtureEventRef `json:"events"`
	}

	fixtureSeed struct {
		Prices []string `json:"prices"`
	}

	fixtureEventRef struct {
		File    string `json:"file"`
		ID      string `json:"id"`
		Type    string `json:"type"`
		Created int64  `json:"created"`
	}

	// fixtureExpect is the expect.json skeleton the atomic replay harness
	// reads: the Passport seed before the first event ("none",
	// "plan_subscribe" or a Passport status), one step per event, and the
	// replay modes ("duplicate", "shuffle") the scenario must survive.
	fixtureExpect struct {
		Seed   fixtureExpectSeed      `json:"seed"`
		Steps  map[string]fixtureStep `json:"steps"`
		Replay []string               `json:"replay"`
	}

	fixtureExpectSeed struct {
		Subscription string `json:"subscription"`
	}

	fixtureStep struct {
		Status         string `json:"status"`
		StripeStatus   string `json:"stripe_status"`
		Entitled       *bool  `json:"entitled"`
		PaymentPending *bool  `json:"payment_pending"`
	}

	rawEvent struct {
		id      string
		typ     string
		created int64
		obj     map[string]any
		body    map[string]any
	}

	fixtureScrubber struct {
		emails map[string]string
	}
)

var (
	stripeFixturesCmd = &cli.Command{
		Name:  "fixtures",
		Usage: "pull Stripe webhook scenarios into replayable test fixtures",
		Commands: []*cli.Command{
			{
				Name:   "pull",
				Usage:  "pull a customer's or subscription's events from the Stripe events API (or a webhook JSONL file) into a fixture directory",
				Action: stripeFixturesPull,
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:     "name",
						Aliases:  []string{"n"},
						Usage:    "scenario name, used as the directory name (e.g. card_first_purchase)",
						Required: true,
					},
					&cli.StringFlag{
						Name:    "output",
						Aliases: []string{"o"},
						Usage:   "directory the scenario directory is created under",
						Value:   "./stripe-fixtures",
					},
					&cli.StringFlag{
						Name:    "customer",
						Aliases: []string{"c"},
						Usage:   "Stripe customer id (cus_...); keeps every event about this customer",
					},
					&cli.StringFlag{
						Name:    "subscription",
						Aliases: []string{"s"},
						Usage:   "Stripe subscription id (sub_...); implies the customer and keeps only this subscription's billing events",
					},
					&cli.StringFlag{
						Name:  "since",
						Usage: "start of the window: RFC3339 time or a duration back from now (e.g. 2h); default is five minutes before the customer or subscription was created",
					},
					&cli.StringFlag{
						Name:  "until",
						Usage: "end of the window: RFC3339 time or a duration back from now; default now",
					},
					&cli.StringSliceFlag{
						Name:  "types",
						Usage: "only these event types; default every type",
					},
					&cli.StringFlag{
						Name:  "from-jsonl",
						Usage: "convert a JSONL file written by `atomic-cli stripe webhook --log-only` instead of querying the events API",
					},
					&cli.BoolFlag{
						Name:  "no-scrub",
						Usage: "keep emails, names, addresses, secrets and hosted URLs as pulled",
					},
					&cli.BoolFlag{
						Name:  "force",
						Usage: "overwrite an existing scenario directory",
					},
				},
			},
		},
	}
)

func stripeFixturesPull(ctx context.Context, cmd *cli.Command) error {
	acct, _ := cmd.Root().Metadata["stripe_account"].(*stripe.Account)

	name := cmd.String("name")
	if strings.ContainsAny(name, "/\\ ") {
		return fmt.Errorf("scenario name must not contain spaces or path separators")
	}

	dir := filepath.Join(cmd.String("output"), name)
	if _, err := os.Stat(dir); err == nil && !cmd.Bool("force") {
		return fmt.Errorf("%s exists; pass --force to overwrite it", dir)
	}

	scenario := fixtureScenario{
		Name:         name,
		PulledAt:     time.Now().UTC(),
		Customer:     cmd.String("customer"),
		Subscription: cmd.String("subscription"),
	}
	if acct != nil {
		scenario.Account = acct.ID
	}

	var (
		events []rawEvent
		err    error
	)

	if path := cmd.String("from-jsonl"); path != "" {
		scenario.Source = "jsonl:" + filepath.Base(path)
		events, err = fixtureEventsFromJSONL(path)
	} else {
		scenario.Source = "events_api"
		events, err = fixtureEventsFromAPI(ctx, cmd, &scenario)
	}
	if err != nil {
		return err
	}

	events = fixtureFilter(events, scenario.Customer, scenario.Subscription)
	if len(events) == 0 {
		return fmt.Errorf("no events matched; check --customer/--subscription and the --since window (the events API keeps 30 days)")
	}

	sort.SliceStable(events, func(i, j int) bool {
		if events[i].created != events[j].created {
			return events[i].created < events[j].created
		}
		return events[i].id < events[j].id
	})

	if !cmd.Bool("no-scrub") {
		s := &fixtureScrubber{emails: map[string]string{}}
		for i := range events {
			s.scrub(events[i].body, "")
		}
	}

	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("failed to create %s: %w", dir, err)
	}

	expect := fixtureExpect{Steps: map[string]fixtureStep{}, Replay: []string{}}
	expect.Seed.Subscription = "plan_subscribe"
	prices := map[string]struct{}{}

	for i, ev := range events {
		if i == 0 {
			if v, _ := ev.body["api_version"].(string); v != "" && scenario.APIVersion == "" {
				scenario.APIVersion = v
			}
		}
		file := fmt.Sprintf("%03d_%s.json", i+1, ev.typ)
		if err := writeJSONFile(filepath.Join(dir, file), ev.body); err != nil {
			return err
		}
		scenario.Events = append(scenario.Events, fixtureEventRef{File: file, ID: ev.id, Type: ev.typ, Created: ev.created})
		expect.Steps[file] = fixtureStep{}
		for _, p := range fixturePrices(ev.obj) {
			prices[p] = struct{}{}
		}
	}

	for p := range prices {
		scenario.Seed.Prices = append(scenario.Seed.Prices, p)
	}
	sort.Strings(scenario.Seed.Prices)

	if err := writeJSONFile(filepath.Join(dir, "scenario.json"), scenario); err != nil {
		return err
	}

	expectPath := filepath.Join(dir, "expect.json")
	if _, err := os.Stat(expectPath); err != nil || cmd.Bool("force") {
		if err := writeJSONFile(expectPath, expect); err != nil {
			return err
		}
	}

	fmt.Fprintf(os.Stderr, "pulled %d events to %s\n", len(events), dir)
	for _, ref := range scenario.Events {
		fmt.Fprintf(os.Stderr, "  %s  %s\n", time.Unix(ref.Created, 0).UTC().Format("15:04:05"), ref.File)
	}
	fmt.Fprintf(os.Stderr, "fill in %s with the expected Passport state after each step\n", expectPath)

	return nil
}

// fixtureEventsFromAPI lists events in the window from the events API,
// resolving the customer and default window from the subscription or customer.
func fixtureEventsFromAPI(_ context.Context, cmd *cli.Command, scenario *fixtureScenario) ([]rawEvent, error) {
	if scenario.Customer == "" && scenario.Subscription == "" {
		return nil, fmt.Errorf("pass --customer or --subscription (or --from-jsonl)")
	}

	var objectCreated int64

	if scenario.Subscription != "" {
		sub, err := subscription.Get(scenario.Subscription, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to get subscription %s: %w", scenario.Subscription, err)
		}
		objectCreated = sub.Created
		if sub.Customer != nil {
			if scenario.Customer != "" && scenario.Customer != sub.Customer.ID {
				return nil, fmt.Errorf("subscription %s belongs to %s, not %s", sub.ID, sub.Customer.ID, scenario.Customer)
			}
			scenario.Customer = sub.Customer.ID
		}
	} else {
		cus, err := customer.Get(scenario.Customer, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to get customer %s: %w", scenario.Customer, err)
		}
		objectCreated = cus.Created
	}

	since, err := parseFixtureTime(cmd.String("since"), time.Unix(objectCreated, 0).Add(-5*time.Minute))
	if err != nil {
		return nil, fmt.Errorf("--since: %w", err)
	}
	until, err := parseFixtureTime(cmd.String("until"), time.Now())
	if err != nil {
		return nil, fmt.Errorf("--until: %w", err)
	}
	scenario.Since, scenario.Until = &since, &until

	params := &stripe.EventListParams{
		CreatedRange: &stripe.RangeQueryParams{
			GreaterThanOrEqual: since.Unix(),
			LesserThanOrEqual:  until.Unix(),
		},
	}
	params.Limit = stripe.Int64(100)
	for _, t := range cmd.StringSlice("types") {
		params.Types = append(params.Types, stripe.String(t))
	}

	var events []rawEvent

	it := event.List(params)
	for it.Next() {
		raw, err := json.Marshal(it.Event())
		if err != nil {
			return nil, err
		}
		ev, err := parseRawEvent(raw)
		if err != nil {
			return nil, err
		}
		events = append(events, ev)
	}
	if err := it.Err(); err != nil {
		return nil, fmt.Errorf("failed to list events: %w", err)
	}

	return events, nil
}

// fixtureEventsFromJSONL reads the records written by `stripe webhook --log-only`
// and keeps one copy of each event id.
func fixtureEventsFromJSONL(path string) ([]rawEvent, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var (
		events []rawEvent
		seen   = map[string]struct{}{}
		sc     = bufio.NewScanner(f)
	)
	sc.Buffer(make([]byte, 0, 1<<20), 64<<20)

	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var rec eventRecord
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			return nil, fmt.Errorf("bad JSONL line: %w", err)
		}
		if rec.RawJSON == "" {
			continue
		}
		ev, err := parseRawEvent([]byte(rec.RawJSON))
		if err != nil {
			return nil, err
		}
		if _, dup := seen[ev.id]; dup {
			continue
		}
		seen[ev.id] = struct{}{}
		events = append(events, ev)
	}

	return events, sc.Err()
}

func parseRawEvent(raw []byte) (rawEvent, error) {
	var body map[string]any
	if err := json.Unmarshal(raw, &body); err != nil {
		return rawEvent{}, fmt.Errorf("bad event JSON: %w", err)
	}
	ev := rawEvent{body: body}
	ev.id, _ = body["id"].(string)
	ev.typ, _ = body["type"].(string)
	if c, ok := body["created"].(float64); ok {
		ev.created = int64(c)
	}
	if data, ok := body["data"].(map[string]any); ok {
		ev.obj, _ = data["object"].(map[string]any)
	}
	if ev.id == "" || ev.typ == "" || ev.obj == nil {
		return rawEvent{}, fmt.Errorf("event %q is missing id, type or data.object", ev.id)
	}
	return ev, nil
}

// fixtureFilter keeps the events about one customer and, when a subscription is
// named, only that subscription's billing chain: the subscription itself, its
// invoices, the payment intents and charges of those invoices, and the
// customer-level objects (customer, payment methods, setup intents) that every
// subscription scenario shares.
func fixtureFilter(events []rawEvent, cus, sub string) []rawEvent {
	if cus == "" && sub == "" {
		return events
	}

	var mine []rawEvent
	for _, ev := range events {
		if cus == "" || objectRef(ev.obj, "customer") == cus || objectRef(ev.obj, "id") == cus {
			mine = append(mine, ev)
		}
	}
	if sub == "" {
		return mine
	}

	invoices := map[string]struct{}{}
	intents := map[string]struct{}{}
	for _, ev := range mine {
		if objectRef(ev.obj, "object") == "invoice" && objectRef(ev.obj, "subscription") == sub {
			if id := objectRef(ev.obj, "id"); id != "" {
				invoices[id] = struct{}{}
			}
			if pi := objectRef(ev.obj, "payment_intent"); pi != "" {
				intents[pi] = struct{}{}
			}
		}
	}

	var out []rawEvent
	for _, ev := range mine {
		switch objectRef(ev.obj, "object") {
		case "customer", "payment_method", "setup_intent":
			out = append(out, ev)
		case "subscription":
			if objectRef(ev.obj, "id") == sub {
				out = append(out, ev)
			}
		case "invoice", "invoiceitem", "credit_note":
			if objectRef(ev.obj, "subscription") == sub {
				out = append(out, ev)
			} else if _, ok := invoices[objectRef(ev.obj, "invoice")]; ok {
				out = append(out, ev)
			}
		default:
			_, inv := invoices[objectRef(ev.obj, "invoice")]
			_, pi := intents[objectRef(ev.obj, "payment_intent")]
			_, self := intents[objectRef(ev.obj, "id")]
			if inv || pi || self {
				out = append(out, ev)
			}
		}
	}

	return out
}

// objectRef returns a field that may be an id string or an expanded object.
func objectRef(obj map[string]any, key string) string {
	switch v := obj[key].(type) {
	case string:
		return v
	case map[string]any:
		id, _ := v["id"].(string)
		return id
	}
	return ""
}

func fixturePrices(obj map[string]any) []string {
	var out []string
	if objectRef(obj, "object") != "subscription" {
		return out
	}
	items, _ := obj["items"].(map[string]any)
	data, _ := items["data"].([]any)
	for _, d := range data {
		item, _ := d.(map[string]any)
		if p := objectRef(item, "price"); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// scrub replaces personal data and secrets in place. Emails are mapped
// consistently so one person stays one person across a scenario.
func (s *fixtureScrubber) scrub(v any, parent string) {
	switch node := v.(type) {
	case map[string]any:
		for k, child := range node {
			switch k {
			case "email", "customer_email", "receipt_email":
				if e, ok := child.(string); ok && e != "" {
					node[k] = s.email(e)
				}
			case "phone", "customer_phone":
				if child != nil {
					node[k] = nil
				}
			case "name", "customer_name":
				if _, ok := child.(string); ok && (k == "customer_name" || parent == "billing_details" || parent == "customer" || parent == "shipping" || parent == "customer_shipping" || node["email"] != nil) {
					node[k] = "Test Member"
				}
			case "address", "customer_address", "shipping", "customer_shipping":
				if child != nil {
					node[k] = nil
				}
			case "client_secret", "hosted_invoice_url", "invoice_pdf", "receipt_url":
				if _, ok := child.(string); ok {
					node[k] = ""
				}
			default:
				s.scrub(child, k)
			}
		}
	case []any:
		for _, child := range node {
			s.scrub(child, parent)
		}
	}
}

func (s *fixtureScrubber) email(e string) string {
	if m, ok := s.emails[e]; ok {
		return m
	}
	m := fmt.Sprintf("member%d@example.test", len(s.emails)+1)
	s.emails[e] = m
	return m
}

func parseFixtureTime(v string, def time.Time) (time.Time, error) {
	if v == "" {
		return def, nil
	}
	if d, err := time.ParseDuration(v); err == nil {
		return time.Now().Add(-d), nil
	}
	return time.Parse(time.RFC3339, v)
}

func writeJSONFile(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}
