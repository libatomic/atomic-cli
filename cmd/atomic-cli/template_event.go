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
	"os"

	"github.com/libatomic/atomic/pkg/atomic"
	"github.com/libatomic/atomic/pkg/email"
	"github.com/urfave/cli/v3"
)

var (
	templateEventCmd = &cli.Command{
		Name:    "event",
		Aliases: []string{"events"},
		Usage:   "manage events on a template",
		Commands: []*cli.Command{
			{
				Name:      "list",
				Usage:     "list events on a template",
				ArgsUsage: "<template_id>",
				Action:    templateEventList,
			},
			{
				Name:      "add",
				Usage:     "add a new event to a template",
				ArgsUsage: "<template_id>",
				Action:    templateEventAdd,
				Flags:     templateEventFlags(),
			},
			{
				Name:      "update",
				Usage:     "update an event on a template by event id",
				ArgsUsage: "<event_id>",
				Action:    templateEventUpdate,
				Flags: append(templateEventFlags(),
					&cli.StringFlag{
						Name:     "template",
						Usage:    "template id whose event is being updated",
						Required: true,
					},
				),
			},
			{
				Name:      "remove",
				Aliases:   []string{"delete"},
				Usage:     "remove an event from a template by event id",
				ArgsUsage: "<event_id>",
				Action:    templateEventRemove,
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:     "template",
						Usage:    "template id whose event is being removed",
						Required: true,
					},
				},
			},
		},
	}
)

// templateEventFlags returns the shared flag set for add and update. add
// expects --channel/--source/--type to all be set; update treats every flag
// as optional and only mutates the fields the caller provided.
func templateEventFlags() []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{
			Name:  "channel",
			Usage: "channel for this event (email, rss, podcast, sms)",
		},
		&cli.BoolFlag{
			Name:  "enabled",
			Usage: "enable or disable this event",
		},
		&cli.StringFlag{
			Name:  "source",
			Usage: "event source (e.g. atomic, stripe)",
		},
		&cli.StringFlag{
			Name:  "type",
			Usage: "event type (e.g. user.created, invoice.paid)",
		},

		// email helper flags — populate EmailChannel without authoring JSON
		&cli.StringFlag{
			Name:  "email-subject",
			Usage: "email subject (helper)",
		},
		&cli.StringSliceFlag{
			Name:  "email-to",
			Usage: "email to-recipient (helper, repeatable)",
		},
		&cli.StringFlag{
			Name:  "email-to-audience",
			Usage: "email to-audience id (helper)",
		},
		&cli.StringFlag{
			Name:  "email-from",
			Usage: "email from address (helper)",
		},
		&cli.StringFlag{
			Name:  "email-reply-to",
			Usage: "email reply-to address (helper)",
		},

		// raw JSON settings — escape hatch for rss/podcast/sms or anything
		// the helper flags don't cover. Mutually exclusive with --settings-file.
		// When either is provided, it replaces the entire TemplateSettings
		// (including any email helpers on the same invocation).
		&cli.StringFlag{
			Name:  "settings",
			Usage: "raw TemplateSettings as JSON (replaces helpers)",
		},
		&cli.StringFlag{
			Name:  "settings-file",
			Usage: "path to JSON file containing TemplateSettings (replaces helpers)",
		},

		// filter rules — repeatable expressions that build TemplateEventFilter.Rules
		&cli.StringSliceFlag{
			Name:    "rules",
			Aliases: []string{"rule"},
			Usage:   "filter rule expression (repeatable)",
		},
	}
}

func templateEventList(ctx context.Context, cmd *cli.Command) error {
	if cmd.NArg() < 1 {
		return fmt.Errorf("template id is required")
	}

	tmp, err := resolveTemplate(ctx, cmd.Args().First())
	if err != nil {
		return err
	}

	events := make([]*atomic.TemplateEvent, len(tmp.Events))
	for i := range tmp.Events {
		events[i] = &tmp.Events[i]
	}

	PrintResult(cmd, events,
		WithFields("id", "event_source", "event_type", "channel", "enabled", "admin", "settings", "filter"),
	)
	return nil
}

func templateEventAdd(ctx context.Context, cmd *cli.Command) error {
	if cmd.NArg() < 1 {
		return fmt.Errorf("template id is required")
	}

	if !cmd.IsSet("channel") || !cmd.IsSet("source") || !cmd.IsSet("type") {
		return fmt.Errorf("--channel, --source, and --type are required for add")
	}

	tmp, err := resolveTemplate(ctx, cmd.Args().First())
	if err != nil {
		return err
	}

	evt := atomic.TemplateEvent{
		ID:          atomic.NewID(),
		TemplateID:  tmp.UUID,
		InstanceID:  tmp.InstanceID,
		Channel:     atomic.Channel(cmd.String("channel")),
		EventSource: cmd.String("source"),
		EventType:   cmd.String("type"),
		Enabled:     cmd.Bool("enabled"),
	}

	if err := applyEventFlags(cmd, &evt, false); err != nil {
		return err
	}

	updated, err := writeTemplateEvents(ctx, tmp, append(tmp.Events, evt))
	if err != nil {
		return err
	}

	for i := range updated.Events {
		if updated.Events[i].ID == evt.ID {
			PrintResult(cmd, []*atomic.TemplateEvent{&updated.Events[i]},
				WithSingleValue(true),
				WithFields("id", "event_source", "event_type", "channel", "enabled", "admin", "settings", "filter"),
			)
			return nil
		}
	}

	return fmt.Errorf("event %s was not present in updated template (unexpected)", evt.ID)
}

func templateEventUpdate(ctx context.Context, cmd *cli.Command) error {
	if cmd.NArg() < 1 {
		return fmt.Errorf("event id is required")
	}

	eventID, err := atomic.ParseID(cmd.Args().First())
	if err != nil {
		return fmt.Errorf("failed to parse event id: %w", err)
	}

	tmp, err := resolveTemplate(ctx, cmd.String("template"))
	if err != nil {
		return err
	}

	idx := -1
	for i := range tmp.Events {
		if tmp.Events[i].ID == eventID {
			idx = i
			break
		}
	}
	if idx < 0 {
		return fmt.Errorf("event %s not found on template %s", eventID, tmp.UUID)
	}

	evt := tmp.Events[idx]

	if cmd.IsSet("channel") {
		evt.Channel = atomic.Channel(cmd.String("channel"))
	}
	if cmd.IsSet("source") {
		evt.EventSource = cmd.String("source")
	}
	if cmd.IsSet("type") {
		evt.EventType = cmd.String("type")
	}
	if cmd.IsSet("enabled") {
		evt.Enabled = cmd.Bool("enabled")
	}

	if err := applyEventFlags(cmd, &evt, true); err != nil {
		return err
	}

	tmp.Events[idx] = evt

	updated, err := writeTemplateEvents(ctx, tmp, tmp.Events)
	if err != nil {
		return err
	}

	for i := range updated.Events {
		if updated.Events[i].ID == eventID {
			PrintResult(cmd, []*atomic.TemplateEvent{&updated.Events[i]},
				WithSingleValue(true),
				WithFields("id", "event_source", "event_type", "channel", "enabled", "admin", "settings", "filter"),
			)
			return nil
		}
	}

	return fmt.Errorf("event %s was not present in updated template (unexpected)", eventID)
}

func templateEventRemove(ctx context.Context, cmd *cli.Command) error {
	if cmd.NArg() < 1 {
		return fmt.Errorf("event id is required")
	}

	eventID, err := atomic.ParseID(cmd.Args().First())
	if err != nil {
		return fmt.Errorf("failed to parse event id: %w", err)
	}

	tmp, err := resolveTemplate(ctx, cmd.String("template"))
	if err != nil {
		return err
	}

	kept := make([]atomic.TemplateEvent, 0, len(tmp.Events))
	found := false
	for _, e := range tmp.Events {
		if e.ID == eventID {
			found = true
			continue
		}
		kept = append(kept, e)
	}
	if !found {
		return fmt.Errorf("event %s not found on template %s", eventID, tmp.UUID)
	}

	if _, err := writeTemplateEvents(ctx, tmp, kept); err != nil {
		return err
	}

	fmt.Printf("Removed event %s from template %s\n", eventID, tmp.UUID)
	return nil
}

// writeTemplateEvents sends the full Events slice through TemplateUpdate.
// TemplateUpdate replaces all events on each call (it deletes and re-inserts
// the row set), so callers must hand it the complete intended state — never
// a delta. The returned template carries the persisted state including any
// server-side defaults applied to each event.
func writeTemplateEvents(ctx context.Context, tmp *atomic.Template, events []atomic.TemplateEvent) (*atomic.Template, error) {
	in := &atomic.TemplateUpdateInput{
		InstanceID: tmp.InstanceID,
		TemplateID: tmp.UUID,
		Events:     events,
	}
	updated, err := backend.TemplateUpdate(ctx, in)
	if err != nil {
		return nil, fmt.Errorf("failed to update template: %w", err)
	}
	return updated, nil
}

// applyEventFlags fills evt.Settings and evt.Filter from CLI flags. When
// --settings or --settings-file is provided, that JSON replaces the entire
// TemplateSettings (the email helpers are ignored on the same invocation,
// since the JSON form is the escape hatch). When only helper flags are
// provided, on update we merge into the existing EmailChannel (preserving
// fields the user did not override); on add (isUpdate=false) we build a
// fresh EmailChannel from scratch.
func applyEventFlags(cmd *cli.Command, evt *atomic.TemplateEvent, isUpdate bool) error {
	if cmd.IsSet("settings") && cmd.IsSet("settings-file") {
		return fmt.Errorf("--settings and --settings-file are mutually exclusive")
	}

	if raw := cmd.String("settings"); raw != "" {
		var s atomic.TemplateSettings
		if err := json.Unmarshal([]byte(raw), &s); err != nil {
			return fmt.Errorf("failed to parse --settings: %w", err)
		}
		evt.Settings = &s
	} else if path := cmd.String("settings-file"); path != "" {
		content, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("failed to read --settings-file: %w", err)
		}
		var s atomic.TemplateSettings
		if err := json.Unmarshal(content, &s); err != nil {
			return fmt.Errorf("failed to parse --settings-file: %w", err)
		}
		evt.Settings = &s
	} else if hasEmailHelperFlags(cmd) {
		// helpers populate only the email channel; rss/podcast/sms must use
		// --settings/--settings-file
		var ec *atomic.EmailChannel
		if isUpdate && evt.Settings != nil && evt.Settings.Email != nil {
			cp := *evt.Settings.Email
			ec = &cp
		} else {
			ec = &atomic.EmailChannel{}
		}

		if cmd.IsSet("email-subject") {
			s := cmd.String("email-subject")
			ec.Subject = &s
		}
		if cmd.IsSet("email-to") {
			recipients := make(email.Recipients, 0)
			for _, addr := range cmd.StringSlice("email-to") {
				parsed, err := email.ParseAddress(addr)
				if err != nil {
					return fmt.Errorf("failed to parse --email-to %q: %w", addr, err)
				}
				recipients = append(recipients, *parsed)
			}
			ec.To = recipients
		}
		if cmd.IsSet("email-to-audience") {
			audID, err := atomic.ParseID(cmd.String("email-to-audience"))
			if err != nil {
				return fmt.Errorf("failed to parse --email-to-audience: %w", err)
			}
			ec.ToAudienceID = &audID
		}
		if cmd.IsSet("email-from") {
			parsed, err := email.ParseAddress(cmd.String("email-from"))
			if err != nil {
				return fmt.Errorf("failed to parse --email-from: %w", err)
			}
			ec.From = parsed
		}
		if cmd.IsSet("email-reply-to") {
			parsed, err := email.ParseAddress(cmd.String("email-reply-to"))
			if err != nil {
				return fmt.Errorf("failed to parse --email-reply-to: %w", err)
			}
			ec.ReplyTo = parsed
		}

		if evt.Settings == nil {
			evt.Settings = &atomic.TemplateSettings{}
		}
		evt.Settings.Email = ec
	}

	if cmd.IsSet("rules") {
		rules := cmd.StringSlice("rules")
		if len(rules) == 0 {
			evt.Filter = nil
		} else {
			evt.Filter = &atomic.TemplateEventFilter{Rules: rules}
		}
	}

	return nil
}

func hasEmailHelperFlags(cmd *cli.Command) bool {
	return cmd.IsSet("email-subject") ||
		cmd.IsSet("email-to") ||
		cmd.IsSet("email-to-audience") ||
		cmd.IsSet("email-from") ||
		cmd.IsSet("email-reply-to")
}
