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
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/evertras/bubble-table/table"
	"github.com/libatomic/atomic/pkg/atomic"
	"github.com/stripe/stripe-go/v79"
	"github.com/stripe/stripe-go/v79/webhook"
	stripewebhookendpoint "github.com/stripe/stripe-go/v79/webhookendpoint"
	"github.com/urfave/cli/v3"
	"golang.ngrok.com/ngrok/v2"
	"gopkg.in/yaml.v3"
)

var (
	stripeWebhookCmd = &cli.Command{
		Name:   "webhook",
		Usage:  "listen for stripe webhook events and display them in a live table",
		Action: stripeWebhook,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "output",
				Aliases: []string{"o"},
				Usage:   "directory for the events JSONL file",
				Value:   ".",
			},
			&cli.StringSliceFlag{
				Name:    "events",
				Aliases: []string{"e"},
				Usage:   "stripe event types to listen for (default: atomic.StripeEvents)",
			},
			&cli.IntFlag{
				Name:  "display-events",
				Usage: "number of recent events to display",
				Value: 20,
			},
			&cli.BoolFlag{
				Name:  "log-only",
				Usage: "log events to the JSONL file without the interactive UI",
			},
			&cli.BoolFlag{
				Name:  "view-only",
				Usage: "browse an existing events JSONL file without starting a listener",
			},
			&cli.BoolFlag{
				Name:  "connect",
				Usage: "receive events from connected accounts (requires a platform account key)",
			},
			&cli.BoolFlag{
				Name:  "ngrok",
				Usage: "use ngrok to create a public tunnel for the webhook endpoint",
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

// --- types ---

type (
	eventRecord struct {
		ID             string `json:"id"`
		Type           string `json:"type"`
		Created        int64  `json:"created"`
		CustomerID     string `json:"customer_id,omitempty"`
		SubscriptionID string `json:"subscription_id,omitempty"`
		InvoiceID      string `json:"invoice_id,omitempty"`
		Amount         int64  `json:"amount,omitempty"`
		Currency       string `json:"currency,omitempty"`
		RawJSON        string `json:"raw_json"`
	}

	eventMsg  eventRecord
	errorMsg  string
	tickMsg   time.Time

	eventLog struct {
		mu      sync.Mutex
		path    string
		file    *os.File
		records []eventRecord
		maxDisp int
	}

	webhookModel struct {
		table       table.Model
		events      []eventRecord
		log         *eventLog
		paused      bool
		showInfo    bool
		focusDetail bool
		viewport    viewport.Model
		lastRowID   string
		width       int
		height      int
		startTime   time.Time
		totalRecv   int
		errors      []string
		maxErrors   int
		accountID   string
		url         string
		endpointID  string
		secret      string
		eventsFile  string
	}
)

// --- table columns ---

const (
	colTime         = "time"
	colType         = "type"
	colCustomer     = "customer"
	colSubscription = "subscription"
	colRawJSON      = "raw"

	tableWidthNarrow = 60
	tableWidthWide   = 120
	wideThreshold    = 180
)

var (
	borderStyle = table.Border{
		Top:            "─",
		Left:           "│",
		Right:          "│",
		Bottom:         "─",
		TopLeft:        "┌",
		TopRight:       "┐",
		BottomLeft:     "└",
		BottomRight:    "┘",
		TopJunction:    "┬",
		LeftJunction:   "├",
		RightJunction:  "┤",
		BottomJunction: "┴",
		InnerJunction:  "┼",
		InnerDivider:   "│",
	}

	styleHeader    = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("12"))
	styleHighlight = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("15")).Background(lipgloss.Color("62"))
	styleBase      = lipgloss.NewStyle().Foreground(lipgloss.Color("252"))
	styleDim       = lipgloss.NewStyle().Foreground(lipgloss.Color("8"))
	styleStatus    = lipgloss.NewStyle().Foreground(lipgloss.Color("10"))
	stylePaused    = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("11"))
	styleError     = lipgloss.NewStyle().Foreground(lipgloss.Color("9"))
	styleInfoBox   = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("62")).
			Padding(1, 2)
	styleInfoLabel = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("12")).Width(14)
	styleInfoValue = lipgloss.NewStyle().Foreground(lipgloss.Color("252"))
)

// --- event log ---

func extractEventRecord(evt stripe.Event) eventRecord {
	raw, _ := json.Marshal(evt)
	rec := eventRecord{
		ID:      evt.ID,
		Type:    string(evt.Type),
		Created: evt.Created,
		RawJSON: string(raw),
	}

	var obj map[string]any
	if err := json.Unmarshal(evt.Data.Raw, &obj); err == nil {
		objType, _ := obj["object"].(string)

		// customer: string ID or nested object
		if cid, ok := obj["customer"].(string); ok {
			rec.CustomerID = cid
		} else if cobj, ok := obj["customer"].(map[string]any); ok {
			rec.CustomerID, _ = cobj["id"].(string)
		}

		// subscription: explicit field, or the object itself is a subscription
		if sid, ok := obj["subscription"].(string); ok {
			rec.SubscriptionID = sid
		} else if objType == "subscription" {
			rec.SubscriptionID, _ = obj["id"].(string)
		}

		// invoice: explicit field, or the object itself is an invoice
		if iid, ok := obj["invoice"].(string); ok {
			rec.InvoiceID = iid
		} else if objType == "invoice" {
			rec.InvoiceID, _ = obj["id"].(string)
		}

		if amt, ok := obj["amount"].(float64); ok {
			rec.Amount = int64(amt)
		} else if amt, ok := obj["amount_paid"].(float64); ok {
			rec.Amount = int64(amt)
		}
		if cur, ok := obj["currency"].(string); ok {
			rec.Currency = strings.ToUpper(cur)
		}
	}

	return rec
}

func openEventLog(path string, maxDisplay int) (*eventLog, error) {
	el := &eventLog{path: path, maxDisp: maxDisplay}

	if data, err := os.ReadFile(path); err == nil {
		for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
			if line == "" {
				continue
			}
			var rec eventRecord
			if json.Unmarshal([]byte(line), &rec) == nil {
				// backfill fields from raw event for older records
				if rec.RawJSON != "" && (rec.CustomerID == "" || rec.SubscriptionID == "") {
					var evt stripe.Event
					if json.Unmarshal([]byte(rec.RawJSON), &evt) == nil {
						filled := extractEventRecord(evt)
						if rec.CustomerID == "" {
							rec.CustomerID = filled.CustomerID
						}
						if rec.SubscriptionID == "" {
							rec.SubscriptionID = filled.SubscriptionID
						}
						if rec.InvoiceID == "" {
							rec.InvoiceID = filled.InvoiceID
						}
					}
				}
				el.records = append(el.records, rec)
			}
		}
	}

	if len(el.records) > maxDisplay {
		el.records = el.records[len(el.records)-maxDisplay:]
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, err
	}
	el.file = f

	return el, nil
}

func (el *eventLog) Append(rec eventRecord) {
	el.mu.Lock()
	defer el.mu.Unlock()

	line, _ := json.Marshal(rec)
	el.file.Write(append(line, '\n'))

	el.records = append(el.records, rec)
	if len(el.records) > el.maxDisp {
		el.records = el.records[len(el.records)-el.maxDisp:]
	}
}

func (el *eventLog) Records() []eventRecord {
	el.mu.Lock()
	defer el.mu.Unlock()
	out := make([]eventRecord, len(el.records))
	copy(out, el.records)
	return out
}

func (el *eventLog) Close() {
	if el.file != nil {
		el.file.Close()
	}
}

// --- bubbletea TUI ---

func webhookColumns(wide bool) []table.Column {
	cols := []table.Column{
		table.NewColumn(colTime, "TIME", 21),
		table.NewFlexColumn(colType, "EVENT TYPE", 1),
	}
	if wide {
		cols = append(cols,
			table.NewColumn(colCustomer, "CUSTOMER", 24),
			table.NewColumn(colSubscription, "SUBSCRIPTION", 30),
		)
	}
	return cols
}

func eventToRow(rec eventRecord) table.Row {
	ts := time.Unix(rec.Created, 0).Format("2006-01-02 15:04:05")
	return table.NewRow(table.RowData{
		colTime:         ts,
		colType:         rec.Type,
		colCustomer:     rec.CustomerID,
		colSubscription: rec.SubscriptionID,
		colRawJSON:      rec.RawJSON,
	})
}

func eventsToRows(events []eventRecord) []table.Row {
	rows := make([]table.Row, len(events))
	for i, e := range events {
		rows[len(events)-1-i] = eventToRow(e)
	}
	return rows
}

func (m webhookModel) tableWidth() int {
	if m.width >= wideThreshold {
		return tableWidthWide
	}
	return tableWidthNarrow
}

func (m webhookModel) isWide() bool {
	return m.width >= wideThreshold
}

func newWebhookModel(log *eventLog, accountID, url, endpointID, secret, eventsFile string) webhookModel {
	events := log.Records()

	t := table.New(webhookColumns(false)).
		WithRows(eventsToRows(events)).
		WithTargetWidth(tableWidthNarrow).
		Border(borderStyle).
		HeaderStyle(styleHeader).
		HighlightStyle(styleHighlight).
		WithBaseStyle(styleBase).
		Focused(true).
		WithMissingDataIndicator("")

	return webhookModel{
		table:      t,
		events:     events,
		log:        log,
		startTime:  time.Now(),
		maxErrors:  5,
		accountID:  accountID,
		url:        url,
		endpointID: endpointID,
		secret:     secret,
		eventsFile: eventsFile,
	}
}

func doTick() tea.Cmd {
	return tea.Tick(time.Second, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}

func (m webhookModel) Init() tea.Cmd {
	return doTick()
}

func (m *webhookModel) updateViewport() {
	vpHeight := m.height - 3 // title + help + padding
	if vpHeight < 3 {
		vpHeight = 3
	}
	vpWidth := m.width - m.tableWidth() - 3 // 3 for divider + padding
	if vpWidth < 20 {
		vpWidth = 20
	}
	m.viewport = viewport.New(vpWidth, vpHeight)
	m.viewport.SetContent(m.selectedYAML())
}

func (m *webhookModel) syncDetailView() {
	row := m.table.HighlightedRow()
	rowID, _ := row.Data[colTime].(string)
	if rowID != m.lastRowID {
		m.lastRowID = rowID
		m.viewport.SetContent(m.selectedYAML())
		m.viewport.GotoTop()
	}
}

func (m webhookModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.table = m.table.
			WithColumns(webhookColumns(m.isWide())).
			WithTargetWidth(m.tableWidth()).
			WithPageSize(m.tablePageSize())
		m.updateViewport()
		return m, nil

	case tickMsg:
		return m, doTick()

	case eventMsg:
		m.totalRecv++
		if !m.paused {
			m.events = m.log.Records()
			m.table = m.table.WithRows(eventsToRows(m.events))
			m.syncDetailView()
		}
		return m, nil

	case errorMsg:
		m.errors = append(m.errors, string(msg))
		if len(m.errors) > m.maxErrors {
			m.errors = m.errors[len(m.errors)-m.maxErrors:]
		}
		return m, nil

	case tea.KeyMsg:
		key := msg.String()

		// info popup
		if m.showInfo {
			if key == "c" || key == "esc" || key == "enter" {
				m.showInfo = false
			}
			return m, nil
		}

		switch key {
		case "q", "ctrl+c":
			return m, tea.Quit
		case "c":
			m.showInfo = true
			return m, nil
		case "p":
			m.paused = !m.paused
			if !m.paused {
				m.events = m.log.Records()
				m.table = m.table.WithRows(eventsToRows(m.events))
			}
			return m, nil
		case "tab":
			m.focusDetail = !m.focusDetail
			m.table = m.table.Focused(!m.focusDetail)
			return m, nil
		}

		if m.focusDetail {
			var cmd tea.Cmd
			m.viewport, cmd = m.viewport.Update(msg)
			return m, cmd
		}

		// pass to table for navigation
		var cmd tea.Cmd
		m.table, cmd = m.table.Update(msg)
		m.syncDetailView()
		return m, cmd
	}

	var cmd tea.Cmd
	m.table, cmd = m.table.Update(msg)
	return m, cmd
}

func (m webhookModel) View() string {
	if m.width == 0 {
		return "loading..."
	}

	var b strings.Builder

	// title bar
	title := styleHeader.Render(fmt.Sprintf(" Webhook Listener (%s) ", m.accountID))
	elapsed := time.Since(m.startTime).Truncate(time.Second)
	status := styleStatus.Render(fmt.Sprintf(" %d events ", m.totalRecv))
	timer := styleDim.Render(fmt.Sprintf(" %s ", elapsed))
	if m.paused {
		status = stylePaused.Render(" PAUSED ")
	}
	b.WriteString(title + "  " + status + timer + "\n")

	// side-by-side: table | detail viewport
	tableView := m.table.View()

	detailBorder := lipgloss.NormalBorder()
	detailTitle := " Event Detail "
	if m.focusDetail {
		detailBorder = lipgloss.ThickBorder()
		detailTitle = " Event Detail (focused) "
	}

	vpWidth := m.width - m.tableWidth() - 4
	if vpWidth < 10 {
		vpWidth = 10
	}

	detailBox := lipgloss.NewStyle().
		Border(detailBorder).
		BorderForeground(lipgloss.Color("62")).
		Width(vpWidth).
		Height(m.tablePageSize() + 2). // match table height
		Render(m.viewport.View())

	// add title to detail box
	detailLines := strings.Split(detailBox, "\n")
	if len(detailLines) > 0 {
		titleStyled := lipgloss.NewStyle().Foreground(lipgloss.Color("12")).Bold(true).Render(detailTitle)
		border := detailLines[0]
		// insert title into top border
		if len(border) > 4 {
			detailLines[0] = border[:2] + titleStyled + border[2+lipgloss.Width(detailTitle):]
		}
		detailBox = strings.Join(detailLines, "\n")
	}

	combined := lipgloss.JoinHorizontal(lipgloss.Top, tableView, " ", detailBox)
	b.WriteString(combined)
	b.WriteString("\n")

	// errors
	if len(m.errors) > 0 {
		for _, e := range m.errors {
			b.WriteString(styleError.Render("  ✗ "+e) + "\n")
		}
	}

	// help
	focusHint := "tab: focus detail"
	if m.focusDetail {
		focusHint = "tab: focus table"
	}
	pauseHint := "p: pause"
	if m.paused {
		pauseHint = "p: unpause"
	}
	help := styleDim.Render(fmt.Sprintf(" ↑/↓: navigate  %s  %s  c: info  q: quit ", focusHint, pauseHint))
	b.WriteString(help)

	// info popup overlay
	if m.showInfo {
		popup := m.renderInfoPopup()
		return m.overlayCenter(b.String(), popup)
	}

	return b.String()
}

func (m webhookModel) renderInfoPopup() string {
	var rows []string
	addRow := func(label, value string) {
		if value != "" {
			rows = append(rows, styleInfoLabel.Render(label)+styleInfoValue.Render(value))
		}
	}

	addRow("Account", m.accountID)
	addRow("Endpoint", m.url+"/webhook")
	addRow("Endpoint ID", m.endpointID)
	addRow("Secret", m.secret)
	addRow("Events File", m.eventsFile)
	addRow("Uptime", time.Since(m.startTime).Truncate(time.Second).String())
	addRow("Total Events", fmt.Sprintf("%d", m.totalRecv))
	rows = append(rows, "")
	rows = append(rows, styleDim.Render("press c or esc to close"))

	content := strings.Join(rows, "\n")
	return styleInfoBox.Render(content)
}

func (m webhookModel) overlayCenter(bg, overlay string) string {
	bgLines := strings.Split(bg, "\n")
	overlayLines := strings.Split(overlay, "\n")

	// find the widest overlay line for consistent centering
	maxWidth := 0
	for _, line := range overlayLines {
		if w := lipgloss.Width(line); w > maxWidth {
			maxWidth = w
		}
	}

	startRow := (m.height - len(overlayLines)) / 2
	if startRow < 0 {
		startRow = 0
	}
	padLeft := (m.width - maxWidth) / 2
	if padLeft < 0 {
		padLeft = 0
	}

	for len(bgLines) < m.height {
		bgLines = append(bgLines, "")
	}

	pad := strings.Repeat(" ", padLeft)
	for i, line := range overlayLines {
		row := startRow + i
		if row < len(bgLines) {
			bgLines[row] = pad + line
		}
	}

	return strings.Join(bgLines, "\n")
}

func (m webhookModel) selectedYAML() string {
	row := m.table.HighlightedRow()
	raw, ok := row.Data[colRawJSON].(string)
	if !ok || raw == "" {
		return styleDim.Render("no event selected")
	}
	var obj any
	json.Unmarshal([]byte(raw), &obj)
	out, err := yaml.Marshal(obj)
	if err != nil {
		return styleDim.Render("failed to render event")
	}
	return string(out)
}

func (m webhookModel) tablePageSize() int {
	// reserve: title(1) + table header/border(3) + errors(len) + help(1) + padding(1)
	used := 6 + len(m.errors)
	size := m.height - used
	if size < 3 {
		size = 3
	}
	return size
}

// --- main command ---

func stripeWebhook(ctx context.Context, cmd *cli.Command) error {
	acct := cmd.Root().Metadata["stripe_account"].(*stripe.Account)
	accountID := strings.TrimPrefix(acct.ID, "acct_")
	outputDir := cmd.String("output")
	maxDisplay := int(cmd.Int("display-events"))
	logOnly := cmd.Bool("log-only")
	viewOnly := cmd.Bool("view-only")

	// open event log
	eventsPath := filepath.Join(outputDir, fmt.Sprintf("events-%s.jsonl", accountID))
	evtLog, err := openEventLog(eventsPath, maxDisplay)
	if err != nil {
		return fmt.Errorf("failed to open events file: %w", err)
	}
	defer evtLog.Close()

	// --- view-only mode: just show the TUI with existing events ---
	if viewOnly {
		m := newWebhookModel(evtLog, acct.ID, "", "", "", eventsPath)
		p := tea.NewProgram(m, tea.WithAltScreen())
		if _, err := p.Run(); err != nil {
			return fmt.Errorf("TUI error: %w", err)
		}
		return nil
	}

	// resolve events
	events := cmd.StringSlice("events")
	if len(events) == 0 {
		for _, e := range atomic.StripeEvents {
			events = append(events, *e)
		}
	}

	// set up listener (ngrok or local)
	var listener net.Listener
	var publicURL string

	useNgrok := cmd.Bool("ngrok") || cmd.IsSet("ngrok-authtoken") || cmd.IsSet("ngrok-config")

	if useNgrok {
		token := cmd.String("ngrok-authtoken")
		if token == "" {
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
		publicURL = ep.URL().String()
	} else {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return fmt.Errorf("failed to start local listener: %w", err)
		}
		defer ln.Close()

		listener = ln
		port := ln.Addr().(*net.TCPAddr).Port
		publicURL = fmt.Sprintf("http://127.0.0.1:%d", port)

		fmt.Fprintf(os.Stderr, "listening locally on %s\n", publicURL)
		fmt.Fprintf(os.Stderr, "note: you must proxy this address to a public URL, then add that URL as a webhook endpoint in Stripe Dashboard:\n")
		fmt.Fprintf(os.Stderr, "  Dashboard > Developers > Webhooks > Add endpoint\n")
		fmt.Fprintf(os.Stderr, "  URL: <your-public-url>/webhook\n")
		fmt.Fprintf(os.Stderr, "  Events: %s\n\n", strings.Join(events, ", "))
	}

	webhookURL := publicURL + "/webhook"

	// register webhook endpoint with Stripe (ngrok only)
	var webhookSecret string
	var endpointID string
	connectMode := cmd.Bool("connect")

	if useNgrok {
		enabledEvents := make([]*string, len(events))
		for i, e := range events {
			enabledEvents[i] = stripe.String(e)
		}

		params := &stripe.WebhookEndpointParams{
			URL:           stripe.String(webhookURL),
			EnabledEvents: enabledEvents,
			Description:   stripe.String("atomic-cli webhook listener"),
			Metadata:      map[string]string{"atomic_cli": "true"},
		}
		if connectMode {
			params.Connect = stripe.Bool(true)
		}

		ep, err := stripewebhookendpoint.New(params)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: could not register webhook endpoint: %v\n", err)
			fmt.Fprintf(os.Stderr, "  listening without signature verification\n")
			fmt.Fprintf(os.Stderr, "  add this URL manually in Stripe Dashboard > Developers > Webhooks:\n")
			fmt.Fprintf(os.Stderr, "    %s\n\n", webhookURL)
		} else {
			endpointID = ep.ID
			webhookSecret = ep.Secret

			defer func() {
				stripewebhookendpoint.Del(endpointID, nil)
			}()
		}
	}

	// --- log-only mode: no TUI, just log to file and print status ---
	if logOnly {
		fmt.Fprintf(os.Stderr, "webhook url: %s\n", webhookURL)
		if endpointID != "" {
			fmt.Fprintf(os.Stderr, "endpoint id: %s\n", endpointID)
			fmt.Fprintf(os.Stderr, "secret:      %s\n", webhookSecret)
		}
		fmt.Fprintf(os.Stderr, "logging to:  %s\n", eventsPath)
		fmt.Fprintf(os.Stderr, "press ctrl+c to stop\n\n")

		mux := http.NewServeMux()
		mux.HandleFunc("/webhook", func(w http.ResponseWriter, r *http.Request) {
			body, err := io.ReadAll(r.Body)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error: failed to read body: %v\n", err)
				http.Error(w, "bad request", http.StatusBadRequest)
				return
			}

			var evt stripe.Event
			if webhookSecret != "" {
				sig := r.Header.Get("Stripe-Signature")
				evt, err = webhook.ConstructEventWithOptions(body, sig, webhookSecret, webhook.ConstructEventOptions{
					IgnoreAPIVersionMismatch: true,
				})
				if err != nil {
					fmt.Fprintf(os.Stderr, "error: signature validation failed: %v\n", err)
					http.Error(w, "invalid signature", http.StatusBadRequest)
					return
				}
			} else {
				if err := json.Unmarshal(body, &evt); err != nil {
					fmt.Fprintf(os.Stderr, "error: invalid json: %v\n", err)
					http.Error(w, "invalid json", http.StatusBadRequest)
					return
				}
			}

			rec := extractEventRecord(evt)
			evtLog.Append(rec)
			fmt.Fprintf(os.Stderr, "  %s  %s\n", time.Unix(rec.Created, 0).Format("15:04:05"), rec.Type)
		})

		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("atomic-cli webhook listener"))
		})

		server := &http.Server{Handler: mux}
		go func() {
			if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
				fmt.Fprintf(os.Stderr, "server error: %v\n", err)
			}
		}()

		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		server.Shutdown(shutdownCtx)

		fmt.Fprintf(os.Stderr, "\nevents saved to %s\n", eventsPath)
		return nil
	}

	// --- full TUI mode ---
	m := newWebhookModel(evtLog, acct.ID, publicURL, endpointID, webhookSecret, eventsPath)
	p := tea.NewProgram(m, tea.WithAltScreen())

	mux := http.NewServeMux()
	mux.HandleFunc("/webhook", func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			p.Send(errorMsg(fmt.Sprintf("failed to read body: %v", err)))
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}

		var evt stripe.Event
		if webhookSecret != "" {
			sig := r.Header.Get("Stripe-Signature")
			evt, err = webhook.ConstructEventWithOptions(body, sig, webhookSecret, webhook.ConstructEventOptions{
				IgnoreAPIVersionMismatch: true,
			})
			if err != nil {
				p.Send(errorMsg(fmt.Sprintf("signature validation failed: %v", err)))
				http.Error(w, "invalid signature", http.StatusBadRequest)
				return
			}
		} else {
			if err := json.Unmarshal(body, &evt); err != nil {
				p.Send(errorMsg(fmt.Sprintf("invalid json: %v", err)))
				http.Error(w, "invalid json", http.StatusBadRequest)
				return
			}
		}

		rec := extractEventRecord(evt)
		evtLog.Append(rec)
		p.Send(eventMsg(rec))

		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status": "ok"}`))
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("atomic-cli webhook listener"))
	})

	server := &http.Server{Handler: mux}

	go func() {
		if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
			p.Send(errorMsg(fmt.Sprintf("server error: %v", err)))
		}
	}()

	if _, err := p.Run(); err != nil {
		return fmt.Errorf("TUI error: %w", err)
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	server.Shutdown(shutdownCtx)

	fmt.Fprintf(os.Stderr, "events saved to %s\n", eventsPath)
	return nil
}
