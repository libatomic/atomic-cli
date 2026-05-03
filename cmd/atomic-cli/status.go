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
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/lensesio/tableprinter"
	"github.com/mattn/go-isatty"
	"github.com/urfave/cli/v3"
)

const minStatusInterval = 60 * time.Second

var (
	statusCmd = &cli.Command{
		Name:  "status",
		Usage: "fetch atomic node and queue status (--top for a live, top-style UI)",
		Description: "Queries the cluster's /.well-known/ping endpoint and prints the " +
			"current node/queue status. Pass --top to launch a continuously-updating " +
			"top-style UI instead (refreshes every 60 seconds; press q or ctrl+c to exit).",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  "nodes",
				Usage: "node filter — comma-separated services (api,scheduler,event,message,work) or 'all'",
				Value: "all",
			},
			&cli.BoolFlag{
				Name:  "queues",
				Usage: "render the queues table below the nodes table (--top mode only)",
				Value: true,
			},
			&cli.DurationFlag{
				Name:  "interval",
				Usage: "polling interval for --top (minimum 60s; smaller values are clamped)",
				Value: minStatusInterval,
			},
			&cli.BoolFlag{
				Name:  "top",
				Usage: "launch the live, top-style UI instead of doing a single-shot fetch",
				Value: false,
			},
		},
		Action: statusAction,
	}
)

// statusNodeInfo / statusQueue mirror the Go types in atomic/internal/app
// (NodeInfo / Status / QueueStatus). Re-declared here so the cli doesn't
// need to depend on the internal package.
type (
	statusNodeInfo struct {
		ID            string         `json:"id"`
		Hostname      string         `json:"hostname,omitempty"`
		IP            string         `json:"ip,omitempty"`
		Services      []string       `json:"services,omitempty"`
		Build         string         `json:"build,omitempty"`
		StartedAt     time.Time      `json:"started_at"`
		LastHeartbeat *time.Time     `json:"last_heartbeat,omitempty"`
		Uptime        *string        `json:"uptime,omitempty"`
		State         *string        `json:"state,omitempty"`
		Status        *statusPayload `json:"status,omitempty"`
	}

	statusPayload struct {
		EventQueue *statusQueue `json:"event_queue,omitempty"`
		Scheduler  *statusQueue `json:"scheduler,omitempty"`
		MsgQueue   *statusQueue `json:"msg_queue,omitempty"`
		Work       *statusQueue `json:"work_queue,omitempty"`
	}

	statusQueue struct {
		Name                 string     `json:"name"`
		Type                 string     `json:"type"`
		LastHeartbeat        *time.Time `json:"last_heartbeat,omitempty"`
		Status               *string    `json:"status,omitempty"`
		LastError            string     `json:"last_error,omitempty"`
		Total                uint64     `json:"total"`
		InProgress           uint64     `json:"in_progress"`
		Workers              int64      `json:"workers,omitempty"`
		LastDispatchAt       *time.Time `json:"last_dispatch_at,omitempty"`
		LastDispatchDuration string     `json:"last_dispatch_duration,omitempty"`
		AvgDispatchDuration  string     `json:"avg_dispatch_duration,omitempty"`
		DispatchRate         float64    `json:"dispatch_rate"`
		ErrorRate            float64    `json:"error_rate,omitempty"`
	}
)

func statusAction(ctx context.Context, cmd *cli.Command) error {
	host := strings.TrimSpace(cmd.String("host"))
	if host == "" {
		return fmt.Errorf("--host is required to reach the status endpoint")
	}

	// --top runs a bubbletea TUI that needs a real terminal. Refuse to
	// launch it when stdout isn't a TTY so MCP/script callers get a clean
	// error instead of a silent hang.
	top := cmd.Bool("top")
	if top && !isatty.IsTerminal(os.Stdout.Fd()) && !isatty.IsCygwinTerminal(os.Stdout.Fd()) {
		return fmt.Errorf("--top requires an interactive terminal")
	}

	if !top {
		nodes, err := fetchClusterStatus(host, cmd.String("nodes"), cmd.String("access_token"))
		if err != nil {
			return err
		}
		PrintResult(cmd, nodes,
			WithFields("id", "hostname", "ip", "services", "state", "uptime", "build"),
		)
		return nil
	}

	interval := max(cmd.Duration("interval"), minStatusInterval)

	model := statusModel{
		host:      host,
		nodes:     cmd.String("nodes"),
		showQueue: cmd.Bool("queues"),
		interval:  interval,
		token:     cmd.String("access_token"),
	}

	p := tea.NewProgram(model, tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		return err
	}
	return nil
}

// --- bubbletea model ---

type (
	statusModel struct {
		host      string
		nodes     string
		showQueue bool
		interval  time.Duration
		token     string

		width, height int

		fetched   []statusNodeInfo
		err       error
		lastFetch time.Time

		// next-refresh ticker — bound to interval but re-fired every
		// second so the "next refresh in N s" countdown stays accurate
		// without forcing a full refetch.
		tick time.Time
	}

	statusFetchedMsg struct {
		nodes []statusNodeInfo
		err   error
		when  time.Time
	}

	statusTickMsg time.Time
)

func (m statusModel) Init() tea.Cmd {
	return tea.Batch(m.fetchCmd(), tickEverySecond())
}

func (m statusModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c", "esc":
			return m, tea.Quit
		case "r":
			// manual refresh; resets the countdown
			return m, m.fetchCmd()
		}
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		return m, nil
	case statusFetchedMsg:
		m.fetched = msg.nodes
		m.err = msg.err
		m.lastFetch = msg.when
		return m, scheduleNextFetch(m.interval)
	case statusTickMsg:
		m.tick = time.Time(msg)
		return m, tickEverySecond()
	case statusRefreshMsg:
		return m, m.fetchCmd()
	}
	return m, nil
}

// --- view ---

var (
	statusHeaderStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("39"))
	statusErrorStyle  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("203"))
	statusOKStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color("42"))
	statusWarnStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("214"))
	statusBadStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("203"))
	statusFooterStyle = lipgloss.NewStyle().Faint(true)
)

func (m statusModel) View() string {
	var sb strings.Builder

	updated := "(no data yet)"
	if !m.lastFetch.IsZero() {
		updated = m.lastFetch.UTC().Format(time.RFC3339)
	}
	nextIn := time.Duration(0)
	if !m.lastFetch.IsZero() {
		nextIn = max(m.interval-time.Since(m.lastFetch), 0)
	}

	header := fmt.Sprintf("Atomic Status • host=%s • nodes=%s • updated=%s • next refresh in %s",
		m.host, m.nodes, updated, nextIn.Round(time.Second))
	sb.WriteString(statusHeaderStyle.Render(header))
	sb.WriteString("\n\n")

	if m.err != nil {
		sb.WriteString(statusErrorStyle.Render(fmt.Sprintf("error fetching /.well-known/ping: %s", m.err)))
		sb.WriteString("\n\n")
	}

	sb.WriteString(renderNodesTable(m.fetched))

	if m.showQueue {
		sb.WriteString("\n")
		sb.WriteString(renderQueuesTable(m.fetched))
	}

	sb.WriteString("\n")
	sb.WriteString(statusFooterStyle.Render("press q or ctrl+c to exit  •  r to refresh now"))
	return sb.String()
}

func renderNodesTable(nodes []statusNodeInfo) string {
	if len(nodes) == 0 {
		return "Nodes\n  (no nodes)\n"
	}
	rows := make([][]string, 0, len(nodes))
	for _, n := range nodes {
		state := "—"
		if n.State != nil {
			state = colorState(*n.State)
		}
		hb := "—"
		if n.LastHeartbeat != nil {
			hb = ago(*n.LastHeartbeat)
		}
		uptime := "—"
		if n.Uptime != nil {
			uptime = *n.Uptime
		}
		services := strings.Join(n.Services, ",")
		rows = append(rows, []string{
			shortNodeID(n.ID),
			n.Hostname,
			n.IP,
			services,
			state,
			uptime,
			hb,
			n.Build,
		})
	}
	return "Nodes\n" + renderASCIITable(
		[]string{"ID", "HOSTNAME", "IP", "SERVICES", "STATE", "UPTIME", "LAST HB", "BUILD"},
		rows,
	)
}

func renderQueuesTable(nodes []statusNodeInfo) string {
	type qrow struct {
		nodeID string
		queue  *statusQueue
		kind   string // "event_queue" / "work_queue" / "msg_queue" / "scheduler"
	}
	var rows []qrow
	for _, n := range nodes {
		if n.Status == nil {
			continue
		}
		shortID := shortNodeID(n.ID)
		if n.Status.EventQueue != nil {
			rows = append(rows, qrow{shortID, n.Status.EventQueue, "event"})
		}
		if n.Status.Scheduler != nil {
			rows = append(rows, qrow{shortID, n.Status.Scheduler, "scheduler"})
		}
		if n.Status.MsgQueue != nil {
			rows = append(rows, qrow{shortID, n.Status.MsgQueue, "msg"})
		}
		if n.Status.Work != nil {
			rows = append(rows, qrow{shortID, n.Status.Work, "work"})
		}
	}
	if len(rows) == 0 {
		return "Queues\n  (no queue data; node may not run any dispatchers)\n"
	}

	out := make([][]string, 0, len(rows))
	for _, r := range rows {
		state := "—"
		if r.queue.Status != nil {
			state = colorState(*r.queue.Status)
		}
		hb := "—"
		if r.queue.LastHeartbeat != nil {
			hb = ago(*r.queue.LastHeartbeat)
		}
		lastDispatch := "—"
		if r.queue.LastDispatchAt != nil {
			lastDispatch = ago(*r.queue.LastDispatchAt)
		}
		out = append(out, []string{
			r.nodeID,
			r.kind,
			r.queue.Name,
			r.queue.Type,
			state,
			fmt.Sprintf("%d", r.queue.Workers),
			fmt.Sprintf("%d", r.queue.InProgress),
			fmt.Sprintf("%d", r.queue.Total),
			fmt.Sprintf("%.2f/s", r.queue.DispatchRate),
			fmt.Sprintf("%.2f%%", r.queue.ErrorRate*100),
			r.queue.AvgDispatchDuration,
			lastDispatch,
			hb,
			truncate(r.queue.LastError, 40),
		})
	}
	return "Queues\n" + renderASCIITable(
		[]string{"NODE", "KIND", "NAME", "TYPE", "STATE", "W", "IN-PROG", "TOTAL", "RATE", "ERR%", "AVG", "LAST DISP", "LAST HB", "LAST ERROR"},
		out,
	)
}

func renderASCIITable(headers []string, rows [][]string) string {
	var buf bytes.Buffer
	p := tableprinter.New(&buf)
	p.BorderTop = true
	p.BorderBottom = true
	p.BorderLeft = true
	p.BorderRight = true
	p.ColumnSeparator = "|"
	p.HeaderAlignment = tableprinter.AlignCenter
	p.RowLine = false
	p.Render(headers, rows, nil, true)
	return buf.String()
}

func colorState(s string) string {
	switch strings.ToUpper(s) {
	case "OK":
		return statusOKStyle.Render(s)
	case "WARN", "WARNING":
		return statusWarnStyle.Render(s)
	case "ERROR":
		return statusBadStyle.Render(s)
	}
	return s
}

func shortNodeID(id string) string {
	if len(id) <= 12 {
		return id
	}
	return id[:12]
}

func ago(t time.Time) string {
	d := time.Since(t).Round(time.Second)
	if d < 0 {
		return "future"
	}
	return d.String() + " ago"
}

func truncate(s string, max int) string {
	if max <= 0 || len(s) <= max {
		return s
	}
	return s[:max-1] + "…"
}

// --- commands / messages ---

type statusRefreshMsg struct{}

func (m statusModel) fetchCmd() tea.Cmd {
	return func() tea.Msg {
		nodes, err := fetchClusterStatus(m.host, m.nodes, m.token)
		return statusFetchedMsg{nodes: nodes, err: err, when: time.Now()}
	}
}

// scheduleNextFetch waits the configured interval before triggering the
// next fetch. Tea handles the sleep on its own goroutine so the UI stays
// responsive — keys / window resizes / the 1s tick still flow.
func scheduleNextFetch(d time.Duration) tea.Cmd {
	return tea.Tick(d, func(time.Time) tea.Msg {
		return statusRefreshMsg{}
	})
}

func tickEverySecond() tea.Cmd {
	return tea.Tick(time.Second, func(t time.Time) tea.Msg {
		return statusTickMsg(t)
	})
}

// --- HTTP ---

// fetchClusterStatus retrieves the cluster's full status payload via the
// well-known /ping endpoint. The status=true query asks for the verbose
// payload (queues, runtime stats); the nodes query restricts which nodes
// are returned. The endpoint returns either a single NodeInfo or a list
// depending on whether `nodes` is set, so we accept both shapes.
func fetchClusterStatus(host, nodesFilter, token string) ([]statusNodeInfo, error) {
	scheme := "https"
	if strings.Contains(host, "localhost") || strings.HasPrefix(host, "127.0.0.1") {
		scheme = "http"
	}
	if strings.HasPrefix(host, "http://") || strings.HasPrefix(host, "https://") {
		// caller already supplied a scheme — strip and let url.Parse pick it up
	} else {
		host = scheme + "://" + host
	}

	u, err := url.Parse(host)
	if err != nil {
		return nil, fmt.Errorf("invalid host %q: %w", host, err)
	}
	u.Path = "/.well-known/ping"
	q := u.Query()
	q.Set("status", "true")
	if nodesFilter != "" {
		q.Set("nodes", nodesFilter)
	}
	u.RawQuery = q.Encode()

	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Accept", "application/json")

	httpClient := &http.Client{Timeout: 15 * time.Second}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body := new(bytes.Buffer)
	if _, err := body.ReadFrom(resp.Body); err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 && resp.StatusCode != http.StatusServiceUnavailable {
		// 503 is OK here — the server still emits the payload, it just
		// flags itself as unhealthy. Anything else is a real failure.
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, truncate(body.String(), 200))
	}

	// The endpoint returns one of three shapes depending on the query:
	//   ?status=true&nodes=<filter>  → []NodeInfo (possibly empty)
	//   ?status=true                 → single NodeInfo (or null if the
	//                                  node is still registering)
	//   no status flag               → bare string ("OK"/"WARN"/etc)
	// Detect by the first non-whitespace byte rather than guessing.
	trimmed := strings.TrimSpace(body.String())
	switch {
	case trimmed == "" || trimmed == "null":
		return nil, nil

	case strings.HasPrefix(trimmed, "["):
		var arr []statusNodeInfo
		if err := json.Unmarshal(body.Bytes(), &arr); err != nil {
			return nil, fmt.Errorf("decode status array: %w (body: %s)", err, truncate(body.String(), 400))
		}
		return arr, nil

	case strings.HasPrefix(trimmed, "{"):
		var single statusNodeInfo
		if err := json.Unmarshal(body.Bytes(), &single); err != nil {
			return nil, fmt.Errorf("decode status object: %w (body: %s)", err, truncate(body.String(), 400))
		}
		return []statusNodeInfo{single}, nil

	default:
		return nil, fmt.Errorf("unexpected response shape: %s", truncate(body.String(), 400))
	}
}

