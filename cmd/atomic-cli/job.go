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
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/libatomic/atomic/pkg/atomic"
	"github.com/libatomic/atomic/pkg/ptr"
	"github.com/urfave/cli/v3"
)

var (
	jobCmd = &cli.Command{
		Name:    "job",
		Aliases: []string{"jobs"},
		Usage:   "job management",
		Commands: []*cli.Command{
			jobCreateCmd,
			jobListCmd,
			jobGetCmd,
			jobCancelCmd,
			jobRestartCmd,
		},
	}

	jobCreateCmd = &cli.Command{
		Name:      "create",
		Usage:     "create a job",
		ArgsUsage: "<type>",
		Flags: []cli.Flag{
			&cli.BoolFlag{
				Name:  "file",
				Usage: "specify job create input from a json file",
			},
			&cli.StringFlag{
				Name:     "params",
				Aliases:  []string{"p"},
				Usage:    "specify job params as a json string",
				Required: true,
			},
			&cli.StringFlag{
				Name:    "state",
				Aliases: []string{"s"},
				Usage:   "specify job state as a json string",
			},
			&cli.StringFlag{
				Name:    "scheduled_at",
				Aliases: []string{"sa"},
				Usage:   "specify job scheduled at as a timestamp",
			},
			&cli.BoolFlag{
				Name:  "wait",
				Usage: "wait for the created job to complete, streaming logs with --verbose; Ctrl+C cancels the job",
			},
		},
		Action: jobCreate,
	}

	jobGetCmd = &cli.Command{
		Name:      "get",
		Usage:     "get one or more jobs",
		ArgsUsage: "<job_id>...",
		Flags: []cli.Flag{
			&cli.BoolFlag{
				Name:  "wait",
				Usage: "tail a running job until it terminates, streaming logs with --verbose; Ctrl+C detaches without canceling the job",
			},
			&cli.BoolFlag{
				Name:  "state",
				Usage: "write the job's full state to <job_id>-state.json",
			},
			&cli.BoolFlag{
				Name:  "logs",
				Usage: "write the job's full log history to <job_id>-logs.jsonl (one log entry per line, chronological order)",
			},
			&cli.BoolFlag{
				Name:  "export",
				Usage: "write the job record to <job_id>-export.json (no expansion unless --expand is set)",
			},
			&cli.BoolFlag{
				Name:  "compress",
				Usage: "bundle any --state/--logs/--export output into <job_id>-export.tar.gz and remove the originals",
			},
			&cli.StringSliceFlag{
				Name:  "expand",
				Usage: "expand related fields on each job (one or more of: logs, state). default: none",
			},
		},
		Action: jobGet,
	}

	jobCancelCmd = &cli.Command{
		Name:      "cancel",
		Usage:     "cancel a job",
		ArgsUsage: "<job_id>",
		Flags: []cli.Flag{
			&cli.BoolFlag{
				Name:  "wait",
				Usage: "wait for the cancel to settle, streaming logs with --verbose; Ctrl+C detaches without re-canceling",
			},
		},
		Action: jobCancel,
	}

	jobRestartCmd = &cli.Command{
		Name:      "restart",
		Usage:     "restart a job",
		ArgsUsage: "<job_id>",
		Action:    jobRestart,
	}

	jobListCmd = &cli.Command{
		Name:   "list",
		Usage:  "list jobs",
		Action: jobList,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "type",
				Aliases: []string{"t"},
				Usage:   "job type",
			},
			&cli.StringFlag{
				Name:    "status",
				Aliases: []string{"s"},
				Usage:   "job status (one of: pending, scheduled, active, queued, dispatching, dispatched, paused, success, error, canceled, expired)",
				Value:   "scheduled",
			},
			&cli.StringFlag{
				Name:  "offset",
				Usage: "offset",
			},
			&cli.IntFlag{
				Name:  "limit",
				Usage: "limit",
				Value: 5,
				Validator: func(v int) error {
					if v < 1 {
						return cli.Exit("limit must be greater than 0", 1)
					}
					if v > 100 {
						return cli.Exit("limit must be less than 100", 1)
					}
					return nil
				},
			},
			&cli.StringFlag{
				Name:  "order_by",
				Usage: "order by",
			},
			&cli.StringSliceFlag{
				Name:  "expand",
				Usage: "expand related fields on each job (one or more of: logs, state). default: none",
			},
		},
	}
)

func jobCreate(ctx context.Context, cmd *cli.Command) error {
	var input atomic.JobCreateInput

	if cmd.IsSet("file") && cmd.Bool("file") {
		content, err := os.ReadFile(cmd.Args().First())
		if err != nil {
			return fmt.Errorf("failed to read job create input file: %w", err)
		}

		if err := json.Unmarshal(content, &input); err != nil {
			return fmt.Errorf("failed to unmarshal job create input: %w", err)
		}
	} else if cmd.Args().First() != "" {
		input.Type = atomic.JobType(cmd.Args().First())
	}

	if err := BindFlagsFromContext(cmd, &input, "params", "state"); err != nil {
		return err
	}

	if len(cmd.String("params")) > 0 {
		params := make(map[string]any)
		if err := json.Unmarshal([]byte(cmd.String("params")), &params); err != nil {
			return fmt.Errorf("failed to unmarshal job params: %w", err)
		}
		input.Params = params
	}

	if len(cmd.String("state")) > 0 {
		if err := json.Unmarshal([]byte(cmd.String("state")), &input.State); err != nil {
			return fmt.Errorf("failed to unmarshal job state: %w", err)
		}
	}

	job, err := backend.JobCreate(ctx, &input)
	if err != nil {
		return err
	}

	PrintResult(cmd, []*atomic.Job{job}, WithFields("id", "type", "status", "scheduled_at", "completed_at"),
		WithVirtualField("status", func(v any) string {
			job := v.(atomic.Job)
			return string(job.Status)
		}),
		WithVirtualField("scheduled_at", func(v any) string {
			job := v.(atomic.Job)
			if job.ScheduledAt == nil {
				return ""
			}
			return job.ScheduledAt.Format(time.RFC3339)
		}),
		WithVirtualField("completed_at", func(v any) string {
			job := v.(atomic.Job)
			if job.CompletedAt == nil {
				return ""
			}
			return job.CompletedAt.Format(time.RFC3339)
		}))

	if cmd.Bool("wait") {
		// job create "owns" the job, so Ctrl+C cancels it
		return waitForJob(ctx, job, mainCmd.Bool("verbose"), true)
	}

	return nil
}

func jobGet(ctx context.Context, cmd *cli.Command) error {
	if cmd.Args().Len() == 0 {
		return cli.Exit("job id is required", 1)
	}

	if cmd.Bool("compress") && !cmd.Bool("state") && !cmd.Bool("logs") && !cmd.Bool("export") {
		return cli.Exit("--compress requires at least one of --state, --logs, or --export", 1)
	}

	args := cmd.Args().Slice()
	jobIDs := make([]atomic.ID, 0, len(args))
	for _, arg := range args {
		id, err := atomic.ParseID(arg)
		if err != nil {
			return cli.Exit(fmt.Sprintf("invalid job id %q: %s", arg, err), 1)
		}
		jobIDs = append(jobIDs, id)
	}

	var (
		jobs      []*atomic.Job
		artifacts []string
	)

	expand := atomic.ExpandFields(cmd.StringSlice("expand"))

	for _, jobID := range jobIDs {
		jobID := jobID

		job, err := backend.JobGet(ctx, &atomic.JobGetInput{
			JobID:  &jobID,
			Expand: expand,
		})
		if err != nil {
			return err
		}
		jobs = append(jobs, job)

		if cmd.Bool("wait") {
			// job get is read-only: Ctrl+C detaches the tail, never cancels
			if err := waitForJob(ctx, job, mainCmd.Bool("verbose"), false); err != nil {
				return err
			}
		}

		if cmd.Bool("state") {
			path, err := writeJobState(jobID, job)
			if err != nil {
				return err
			}
			artifacts = append(artifacts, path)
		}

		if cmd.Bool("logs") {
			path, err := writeJobLogs(ctx, jobID)
			if err != nil {
				return err
			}
			artifacts = append(artifacts, path)
		}

		if cmd.Bool("export") {
			path, err := writeJobExport(jobID, job)
			if err != nil {
				return err
			}
			artifacts = append(artifacts, path)
		}
	}

	PrintResult(cmd, jobs, WithFields("id", "type", "status", "scheduled_at", "completed_at", "params"),
		WithVirtualField("status", func(v any) string {
			job := v.(atomic.Job)
			return string(job.Status)
		}),
		WithVirtualField("scheduled_at", func(v any) string {
			job := v.(atomic.Job)
			if job.ScheduledAt == nil {
				return ""
			}
			return job.ScheduledAt.Format(time.RFC3339)
		}),
		WithVirtualField("completed_at", func(v any) string {
			job := v.(atomic.Job)
			if job.CompletedAt == nil {
				return ""
			}
			return job.CompletedAt.Format(time.RFC3339)
		}),
		WithVirtualField("params", func(v any) string {
			job := v.(atomic.Job)
			return formatJobParams(job.Params)
		}))

	if cmd.Bool("compress") && len(artifacts) > 0 {
		bundle := jobIDs[0].String() + "-export.tar.gz"
		if len(jobIDs) > 1 {
			bundle = "job-export-" + time.Now().UTC().Format("20060102-150405") + ".tar.gz"
		}
		if err := bundleJobArtifacts(bundle, artifacts); err != nil {
			return err
		}
	}

	return nil
}

// formatJobParams renders a job's params as one "key: value" per line so a
// table cell stays narrow. Non-scalar values are kept as compact JSON.
func formatJobParams(p atomic.JobParams) string {
	if len(p) == 0 {
		return ""
	}

	var fields map[string]json.RawMessage
	if err := json.Unmarshal(p, &fields); err != nil {
		var buf bytes.Buffer
		if err := json.Compact(&buf, p); err != nil {
			return string(p)
		}
		return buf.String()
	}

	keys := make([]string, 0, len(fields))
	for k := range fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var b strings.Builder
	for i, k := range keys {
		if i > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(k)
		b.WriteString(": ")
		b.WriteString(scalarFromJSON(fields[k]))
	}
	return b.String()
}

// scalarFromJSON unquotes string values and compacts everything else so the
// rendered line is the cleanest representation of a JSON value.
func scalarFromJSON(raw json.RawMessage) string {
	v := bytes.TrimSpace(raw)
	if len(v) == 0 {
		return ""
	}
	if v[0] == '"' {
		var s string
		if err := json.Unmarshal(v, &s); err == nil {
			return s
		}
	}
	var buf bytes.Buffer
	if err := json.Compact(&buf, v); err != nil {
		return string(v)
	}
	return buf.String()
}

// writeJobState writes the job's state object to <job_id>-state.json.
func writeJobState(jobID atomic.ID, job *atomic.Job) (string, error) {
	path := jobID.String() + "-state.json"
	f, err := os.Create(path)
	if err != nil {
		return "", fmt.Errorf("failed to create state file: %w", err)
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(job.State); err != nil {
		return "", fmt.Errorf("failed to write state: %w", err)
	}
	fmt.Fprintf(os.Stderr, "wrote job state → %s\n", path)
	return path, nil
}

// writeJobExport writes the unexpanded job record to <job_id>-export.json.
func writeJobExport(jobID atomic.ID, job *atomic.Job) (string, error) {
	path := jobID.String() + "-export.json"
	f, err := os.Create(path)
	if err != nil {
		return "", fmt.Errorf("failed to create export file: %w", err)
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(job); err != nil {
		return "", fmt.Errorf("failed to write export: %w", err)
	}
	fmt.Fprintf(os.Stderr, "wrote job export → %s\n", path)
	return path, nil
}

// writeJobLogs fetches the job's full log history and writes it to
// <job_id>-logs.jsonl in chronological order, one JSON object per line.
// The default JobGet log limit is 100; we re-fetch with a high cap so the
// dump is complete in one shot. (The job_logs API only supports a "since"
// filter and orders DESC, so true backward pagination isn't available.)
func writeJobLogs(ctx context.Context, jobID atomic.ID) (string, error) {
	full, err := backend.JobGet(ctx, &atomic.JobGetInput{
		JobID:    &jobID,
		LogLimit: ptr.Uint64(10_000_000),
	})
	if err != nil {
		return "", fmt.Errorf("failed to fetch logs: %w", err)
	}

	path := jobID.String() + "-logs.jsonl"
	f, err := os.Create(path)
	if err != nil {
		return "", fmt.Errorf("failed to create logs file: %w", err)
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	// API returns DESC (newest first); reverse for chronological order on disk.
	for i := len(full.Logs) - 1; i >= 0; i-- {
		if err := enc.Encode(full.Logs[i]); err != nil {
			return "", fmt.Errorf("failed to write log entry: %w", err)
		}
	}
	fmt.Fprintf(os.Stderr, "wrote %d log entries → %s\n", len(full.Logs), path)
	return path, nil
}

// bundleJobArtifacts gzip-tars the given files into bundle and removes the
// originals on success.
func bundleJobArtifacts(bundle string, paths []string) error {
	out, err := os.Create(bundle)
	if err != nil {
		return fmt.Errorf("failed to create archive: %w", err)
	}
	defer out.Close()

	gz := gzip.NewWriter(out)
	defer gz.Close()

	tw := tar.NewWriter(gz)
	defer tw.Close()

	for _, p := range paths {
		info, err := os.Stat(p)
		if err != nil {
			return fmt.Errorf("failed to stat %s: %w", p, err)
		}

		hdr, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return fmt.Errorf("failed to build header for %s: %w", p, err)
		}
		hdr.Name = filepath.Base(p)

		if err := tw.WriteHeader(hdr); err != nil {
			return fmt.Errorf("failed to write header for %s: %w", p, err)
		}

		f, err := os.Open(p)
		if err != nil {
			return fmt.Errorf("failed to open %s: %w", p, err)
		}
		if _, err := io.Copy(tw, f); err != nil {
			f.Close()
			return fmt.Errorf("failed to write %s: %w", p, err)
		}
		f.Close()
	}

	if err := tw.Close(); err != nil {
		return fmt.Errorf("failed to finalize tar: %w", err)
	}
	if err := gz.Close(); err != nil {
		return fmt.Errorf("failed to finalize gzip: %w", err)
	}

	for _, p := range paths {
		if err := os.Remove(p); err != nil {
			fmt.Fprintf(os.Stderr, "warning: failed to remove %s: %s\n", p, err)
		}
	}

	fmt.Fprintf(os.Stderr, "bundled %d file(s) → %s\n", len(paths), bundle)
	return nil
}

func jobList(ctx context.Context, cmd *cli.Command) error {
	var input atomic.JobListInput

	if err := BindFlagsFromContext(cmd, &input); err != nil {
		return err
	}

	jobs, err := backend.JobList(ctx, &input)
	if err != nil {
		return err
	}

	if len(jobs) == 0 {
		return cli.Exit("no jobs found", 1)
	}

	PrintResult(cmd, jobs, WithFields("id", "type", "status", "scheduled_at", "completed_at"),
		WithVirtualField("status", func(v any) string {
			job := v.(atomic.Job)
			return string(job.Status)
		}),
		WithVirtualField("scheduled_at", func(v any) string {
			job := v.(atomic.Job)
			if job.ScheduledAt == nil {
				return ""
			}
			return job.ScheduledAt.Format(time.RFC3339)
		}),
		WithVirtualField("completed_at", func(v any) string {
			job := v.(atomic.Job)
			if job.CompletedAt == nil {
				return ""
			}
			return job.CompletedAt.Format(time.RFC3339)
		}))

	return nil
}

func jobCancel(ctx context.Context, cmd *cli.Command) error {
	var input atomic.JobCancelInput

	if cmd.Args().Len() == 0 {
		return cli.Exit("job id is required", 1)
	}

	jobID, err := atomic.ParseID(cmd.Args().First())
	if err != nil {
		return cli.Exit(err.Error(), 1)
	}

	input.JobID = jobID

	if err := backend.JobCancel(ctx, &input); err != nil {
		return err
	}

	if cmd.Bool("wait") {
		// fetch the job to wait on; cancel was already requested so Ctrl+C
		// just detaches (no point re-canceling)
		job, err := backend.JobGet(ctx, &atomic.JobGetInput{JobID: &jobID})
		if err != nil {
			return fmt.Errorf("failed to fetch job for wait: %w", err)
		}
		return waitForJob(ctx, job, mainCmd.Bool("verbose"), false)
	}

	return nil
}

func jobRestart(ctx context.Context, cmd *cli.Command) error {
	var input atomic.JobRestartInput

	if cmd.Args().Len() == 0 {
		return cli.Exit("job id is required", 1)
	}

	jobID, err := atomic.ParseID(cmd.Args().First())
	if err != nil {
		return cli.Exit(err.Error(), 1)
	}

	input.JobID = jobID

	job, err := backend.JobRestart(ctx, &input)
	if err != nil {
		return err
	}

	PrintResult(cmd, []*atomic.Job{job}, WithFields("id", "type", "status", "scheduled_at", "completed_at"),
		WithVirtualField("status", func(v any) string {
			job := v.(atomic.Job)
			return string(job.Status)
		}),
		WithVirtualField("scheduled_at", func(v any) string {
			job := v.(atomic.Job)
			if job.ScheduledAt == nil {
				return ""
			}
			return job.ScheduledAt.Format(time.RFC3339)
		}),
		WithVirtualField("completed_at", func(v any) string {
			job := v.(atomic.Job)
			if job.CompletedAt == nil {
				return ""
			}
			return job.CompletedAt.Format(time.RFC3339)
		}))

	return nil
}
