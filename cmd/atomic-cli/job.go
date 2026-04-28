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
		Usage:     "get a job",
		ArgsUsage: "<job_id>",
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
				Usage:   "job status",
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
				Usage: "expand",
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
	var input atomic.JobGetInput

	if cmd.Args().Len() == 0 {
		return cli.Exit("job id is required", 1)
	}

	jobID, err := atomic.ParseID(cmd.Args().First())
	if err != nil {
		return cli.Exit(err.Error(), 1)
	}

	input.JobID = &jobID

	job, err := backend.JobGet(ctx, &input)
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
		// job get is read-only: Ctrl+C detaches the tail, never cancels
		if err := waitForJob(ctx, job, mainCmd.Bool("verbose"), false); err != nil {
			return err
		}
	}

	if cmd.Bool("state") {
		if err := writeJobState(jobID, job); err != nil {
			return err
		}
	}

	if cmd.Bool("logs") {
		if err := writeJobLogs(ctx, jobID); err != nil {
			return err
		}
	}

	return nil
}

// writeJobState writes the job's state object to <job_id>-state.json.
func writeJobState(jobID atomic.ID, job *atomic.Job) error {
	path := jobID.String() + "-state.json"
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create state file: %w", err)
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(job.State); err != nil {
		return fmt.Errorf("failed to write state: %w", err)
	}
	fmt.Fprintf(os.Stderr, "wrote job state → %s\n", path)
	return nil
}

// writeJobLogs fetches the job's full log history and writes it to
// <job_id>-logs.jsonl in chronological order, one JSON object per line.
// The default JobGet log limit is 100; we re-fetch with a high cap so the
// dump is complete in one shot. (The job_logs API only supports a "since"
// filter and orders DESC, so true backward pagination isn't available.)
func writeJobLogs(ctx context.Context, jobID atomic.ID) error {
	full, err := backend.JobGet(ctx, &atomic.JobGetInput{
		JobID:    &jobID,
		LogLimit: ptr.Uint64(10_000_000),
	})
	if err != nil {
		return fmt.Errorf("failed to fetch logs: %w", err)
	}

	path := jobID.String() + "-logs.jsonl"
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create logs file: %w", err)
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	// API returns DESC (newest first); reverse for chronological order on disk.
	for i := len(full.Logs) - 1; i >= 0; i-- {
		if err := enc.Encode(full.Logs[i]); err != nil {
			return fmt.Errorf("failed to write log entry: %w", err)
		}
	}
	fmt.Fprintf(os.Stderr, "wrote %d log entries → %s\n", len(full.Logs), path)
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
