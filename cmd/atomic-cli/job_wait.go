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
	"fmt"
	"os"
	"os/signal"
	"sort"
	"syscall"
	"time"

	"github.com/libatomic/atomic/pkg/atomic"
	"github.com/libatomic/atomic/pkg/ptr"
	"github.com/libatomic/atomic/pkg/queue"
	"github.com/schollz/progressbar/v3"
)

// waitForJob polls a job until it reaches a terminal state, streaming logs
// (verbose only) and rendering a progress bar from the job's reported state.
//
// When cancelOnInterrupt is true, an interrupt (Ctrl+C) requests job
// cancellation and polls until the server confirms. Used for commands that
// "own" the job — user import, job create with --wait.
//
// When cancelOnInterrupt is false, an interrupt just detaches the tail and
// returns nil, leaving the job running on the server. Used for observers —
// job get --wait, job cancel --wait.
func waitForJob(ctx context.Context, job *atomic.Job, verbose, cancelOnInterrupt bool) error {
	fmt.Fprintf(os.Stderr, "\nwaiting for job %s...\n", job.UUID)

	var bar *progressbar.ProgressBar
	var barTotal int64

	// start with an indeterminate spinner until we know the total
	bar = progressbar.NewOptions(-1,
		progressbar.OptionSetDescription("Starting"),
		progressbar.OptionSetWriter(os.Stderr),
		progressbar.OptionSpinnerType(14),
		progressbar.OptionClearOnFinish(),
	)

	var logSinceMs *int64
	pollInterval := time.Second
	logLimit := ptr.Uint64(20)

	for {
		select {
		case <-ctx.Done():
			bar.Finish()
			if cancelOnInterrupt {
				return cancelAndWaitJob(job, &logSinceMs, verbose)
			}
			fmt.Fprintf(os.Stderr, "\ndetached from job %s (still running on server)\n", job.UUID)
			return nil
		case <-time.After(pollInterval):
		}

		getInput := &atomic.JobGetInput{
			JobID:    &job.UUID,
			LogLimit: logLimit,
			LogSince: logSinceMs,
		}

		updated, err := backend.JobGet(ctx, getInput)
		if err != nil {
			bar.Finish()
			return fmt.Errorf("failed to poll job: %w", err)
		}

		// show new logs above the progress bar if verbose
		if verbose && len(updated.Logs) > 0 {
			bar.Clear()

			// logs come in reverse chronological order, print oldest first
			for i := len(updated.Logs) - 1; i >= 0; i-- {
				entry := updated.Logs[i]
				fmt.Fprintf(os.Stderr, "  [%s] %s: %s\n", entry.Timestamp.Format("15:04:05"), entry.Level, entry.Message)
			}

			// update logSince to the most recent log timestamp (unix millis)
			ms := updated.Logs[0].Timestamp.UnixMilli()
			logSinceMs = &ms
		}

		// update progress bar from state status
		if updated.State != nil {
			status := updated.State.Status()

			// find the current stage for precise unit-based progress
			var currentStage *atomic.JobStateStage
			if status.CurrentStage != "" && status.Stages != nil {
				currentStage = status.Stages[status.CurrentStage]
			}

			if currentStage != nil && currentStage.UnitsTotal > 0 {
				// switch to a unit-based progress bar if the total changed
				if barTotal != currentStage.UnitsTotal {
					bar.Finish()
					barTotal = currentStage.UnitsTotal
					bar = progressbar.NewOptions(int(barTotal),
						progressbar.OptionSetDescription(currentStage.Name),
						progressbar.OptionSetWriter(os.Stderr),
						progressbar.OptionShowCount(),
						progressbar.OptionClearOnFinish(),
						progressbar.OptionSetPredictTime(true),
					)
				}
				bar.Set(int(currentStage.UnitsCompleted))
			} else {
				// fallback to percentage-based progress
				if barTotal == 0 && status.Progress > 0 {
					bar.Finish()
					barTotal = 100
					bar = progressbar.NewOptions(100,
						progressbar.OptionSetDescription("Processing"),
						progressbar.OptionSetWriter(os.Stderr),
						progressbar.OptionShowCount(),
						progressbar.OptionClearOnFinish(),
					)
				}
				if barTotal > 0 {
					pct := int(status.Progress * 100)
					if pct > 100 {
						pct = 100
					}
					bar.Set(pct)
				}
			}

			if status.Message != "" {
				bar.Describe(status.Message)
			}
		}

		// check terminal states
		switch updated.Status {
		case queue.StatusSuccess:
			bar.Finish()
			// jobs can finish faster than a poll tick — fetch any remaining
			// logs so verbose users see the tail, and so we don't miss errors.
			flushRemainingLogs(ctx, job, &logSinceMs, verbose)

			// queue success only means "the handler returned without a queue
			// error"; check the job-reported status for internal success/failure
			reported := reportedJobStatus(updated)
			if reported == atomic.JobStatusFailed {
				printJobErrors(updated)
				printJobSummary(updated)
				return fmt.Errorf("job %s reported internal failure", job.UUID)
			}
			fmt.Fprintf(os.Stderr, "\njob %s completed successfully\n", job.UUID)
			printJobErrors(updated) // non-fatal errors can coexist with success
			printJobSummary(updated)
			return nil

		case queue.StatusError:
			bar.Finish()
			flushRemainingLogs(ctx, job, &logSinceMs, verbose)
			errMsg := "unknown error"
			if updated.Error != nil {
				errMsg = *updated.Error
			}
			printJobErrors(updated)
			return fmt.Errorf("job %s failed: %s", job.UUID, errMsg)

		case queue.StatusCanceled:
			bar.Finish()
			flushRemainingLogs(ctx, job, &logSinceMs, verbose)
			printJobErrors(updated)
			return fmt.Errorf("job %s was canceled", job.UUID)
		}
	}
}

// reportedJobStatus returns the job-handler-reported status from state when
// present, falling back to "" if the job never published one.
func reportedJobStatus(job *atomic.Job) atomic.JobStatus {
	if job.State == nil {
		return ""
	}
	return job.State.Status().Status
}

// flushRemainingLogs fetches any logs newer than logSinceMs and prints them
// (verbose only). Used right before reporting a terminal state so short-lived
// jobs don't drop their log tail.
func flushRemainingLogs(ctx context.Context, job *atomic.Job, logSinceMs **int64, verbose bool) {
	if !verbose {
		return
	}
	limit := ptr.Uint64(1000)
	tail, err := backend.JobGet(ctx, &atomic.JobGetInput{
		JobID:    &job.UUID,
		LogLimit: limit,
		LogSince: *logSinceMs,
	})
	if err != nil || len(tail.Logs) == 0 {
		return
	}
	for i := len(tail.Logs) - 1; i >= 0; i-- {
		e := tail.Logs[i]
		fmt.Fprintf(os.Stderr, "  [%s] %s: %s\n", e.Timestamp.Format("15:04:05"), e.Level, e.Message)
	}
	ms := tail.Logs[0].Timestamp.UnixMilli()
	*logSinceMs = &ms
}

// printJobErrors prints any per-row errors captured in job.Errors. Safe to
// call when the job succeeded — many jobs (like user import) treat individual
// row failures as non-fatal but still want the user to see them.
func printJobErrors(job *atomic.Job) {
	if len(job.Errors) == 0 {
		return
	}
	fmt.Fprintf(os.Stderr, "\njob errors (%d):\n", len(job.Errors))
	for _, e := range job.Errors {
		fmt.Fprintf(os.Stderr, "  [%s] %s\n", e.CreatedAt.Format("15:04:05"), e.Error)
	}
}

// printJobSummary prints total duration and a per-stage breakdown (duration
// and items/sec) for a completed job. Falls back gracefully when timing or
// unit counts are missing (e.g. stages that don't track units).
func printJobSummary(job *atomic.Job) {
	if job.CompletedAt != nil {
		total := job.CompletedAt.Sub(job.CreatedAt)
		fmt.Fprintf(os.Stderr, "total duration: %s\n", total.Round(time.Millisecond))
	}

	if job.State == nil {
		return
	}
	status := job.State.Status()
	if len(status.Stages) == 0 {
		return
	}

	stages := make([]*atomic.JobStateStage, 0, len(status.Stages))
	for _, s := range status.Stages {
		stages = append(stages, s)
	}
	sort.Slice(stages, func(i, j int) bool {
		if stages[i].Order != stages[j].Order {
			return stages[i].Order < stages[j].Order
		}
		return stages[i].Name < stages[j].Name
	})

	fmt.Fprintf(os.Stderr, "stages:\n")
	for _, s := range stages {
		var (
			dur     time.Duration
			durStr  = "—"
			rateStr = ""
		)
		if s.StartedAt != nil && s.CompletedAt != nil {
			dur = s.CompletedAt.Sub(*s.StartedAt)
			durStr = dur.Round(time.Millisecond).String()
		} else if s.StartedAt != nil && !s.Completed {
			dur = time.Since(*s.StartedAt)
			durStr = dur.Round(time.Millisecond).String() + " (ongoing)"
		}
		if s.UnitsCompleted > 0 && dur > 0 {
			rate := float64(s.UnitsCompleted) / dur.Seconds()
			rateStr = fmt.Sprintf(" — %d/%d units @ %.1f/s", s.UnitsCompleted, s.UnitsTotal, rate)
		} else if s.UnitsCompleted > 0 {
			rateStr = fmt.Sprintf(" — %d/%d units", s.UnitsCompleted, s.UnitsTotal)
		}
		fmt.Fprintf(os.Stderr, "  %-30s %s%s\n", s.Name, durStr, rateStr)
	}
}

// cancelAndWaitJob requests cancellation of the job and polls until it reaches
// a terminal state, timing out after 90s. A second interrupt abandons the wait
// and returns immediately (the job may still be running on the server).
//
// On terminal state (including timeout/abandon), dumps any logs emitted after
// the cancel request (verbose only) and prints job errors + the stage summary
// so the user sees why the job stopped, not just that it stopped.
func cancelAndWaitJob(job *atomic.Job, logSinceMs **int64, verbose bool) error {
	const (
		cancelTimeout = 90 * time.Second
		pollInterval  = 2 * time.Second
	)

	fmt.Fprintf(os.Stderr, "\ninterrupt received, attempting to cancel job %s (timeout %s, Ctrl+C again to abandon wait)...\n", job.UUID, cancelTimeout)

	// Fresh background context — the inherited ctx is already canceled.
	cancelCtx, cancelFn := context.WithTimeout(context.Background(), cancelTimeout)
	defer cancelFn()

	if err := backend.JobCancel(cancelCtx, &atomic.JobCancelInput{JobID: job.UUID}); err != nil {
		return fmt.Errorf("failed to request job cancel: %w", err)
	}

	// Register our own signal channel so a second Ctrl+C abandons the wait.
	// signal.Notify is additive, so this coexists with the parent's NotifyContext.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	// dumpTail prints any logs newer than logSinceMs and advances the cursor.
	// Used while polling so the user sees what the job does *during* the
	// cancel window (e.g. "finalize stage: rolling back N records").
	dumpTail := func() {
		if !verbose {
			return
		}
		limit := ptr.Uint64(200)
		tail, err := backend.JobGet(cancelCtx, &atomic.JobGetInput{
			JobID:    &job.UUID,
			LogLimit: limit,
			LogSince: *logSinceMs,
		})
		if err != nil || len(tail.Logs) == 0 {
			return
		}
		for i := len(tail.Logs) - 1; i >= 0; i-- {
			e := tail.Logs[i]
			fmt.Fprintf(os.Stderr, "  [%s] %s: %s\n", e.Timestamp.Format("15:04:05"), e.Level, e.Message)
		}
		ms := tail.Logs[0].Timestamp.UnixMilli()
		*logSinceMs = &ms
	}

	for {
		select {
		case <-cancelCtx.Done():
			dumpTail()
			return fmt.Errorf("timed out after %s waiting for job %s to cancel (job may still be running)", cancelTimeout, job.UUID)
		case <-sigCh:
			dumpTail()
			return fmt.Errorf("abandoned wait for job %s cancel (job may still be running)", job.UUID)
		case <-ticker.C:
		}

		// stream logs while we poll — the handler may still be running
		// during the cancel grace window
		dumpTail()

		updated, err := backend.JobGet(cancelCtx, &atomic.JobGetInput{JobID: &job.UUID})
		if err != nil {
			fmt.Fprintf(os.Stderr, "  failed to poll job during cancel: %s\n", err)
			continue
		}

		switch updated.Status {
		case queue.StatusCanceled:
			flushRemainingLogs(cancelCtx, job, logSinceMs, verbose)
			fmt.Fprintf(os.Stderr, "job %s canceled\n", job.UUID)
			printJobErrors(updated)
			printJobSummary(updated)
			return fmt.Errorf("job %s was canceled", job.UUID)
		case queue.StatusSuccess:
			flushRemainingLogs(cancelCtx, job, logSinceMs, verbose)
			fmt.Fprintf(os.Stderr, "job %s completed before cancel took effect\n", job.UUID)
			printJobErrors(updated)
			printJobSummary(updated)
			return nil
		case queue.StatusError:
			flushRemainingLogs(cancelCtx, job, logSinceMs, verbose)
			errMsg := "unknown error"
			if updated.Error != nil {
				errMsg = *updated.Error
			}
			printJobErrors(updated)
			printJobSummary(updated)
			return fmt.Errorf("job %s failed: %s", job.UUID, errMsg)
		}
	}
}
