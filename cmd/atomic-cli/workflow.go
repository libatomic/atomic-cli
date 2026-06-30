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
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	client "github.com/libatomic/atomic-go"
	"github.com/libatomic/atomic/pkg/atomic"
	"github.com/libatomic/atomic/pkg/ptr"
	"github.com/urfave/cli/v3"
)

var (
	workflowCmd = &cli.Command{
		Name:    "workflow",
		Aliases: []string{"workflows", "wf"},
		Usage:   "workflow management",
		Commands: []*cli.Command{
			workflowListCmd,
			workflowGetCmd,
			workflowCreateCmd,
			workflowUpdateCmd,
			workflowDeleteCmd,
			workflowRunCmd,
			workflowRunsCmd,
			workflowRunGetCmd,
		},
	}

	workflowListCmd = &cli.Command{
		Name:   "list",
		Usage:  "list workflows",
		Action: workflowList,
		Flags: []cli.Flag{
			&cli.IntFlag{
				Name:  "limit",
				Usage: "limit the number of workflows",
			},
			&cli.IntFlag{
				Name:  "offset",
				Usage: "offset the number of workflows",
			},
		},
	}

	workflowGetCmd = &cli.Command{
		Name:      "get",
		Usage:     "get a workflow by id or slug",
		ArgsUsage: "<workflow_id_or_slug>",
		Action:    workflowGet,
		Flags: []cli.Flag{
			&cli.BoolFlag{
				Name:  "definition",
				Usage: "output just the workflow definition as YAML-compatible JSON",
			},
		},
	}

	workflowCreateCmd = &cli.Command{
		Name:      "create",
		Usage:     "create a workflow from a YAML or JSON definition file",
		ArgsUsage: "<definition_file>",
		Action:    workflowCreate,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "name",
				Aliases: []string{"n"},
				Usage:   "workflow name (defaults to name in definition)",
			},
			&cli.StringFlag{
				Name:  "slug",
				Usage: "workflow slug (defaults to slugified name)",
			},
			&cli.BoolFlag{
				Name:  "disabled",
				Usage: "create the workflow in a disabled state",
			},
		},
	}

	workflowUpdateCmd = &cli.Command{
		Name:      "update",
		Usage:     "update a workflow from a YAML or JSON definition file",
		ArgsUsage: "<workflow_id> [definition_file]",
		Action:    workflowUpdate,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "name",
				Aliases: []string{"n"},
				Usage:   "update the workflow name",
			},
			&cli.StringFlag{
				Name:  "slug",
				Usage: "update the workflow slug",
			},
			&cli.BoolFlag{
				Name:  "enable",
				Usage: "enable the workflow",
			},
			&cli.BoolFlag{
				Name:  "disable",
				Usage: "disable the workflow",
			},
		},
	}

	workflowDeleteCmd = &cli.Command{
		Name:      "delete",
		Usage:     "delete a workflow",
		ArgsUsage: "<workflow_id>",
		Action:    workflowDelete,
	}

	workflowRunCmd = &cli.Command{
		Name:      "run",
		Usage:     "manually trigger a workflow run",
		ArgsUsage: "<workflow_id>",
		Action:    workflowRunAction,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "inputs",
				Aliases: []string{"in"},
				Usage:   "workflow inputs as a JSON string",
			},
			&cli.BoolFlag{
				Name:  "wait",
				Usage: "wait for the run to complete, streaming logs with --verbose",
			},
		},
	}

	workflowRunsCmd = &cli.Command{
		Name:      "runs",
		Usage:     "list runs for a workflow",
		ArgsUsage: "<workflow_id>",
		Action:    workflowRunsList,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "status",
				Aliases: []string{"s"},
				Usage:   "filter by status (pending, running, success, failed)",
			},
			&cli.IntFlag{
				Name:  "limit",
				Usage: "limit",
				Value: 10,
			},
			&cli.IntFlag{
				Name:  "offset",
				Usage: "offset",
			},
		},
	}

	workflowRunGetCmd = &cli.Command{
		Name:      "run-get",
		Usage:     "get a workflow run by id",
		ArgsUsage: "<run_id>",
		Action:    workflowRunGetAction,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  "workflow_id",
				Usage: "workflow id (optional, narrows the lookup)",
			},
			&cli.StringSliceFlag{
				Name:  "expand",
				Usage: "expand related fields on the run's job (logs, state)",
			},
			&cli.BoolFlag{
				Name:  "wait",
				Usage: "wait for the run's job to complete, streaming logs with --verbose",
			},
		},
	}
)

func workflowList(ctx context.Context, cmd *cli.Command) error {
	if inst == nil {
		return cli.Exit("instance is required", 1)
	}

	input := atomic.WorkflowListInput{
		InstanceID: inst.UUID,
	}

	if cmd.IsSet("limit") {
		input.Limit = ptr.Uint64(uint64(cmd.Int("limit")))
	}
	if cmd.IsSet("offset") {
		input.Offset = ptr.Uint64(uint64(cmd.Int("offset")))
	}

	workflows, err := backend.WorkflowList(ctx, &input)
	if err != nil {
		return err
	}

	if len(workflows) == 0 {
		return cli.Exit("no workflows found", 1)
	}

	PrintResult(cmd, workflows,
		WithFields("id", "name", "slug", "enabled", "version", "created_at"),
		WithVirtualField("created_at", func(v any) string {
			wf := v.(atomic.Workflow)
			return wf.CreatedAt.Format(time.RFC3339)
		}),
	)

	return nil
}

func workflowGet(ctx context.Context, cmd *cli.Command) error {
	if inst == nil {
		return cli.Exit("instance is required", 1)
	}

	if cmd.Args().Len() == 0 {
		return cli.Exit("workflow id or slug is required", 1)
	}

	input := atomic.WorkflowGetInput{
		InstanceID: inst.UUID,
	}

	idOrSlug := cmd.Args().First()
	if id, err := atomic.ParseID(idOrSlug); err == nil {
		input.WorkflowID = &id
	} else {
		input.Slug = ptr.String(idOrSlug)
	}

	wf, err := backend.WorkflowGet(ctx, &input)
	if err != nil {
		return err
	}

	if cmd.Bool("definition") {
		out, err := json.MarshalIndent(wf.Definition, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(out))
		return nil
	}

	PrintResult(cmd, []*atomic.Workflow{wf},
		WithSingleValue(true),
		WithFields("id", "name", "slug", "enabled", "version", "created_at"),
		WithVirtualField("created_at", func(v any) string {
			wf := v.(atomic.Workflow)
			return wf.CreatedAt.Format(time.RFC3339)
		}),
	)

	return nil
}

func workflowCreate(ctx context.Context, cmd *cli.Command) error {
	if inst == nil {
		return cli.Exit("instance is required", 1)
	}

	if cmd.Args().Len() == 0 {
		return cli.Exit("definition file is required", 1)
	}

	data, err := os.ReadFile(cmd.Args().First())
	if err != nil {
		return fmt.Errorf("failed to read definition file: %w", err)
	}

	input := atomic.WorkflowCreateInput{
		InstanceID: inst.UUID,
	}

	if cmd.IsSet("name") {
		input.Name = cmd.String("name")
	}
	if cmd.IsSet("slug") {
		input.Slug = ptr.String(cmd.String("slug"))
	}
	if cmd.Bool("disabled") {
		input.Enabled = ptr.Bool(false)
	}

	apiBackend, ok := backend.(*client.Client)
	if !ok {
		return cli.Exit("workflow create requires an API backend (not db_source)", 1)
	}

	wf, err := apiBackend.WorkflowCreateFromBytes(ctx, &input, data)
	if err != nil {
		return err
	}

	PrintResult(cmd, []*atomic.Workflow{wf},
		WithSingleValue(true),
		WithFields("id", "name", "slug", "enabled", "version", "created_at"),
		WithVirtualField("created_at", func(v any) string {
			wf := v.(atomic.Workflow)
			return wf.CreatedAt.Format(time.RFC3339)
		}),
	)

	return nil
}

func workflowUpdate(ctx context.Context, cmd *cli.Command) error {
	if inst == nil {
		return cli.Exit("instance is required", 1)
	}

	if cmd.Args().Len() == 0 {
		return cli.Exit("workflow id is required", 1)
	}

	workflowID, err := atomic.ParseID(cmd.Args().First())
	if err != nil {
		return cli.Exit(fmt.Sprintf("invalid workflow id: %s", err), 1)
	}

	input := atomic.WorkflowUpdateInput{
		InstanceID: inst.UUID,
		WorkflowID: workflowID,
	}

	if cmd.IsSet("name") {
		input.Name = ptr.String(cmd.String("name"))
	}
	if cmd.IsSet("slug") {
		input.Slug = ptr.String(cmd.String("slug"))
	}
	if cmd.Bool("enable") {
		input.Enabled = ptr.Bool(true)
	}
	if cmd.Bool("disable") {
		input.Enabled = ptr.Bool(false)
	}

	apiBackend, ok := backend.(*client.Client)
	if !ok {
		return cli.Exit("workflow update requires an API backend (not db_source)", 1)
	}

	var defFile string
	if cmd.Args().Len() > 1 {
		defFile = cmd.Args().Get(1)
	}

	var wf *atomic.Workflow
	if defFile != "" {
		data, err := os.ReadFile(defFile)
		if err != nil {
			return fmt.Errorf("failed to read definition file: %w", err)
		}
		wf, err = apiBackend.WorkflowUpdateFromBytes(ctx, &input, data)
		if err != nil {
			return err
		}
	} else {
		wf, err = apiBackend.WorkflowUpdate(ctx, &input, nil, "application/json")
		if err != nil {
			return err
		}
	}

	PrintResult(cmd, []*atomic.Workflow{wf},
		WithSingleValue(true),
		WithFields("id", "name", "slug", "enabled", "version", "created_at"),
		WithVirtualField("created_at", func(v any) string {
			wf := v.(atomic.Workflow)
			return wf.CreatedAt.Format(time.RFC3339)
		}),
	)

	return nil
}

func workflowDelete(ctx context.Context, cmd *cli.Command) error {
	if inst == nil {
		return cli.Exit("instance is required", 1)
	}

	if cmd.Args().Len() == 0 {
		return cli.Exit("workflow id is required", 1)
	}

	workflowID, err := atomic.ParseID(cmd.Args().First())
	if err != nil {
		return cli.Exit(fmt.Sprintf("invalid workflow id: %s", err), 1)
	}

	if err := backend.WorkflowDelete(ctx, &atomic.WorkflowDeleteInput{
		InstanceID: inst.UUID,
		WorkflowID: workflowID,
	}); err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "workflow %s deleted\n", workflowID)

	return nil
}

func workflowRunAction(ctx context.Context, cmd *cli.Command) error {
	if inst == nil {
		return cli.Exit("instance is required", 1)
	}

	if cmd.Args().Len() == 0 {
		return cli.Exit("workflow id is required", 1)
	}

	workflowID, err := atomic.ParseID(cmd.Args().First())
	if err != nil {
		return cli.Exit(fmt.Sprintf("invalid workflow id: %s", err), 1)
	}

	input := atomic.WorkflowRunInput{
		InstanceID:  inst.UUID,
		WorkflowID:  workflowID,
		TriggerType: atomic.WorkflowTriggerTypeManual,
	}

	if cmd.IsSet("inputs") {
		var inputs map[string]any
		if err := json.Unmarshal([]byte(cmd.String("inputs")), &inputs); err != nil {
			return fmt.Errorf("failed to parse inputs: %w", err)
		}
		input.Inputs = inputs
	}

	run, err := backend.WorkflowRun(ctx, &input)
	if err != nil {
		return err
	}

	PrintResult(cmd, []*atomic.WorkflowRun{run},
		WithSingleValue(true),
		WithFields("id", "workflow_id", "trigger_type", "status", "job_id", "created_at"),
		WithVirtualField("created_at", func(v any) string {
			r := v.(atomic.WorkflowRun)
			return r.CreatedAt.Format(time.RFC3339)
		}),
		WithVirtualField("job_id", func(v any) string {
			r := v.(atomic.WorkflowRun)
			if r.JobID != nil {
				return r.JobID.String()
			}
			return ""
		}),
	)

	if cmd.Bool("wait") && run.JobID != nil {
		job, err := backend.JobGet(ctx, &atomic.JobGetInput{JobID: run.JobID})
		if err != nil {
			return fmt.Errorf("failed to fetch run job: %w", err)
		}
		return waitForJob(ctx, job, mainCmd.Bool("verbose"), false)
	}

	return nil
}

func workflowRunsList(ctx context.Context, cmd *cli.Command) error {
	if inst == nil {
		return cli.Exit("instance is required", 1)
	}

	if cmd.Args().Len() == 0 {
		return cli.Exit("workflow id is required", 1)
	}

	workflowID, err := atomic.ParseID(cmd.Args().First())
	if err != nil {
		return cli.Exit(fmt.Sprintf("invalid workflow id: %s", err), 1)
	}

	input := atomic.WorkflowRunListInput{
		InstanceID: inst.UUID,
		WorkflowID: workflowID,
	}

	if cmd.IsSet("status") {
		input.Status = ptr.String(cmd.String("status"))
	}
	if cmd.IsSet("limit") {
		input.Limit = ptr.Uint64(uint64(cmd.Int("limit")))
	}
	if cmd.IsSet("offset") {
		input.Offset = ptr.Uint64(uint64(cmd.Int("offset")))
	}

	runs, err := backend.WorkflowRunList(ctx, &input)
	if err != nil {
		return err
	}

	if len(runs) == 0 {
		return cli.Exit("no runs found", 1)
	}

	PrintResult(cmd, runs,
		WithFields("id", "workflow_id", "trigger_type", "status", "job_id", "created_at", "completed_at"),
		WithVirtualField("created_at", func(v any) string {
			r := v.(atomic.WorkflowRun)
			return r.CreatedAt.Format(time.RFC3339)
		}),
		WithVirtualField("completed_at", func(v any) string {
			r := v.(atomic.WorkflowRun)
			if r.CompletedAt == nil {
				return ""
			}
			return r.CompletedAt.Format(time.RFC3339)
		}),
		WithVirtualField("job_id", func(v any) string {
			r := v.(atomic.WorkflowRun)
			if r.JobID != nil {
				return r.JobID.String()
			}
			return ""
		}),
	)

	return nil
}

func workflowRunGetAction(ctx context.Context, cmd *cli.Command) error {
	if inst == nil {
		return cli.Exit("instance is required", 1)
	}

	if cmd.Args().Len() == 0 {
		return cli.Exit("run id is required", 1)
	}

	runID, err := atomic.ParseID(cmd.Args().First())
	if err != nil {
		return cli.Exit(fmt.Sprintf("invalid run id: %s", err), 1)
	}

	input := atomic.WorkflowRunGetInput{
		InstanceID: inst.UUID,
		RunID:      runID,
		Expand:     atomic.ExpandFields(cmd.StringSlice("expand")),
	}

	if cmd.IsSet("workflow_id") {
		wfID, err := atomic.ParseID(cmd.String("workflow_id"))
		if err != nil {
			return cli.Exit(fmt.Sprintf("invalid workflow id: %s", err), 1)
		}
		input.WorkflowID = &wfID
	}

	run, err := backend.WorkflowRunGet(ctx, &input)
	if err != nil {
		return err
	}

	PrintResult(cmd, []*atomic.WorkflowRun{run},
		WithSingleValue(true),
		WithFields("id", "workflow_id", "trigger_type", "status", "job_id", "created_at", "completed_at", "error"),
		WithVirtualField("created_at", func(v any) string {
			r := v.(atomic.WorkflowRun)
			return r.CreatedAt.Format(time.RFC3339)
		}),
		WithVirtualField("completed_at", func(v any) string {
			r := v.(atomic.WorkflowRun)
			if r.CompletedAt == nil {
				return ""
			}
			return r.CompletedAt.Format(time.RFC3339)
		}),
		WithVirtualField("job_id", func(v any) string {
			r := v.(atomic.WorkflowRun)
			if r.JobID != nil {
				return r.JobID.String()
			}
			return ""
		}),
		WithVirtualField("error", func(v any) string {
			r := v.(atomic.WorkflowRun)
			if r.Error != nil {
				return *r.Error
			}
			return ""
		}),
	)

	if cmd.Bool("wait") && run.JobID != nil {
		job, err := backend.JobGet(ctx, &atomic.JobGetInput{JobID: run.JobID})
		if err != nil {
			return fmt.Errorf("failed to fetch run job: %w", err)
		}
		return waitForJob(ctx, job, mainCmd.Bool("verbose"), false)
	}

	return nil
}
