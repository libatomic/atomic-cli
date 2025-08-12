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
	"database/sql"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"ariga.io/atlas-go-sdk/atlasexec"
	"github.com/apex/log"
	"github.com/go-sql-driver/mysql"
	"github.com/libatomic/atomic/assets"
	deploy "github.com/libatomic/atomic/deployments"
	"github.com/libatomic/atomic/pkg/atomic"
	"github.com/urfave/cli/v3"
)

var (
	dbCommand = &cli.Command{
		Name:  "db",
		Usage: "database management",
		Commands: []*cli.Command{
			{
				Name:        "migrate",
				Usage:       "auto-migrate the database using latest SQL version",
				Description: "This operation will initialize or update the database functions, tables, and views",
				Action:      dbMigrate,
				Flags: []cli.Flag{
					&cli.BoolFlag{
						Name:  "create",
						Usage: "create the database if it doesn't exist",
						Value: false,
					},
					&cli.BoolFlag{
						Name:  "apply",
						Usage: "do not execute migrations",
					},
					&cli.BoolFlag{
						Name:  "verbose",
						Usage: "enable verbose output",
					},
				},
			},
		},
		Before: func(ctx context.Context, cmd *cli.Command) (context.Context, error) {
			if _, ok := backend.(*atomic.Atomic); !ok {
				return nil, fmt.Errorf("database connection not found")
			}

			return ctx, nil
		},
	}
)

func dbMigrate(ctx context.Context, c *cli.Command) error {
	tmpdir, err := os.MkdirTemp("", "atomic-migrate")
	if err != nil {
		return fmt.Errorf("cannot create temporary directory: %w", err)
	}

	hclfile, err := os.Create(fmt.Sprintf("%s/schema.hcl", tmpdir))
	if err != nil {
		return fmt.Errorf("cannot create temporary file: %w", err)
	}

	schema := assets.Schema

	if _, err := hclfile.Write(schema); err != nil {
		return fmt.Errorf("cannot write schema file: %w", err)
	}
	hclfile.Close()

	cfg, err := os.Create(fmt.Sprintf("%s/atlas.hcl", tmpdir))
	if err != nil {
		return fmt.Errorf("cannot create temporary file: %w", err)
	}

	if _, err := cfg.Write(assets.Atlas); err != nil {
		return fmt.Errorf("cannot write config file: %w", err)
	}
	cfg.Close()

	workdir, err := atlasexec.NewWorkingDir(
		atlasexec.WithMigrations(os.DirFS(tmpdir)),
	)
	if err != nil {
		return fmt.Errorf("cannot create working directory: %w", err)
	}
	defer workdir.Close()

	client, err := atlasexec.NewClient(workdir.Path(), "atlas")
	if err != nil {
		return fmt.Errorf("cannot create atlas client: %w", err)
	}

	dsn, err := mysql.ParseDSN(c.String("db_source"))
	if err != nil {
		return fmt.Errorf("cannot parse database URL: %w", err)
	}

	if c.Bool("create") {
		db, err := sql.Open("mysql", dsn.FormatDSN())
		if err != nil {
			return fmt.Errorf("cannot connect to MySQL server: %w", err)
		}
		defer db.Close()

		_, err = db.Exec(fmt.Sprintf("CREATE DATABASE IF NOT EXISTS `%s`", dsn.DBName))
		if err != nil {
			return fmt.Errorf("cannot create database %s: %w", dsn.DBName, err)
		}

		log.Infof("Database %s created successfully", dsn.DBName)
	}

	log.Debugf("migrating database %s", dsn.FormatDSN())

	dburl := fmt.Sprintf("mysql://%s:%s@%s/%s", dsn.User, dsn.Passwd, dsn.Addr, dsn.DBName)
	dbname := filepath.Base(dsn.DBName)
	devurl := "docker://mysql/8/dev"

	res, err := client.SchemaApply(context.Background(), &atlasexec.SchemaApplyParams{
		URL:       dburl,
		ConfigURL: fmt.Sprintf("file://%s", cfg.Name()),
		To:        fmt.Sprintf("file://%s", hclfile.Name()),
		DryRun:    !c.Bool("apply"),
		Vars: atlasexec.Vars{
			"dbname": dbname,
		},
		DevURL: devurl,
	})
	if err != nil {
		log.Errorf("cannot apply migrations directly: %s", err)

		// fallback to the script which is more reliable, but less efficient
		schapply, err := os.Create(fmt.Sprintf("%s/schema-apply.sh", tmpdir))
		if err != nil {
			return fmt.Errorf("cannot create temporary file: %w", err)
		}

		if _, err := schapply.Write(deploy.SchemaApply); err != nil {
			return fmt.Errorf("cannot write schema apply script: %w", err)
		}
		schapply.Close()

		if err := os.Chmod(schapply.Name(), 0777); err != nil {
			return fmt.Errorf("cannot change script permissions: %w", err)
		}

		cmd := exec.Command(
			schapply.Name(),
			"-u", dburl,
			"-c", cfg.Name(),
			"-s", hclfile.Name(),
			"-d", dbname,
		)

		fmt.Printf("Running command: %s %s\n", cmd.Path, strings.Join(cmd.Args[1:], " "))

		std, err := cmd.CombinedOutput()

		fmt.Println(string(std))

		if err != nil {
			return fmt.Errorf("cannot apply migrations: %s", err)
		}

		return nil
	}

	if !c.Bool("apply") {
		for i, change := range res.Changes.Pending {
			fmt.Printf("proposed change %d >>>\n", i+1)
			fmt.Println(change)
			fmt.Printf("<<<\n\n")
		}

		fmt.Printf("Total %d migrations proposed\n", len(res.Changes.Pending))
	} else {
		if c.Bool("verbose") {
			for _, change := range res.Changes.Applied {
				fmt.Println(change)
			}
		}

		fmt.Printf("Applied %d migrations\n", len(res.Changes.Applied))
	}

	return nil
}
