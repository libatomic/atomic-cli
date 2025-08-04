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
	"reflect"
	"strings"

	"github.com/apex/log"
	"github.com/lensesio/tableprinter"
	client "github.com/libatomic/atomic-go"
	"github.com/libatomic/atomic/pkg/atomic"
	"github.com/libatomic/atomic/pkg/util"
	"github.com/spf13/cast"
	"github.com/urfave/cli/v3"
)

var (
	backend atomic.Backend
	mainCmd *cli.Command

	Version = "1.1.10-dev"
)

func main() {
	mainCmd = &cli.Command{
		Name:               "atomic-cli",
		Usage:              "The atomic cli",
		Version:            Version,
		SliceFlagSeparator: "++",
	}

	mainCmd.Flags = []cli.Flag{
		&cli.StringFlag{
			Name:    "access-token",
			Usage:   "specify the access token",
			Sources: cli.EnvVars("ATOMIC_ACCESS_TOKEN"),
		},
		&cli.StringFlag{
			Name:    "client-id",
			Usage:   "specify the client id",
			Sources: cli.EnvVars("ATOMIC_CLIENT_ID"),
		},
		&cli.StringFlag{
			Name:    "client-secret",
			Usage:   "specify the client secret",
			Sources: cli.EnvVars("ATOMIC_CLIENT_SECRET"),
		},
		&cli.StringFlag{
			Name:    "host",
			Usage:   "specify the host",
			Sources: cli.EnvVars("ATOMIC_API_HOST"),
			Value:   client.DefaultAPIHost,
		},
		&cli.BoolFlag{
			Name:    "silent",
			Aliases: []string{"s"},
			Usage:   "do not print any output",
		},
		&cli.StringFlag{
			Name:    "out-format",
			Aliases: []string{"o"},
			Usage:   "specify the output format",
			Value:   "table",
		},
		&cli.StringSliceFlag{
			Name:    "fields",
			Aliases: []string{"f"},
			Usage:   "specify the fields to print",
		},
	}

	mainCmd.Commands = []*cli.Command{
		instCmd,
		appCmd,
		userCmd,
	}

	mainCmd.Before = func(ctx context.Context, cmd *cli.Command) (context.Context, error) {
		opts := []client.ApiOption{}

		if cmd.IsSet("host") {
			opts = append(opts, client.WithHost(cmd.String("host")))
		}

		if cmd.IsSet("client-id") && cmd.IsSet("client-secret") {
			opts = append(opts, client.WithClientCredentials(cmd.String("client-id"), cmd.String("client-secret")))
		} else if cmd.IsSet("access-token") {
			opts = append(opts, client.WithToken(cmd.String("access-token")))
		}

		backend = client.New(opts...)

		return ctx, nil
	}

	if err := mainCmd.Run(context.Background(), os.Args); err != nil {
		log.Error(err.Error())
		os.Exit(-1)
	}
}

func PrintResult[T any](cmd *cli.Command, v []T, fields ...string) bool {
	if cmd.Bool("silent") {
		return true
	}

	switch cmd.String("out-format") {
	case "json":
		out, err := json.Marshal(v)
		if err != nil {
			fmt.Println(err.Error())
		}
		fmt.Println(string(out))
		return true

	case "json-pretty":
		out, err := json.MarshalIndent(v, "", "\t")
		if err != nil {
			fmt.Println(err.Error())
		}
		fmt.Println(string(out))
		return true

	case "table":
		if cmd.IsSet("fields") {
			fields = cmd.StringSlice("fields")
		}

		if err := PrintTable(v, fields...); err != nil {
			fmt.Println(err.Error())
		}
		return true

	default:
		log.Warnf("unknown output format %q; default to table", cmd.String("out-format"))
	}

	return false
}

func PrintTable[T any](slice []T, fields ...string) error {
	table := make(map[string][]string)

	// determine field access paths
	fieldPaths := make([][]string, len(fields))
	fieldHeaders := make([]string, len(fields))

	for i, f := range fields {
		parts := strings.Split(f, ".")
		fieldPaths[i] = parts
		fieldHeaders[i] = strings.ToUpper(parts[len(parts)-1])
	}

	for _, item := range slice {
		val := reflect.ValueOf(item)
		if val.Kind() == reflect.Ptr {
			val = val.Elem()
		}
		if val.Kind() != reflect.Struct {
			return fmt.Errorf("elements must be structs or pointers to structs")
		}

		for i, path := range fieldPaths {
			v := val
			for _, key := range path {
				if v.Kind() == reflect.Ptr {
					if v.IsNil() {
						v = reflect.Zero(v.Type().Elem())
					} else {
						v = v.Elem()
					}
				}
				if v.Kind() != reflect.Struct {
					v = reflect.Zero(reflect.TypeOf(""))
					break
				}
				v = v.FieldByNameFunc(func(name string) bool {
					field, _ := v.Type().FieldByName(name)
					jsonTag := strings.Split(field.Tag.Get("json"), ",")[0]
					return jsonTag == key || field.Name == key
				})
			}

			str := ""
			if v.IsValid() && v.CanInterface() {
				if v.Kind() == reflect.Slice {
					elems := []string{}
					for i := 0; i < v.Len(); i++ {
						s, _ := cast.ToStringE(v.Index(i).Interface())
						elems = append(elems, s)
					}
					str = strings.Join(elems, ", ")
				} else {
					str, _ = cast.ToStringE(v.Interface())
				}
			}

			table[fields[i]] = append(table[fields[i]], str)
		}
	}

	// assemble rows from table[fields]
	rows := make([][]string, 0)
	length := 0
	if len(fields) > 0 {
		length = len(table[fields[0]])
	}
	for i := 0; i < length; i++ {
		row := make([]string, len(fields))
		for j, field := range fields {
			row[j] = table[field][i]
		}
		rows = append(rows, row)
	}

	// print using tableprinter
	printer := tableprinter.New(os.Stdout)
	printer.BorderTop = true
	printer.BorderBottom = true
	printer.BorderLeft = true
	printer.BorderRight = true
	printer.ColumnSeparator = "|"
	printer.HeaderAlignment = tableprinter.AlignCenter
	printer.RowLine = true

	printer.Render(fieldHeaders, rows, nil, true)
	return nil
}

func BindFlagsFromContext(cmd *cli.Command, target interface{}, skip ...string) error {
	flagMap := map[string]interface{}{}

	skipSlice := util.MakeSlice(skip)

	for _, name := range cmd.FlagNames() {
		if skipSlice.Contains(name) {
			continue
		}

		if !cmd.IsSet(name) {
			continue
		}

		val := cmd.Value(name)
		flagMap[name] = val
	}

	data, err := json.Marshal(flagMap)
	if err != nil {
		return err
	}

	return json.Unmarshal(data, target)
}
