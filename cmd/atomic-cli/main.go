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
	"os/signal"
	"os/user"
	"reflect"
	"strings"
	"syscall"
	"time"

	"github.com/apex/log"
	"github.com/lensesio/tableprinter"
	client "github.com/libatomic/atomic-go"
	"github.com/libatomic/atomic/pkg/atomic"
	"github.com/libatomic/atomic/pkg/db"
	"github.com/libatomic/atomic/pkg/ptr"
	"github.com/libatomic/atomic/pkg/util"
	"github.com/spf13/cast"
	"github.com/urfave/cli/v3"
)

type (
	PrintResultOptions struct {
		Fields          []string
		FieldFormatters map[string]FieldFormatterFunc
		VirtualFields   map[string]FieldFormatterFunc
		SingleValue     bool
	}

	PrintResultOption func(o *PrintResultOptions)

	FieldFormatterFunc func(v any) string

	MetadataFlag = cli.FlagBase[atomic.Metadata, cli.NoConfig, metadataValue]

	metadataValue struct {
		destination atomic.Metadata
	}
)

var (
	backend atomic.Backend
	mainCmd *cli.Command
	inst    *atomic.Instance

	// profile and creds are exposed at package scope so subcommand flag
	// definitions in other files can reference them via NewCredentialsSource.
	// The mainCmd flags below bind these via Destination so the live values
	// reflect what the user passed on the command line.
	profile = DefaultProfile
	creds   string

	Version = "dev"
	Commit  = "dev"
	Date    = time.Now().Format(time.RFC3339)
)

const (
	DefaultProfile = "default"
)

func main() {
	profile = DefaultProfile

	usr, _ := user.Current()
	dir := usr.HomeDir

	creds = dir + "/.atomic/credentials"

	mainCmd = &cli.Command{
		Name:               "atomic-cli",
		Usage:              "The atomic cli",
		Version:            fmt.Sprintf("%s+%s", Version, Commit),
		Copyright:          fmt.Sprintf("Copyright (c) 2026 Passport, LLC. [%s]", Date),
		SliceFlagSeparator: "++",
	}

	mainCmd.Flags = []cli.Flag{
		&cli.StringFlag{
			Name:        "profile",
			Aliases:     []string{"p"},
			Usage:       "specify the profile",
			Value:       DefaultProfile,
			Destination: &profile,
		},
		&cli.StringFlag{
			Name:        "credentials",
			Aliases:     []string{"c"},
			Usage:       "specify the credentials file",
			Value:       creds,
			Destination: &creds,
		},
		&cli.StringFlag{
			Name:  "db_source",
			Usage: "specify the db host",
			Sources: cli.NewValueSourceChain(
				cli.EnvVar("PASSPORT_DB_SOURCE"),
				cli.EnvVar("DB_SOURCE"),
				NewCredentialsSource("db_source", func() string { return creds }, func() string { return profile }),
			),
			Hidden: true,
		},
		&cli.StringFlag{
			Name:  "access_token",
			Usage: "specify the access token",
			Sources: cli.NewValueSourceChain(
				cli.EnvVar("PASSPORT_ACCESS_TOKEN"),
				NewCredentialsSource("access_token", func() string { return creds }, func() string { return profile }),
			),
		},
		&cli.StringFlag{
			Name:  "client_id",
			Usage: "specify the client id",
			Sources: cli.NewValueSourceChain(
				cli.EnvVar("PASSPORT_CLIENT_ID"),
				NewCredentialsSource("client_id", func() string { return creds }, func() string { return profile }),
			),
		},
		&cli.StringFlag{
			Name:  "client_secret",
			Usage: "specify the client secret",
			Sources: cli.NewValueSourceChain(
				cli.EnvVar("PASSPORT_CLIENT_SECRET"),
				NewCredentialsSource("client_secret", func() string { return creds }, func() string { return profile }),
			),
		},
		&cli.StringFlag{
			Name:    "host",
			Usage:   "specify the host",
			Aliases: []string{"h"},
			Sources: cli.NewValueSourceChain(
				cli.EnvVar("PASSPORT_API_HOST"),
				NewCredentialsSource("host", func() string { return creds }, func() string { return profile }),
			),
			Value: client.DefaultAPIHost,
		},
		&cli.StringFlag{
			Name:    "out-format",
			Aliases: []string{"o"},
			Usage:   "specify the output format",
			Sources: cli.NewValueSourceChain(
				cli.EnvVar("PASSPORT_OUT_FORMAT"),
				NewCredentialsSource("out_format", func() string { return creds }, func() string { return profile }),
			),
			Value: "table",
		},
		&cli.StringSliceFlag{
			Name:    "fields",
			Aliases: []string{"f"},
			Usage:   "specify the fields to print",
		},
		&cli.BoolFlag{
			Name:    "verbose",
			Aliases: []string{"v"},
			Usage:   "enable verbose output",
			Value:   false,
		},
		&cli.StringFlag{
			Name:    "instance_id",
			Usage:   "set the instance id for the command",
			Aliases: []string{"i", "instance"},
			Sources: cli.NewValueSourceChain(
				cli.EnvVar("PASSPORT_INSTANCE_ID"),
				NewCredentialsSource("instance_id", func() string { return creds }, func() string { return profile }),
			),
		},
	}

	mainCmd.Commands = []*cli.Command{
		instCmd,
		appCmd,
		userCmd,
		planCmd,
		priceCmd,
		categoryCmd,
		audienceCmd,
		templateCmd,
		optionCmd,
		accessTokenCmd,
		dbCommand,
		partnerCmd,
		assetCmd,
		jobCmd,
		importCmd,
		migrateCmd,
		stripeCmd,
		sessionCmd,
		statusCmd,
		mcpCmd,
	}

	mainCmd.Before = func(ctx context.Context, cmd *cli.Command) (context.Context, error) {
		if cmd.IsSet("db_source") && cmd.String("db_source") != "" {
			conn, err := db.Connect(ctx, cmd.String("db_source"))
			if err != nil {
				return nil, fmt.Errorf("failed to connect to datastore %s: %w", cmd.String("db_source"), err)
			}

			a, err := atomic.New(conn)
			if err != nil {
				return nil, fmt.Errorf("failed to initialize atomic: %w", err)
			}

			backend = a

			log.Infof("connected to datastore %s", cmd.String("db_source"))

		} else {

			opts := []client.ApiOption{}

			opts = append(opts, client.WithHost(cmd.String("host")))

			if cmd.IsSet("client_id") && cmd.IsSet("client_secret") {
				opts = append(opts, client.WithClientCredentials(cmd.String("client_id"), cmd.String("client_secret")))
			} else if cmd.IsSet("access_token") {
				opts = append(opts, client.WithToken(cmd.String("access-token")))
			}

			backend = client.New(opts...)
		}

		instanceLookup := cmd.String("instance_id")
		instanceExplicit := cmd.IsSet("instance_id")
		if !instanceExplicit {
			instanceLookup = cmd.String("host")
		}

		if instanceLookup != "" {
			if id, err := atomic.ParseID(instanceLookup); err == nil {
				inst, err = backend.InstanceGet(ctx, &atomic.InstanceGetInput{
					InstanceID: &id,
				})
				if err != nil {
					if instanceExplicit {
						return nil, fmt.Errorf("failed to get instance %s: %w", instanceLookup, err)
					}
					inst = nil
				}
			} else {
				insts, err := backend.InstanceList(ctx, &atomic.InstanceListInput{
					Name: ptr.String(instanceLookup),
				})
				if err != nil {
					if instanceExplicit {
						return nil, fmt.Errorf("failed to list instances: %w", err)
					}
				} else if len(insts) > 0 {
					inst = insts[0]
				} else if instanceExplicit {
					return nil, fmt.Errorf("instance not found")
				}
			}

			if inst != nil {
				log.Infof("using instance %s", inst.Name)
			}
		}

		return ctx, nil
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if err := mainCmd.Run(ctx, os.Args); err != nil {
		log.Error(err.Error())
		os.Exit(-1)
	}
}

func PrintResult[T any](cmd *cli.Command, v []T, options ...PrintResultOption) bool {
	opts := PrintResultOptions{
		FieldFormatters: make(map[string]FieldFormatterFunc),
		VirtualFields:   make(map[string]FieldFormatterFunc),
	}

	for _, o := range options {
		o(&opts)
	}

	switch cmd.String("out-format") {
	case "json":
		var out []byte
		var err error

		if opts.SingleValue {
			out, err = json.Marshal(v[0])
		} else {
			out, err = json.Marshal(v)
		}
		if err != nil {
			fmt.Println(err.Error())
		}
		fmt.Println(string(out))

		return true

	case "json-pretty":
		var out []byte
		var err error

		if opts.SingleValue {
			out, err = json.MarshalIndent(v[0], "", "\t")
		} else {
			out, err = json.MarshalIndent(v, "", "\t")
		}
		if err != nil {
			fmt.Println(err.Error())
		}
		fmt.Println(string(out))
		return true

	case "jsonl", "ndjson":
		// one compact JSON object per line; --single-value collapses to a
		// single line, matching `json` output.
		if opts.SingleValue {
			out, err := json.Marshal(v[0])
			if err != nil {
				fmt.Println(err.Error())
				return true
			}
			fmt.Println(string(out))
			return true
		}
		for _, item := range v {
			out, err := json.Marshal(item)
			if err != nil {
				fmt.Println(err.Error())
				continue
			}
			fmt.Println(string(out))
		}
		return true

	case "table":
		if cmd.IsSet("fields") {
			opts.Fields = cmd.StringSlice("fields")
		}

		if len(opts.Fields) == 0 {
			opts.Fields = util.JSONTagFields(v)
		}

		if err := PrintTable(v, opts); err != nil {
			fmt.Println(err.Error())
		}
		return true

	default:
		log.Warnf("unknown output format %q; default to table", cmd.String("out-format"))
	}

	return false
}

func PrintTable[T any](slice []T, opts PrintResultOptions) error {
	table := make(map[string][]string)

	fields := opts.Fields

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

			if f, ok := opts.VirtualFields[path[0]]; ok {
				table[path[0]] = append(table[path[0]], f(v.Interface()))
				continue
			}

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
				if v.Kind() == reflect.Ptr {
					if v.IsNil() {
						v = reflect.Zero(v.Type().Elem())
					} else {
						v = v.Elem()
					}
				}

				if formatter, ok := opts.FieldFormatters[fields[i]]; ok {
					str = formatter(v.Interface())
				} else if v.Kind() == reflect.Slice {
					elems := []string{}
					for j := 0; j < v.Len(); j++ {
						s, _ := cast.ToStringE(v.Index(j).Interface())
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

	for _, flag := range cmd.Flags {
		name := flag.Names()[0]

		if skipSlice.Contains(name) {
			continue
		}

		if !cmd.IsSet(name) && util.IsZero(flag.Get()) {
			continue
		}

		val := cmd.Value(name)
		flagMap[name] = val
	}

	if inst != nil {
		flagMap["instance_id"] = inst.UUID
	}

	data, err := json.Marshal(flagMap)
	if err != nil {
		return err
	}

	return json.Unmarshal(data, target)
}

func WithFields(fields ...string) PrintResultOption {
	return func(o *PrintResultOptions) {
		o.Fields = fields
	}
}

func WithSingleValue(singleValue bool) PrintResultOption {
	return func(o *PrintResultOptions) {
		o.SingleValue = singleValue
	}
}

func WithFieldFormatter(field string, formatter FieldFormatterFunc) PrintResultOption {
	return func(o *PrintResultOptions) {
		o.FieldFormatters[field] = formatter
	}
}

func WithVirtualField(field string, formatter FieldFormatterFunc) PrintResultOption {
	return func(o *PrintResultOptions) {
		o.VirtualFields[field] = formatter
	}
}

func (k *metadataValue) Set(value string) error {
	if k.destination == nil {
		k.destination = make(atomic.Metadata)
	}
	parts := strings.SplitN(value, "=", 1)
	k.destination[parts[0]] = parts[1]
	return nil
}

func (k *metadataValue) String() string {
	var s string

	for k, v := range k.destination {
		s += k + "=" + cast.ToString(v) + ";"
	}
	return s
}

func (k *metadataValue) Get() any {
	return k.destination
}

func (k *metadataValue) IsSet() bool {
	return len(k.destination) > 0
}

func (k metadataValue) Create(val atomic.Metadata, p *atomic.Metadata, c cli.NoConfig) cli.Value {
	return &metadataValue{
		destination: val,
	}
}

func (k metadataValue) ToString(val atomic.Metadata) string {
	s := ""

	for k, v := range val {
		s += k + "=" + cast.ToString(v) + ";"
	}

	return s
}
