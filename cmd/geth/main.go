// Copyright 2014 The go-ethereum Authors
// This file is part of go-ethereum.
//
// go-ethereum is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// go-ethereum is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with go-ethereum. If not, see <http://www.gnu.org/licenses/>.

// geth is a command-line client for Ethereum.
package main

import (
	"fmt"
	"os"
	"sort"

	"github.com/ethereum/go-ethereum/console/prompt"

	"github.com/urfave/cli/v2"
)

const (
	clientIdentifier = "geth" // Client identifier to advertise over the network
)

// NewApp creates an app with sane defaults.
func NewApp(usage string) *cli.App {
	app := cli.NewApp()
	app.EnableBashCompletion = true
	app.Version = "0.0.1"
	app.Usage = usage
	return app
}

var app = NewApp("the go-ethereum command line interface")

func init() {
	// Initialize the CLI app and start Geth
	//app.Action = geth
	app.Commands = []*cli.Command{
		dumpCommand,
		dumpGenesisCommand,
	}
	sort.Sort(cli.CommandsByName(app.Commands))

	app.Action = func(c *cli.Context) error {
		cli.ShowAppHelpAndExit(c, 0)
		return nil
	}

	app.Before = func(ctx *cli.Context) error {
		return nil
	}
	app.After = func(ctx *cli.Context) error {
		prompt.Stdin.Close() // Resets terminal mode.
		return nil
	}
}

func main() {
	if err := app.Run(os.Args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
