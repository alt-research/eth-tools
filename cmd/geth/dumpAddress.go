package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/ethereum/go-ethereum/cmd/utils"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/log"
	"github.com/fyInALT/eth-tools/state"
	"github.com/urfave/cli/v2"
)

func dumpAddress(ctx *cli.Context) error {
	log.SetDefault(log.NewLogger(log.NewTerminalHandlerWithLevel(os.Stderr, log.LevelTrace, false)))

	stack, _ := makeConfigNode(ctx)
	defer stack.Close()

	db := utils.MakeChainDatabase(ctx, stack, true)
	defer db.Close()

	// printChainMetadata(db)

	conf, root, err := parseDumpConfig(ctx, db)
	if err != nil {
		return err
	}
	conf.Max = 0
	// conf.OnlyWithAddresses = true
	conf.SkipCode = true
	conf.SkipStorage = true

	triedb := utils.MakeTrieDatabase(ctx, db, true, true, false) // always enable preimage lookup
	defer triedb.Close()

	statedb := state.NewDatabase(triedb, nil)

	reader, err := statedb.Reader(root)
	if err != nil {
		return err
	}

	state, err := state.New(root, statedb)
	if err != nil {
		return err
	}

	fileName := ctx.String(JSONFileFlag.Name)
	if fileName == "" {
		return fmt.Errorf("need use file")
	}
	dateString := time.Now().Format("2006-01-02-03-04-05")
	fileNameFull := fmt.Sprintf("%s-%s.json", fileName, dateString)

	if _, err := os.Stat(fileNameFull); err == nil {
		return fmt.Errorf("file %s had exist", fileNameFull)
	}

	file, err := os.Create(fileNameFull)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()

	return DumpAddress(ctx.Context, file, state, reader, conf, ctx.Bool(WithZeroBalanceFlag.Name))
}

// Dump returns a JSON string representing the entire state as a single json-object
func DumpAddress(ctx context.Context, file *os.File, s *state.StateDB, reader state.Reader, opts *state.DumpConfig, withZeroBalance bool) error {
	log.Info("start write address", "flag", withZeroBalance)
	writer := &WriterAddress{
		withZeroBalance: withZeroBalance,
		encoder:         json.NewEncoder(file),
		accounts:        make(chan *state.DumpAccount, 4096),
		roots:           make(chan common.Hash, 4096),
	}
	writer.Run(ctx)

	dump := &DumpData{
		writer:    writer,
		startTime: time.Now(),
		lastTime:  time.Now(),
	}
	dump.Next = s.DumpToCollector(dump, opts)
	return nil
}
