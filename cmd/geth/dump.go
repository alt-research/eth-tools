package main

import (
	"context"
	"encoding/json"
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/log"

	"github.com/fyInALT/eth-tools/state"
)

type DumpWriter interface {
	OnRoot(root common.Hash)
	OnAccount(account *state.DumpAccount)
}

type Writer struct {
	encoder  *json.Encoder
	accounts chan *state.DumpAccount
	roots    chan common.Hash
	wg       sync.WaitGroup
}

// OnRoot implements DumpCollector interface
func (d *Writer) OnRoot(root common.Hash) {
	d.roots <- root
}

// OnAccount implements DumpCollector interface
func (d *Writer) OnAccount(account *state.DumpAccount) {
	d.accounts <- account
}

// OnRoot implements DumpCollector interface
func (d *Writer) onRoot(root common.Hash) {
	d.encoder.Encode(struct {
		Root common.Hash `json:"root"`
	}{root})
}

// OnAccount implements DumpCollector interface
func (d *Writer) onAccount(account state.DumpAccount) {
	d.encoder.Encode(account)
}

func (d *Writer) Run(ctx context.Context) {
	d.wg.Add(1)
	go func() {
		defer d.wg.Done()
		for {
			select {
			case <-ctx.Done():
				{
					log.Info("writer exit by done")
					return
				}
			case acc := <-d.accounts:
				{
					d.onAccount(*acc)
				}
			case root := <-d.roots:
				{
					d.onRoot(root)
				}
			}
		}
	}()
}

func (d *Writer) Wait() {
	d.wg.Wait()
}

type WriterAddress struct {
	withZeroBalance bool
	onlyAddress     bool
	encoder         *json.Encoder
	accounts        chan *state.DumpAccount
	roots           chan common.Hash
	wg              sync.WaitGroup
}

// OnRoot implements DumpCollector interface
func (d *WriterAddress) OnRoot(root common.Hash) {
	d.roots <- root
}

// OnAccount implements DumpCollector interface
func (d *WriterAddress) OnAccount(account *state.DumpAccount) {
	d.accounts <- account
}

// OnRoot implements DumpCollector interface
func (d *WriterAddress) onRoot(root common.Hash) {
}

// OnAccount implements DumpCollector interface
func (d *WriterAddress) onAccount(account state.DumpAccount) {
	if account.Address == nil {
		return
	}

	if d.onlyAddress {
		d.encoder.Encode(*account.Address)
		return
	}

	if account.Balance == "0" && !d.withZeroBalance {
		return
	}

	d.encoder.Encode(struct {
		Address common.Address `json:"address"`
		Balance string         `json:"balance"`
	}{
		Address: *account.Address,
		Balance: account.Balance,
	})

}

func (d *WriterAddress) Run(ctx context.Context) {
	d.wg.Add(1)
	go func() {
		defer d.wg.Done()
		for {
			select {
			case <-ctx.Done():
				{
					log.Info("writerAddress exit by done")
					return
				}
			case acc := <-d.accounts:
				{
					d.onAccount(*acc)
				}
			case root := <-d.roots:
				{
					d.onRoot(root)
				}
			}
		}
	}()
}

func (d *WriterAddress) Wait() {
	d.wg.Wait()
}
