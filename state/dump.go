// Copyright 2014 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package state

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"
)

// DumpConfig is a set of options to control what portions of the state will be
// iterated and collected.
type DumpConfig struct {
	SkipCode          bool
	SkipStorage       bool
	OnlyWithAddresses bool
	Start             []byte
	Max               uint64
}

// DumpCollector interface which the state trie calls during iteration
type DumpCollector interface {
	// OnRoot is called with the state root
	OnRoot(common.Hash)
	// OnAccount is called once for each account in the trie
	OnAccount(*common.Address, DumpAccount)
}

// DumpAccount represents an account in the state.
type DumpAccount struct {
	Balance     string                 `json:"balance"`
	Nonce       uint64                 `json:"nonce"`
	Root        hexutil.Bytes          `json:"root"`
	CodeHash    hexutil.Bytes          `json:"codeHash"`
	Code        hexutil.Bytes          `json:"code,omitempty"`
	Storage     map[common.Hash]string `json:"storage,omitempty"`
	Address     *common.Address        `json:"address,omitempty"` // Address only present in iterative (line-by-line) mode
	AddressHash hexutil.Bytes          `json:"key,omitempty"`     // If we don't have address, we can output the key
}

// Dump represents the full dump in a collected format, as one large map.
type Dump struct {
	Root     string                 `json:"root"`
	Accounts map[string]DumpAccount `json:"accounts"`
	// Next can be set to represent that this dump is only partial, and Next
	// is where an iterator should be positioned in order to continue the dump.
	Next []byte `json:"next,omitempty"` // nil if no more accounts
}

// OnRoot implements DumpCollector interface
func (d *Dump) OnRoot(root common.Hash) {
	d.Root = fmt.Sprintf("%x", root)
}

// OnAccount implements DumpCollector interface
func (d *Dump) OnAccount(addr *common.Address, account DumpAccount) {
	if addr == nil {
		d.Accounts[fmt.Sprintf("pre(%s)", account.AddressHash)] = account
	}
	if addr != nil {
		d.Accounts[(*addr).String()] = account
	}
}

// iterativeDump is a DumpCollector-implementation which dumps output line-by-line iteratively.
type iterativeDump struct {
	*json.Encoder
}

// OnAccount implements DumpCollector interface
func (d iterativeDump) OnAccount(addr *common.Address, account DumpAccount) {
	dumpAccount := &DumpAccount{
		Balance:     account.Balance,
		Nonce:       account.Nonce,
		Root:        account.Root,
		CodeHash:    account.CodeHash,
		Code:        account.Code,
		Storage:     account.Storage,
		AddressHash: account.AddressHash,
		Address:     addr,
	}
	d.Encode(dumpAccount)
}

// OnRoot implements DumpCollector interface
func (d iterativeDump) OnRoot(root common.Hash) {
	d.Encode(struct {
		Root common.Hash `json:"root"`
	}{root})
}

func DebugForDetail(accountCount uint64, msg string, ctx ...interface{}) {
	return
}

// Iterator is a key-value trie iterator that traverses a Trie.
type Iterator struct {
	nodeIt trie.NodeIterator

	Key   []byte // Current data key on which the iterator is positioned on
	Value []byte // Current data value on which the iterator is positioned on
	Err   error
}

// NewIterator creates a new key-value iterator from a node iterator.
// Note that the value returned by the iterator is raw. If the content is encoded
// (e.g. storage value is RLP-encoded), it's caller's duty to decode it.
func NewIterator(it trie.NodeIterator) *Iterator {
	return &Iterator{
		nodeIt: it,
	}
}

// Next moves the iterator forward one key-value entry.
func (it *Iterator) Next() (bool, bool) {
	nextCount := 0
	rootPaths := make([][]byte, 0, 1024)
	rootPaths = append(rootPaths, it.nodeIt.Path())

	defer func() {
		if nextCount >= 150000 {
			log.Error("Paths Begin")
			for idx, rootPath := range rootPaths {
				log.Error("Paths", "idx", idx, "key", hexutil.Encode(rootPath))
			}
			log.Error("Paths End")
		}
	}()

	for it.nodeIt.Next(true) {
		nextCount += 1

		if it.nodeIt.Leaf() {
			it.Key = it.nodeIt.LeafKey()
			it.Value = it.nodeIt.LeafBlob()
			return true, false
		}

		if len(rootPaths) < 1024 {
			rootPaths = append(rootPaths, it.nodeIt.Path())
		}

		if nextCount >= 150000 {
			log.Error("cancel next storage iterator by too much counts")
			it.Key = nil
			it.Value = nil
			it.Err = it.nodeIt.Error()
			return false, true
		}
	}
	it.Key = nil
	it.Value = nil
	it.Err = it.nodeIt.Error()
	return false, false
}

// Prove generates the Merkle proof for the leaf node the iterator is currently
// positioned on.
func (it *Iterator) Prove() [][]byte {
	return it.nodeIt.LeafProof()
}

// DumpToCollector iterates the state according to the given options and inserts
// the items into a collector for aggregation or serialization.
func (s *StateDB) DumpToCollector(c DumpCollector, conf *DumpConfig) (nextKey []byte) {
	// Sanitize the input to allow nil configs
	if conf == nil {
		conf = new(DumpConfig)
	}
	var (
		missingPreimages int
		accounts         uint64
		start            = time.Now()
		logged           = time.Now()
	)
	log.Info("Trie dumping started", "root", s.GetTrie().Hash().Hex())
	c.OnRoot(s.GetTrie().Hash())

	trieIt, err := s.GetTrie().NodeIterator(conf.Start)
	if err != nil {
		log.Error("Trie dumping error", "err", err)
		return nil
	}
	it := trie.NewIterator(trieIt)
	for it.Next() {
		// log.Debug("start process", "count", accounts, "missingPreimages", missingPreimages)

		isBreak := func() bool {
			var data types.StateAccount
			if err := rlp.DecodeBytes(it.Value, &data); err != nil {
				panic(err)
			}

			DebugForDetail(accounts, "data got")
			var (
				account = DumpAccount{
					Balance:     data.Balance.String(),
					Nonce:       data.Nonce,
					Root:        data.Root[:],
					CodeHash:    data.CodeHash,
					AddressHash: it.Key,
				}
				address   *common.Address
				addr      common.Address
				addrBytes = s.GetTrie().GetKey(it.Key)
			)

			DebugForDetail(accounts, "GetTrie got")

			if addrBytes == nil {
				DebugForDetail(accounts, "addrBytes is nil")
				missingPreimages++
				if missingPreimages%10000 == 0 {
					log.Debug("missing perimages", "count", missingPreimages)
				}
				if conf.OnlyWithAddresses {
					DebugForDetail(accounts, "return by OnlyWithAddresses")
					return false
				}
			} else {
				DebugForDetail(accounts, "addrBytes not nil")
				addr = common.BytesToAddress(addrBytes)
				address = &addr
				account.Address = address
			}
			obj := newObject(s, addr, &data)
			DebugForDetail(accounts, "newObject")
			if !conf.SkipCode {
				account.Code = obj.Code()
				DebugForDetail(accounts, "got code")
			}
			if !conf.SkipStorage {
				accountStorages, ok := s.fetchStoragesForAccount(obj, address, account)
				if !ok {
					return false
				}

				account.Storage = accountStorages
			}
			c.OnAccount(address, account)
			DebugForDetail(accounts, "OnAccount finished")
			accounts++
			if time.Since(logged) > 8*time.Second {
				log.Info("Trie dumping in progress", "at", it.Key, "accounts", accounts,
					"elapsed", common.PrettyDuration(time.Since(start)))
				logged = time.Now()
			}
			if conf.Max > 0 && accounts >= conf.Max {
				if it.Next() {
					DebugForDetail(accounts, "next stopped")
					nextKey = it.Key
				}
				return true
			}

			return false
		}()

		// log.Debug("stop process", "count", accounts, "missingPreimages", missingPreimages)

		if isBreak {
			break
		}
	}
	if missingPreimages > 0 {
		log.Warn("Dump incomplete due to missing preimages", "missing", missingPreimages)
	}
	log.Info("Trie dumping complete", "accounts", accounts,
		"elapsed", common.PrettyDuration(time.Since(start)))

	return nextKey
}

func (s *StateDB) fetchStoragesForAccount(obj *stateObject, address *common.Address, account DumpAccount) (map[common.Hash]string, bool) {
	accountStorage := make(map[common.Hash]string)
	tr, err := obj.getTrie()
	if err != nil {
		log.Error("Failed to load storage trie", "err", err)
		return accountStorage, false
	}
	trieIt, err := tr.NodeIterator(nil)
	if err != nil {
		log.Error("Failed to create trie iterator", "err", err)
		return accountStorage, false
	}

	storageIt := NewIterator(trieIt)

	count := 0
	for {
		next, isCancel := storageIt.Next()
		if !next {
			break
		}

		if storageIt.Err != nil && !strings.Contains(storageIt.Err.Error(), "end of iteration") {
			log.Error("storageIt Err", "err", err)
		}

		if isCancel {
			log.Error(
				"got next storage failed by too much next count",
				"account", address,
				"root", account.Root.String(),
			)
			break
		}

		if count >= 102400 {
			log.Error(
				"got storage failed by too much count",
				"account", address,
				"root", account.Root.String(),
			)
			break
		}

		count += 1
		_, content, _, err := rlp.Split(storageIt.Value)
		if err != nil {
			log.Error("Failed to decode the value returned by iterator", "error", err)
			return accountStorage, false
		}
		accountStorage[common.BytesToHash(s.GetTrie().GetKey(storageIt.Key))] = common.Bytes2Hex(content)
	}

	return accountStorage, true
}

// RawDump returns the state. If the processing is aborted e.g. due to options
// reaching Max, the `Next` key is set on the returned Dump.
func (s *StateDB) RawDump(opts *DumpConfig) Dump {
	dump := &Dump{
		Accounts: make(map[string]DumpAccount),
	}
	dump.Next = s.DumpToCollector(dump, opts)
	return *dump
}

// Dump returns a JSON string representing the entire state as a single json-object
func (s *StateDB) Dump(opts *DumpConfig) []byte {
	dump := s.RawDump(opts)
	json, err := json.MarshalIndent(dump, "", "    ")
	if err != nil {
		log.Error("Error dumping state", "err", err)
	}
	return json
}

// IterativeDump dumps out accounts as json-objects, delimited by linebreaks on stdout
func (s *StateDB) IterativeDump(opts *DumpConfig, output *json.Encoder) {
	s.DumpToCollector(iterativeDump{output}, opts)
}
