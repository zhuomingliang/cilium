// Copyright 2016-2017 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ctmap

import (
	"github.com/op/go-logging"
	"github.com/cilium/cilium/common"
	"github.com/cilium/cilium/pkg/bpf"
	"unsafe"
	"bytes"
	"fmt"
)

var log    = logging.MustGetLogger("cilium")

const (
	MapName6 = "cilium_ct6_"
	MapName4 = "cilium_ct4_"
	// Maximum number of entries in each hashtable
	maxEntries   = 65536
	TUPLE_F_OUT     = 0
	TUPLE_F_IN      = 1
	TUPLE_F_RELATED = 2
)

// ServiceKey is the interface describing protocol independent key for services map.
type ServiceKey interface {
	bpf.MapKey

	// Returns human readable string representation
	String() string

	// Returns the BPF map matching the key type
	Map() *bpf.Map

	// Convert converts fields between host byte order and map byte order if necessary.
	Convert() ServiceKey

	// Dumps contents of key to buffer. Returns true if successful.
	Dump(buffer *bytes.Buffer) bool
}

// ServiceValue is the interface describing protocol independent value for services map.
type ServiceValue interface {
	bpf.MapValue

	// Convert converts fields between host byte order and map byte order if necessary.
	Convert() ServiceValue
}

// CtEntry represents an entry in the connection tracking table.
type CtEntry struct {
	rx_packets uint64
	rx_bytes   uint64
	tx_packets uint64
	tx_bytes   uint64
	lifetime   uint16
	flags      uint16
	revnat     uint16
	proxy_port uint16
}

func (s *CtEntry) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(s) }

func (s *CtEntry) Convert() ServiceValue {
	n := *s
	n.revnat = common.Swab16(n.revnat)
	return &n
}

// CtEntryDump represents the key and value contained in the conntrack map.
type CtEntryDump struct {
	Key   ServiceKey
	Value CtEntry
}

// ToString iterates through Map m and writes the values of the ct entries in m to a string.
func ToString(m *bpf.Map, mapName string) (string, error) {
	var buffer bytes.Buffer
	entries, err := DumpToSlice(m, mapName)
	if err != nil {
		return "", err
	}
	for _, entry := range entries {
		if !entry.Key.Dump(&buffer) {
			continue
		}

		value := entry.Value
		buffer.WriteString(
			fmt.Sprintf(" expires=%d rx_packets=%d rx_bytes=%d tx_packets=%d tx_bytes=%d flags=%x revnat=%d proxyport=%d\n",
				value.lifetime,
				value.rx_packets,
				value.rx_bytes,
				value.tx_packets,
				value.tx_bytes,
				value.flags,
				common.Swab16(value.revnat),
				common.Swab16(value.proxy_port)),
		)

	}
	return buffer.String(), nil
}

// DumpToSlice iterates through map m and returns a slice mapping each key to its value in m.
func DumpToSlice(m *bpf.Map, mapName string) ([]CtEntryDump, error) {
	entries := []CtEntryDump{}

	switch mapName {
	case MapName6:
		var key, nextKey CtKey6
		for {
			err := m.GetNextKey(&key, &nextKey)
			if err != nil {
				break
			}

			entry, err := m.Lookup(&nextKey)
			if err != nil {
				return nil, err
			}
			ctEntry := entry.(*CtEntry)
			nK := nextKey
			eDump := CtEntryDump{Key: &nK, Value: *ctEntry}
			entries = append(entries, eDump)

			key = nextKey
		}

	case MapName4:
		var key, nextKey CtKey4
		for {
			err := m.GetNextKey(&key, &nextKey)
			if err != nil {
				break
			}

			entry, err := m.Lookup(&nextKey)
			if err != nil {
				return nil, err
			}
			ctEntry := entry.(*CtEntry)

			nK := nextKey
			eDump := CtEntryDump{Key: &nK, Value: *ctEntry}
			entries = append(entries, eDump)

			key = nextKey
		}

	}
	return entries, nil
}

// doGC removes key and its corresponding value from Map m if key has a lifetime less than interval. It sets nextKey's address to be the key after key in map m.
// Returns false if there is no other key after key in Map m, and increments deleted if an item is removed from m.
func doGc(m *bpf.Map, interval uint16, key ServiceKey, nextKey ServiceKey, deleted *int) bool {
	err := m.GetNextKey(key, nextKey)

	if err != nil {
		return false
	}

	nextEntry , err := m.Lookup(nextKey.Convert())

	//log.Infof("doGC: lookup completed")
	if err != nil {
		log.Errorf("error during map Lookup: %s", err)
		return false
	}

	entry := nextEntry.(*CtEntry)
	//log.Infof("doGc: entry lifetime: %d", entry.lifetime)
	//log.Infof("interval: %d", interval)
	if entry.lifetime <= interval {
		m.Delete(nextKey.Convert())
		(*deleted)++
		//log.Infof("doGC: entry deleted")
	} else {
		entry.lifetime -= interval
		//log.Infof("doGC: entry not deleted")
		m.Update(nextKey.Convert(), entry.Convert())
		//log.Infof("doGC: entry lifetime updated: %d", entry.lifetime)
		//log.Infof("doGC: checking if entry was actually updated...")
		//dummy, _ := m.Lookup(nextKey.Convert())
		//dummyEntry := dummy.(*CtEntry)
		//log.Infof("doGC: entry lifetime after update: %d", dummyEntry.lifetime)
	}

	//log.Infof("doGC: exiting doGc")
	return true
}

// GC runs garbage collection for map m with name mapName with interval interval. It returns how many items were deleted from m.
func GC(m *bpf.Map, interval uint16, mapName string) int {
	deleted := 0

	switch mapName {
	case MapName6:
		//log.Infof("GC MapName6")
		var key, nextKey CtKey6
		for doGc(m, interval, &key, &nextKey, &deleted) {
			//log.Infof("GC: key address: %p", key)
			//log.Infof("GC: nextKey address: %p", nextKey)
			key = nextKey
		}
	case MapName4:
		//log.Infof("GC MapName4")
		var key, nextKey CtKey4
		for doGc(m, interval, &key, &nextKey, &deleted) {
			key = nextKey
		}
	}

	//log.Infof("exiting ctmap GC, deleted = %d", deleted)
	return deleted
}