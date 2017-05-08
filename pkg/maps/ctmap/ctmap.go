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
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/u8proto"
	"unsafe"
)

var log    = logging.MustGetLogger("cilium")

type CtType int

const (
       CtTypeIPv6 CtType = iota
       CtTypeIPv4
)

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

	// Returns true if the key is of type IPv6
	IsIPv6() bool

	// Returns the BPF map matching the key type
	Map() *bpf.Map

	// Returns a RevNatValue matching a ServiceKey
	//RevNatValue() uint16

	// Returns the source port set in the key or 0
	//GetSrcPort() uint16

	// Set source port to map to (left blank for master)
	SetSrcPort(uint16)

	// Returns the destination port set in the key or 0
	//GetDstPort() uint16

	//Set destination port to map to (left blank for master)
	SetDstPort(uint16)

	// Returns the next header
	//GetNextHdr() u8proto.U8proto

	SetNextHdr(u8proto.U8proto)


	// Returns the flags
	//GetFlags() uint8

	// Sets the flags
	SetFlags(uint8)

	// Convert between host byte order and map byte order
	Convert() ServiceKey
}

// ServiceValue is the interface describing protocol independent value for services map.
type ServiceValue interface {
	bpf.MapValue

	// Returns human readable string representation
	//String() string

	// Returns the  matching a ServiceValue
	//RevNatKey() uint16

	// Set source port to map to (left blank for master)
	//SetSrcPort(uint16)

	//Set destination port to map to (left blank for master)
	//SetDstPort(uint16)

	// Sets the next header
	//SetNextHdr(u8proto.U8proto)

	// Sets the flags
	//SetFlags(uint8)

	// Convert between host byte order and map byte order
	// Convert() ServiceValue
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
	//TODO: figure out if need to run Swab16 here
	n := *s
	//n.RevNat = common.Swab16(n.RevNat)
	//n.Port = common.Swab16(n.Port)
	//n.Weight = common.Swab16(n.Weight)
	return &n
}

//type CtKey interface {
//	Dump(buffer *bytes.Buffer) bool
//}

//type CtEntryDump struct {
//	Key   CtKey
//	Value CtEntry
//}

// Dump iterates through Map m and writes the values of the ct entries to a string.
/*func (m *CtMap) Dump() (string, error) {
	var buffer bytes.Buffer
	entries, err := m.DumpToSlice()
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

func (m *CtMap) DumpToSlice() ([]CtEntryDump, error) {
	var entry CtEntry
	entries := []CtEntryDump{}

	switch m.Type {
	case CtTypeIPv6:
		var key, nextKey CtKey6
		for {
			err := bpf.GetNextKey(m.Fd, unsafe.Pointer(&key), unsafe.Pointer(&nextKey))
			if err != nil {
				break
			}

			entry, err = key.Map().Lookup(key.Convert())
			//err = bpf.LookupElement(
			//	m.Fd,
			//	unsafe.Pointer(&nextKey),
			//	unsafe.Pointer(&entry),
			//)
			if err != nil {
				return nil, err
			}

			eDump := CtEntryDump{Key: nextKey, Value: entry}
			entries = append(entries, eDump)

			key = nextKey
		}

	case CtTypeIPv4:
		var key, nextKey CtKey4
		for {
			err := bpf.GetNextKey(m.Fd, unsafe.Pointer(&key), unsafe.Pointer(&nextKey))
			if err != nil {
				break
			}

			err = bpf.LookupElement(
				m.Fd,
				unsafe.Pointer(&nextKey),
				unsafe.Pointer(&entry),
			)
			if err != nil {
				return nil, err
			}

			eDump := CtEntryDump{Key: nextKey, Value: entry}
			entries = append(entries, eDump)

			key = nextKey
		}
	}

	return entries, nil
}*/

// TODO: callees of this iterate through the map using a for loop until 'false' is returned
func doGc(m *bpf.Map, interval uint16, key ServiceKey, nextKey ServiceKey, deleted *int) bool {
	err := m.GetNextKey(key, nextKey)

	if err != nil {
		return false
	}

	nextEntry , err := m.Lookup(nextKey.Convert())

	log.Infof("doGC: lookup completed")
	if err != nil {
		log.Errorf("error during map Lookup: %s", err)
		return false
	}

	entry := nextEntry.(*CtEntry)
	log.Infof("doGc: entry lifetime: %d", entry.lifetime)
	log.Infof("interval: %d", interval)
	if entry.lifetime <= interval {
		m.Delete(nextKey.Convert())
		(*deleted)++
		log.Infof("doGC: entry deleted")
	} else {
		entry.lifetime -= interval
		log.Infof("doGC: entry not deleted")
		m.Update(nextKey.Convert(), entry.Convert())
		log.Infof("doGC: entry lifetime updated: %d", entry.lifetime)
		log.Infof("doGC: checking if entry was actually updated...")
		dummy, _ := m.Lookup(nextKey.Convert())
		dummyEntry := dummy.(*CtEntry)
		log.Infof("doGC: entry lifetime after update: %d", dummyEntry.lifetime)
	}

	log.Infof("doGC: exiting doGc")
	return true
}

func GC(m *bpf.Map, interval uint16, mapName string) int {
	deleted := 0


	switch mapName {
	case MapName6:
		log.Infof("GC MapName6")
		var key, nextKey CtKey6
		for doGc(m, interval, &key, &nextKey, &deleted) {
			log.Infof("GC: key address: %p", key)
			log.Infof("GC: nextKey address: %p", nextKey)
			key = nextKey
		}
	case MapName4:
		log.Infof("GC MapName4")
		var key, nextKey CtKey4
		for doGc(m, interval, &key, &nextKey, &deleted) {
			key = nextKey
		}
	}

	log.Infof("exiting ctmap GC, deleted = %d", deleted)
	return deleted
}
