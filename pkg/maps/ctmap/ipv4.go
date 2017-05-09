package ctmap

import (
	"github.com/cilium/cilium/pkg/u8proto"
	"github.com/cilium/cilium/common"
	"github.com/cilium/cilium/common/types"
	"bytes"
	"fmt"
	"net"
	"github.com/cilium/cilium/pkg/bpf"
	"unsafe"
)

var (
	Service4Map = bpf.NewMap(MapName4 +"_services",
		bpf.MapTypeHash,
		int(unsafe.Sizeof(CtKey4{})),
		int(unsafe.Sizeof(CtEntry{})),
		maxEntries)
)

type CtKey4 struct {
       addr    types.IPv4
       sport   uint16
       dport   uint16
       nexthdr u8proto.U8proto
       flags   uint8
}

// NewCtKey4 creates a CtKey4 with the provided ip, source port, destination port, next header, and flags.
func NewCtKey4(addr net.IP, sport uint16, dport uint16, nexthdr u8proto.U8proto, flags uint8) *CtKey4 {
	key := CtKey4{
		sport: sport,
		dport: dport,
		nexthdr: nexthdr,
		flags: flags,
	}

	copy(key.addr[:], addr.To4())

	return &key
}

func (k *CtKey4) GetKeyPtr() unsafe.Pointer { return unsafe.Pointer(k) }
func (k *CtKey4) NewValue() bpf.MapValue    { return &CtEntry{} }

func (k CtKey4) Map() *bpf.Map              { return Service6Map }

func (k *CtKey4) Convert() ServiceKey {
	n := *k
	n.sport = common.Swab16(n.sport)
	n.dport = common.Swab16(n.dport)
	return &n
}

func (k *CtKey4) String() string {
	return fmt.Sprintf("%s:%d, %d, %d, %d", k.addr, k.sport, k.dport, k.nexthdr, k.flags)
}


func (key CtKey4) Dump(buffer *bytes.Buffer) bool {
	if key.nexthdr == 0 {
		return false
	}

	if key.flags&TUPLE_F_IN != 0 {
		buffer.WriteString(fmt.Sprintf("%s IN %s %d:%d ",
			key.nexthdr.String(),
			key.addr.IP().String(),
			key.sport, key.dport),
		)

	} else {
		buffer.WriteString(fmt.Sprintf("%s OUT %s %d:%d ",
			key.nexthdr.String(),
			key.addr.IP().String(),
			key.dport,
			key.sport),
		)
	}

	if key.flags&TUPLE_F_RELATED != 0 {
		buffer.WriteString("related ")
	}

	return true
}
