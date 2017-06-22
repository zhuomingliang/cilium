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

package tunnel

/*
#cgo CFLAGS: -I../../../bpf/include
#include <linux/bpf.h>
*/
import "C"

import (
	"net"
	"unsafe"

	"github.com/cilium/cilium/pkg/bpf"
)

const (
	mapName    = "tunnel_endpoints"
	maxEntries = 65536
)

var (
	mapInstance = bpf.NewMap(mapName,
		bpf.MapTypeHash,
		int(unsafe.Sizeof(tunnelKey{})),
		int(unsafe.Sizeof(tunnelEndpoint{})),
		maxEntries, 0)
)

type v6Addr [16]byte

func (v6 v6Addr) String() string {
	return net.IP(v6[:]).String()
}

type tunnelKey struct {
	ip v6Addr
}

func (k tunnelKey) GetKeyPtr() unsafe.Pointer { return unsafe.Pointer(&k) }
func (k tunnelKey) NewValue() bpf.MapValue    { return &tunnelEndpoint{} }

type tunnelEndpoint struct {
	ip v6Addr
}

func (v tunnelEndpoint) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(&v) }
func (v tunnelEndpoint) String() string              { return v.ip.String() }

// SetTunnelEndpoint adds/replaces a prefix => tunnel-endpoint mapping
func SetTunnelEndpoint(prefix net.IP, endpoint net.IP) error {
	key := tunnelKey{}
	copy(key.ip[:], prefix)

	val := tunnelEndpoint{}
	copy(val.ip[:], endpoint)

	return mapInstance.Update(key, val)
}

// DeleteTunnelEndpoint removes a prefix => tunnel-endpoint mapping
func DeleteTunnelEndpoint(prefix net.IP) error {
	key := tunnelKey{}
	copy(key.ip[:], prefix)

	return mapInstance.Delete(key)
}
