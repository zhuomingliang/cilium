package daemon

//
//import (
//	"io/ioutil"
//	"net"
//	"os"
//	"path/filepath"
//
//	"github.com/noironetworks/cilium-net/bpf/policymap"
//	"github.com/noironetworks/cilium-net/common"
//	. "github.com/noironetworks/cilium-net/common/types"
//
//	"golang.org/x/net/context"
//	. "gopkg.in/check.v1"
//)
//
//var (
//	epsWanted = []*Endpoint{
//		&Endpoint{
//			ID:               "foo",
//			DockerID:         "",
//			DockerNetworkID:  "603e047d2268a57f5a5f93f7f9e1263e9207e348a06654bf64948defbba77b0f",
//			DockerEndpointID: "93529fda8c401a071d21d6bd46fdf5499b9014dcb5a35f2e3efaa8d8bbc2e832",
//			IfName:           "lx82311",
//			LXCMAC:           MAC([]byte{0x0, 0xff, 0xf2, 0x12, 0x21, 0x32}),
//			LXCIP:            net.IP{0xbe, 0xef, 0xbe, 0xef, 0xbe, 0xef, 0xbe, 0xef, 0xaa, 0xaa, 0xaa, 0xaa, 0x11, 0x11, 0x11, 0x12},
//			IfIndex:          12,
//			NodeMAC:          MAC([]byte{0x0, 0xff, 0xf2, 0x12, 0x21, 0x23}),
//			NodeIP:           net.IP{0xbe, 0xef, 0xbe, 0xef, 0xbe, 0xef, 0xbe, 0xef, 0xaa, 0xaa, 0xaa, 0xaa, 0x11, 0x11, 0, 0},
//			SecLabel: &SecCtxLabel{
//				ID:       12345,
//				RefCount: 3,
//				Labels: Labels{
//					"foo": NewLabel("foo", "", ""),
//				},
//			},
//			PortMap: nil,
//			Consumable: &Consumable{
//				ID:        3123,
//				Iteration: 0,
//				Labels: &SecCtxLabel{
//					ID:       12345,
//					RefCount: 3,
//					Labels: Labels{
//						"foo": NewLabel("foo", "", ""),
//					},
//				},
//				Maps:         map[int]*policymap.PolicyMap{},
//				Consumers:    map[string]*Consumer{},
//				ReverseRules: map[uint32]*Consumer{},
//			},
//		},
//		&Endpoint{
//			ID:               "123",
//			DockerID:         "",
//			DockerNetworkID:  "603e047d2268a57f5a5f93f7f9e1263e9207e348a06654bf64948defbba77b0f",
//			DockerEndpointID: "93529fda8c401a071d21d6bd46fdf5499b9014dcb5a35f2e3efaa8d8bbc2e832",
//			IfName:           "lx82311",
//			LXCMAC:           MAC([]byte{0x0, 0xff, 0xf2, 0x12, 0x21, 0x32}),
//			LXCIP:            net.IP{0xbe, 0xef, 0xbe, 0xef, 0xbe, 0xef, 0xbe, 0xef, 0xaa, 0xaa, 0xaa, 0xaa, 0x11, 0x11, 0x11, 0x12},
//			IfIndex:          12,
//			NodeMAC:          MAC([]byte{0x0, 0xff, 0xf2, 0x12, 0x21, 0x23}),
//			NodeIP:           net.IP{0xbe, 0xef, 0xbe, 0xef, 0xbe, 0xef, 0xbe, 0xef, 0xaa, 0xaa, 0xaa, 0xaa, 0x11, 0x11, 0, 0},
//			SecLabel: &SecCtxLabel{
//				ID:       12345,
//				RefCount: 3,
//				Labels:   nil,
//			},
//			PortMap: nil,
//			Consumable: &Consumable{
//				ID:        3123,
//				Iteration: 0,
//				Labels: &SecCtxLabel{
//					ID:       12345,
//					RefCount: 3,
//					Labels:   nil,
//				},
//				Maps:         map[int]*policymap.PolicyMap{},
//				Consumers:    map[string]*Consumer{},
//				ReverseRules: map[uint32]*Consumer{},
//			},
//		},
//		&Endpoint{
//			ID:               "1234",
//			DockerID:         "",
//			DockerNetworkID:  "603e047d2268a57f5a5f93f7f9e1263e9207e348a06654bf64948defbba77b0f",
//			DockerEndpointID: "93529fda8c401a071d21d6bd46fdf5499b9014dcb5a35f2e3efaa8d8bbc2e832",
//			IfName:           "lx82311",
//			LXCMAC:           MAC([]byte{0x0, 0xff, 0xf2, 0x12, 0x21, 0x32}),
//			LXCIP:            net.IP{0xbe, 0xef, 0xbe, 0xef, 0xbe, 0xef, 0xbe, 0xef, 0xaa, 0xaa, 0xaa, 0xaa, 0x11, 0x11, 0x11, 0x12},
//			IfIndex:          12,
//			NodeMAC:          MAC([]byte{0x0, 0xff, 0xf2, 0x12, 0x21, 0x23}),
//			NodeIP:           net.IP{0xbe, 0xef, 0xbe, 0xef, 0xbe, 0xef, 0xbe, 0xef, 0xaa, 0xaa, 0xaa, 0xaa, 0x11, 0x11, 0, 0},
//			SecLabel: &SecCtxLabel{
//				ID:       12345,
//				RefCount: 3,
//				Labels: Labels{
//					"foo": NewLabel("foo", "", ""),
//				},
//			},
//			PortMap: nil,
//			Consumable: &Consumable{
//				ID:        3123,
//				Iteration: 0,
//				Labels: &SecCtxLabel{
//					ID:       12345,
//					RefCount: 3,
//					Labels: Labels{
//						"foo": NewLabel("foo", "", ""),
//					},
//				},
//				Maps:         map[int]*policymap.PolicyMap{},
//				Consumers:    map[string]*Consumer{},
//				ReverseRules: map[uint32]*Consumer{},
//			},
//		},
//		&Endpoint{
//			ID:               "12345",
//			DockerID:         "",
//			DockerNetworkID:  "603e047d2268a57f5a5f93f7f9e1263e9207e348a06654bf64948defbba77b0f",
//			DockerEndpointID: "93529fda8c401a071d21d6bd46fdf5499b9014dcb5a35f2e3efaa8d8bbc2e832",
//			IfName:           "lx82311",
//			LXCMAC:           MAC([]byte{0x0, 0xff, 0xf2, 0x12, 0x21, 0x32}),
//			LXCIP:            net.IP{0xbe, 0xef, 0xbe, 0xef, 0xbe, 0xef, 0xbe, 0xef, 0xaa, 0xaa, 0xaa, 0xaa, 0x11, 0x11, 0x11, 0x12},
//			IfIndex:          12,
//			NodeMAC:          MAC([]byte{0x0, 0xff, 0xf2, 0x12, 0x21, 0x23}),
//			NodeIP:           net.IP{0xbe, 0xef, 0xbe, 0xef, 0xbe, 0xef, 0xbe, 0xef, 0xaa, 0xaa, 0xaa, 0xaa, 0x11, 0x11, 0, 0},
//			SecLabel: &SecCtxLabel{
//				ID:       12345,
//				RefCount: 3,
//				Labels: Labels{
//					"foo": NewLabel("foo", "", ""),
//				},
//			},
//			PortMap: nil,
//			Consumable: &Consumable{
//				ID:        3123,
//				Iteration: 0,
//				Labels: &SecCtxLabel{
//					ID:       12345,
//					RefCount: 3,
//					Labels: Labels{
//						"foo": NewLabel("foo", "", ""),
//					},
//				},
//				Maps:         map[int]*policymap.PolicyMap{},
//				Consumers:    map[string]*Consumer{},
//				ReverseRules: map[uint32]*Consumer{},
//			},
//		},
//	}
//	epsMap = map[string]*Endpoint{
//		"foo":   epsWanted[0],
//		"123":   epsWanted[1],
//		"1234":  epsWanted[2],
//		"12345": epsWanted[3],
//	}
//)
//
////turn NewClient(host, os.Getenv("DOCKER_API_VERSION"), client, nil)
////}
////
////// NewClient initializes a new API client for the given host and API version.
////// It won't send any version information if the version number is empty.
////// It uses the given http client as transport.
////// It also initializes the custom http headers to add to each request.
////func NewClient(host string, version string, client *http.Client, httpHeaders map[string]string) (*Client, error) {
////	proto, addr, basePath, err := ParseHost(host)
////	if err != nil {
////		return nil, err
////	}
//
//func (ds *DaemonSuite) createDummyEPs(baseDir string) ([]string, error) {
//	var err error
//	defer func() {
//		if err != nil {
//			log.Debugf("removing... %s", baseDir)
//			os.RemoveAll(baseDir)
//		}
//	}()
//	ds.d.ipv4Range = &net.IPNet{
//		net.IP{0xbe, 0xef, 0xbe, 0xef},
//		net.IPMask{0xff, 0xff},
//	}
//	var f *os.File
//	epsNames := []string{}
//	for _, ep := range epsMap {
//		os.Mkdir(filepath.Join(baseDir, ep.ID), 0777)
//		f, err = os.Create(filepath.Join(baseDir, ep.ID, common.CHeaderFileName))
//		if err != nil {
//			return nil, err
//		}
//		err = ds.d.createBPFFile(f, ep, nil)
//		if err != nil {
//			return nil, err
//		}
//		epsNames = append(epsNames, ep.ID)
//	}
//	return epsNames, nil
//}
//
//func (ds *DaemonSuite) TestReadEPsFromDirNames(c *C) {
//	tmpDir, err := ioutil.TempDir("", "cilium-tests")
//	defer func() {
//		os.RemoveAll(tmpDir)
//	}()
//	c.Assert(err, IsNil)
//	epsNames, err := ds.createDummyEPs(tmpDir)
//	c.Assert(err, IsNil)
//	eps := readEPsFromDirNames(tmpDir, epsNames)
//	c.Assert(len(eps), Equals, len(epsWanted))
//}
//
//func (ds *DaemonSuite) TestSyncLabels(c *C) {
//}
//
//func (ds *DaemonSuite) TestCleanUpDockerDandlingEndpoints(c *C) {
//	dc, err := CreateDockerMockClient()
//	c.Assert(err, IsNil)
//	ds.d.dockerClient = dc
//	_, err = dc.VolumeInspect(context.Background(), "123")
//	c.Assert(err, IsNil)
//}
