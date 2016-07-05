// +build test
package daemon

//
//import (
//	"fmt"
//	"io/ioutil"
//	"net/http"
//	"strings"
//
//	//"crypto/tls"
//	dClient "github.com/docker/engine-api/client"
//	//"github.com/docker/go-connections/tlsconfig"
//	"os"
//)
//
//type MyHandler struct {
//}
//
//func (h *MyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
//	fmt.Fprintf(w, "Visitor count")
//}
//
//type mockTransport http.Transport
//
//func newMockTransport() http.Transport {
//	return http.Transport(mockTransport{})
//}
//
//// Implement http.RoundTripper
//func (t *mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
//	fmt.Fprintf(os.Stderr, "OHEG\n\n\n\n\n\n\n")
//	// Create mocked http.Response
//	response := &http.Response{
//		Header:     make(http.Header),
//		Request:    req,
//		StatusCode: http.StatusOK,
//	}
//	response.Header.Set("Content-Type", "application/json")
//
//	responseBody :=
//		`{
//	    "Accept-Encoding": [
//		"mock"
//	    ],
//	    "User-Agent": [
//		"mock"
//	    ],
//	    "X-Ip-Country": [
//		"Japan(Mock)"
//	    ],
//	    "X-Real-Ip": [
//		"192.168.1.1"
//	    ]
//	}`
//	response.Body = ioutil.NopCloser(strings.NewReader(responseBody))
//	return response, nil
//}
//
//func CreateDockerMockClient() (*dClient.Client, error) {
//	tr := newMockTransport()
//	myHTTPC := http.Client{
//		Transport: &tr,
//	}
//	return dClient.NewClient("tcp://127.0.0.1:1", "v1.21", &myHTTPC, nil)
//}
