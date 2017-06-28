// Copyright 2017 Authors of Cilium
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

package cmd

import (
	"fmt"
	"strconv"
	"strings"

	. "github.com/cilium/cilium/api/v1/client/policy"
	"github.com/cilium/cilium/api/v1/models"

	"github.com/spf13/cobra"
)

const (
	defaultSecurityId = -1
)

var src, dst, dports, srcK8sPod, dstK8sPod []string
var srcIdentity, dstIdentity int64
var srcEndpoint, dstEndpoint string
var verbose bool

// policyTraceCmd represents the policy_trace command
var policyTraceCmd = &cobra.Command{
	Use:   "trace -s <context> -d <context> [--dport <port>[/<protocol>]",
	Short: "Trace a policy decision",
	Long: `Verifies if source ID or LABEL(s) is allowed to consume
destination ID or LABEL(s). LABEL is represented as
SOURCE:KEY[=VALUE].
dports can be can be for example: 80/tcp, 53 or 23/udp.`,
	Run: func(cmd *cobra.Command, args []string) {

		var srcSlice, dstSlice, dports []string
		var dPorts []*models.Port
		var err error
		// Parse provided labels
		if len(src) > 0 {
			srcSlice, err = parseLabels(src)
			if err != nil {
				Fatalf("Invalid source: %s", err)
			}
		}

		if len(dst) > 0 {
			dstSlice, err = parseLabels(dst)
			if err != nil {
				Fatalf("Invalid destination: %s", err)
			}

			dPorts, err = parseL4PortsSlice(dports)
			if err != nil {
				Fatalf("Invalid destination port: %s", err)
			}
		}

		// Parse security identities.
		if srcIdentity != defaultSecurityId {
			srcSecurityIdLabels, err := parseIdentity(srcIdentity)
			if err != nil {
				Fatalf("Invalid source security ID")
			}
			srcSlice = append(srcSlice, srcSecurityIdLabels...)
		}
		if dstIdentity != defaultSecurityId {
			dstSecurityIdLabels, err := parseIdentity(dstIdentity)
			if err != nil {
				Fatalf("Invalid destination security ID")
			}
			dstSlice = append(dstSlice, dstSecurityIdLabels...)
		}

		// Parse endpoint IDs.
		if srcEndpoint != "" {
			srcEndpointLabels, err := parseEndpoint(srcEndpoint)
			if err != nil {
				Fatalf("Invalid source endpoint")
			}
			for _, v := range srcEndpointLabels {
				fmt.Printf("srcEndpointLabels: %s\n", v)
			}
			srcSlice = append(srcSlice, srcEndpointLabels...)
		}

		if dstEndpoint != "" {
			dstEndpointLabels, err := parseEndpoint(dstEndpoint)
			if err != nil {
				Fatalf("Invalid destination endpoint")
			}
			for _, v := range dstEndpointLabels {
				fmt.Printf("dstEndpointLabels: %s\n", v)
			}
			dstSlice = append(dstSlice, dstEndpointLabels...)
		}

		search := models.IdentityContext{
			From:    srcSlice,
			To:      dstSlice,
			Dports:  dPorts,
			Verbose: verbose,
		}

		params := NewGetPolicyResolveParams().WithIdentityContext(&search)
		if scr, err := client.Policy.GetPolicyResolve(params); err != nil {
			Fatalf("Error while retrieving policy consume result: %s\n", err)
		} else if scr != nil && scr.Payload != nil {
			fmt.Printf("%s\n", scr.Payload.Log)
			fmt.Printf("Verdict: %s\n", scr.Payload.Verdict)
		}
	},
}

func init() {
	policyCmd.AddCommand(policyTraceCmd)
	policyTraceCmd.Flags().StringSliceVarP(&src, "src", "s", []string{}, "Source label context")
	policyTraceCmd.Flags().StringSliceVarP(&dst, "dst", "d", []string{}, "Destination label context")
	policyTraceCmd.Flags().StringSliceVarP(&dports, "dport", "", []string{}, "L4 destination port to search on outgoing traffic of the source label context and on incoming traffic of the destination label context")
	policyTraceCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "set tracing to TRACE_VERBOSE")
	policyTraceCmd.Flags().Int64VarP(&srcIdentity, "src-identity", "", defaultSecurityId, "source identity")
	policyTraceCmd.Flags().Int64VarP(&dstIdentity, "dst-identity", "", defaultSecurityId, "destination identity")
	policyTraceCmd.Flags().StringSliceVarP(&srcK8sPod, "src-k8s-pod", "", []string{}, "source Kubernetes pod")
	policyTraceCmd.Flags().StringSliceVarP(&dstK8sPod, "dst-k8s-pod", "", []string{}, "destination Kubernetes pod")
	policyTraceCmd.Flags().StringVarP(&srcEndpoint, "src-endpoint", "", "", "source endpoint")
	policyTraceCmd.Flags().StringVarP(&dstEndpoint, "dst-endpoint", "", "", "destination endpoint")
}

func parseK8sPod(slice []string) ([]string, error) {
	/*conf, err := client.Daemon.GetConfig(nil)
	if err != nil {
		Fatalf("error getting daemon config to get k8s info")

	}
	for k, v := range conf.Payload.Configuration.Mutable {
		fmt.Printf("k, v: %s, %s", k, v)
	}*/
	str := slice[0]
	if strings.Contains(str, ":") {
		fmt.Printf("using namespace and podname")
	} else {
		fmt.Printf("using podname only, assuming default namespace")
	}

	//params := NewGetPolicyResolveParams().WithIdentityContext(&search)
	//if scr, err := client.Policy.GetPolicyResolve(params); err != nil {
	//	Fatalf("Error while retrieving policy consume result: %s\n", err)
	//} else if scr != nil && scr.Payload != nil {
	//	fmt.Printf("%s\n", scr.Payload.Log)
	//	fmt.Printf("Verdict: %s\n", scr.Payload.Verdict)
	//}

	return nil, nil
}

func parseEndpoint(ep string) ([]string, error) {
	resp, err := client.EndpointLabelsGet(ep)
	if err != nil {
		return nil, fmt.Errorf("unable to retrieve labels for endpoint ID %s: %s", ep, err)
	}
	if resp == nil {
		return nil, fmt.Errorf("endpoint id %s not found", ep)
	}
	return append(append(append([]string{}, resp.Custom...),resp.Disabled...), resp.OrchestrationSystem...), nil
}


// Returns the labels for security identity ID and an error if the labels cannot be retrieved, or if there are no labels.
func parseIdentity(ID int64) ([]string, error) {
	fmt.Printf("ID: %v", ID)
	resp, err := client.IdentityGet(strconv.FormatInt(ID, 10))
	if err != nil {
		return nil, fmt.Errorf("unable to retrieve labels for security identity %s: %s", ID, err)
	}
	if resp == nil {
		return nil, fmt.Errorf("security identity %s not found", ID)
	}
	return resp.Labels, nil
}

func parseLabels(slice []string) ([]string, error) {
	if len(slice) == 0 {
		return nil, fmt.Errorf("No labels provided")
	}

	return slice, nil
}

// parseL4PortsSlice parses a given `slice` of strings. Each string should be in
// the form of `<port>[/<protocol>]`, where the `<port>` in an integer and an
// `<protocol>` is an optional layer 4 protocol `tcp` or `udp`. In case
// `protocol` is not present, or is set to `any`, the parsed port will be set to
// `models.PortProtocolAny`.
func parseL4PortsSlice(slice []string) ([]*models.Port, error) {
	rules := []*models.Port{}
	for _, v := range slice {
		vSplit := strings.Split(v, "/")
		var protoStr string
		switch len(vSplit) {
		case 1:
			protoStr = models.PortProtocolAny
		case 2:
			protoStr = strings.ToLower(vSplit[1])
			switch protoStr {
			case models.PortProtocolTCP, models.PortProtocolUDP, models.PortProtocolAny:
			default:
				return nil, fmt.Errorf("invalid protocol %q", protoStr)
			}
		default:
			return nil, fmt.Errorf("invalid format %q. Should be <port>[/<protocol>]", v)
		}
		portStr := vSplit[0]
		port, err := strconv.Atoi(portStr)
		if err != nil {
			return nil, fmt.Errorf("invalid port %q: %s", portStr, err)
		}
		l4 := &models.Port{
			Port:     uint16(port),
			Protocol: protoStr,
		}
		rules = append(rules, l4)
	}
	return rules, nil
}
