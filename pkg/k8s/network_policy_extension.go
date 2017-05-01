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

package k8s

import (
	"encoding/json"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type NetworkPolicyExtensionSpec struct {
	Ingress []NetworkPolicyIngressRule `json:"ingress"`
}

type NetworkPolicyIngressRule struct {
	From              []NetworkPolicyPeer `json:"from"`
	MatchApplications []Application       `json:"matchApplications"`
}

func (n *NetworkPolicyIngressRule) UnmarshalJSON(b []byte) error {
	var objMap map[string]*json.RawMessage
	err := json.Unmarshal(b, &objMap)
	if err != nil {
		return err
	}

	var netPolicyPeers []NetworkPolicyPeer
	if objMap["from"] != nil {
		err = json.Unmarshal(*objMap["from"], &netPolicyPeers)
		if err != nil {
			return err
		}
	} else {
		netPolicyPeers = []NetworkPolicyPeer{}
	}
	n.From = netPolicyPeers

	var rawMessagesForMatchApplications []*json.RawMessage

	if objMap["matchApplications"] == nil {
		n.MatchApplications = []Application{}
		return nil
	}

	err = json.Unmarshal(*objMap["matchApplications"], &rawMessagesForMatchApplications)
	if err != nil {
		return err
	}
	n.MatchApplications = make([]Application, len(rawMessagesForMatchApplications))
	var objKind ObjectKind
	for index, rawMessage := range rawMessagesForMatchApplications {
		err = json.Unmarshal(*rawMessage, &objKind)
		if err != nil {
			return err
		}
		switch objKind.Kind {
		case HTTPKind:
			var h HTTP
			err := json.Unmarshal(*rawMessage, &h)
			if err != nil {
				return err
			}
			n.MatchApplications[index] = h
		default:
			return fmt.Errorf("unsupported type found for: %s", objKind.Kind)
		}
	}
	return nil
}

type NetworkPolicyPeer struct {
	CiliumSelector *metav1.LabelSelector `json:"ciliumSelector,omitempty"`
}

type Application interface {
	GetObjectKind() ObjectKind
}

type ObjectKind struct {
	Kind       string
	APIVersion string
}

const (
	HTTPKind = "http"
)

type HTTP struct {
	ObjectKind
	Rules []HTTPRule `json:"rules"`
}

func (h HTTP) GetObjectKind() ObjectKind {
	return ObjectKind{
		Kind:       HTTPKind,
		APIVersion: "alphav1",
	}
}

type HTTPRule struct {
	Method string `json:"method"`
	Path   string `json:"path"`
}
