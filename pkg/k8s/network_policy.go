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
	"net"
	"strings"

	"github.com/cilium/cilium/common"
	k8sTypes "github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api"

	"k8s.io/client-go/pkg/api/v1"
	"k8s.io/client-go/pkg/apis/extensions/v1beta1"
)

// ParseNetworkPolicy parses a k8s NetworkPolicy and returns a Cilium policy
// node that can be merged into the return parent path.
func ParseNetworkPolicy(np *v1beta1.NetworkPolicy) (string, *policy.Node, error) {
	// The parent policy node can optionally be specified via an annotation
	// FIXME should we always prefix the k8sTypes.DefaultPolicyParentPath even if the AnnotationParentPath is set?
	parentNodeName := np.Annotations[k8sTypes.AnnotationParentPath]
	if parentNodeName == "" {
		parentNodeName = k8sTypes.DefaultPolicyParentPath
	}

	policyName := np.Annotations[k8sTypes.AnnotationName]
	if policyName == "" {
		policyName = np.Name
	}

	var namespace string
	if np.Namespace != "" {
		namespace = np.Namespace
	} else {
		namespace = v1.NamespaceDefault
	}

	allowRules := []policy.Rule{}
	l4Rules := []policy.AllowL4{}
	for _, iRule := range np.Spec.Ingress {
		// Based on NetworkPolicyIngressRule docs:
		//   From []NetworkPolicyPeer
		// If this field is empty or missing, this rule matches all sources (traffic not restricted by source).
		if iRule.From == nil || len(iRule.From) == 0 {
			all := labels.NewLabel(labels.IDNameAll, "", common.ReservedLabelSource)
			ar := &policy.AllowRule{
				Action: api.ACCEPT,
				Labels: labels.LabelArray{all},
			}
			allowRules = append(allowRules, ar)
		} else {
			for _, rule := range iRule.From {
				// Only one or the other can be set, not both
				if rule.PodSelector != nil {
					if rule.PodSelector.MatchLabels == nil {
						rule.PodSelector.MatchLabels = map[string]string{}
					}
					// The PodSelector should only reflect to the same namespace
					// the policy is being stored, thus we add the namespace to
					// the MatchLabels map.
					rule.PodSelector.MatchLabels[k8sTypes.PodNamespaceLabel] = namespace
					ar := &policy.K8sAllowRule{
						Action: api.ACCEPT,
						Selector: policy.K8sSelector{
							PodSelector: rule.PodSelector,
						},
					}
					allowRules = append(allowRules, ar)
				} else if rule.NamespaceSelector != nil {
					matchLabels := map[string]string{}
					// We use our own special label prefix for namespace metadata,
					// thus we need to prefix that prefix to all NamespaceSelector.MatchLabels
					for k, v := range rule.NamespaceSelector.MatchLabels {
						matchLabels[policy.JoinPath(k8sTypes.PodNamespaceMetaLabels, k)] = v
					}
					rule.NamespaceSelector.MatchLabels = matchLabels

					// We use our own special label prefix for namespace metadata,
					// thus we need to prefix that prefix to all NamespaceSelector.MatchLabels
					for i, lsr := range rule.NamespaceSelector.MatchExpressions {
						lsr.Key = policy.JoinPath(k8sTypes.PodNamespaceMetaLabels, lsr.Key)
						rule.NamespaceSelector.MatchExpressions[i] = lsr
					}
					ar := &policy.K8sAllowRule{
						Action: api.ACCEPT,
						Selector: policy.K8sSelector{
							NamespaceSelector: rule.NamespaceSelector,
						},
					}
					allowRules = append(allowRules, ar)
				}
			}
		}

		if iRule.Ports != nil && len(iRule.Ports) > 0 {
			l4filters := []policy.L4Filter{}
			for _, port := range iRule.Ports {
				if port.Protocol == nil && port.Port == nil {
					continue
				}

				protocol := "tcp"
				if port.Protocol != nil {
					protocol = string(*port.Protocol)
				}

				portNum := 0
				if port.Port != nil {
					portStr := port.Port.String()
					p, err := net.LookupPort(protocol, portStr)
					if err != nil {
						return "", nil, fmt.Errorf("Unable to parse port %s: %s",
							portStr, err)
					}
					portNum = p
				}

				l4filters = append(l4filters, policy.L4Filter{
					Port:     portNum,
					Protocol: strings.ToLower(protocol),
				})
			}

			if len(l4filters) > 0 {
				l4Rules = append(l4Rules, policy.AllowL4{
					Ingress: l4filters,
				})
			}
		}
	}

	if np.Spec.PodSelector.MatchLabels == nil {
		np.Spec.PodSelector.MatchLabels = map[string]string{}
	}
	np.Spec.PodSelector.MatchLabels[k8sTypes.PodNamespaceLabel] = namespace

	pn := policy.NewNode(policyName, nil)
	pn.CoverAll = true
	pn.Rules = []policy.PolicyRule{
		&policy.RuleK8s{
			PodSelector: np.Spec.PodSelector,
			Allow:       allowRules,
		},
	}

	if len(l4Rules) > 0 {
		pn.Rules = append(pn.Rules, &policy.RuleL4K8s{
			PodSelector: np.Spec.PodSelector,
			Allow:       l4Rules,
		})
	}

	if np.Annotations[k8sTypes.AnnotationCiliumPolicy] != "" {
		if err := ParseNetworkPolicyExtension(np, pn); err != nil {
			return "", nil, err
		}
	}

	return parentNodeName, pn, nil
}

func ParseNetworkPolicyExtension(np *v1beta1.NetworkPolicy, pn *policy.Node) error {
	ciliumPolicyJson := np.Annotations[k8sTypes.AnnotationCiliumPolicy]
	npes := NetworkPolicyExtensionSpec{}
	if err := json.Unmarshal([]byte(ciliumPolicyJson), &npes); err != nil {
		return err
	}
	allowRules := []policy.Rule{}
	auxRules := []policy.AuxRule{}
	for _, ing := range npes.Ingress {
		for _, rule := range ing.From {
			lbsl := labels.Map2Labels(rule.CiliumSelector.MatchLabels, "")
			rule.CiliumSelector.MatchLabels = map[string]string{}
			for k, v := range lbsl {
				rule.CiliumSelector.MatchLabels[k] = v.Value
			}
			ar := &policy.K8sAllowRule{
				Action: api.ACCEPT,
				Selector: policy.K8sSelector{
					PodSelector: rule.CiliumSelector,
				},
			}
			allowRules = append(allowRules, ar)
		}
		for _, appRule := range ing.MatchApplications {
			switch appRule.GetObjectKind().Kind {
			case HTTPKind:
				http, ok := appRule.(HTTP)
				if !ok {
					break
				}
				for _, rule := range http.Rules {
					var expr string
					if rule.Path != "" {
						expr = fmt.Sprintf(`Method(%q) && Path(%q)`, rule.Method, rule.Path)
					} else {
						expr = fmt.Sprintf(`Method(%q)`)
					}
					auxRules = append(auxRules, policy.AuxRule{
						Expr: expr,
					})
				}
			}
		}
	}
	if len(allowRules) > 0 {
		pn.Rules = append(pn.Rules, &policy.RuleK8s{
			PodSelector: np.Spec.PodSelector,
			Allow:       allowRules,
		})
	}
	if len(auxRules) > 0 {
		for _, nodeRule := range pn.Rules {
			nodeRuleL4K8s, ok := nodeRule.(*policy.RuleL4K8s)
			fmt.Printf("Not ablee to %+v %+v\n", nodeRuleL4K8s, ok)
			if !ok {
				continue
			}
			for i := range nodeRuleL4K8s.Allow {
				for j, ing := range nodeRuleL4K8s.Allow[i].Ingress {
					fmt.Printf("Not ablee to %+v\n", ing)
					if ing.L7Parser == "" && len(ing.L7Rules) == 0 {
						ing.L7Rules = auxRules
						ing.L7Parser = "http"
						nodeRuleL4K8s.Allow[i].Ingress[j] = ing
					}
				}
			}
		}
	}
	return nil
}
