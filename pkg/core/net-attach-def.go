// Copyright (c) 2019 XXX
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

package core

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/containernetworking/cni/pkg/types/current"
	cnitypes "github.com/containernetworking/cni/pkg/types"

        npclient "github.com/intel/multus-cni/pkg/client"
        nptypes "github.com/intel/multus-cni/pkg/types"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/util/retry"
)

// SetNetworkStatus updates the Pod status 
func SetNetworkStatus(client npclient.Client, pod *corev1.Pod, statuses []*nptypes.NetworkStatus) error {
	if client == nil {
		return fmt.Errorf("no client set")
	}

	if pod == nil {
		return fmt.Errorf("no pod set")
	}

	var networkStatus []string
	if statuses != nil {
		for _, status := range statuses {
			data, err := json.MarshalIndent(status, "", "    ")
			if err != nil {
				return fmt.Errorf("SetNetworkStatus: error with Marshal Indent: %v", err)
			}
			networkStatus = append(networkStatus, string(data))
		}
	}

	_, err := setPodNetworkAnnotation(client, pod, fmt.Sprintf("[%s]", strings.Join(networkStatus, ",")))
	if err != nil {
		return fmt.Errorf("SetNetworkStatus: failed to update the pod %s in out of cluster comm: %v", pod.Name, err)
	}
	return nil
}

func setPodNetworkAnnotation(client npclient.Client, pod *corev1.Pod, networkstatus string) (*corev1.Pod, error) {
	if len(pod.Annotations) == 0 {
		pod.Annotations = make(map[string]string)
	}

	pod.Annotations[nptypes.NetworkStatusAnnot] = networkstatus
	pod = pod.DeepCopy()
	var err error

	if resultErr := retry.RetryOnConflict(retry.DefaultBackoff, func() error {
                if err != nil {
                        // Re-get the pod unless it's the first attempt to update
                        pod, err = client.GetPod(pod.Namespace, pod.Name)
                        if err != nil {
                                return err
                        }
                }

                pod, err = client.UpdatePodStatus(pod)
                return err
        }); resultErr != nil {
                return nil, fmt.Errorf("status update failed for pod %s/%s: %v", pod.Namespace, pod.Name, resultErr)
        }
        return pod, nil
}

// CreateNetworkStatus create NetworkStatus from CNI result
func CreateNetworkStatus(r cnitypes.Result, networkName string, defaultNetwork bool) (*nptypes.NetworkStatus, error) {
	netStatus := &nptypes.NetworkStatus{}
	netStatus.Name = networkName
	netStatus.Default = defaultNetwork

	// Convert whatever the IPAM result was into the current Result type
	result, err := current.NewResultFromResult(r)
	if err != nil {
		return netStatus, fmt.Errorf("error convert the type.Result to current.Result: %v", err)
	}

	for _, ifs := range result.Interfaces {
		// Only pod interfaces can have sandbox information
		if ifs.Sandbox != "" {
			netStatus.Interface = ifs.Name
			netStatus.Mac = ifs.Mac
		}
	}

	for _, ipconfig := range result.IPs {
		if ipconfig.Version == "4" && ipconfig.Address.IP.To4() != nil {
			netStatus.IPs = append(netStatus.IPs, ipconfig.Address.IP.String())
                }

                if ipconfig.Version == "6" && ipconfig.Address.IP.To16() != nil {
                        netStatus.IPs = append(netStatus.IPs, ipconfig.Address.IP.String())
                }
        }

        netStatus.DNS = result.DNS

        return netStatus, nil
}

// ParsePodNetworkAnnotation parses Pod annotation for net-attach-def and get NetworkSelectionElement
func ParsePodNetworkAnnotation(pod *corev1.Pod) ([]*nptypes.NetworkSelectionElement, error) {
	netAnnot := pod.Annotations[nptypes.NetworkAttachmentAnnot]
	defaultNamespace := pod.Namespace

	if len(netAnnot) == 0 {
		return nil, &npclient.NoK8sNetworkError{"no kubernetes network found"}
	}

	networks, err := ParseNetworkAnnotation(netAnnot, defaultNamespace)
	if err != nil {
		return nil, err
	}
	return networks, nil
}

// ParseNetworkAnnotation parses actual annotation string and get NetworkSelectionElement
func ParseNetworkAnnotation(podNetworks, defaultNamespace string) ([]*nptypes.NetworkSelectionElement, error) {
	var networks []*nptypes.NetworkSelectionElement

	if podNetworks == "" {
		return nil, fmt.Errorf("parsePodNetworkAnnotation: pod annotation not having \"network\" as key")
	}

        if strings.IndexAny(podNetworks, "[{\"") >= 0 {
                if err := json.Unmarshal([]byte(podNetworks), &networks); err != nil {
                        return nil, fmt.Errorf("parsePodNetworkAnnotation: failed to parse pod Network Attachment Selection Annotation JSON format: %v", err)
                }
        } else {
                // Comma-delimited list of network attachment object names
                for _, item := range strings.Split(podNetworks, ",") {
                        // Remove leading and trailing whitespace.
                        item = strings.TrimSpace(item)

                        // Parse network name (i.e. <namespace>/<network name>@<ifname>)
                        netNsName, networkName, netIfName, err := parsePodNetworkObjectText(item)
                        if err != nil {
                                return nil, fmt.Errorf("parsePodNetworkAnnotation: %v", err)
                        }

                        networks = append(networks, &nptypes.NetworkSelectionElement{
                                Name:             networkName,
                                Namespace:        netNsName,
                                InterfaceRequest: netIfName,
                        })
                }
        }

        for _, net := range networks {
                if net.Namespace == "" {
                        net.Namespace = defaultNamespace
                }
        }

        return networks, nil
}

// parsePodNetworkObjectText parses annotation text and returns 
// its triplet, (namespace, name, interface name).
func parsePodNetworkObjectText(podnetwork string) (string, string, string, error) {
        var netNsName string
        var netIfName string
        var networkName string

        slashItems := strings.Split(podnetwork, "/")
        if len(slashItems) == 2 {
                netNsName = strings.TrimSpace(slashItems[0])
                networkName = slashItems[1]
        } else if len(slashItems) == 1 {
                networkName = slashItems[0]
        } else {
                return "", "", "", fmt.Errorf("Invalid network object (failed at '/')")
        }

        atItems := strings.Split(networkName, "@")
        networkName = strings.TrimSpace(atItems[0])
        if len(atItems) == 2 {
                netIfName = strings.TrimSpace(atItems[1])
        } else if len(atItems) != 1 {
                return "", "", "", fmt.Errorf("Invalid network object (failed at '@')")
        }

        // Check and see if each item matches the specification for valid attachment name.
        // "Valid attachment names must be comprised of units of the DNS-1123 label format"
        // [a-z0-9]([-a-z0-9]*[a-z0-9])?
        // And we allow at (@), and forward slash (/) (units separated by commas)
        // It must start and end alphanumerically.
        allItems := []string{netNsName, networkName, netIfName}
        for i := range allItems {
                matched, _ := regexp.MatchString("^[a-z0-9]([-a-z0-9]*[a-z0-9])?$", allItems[i])
                if !matched && len([]rune(allItems[i])) > 0 {
                        return "", "", "", fmt.Errorf(fmt.Sprintf("Failed to parse: one or more items did not match comma-delimited format (must consist of lower case alphanumeric characters). Must start and end with an alphanumeric character), mismatch @ '%v'", allItems[i]))
                }
        }

        return netNsName, networkName, netIfName, nil
}
