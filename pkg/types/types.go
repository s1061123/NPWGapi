// Copyright 2019 XXX
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
//

package types

import (
	"net"

        "github.com/containernetworking/cni/pkg/types"

        metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// K8sCNIArgs is the valid CNI_ARGS used for Kubernetes
type K8sCNIArgs struct {
        types.CommonArgs
        IP                         net.IP
        K8S_POD_NAME               types.UnmarshallableString
        K8S_POD_NAMESPACE          types.UnmarshallableString
        K8S_POD_INFRA_CONTAINER_ID types.UnmarshallableString
}

// NetworkStatus is for network status annotation for pod
type NetworkStatus struct {
        Name      string    `json:"name"`
        Interface string    `json:"interface,omitempty"`
        IPs       []string  `json:"ips,omitempty"`
        Mac       string    `json:"mac,omitempty"`
        Default   bool      `json:"default,omitempty"`
        DNS       types.DNS `json:"dns,omitempty"`
}

// NetworkAttachmentDefinition represents net-attach-def of K8s NPWG spec
type NetworkAttachmentDefinition struct {
        metav1.TypeMeta `json:",inline"`
        // Note that ObjectMeta is mandatory, as an object
        // name is required
        Metadata metav1.ObjectMeta `json:"metadata,omitempty" description:"standard object metadata"`

        // Specification describing how to invoke a CNI plugin to
        // add or remove network attachments for a Pod.
        // In the absence of valid keys in a Spec, the runtime (or
        // meta-plugin) should load and execute a CNI .configlist
        // or .config (in that order) file on-disk whose JSON
        // “name” key matches this Network object’s name.
        // +optional
        Spec NetworkAttachmentDefinitionSpec `json:"spec"`
}

// NetworkAttachmentDefinitionSpec represents net-attach-def spec of K8s NPWG spec
type NetworkAttachmentDefinitionSpec struct {
        // Config contains a standard JSON-encoded CNI configuration
        // or configuration list which defines the plugin chain to
        // execute.  If present, this key takes precedence over
        // ‘Plugin’.
        // +optional
        Config string `json:"config"`
}

// NetworkSelectionElement represents one element of the JSON format
// Network Attachment Selection Annotation as described in section 4.1.2
// of the CRD specification.
type NetworkSelectionElement struct {
        // Name contains the name of the Network object this element selects
        Name string `json:"name"`
        // Namespace contains the optional namespace that the network referenced
        // by Name exists in
        Namespace string `json:"namespace,omitempty"`
        // IPRequest contains an optional requested IP address for this network
        // attachment
        IPRequest string `json:"ips,omitempty"`
        // MacRequest contains an optional requested MAC address for this
        // network attachment
        MacRequest string `json:"mac,omitempty"`
        // InterfaceRequest contains an optional requested name for the
        // network interface this attachment will create in the container
        InterfaceRequest string `json:"interface,omitempty"`
}

