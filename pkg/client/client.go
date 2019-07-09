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

package client

import (
        "encoding/json"
        "fmt"
        "os"

        v1 "k8s.io/api/core/v1"
        metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
        "k8s.io/client-go/kubernetes"
        "k8s.io/client-go/rest"
        "k8s.io/client-go/tools/clientcmd"

	"github.com/intel/multus-cni/pkg/types"
)

// NoK8sNetworkError indicates error, no network in kubernetes
type NoK8sNetworkError struct {
        Message string
}

func (e *NoK8sNetworkError) Error() string { return string(e.Message) }

// Client is abstraction layer for k8s client (used testing package)
type Client interface {
        GetNetworkAttachmentDefinition(namespace, name string) (*types.NetworkAttachmentDefinition, error)
        GetPod(namespace, name string) (*v1.Pod, error)
        UpdatePodStatus(pod *v1.Pod) (*v1.Pod, error)
}

type defaultClient struct {
        client kubernetes.Interface
}

// defaultClient implements Client
var _ Client = &defaultClient{}

// GetNetworkAttachmentDefinition returns corresponding NetworkAttachmentDefinition
func (d *defaultClient) GetNetworkAttachmentDefinition(namespace, name string) (*types.NetworkAttachmentDefinition, error) {
	rawPath := fmt.Sprintf("/apis/k8s.cni.cncf.io/v1/namespaces/%s/network-attachment-definitions/%s", namespace, name)
	netData, err := d.client.ExtensionsV1beta1().RESTClient().Get().AbsPath(rawPath).DoRaw()
	if err != nil {
		return nil, fmt.Errorf("failed to get network attachment definition: %s", rawPath)
	}
	net := &types.NetworkAttachmentDefinition{}
	if err := json.Unmarshal(netData, net); err != nil {
		return nil, fmt.Errorf("failed to unmarshal json:json %v", netData)
	}
	return net, nil
}

// GetPod returns Pod object
func (d *defaultClient) GetPod(namespace, name string) (*v1.Pod, error) {
        return d.client.Core().Pods(namespace).Get(name, metav1.GetOptions{})
}

// UpdatePodStatus invokes UpdateStatus
func (d *defaultClient) UpdatePodStatus(pod *v1.Pod) (*v1.Pod, error) {
        return d.client.Core().Pods(pod.Namespace).UpdateStatus(pod)
}

// GetClient gets client info from kubeconfig or incluster config (KUBERNETES_SERVICE_HOST:KUBERNETES_SERVICE_PORT)
func GetClient(kubeconfig string) (Client, error) {
	// XXX: logging?
	var err error
	var config *rest.Config

	// kubeconfig is specified in config
	if kubeconfig != "" {
		config, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			return nil, fmt.Errorf("GetClient: failed to get context for the kubeconfig %s: %v", kubeconfig, err)
		}
	} else if os.Getenv("KUBERNETES_SERVICE_HOST") != "" && os.Getenv("KUBERNETES_SERVICE_PORT") != "" {
		// KUBERNETES_SERVICE_HOST:KUBERNETES_SERVICE_PORT is supplied through environment
		config, err = rest.InClusterConfig()
		if err != nil {
			return nil, fmt.Errorf("GetClient: failed to get context for in-cluster config: %v", err)
		}
	} else {
		// No kubeconfig; assume we shouldn't talk to Kubernetes at all (XXX: need it?)
		return nil, nil
	}

        // Specify that we use gRPC
        config.AcceptContentTypes = "application/vnd.kubernetes.protobuf,application/json"
        config.ContentType = "application/vnd.kubernetes.protobuf"

        // creates the clientset
        client, err := kubernetes.NewForConfig(config)
        if err != nil {
                return nil, err
        }

        return &defaultClient{client: client}, nil
}
