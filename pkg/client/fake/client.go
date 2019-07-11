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

package fake

import (
        "fmt"
        "io/ioutil"
        "net"
        "strings"

        v1 "k8s.io/api/core/v1"
        metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

        "github.com/onsi/gomega"
)

// FakeClient is stub Client for testing
type fakeClient struct {
	pods	map[string]*v1.Pod
	PodCount int
	nets	map[string]*types.NetworkAttachmentDefinition
	NetCount int
}

// NewFakeClient returns the new fake client
func NewFakeClient() *FakeClient {
	return &FakeClient{
		pods: make(map[string]*v1.Pod),
		nets: make(map[string]string),
	}
}

// fakeClient implements Client
var _ Client = &fakeClient{}

// GetNetworkAttachmentDefinition returns corresponding NetworkAttachmentDefinition
func (c *controllerClient) GetNetworkAttachmentDefinition(namespace, name string) (*types.NetworkAttachmentDefinition, error) {
        key := fmt.Sprintf("%s/%s", namespace, name)
	net, ok := f.nets[key]
        if !ok {
                return nil, fmt.Errorf("resource not found")
        }

        f.NetCount++
	return net, nil
}

// GetPod query pod by namespace/pod and return it if exists
func (f *FakeClient) GetPod(namespace, name string) (*v1.Pod, error) {
        key := fmt.Sprintf("%s/%s", namespace, name)
        pod, ok := f.pods[key]
        if !ok {
                return nil, fmt.Errorf("pod not found")
        }
        f.PodCount++
        return pod, nil
}

// UpdatePodStatus update pod status
func (f *FakeClient) UpdatePodStatus(pod *v1.Pod) (*v1.Pod, error) {
        key := fmt.Sprintf("%s/%s", pod.Namespace, pod.Name)
        f.pods[key] = pod
        return f.pods[key], nil
}

// AddNetConfig adds net-attach-def into its client
func (f *FakeClient) AddNetConfig(namespace, name, data string) {
        cr := fmt.Sprintf(`{
  "apiVersion": "k8s.cni.cncf.io/v1",
  "kind": "Network",
  "metadata": {
    "namespace": "%s",
    "name": "%s"
  },
  "spec": {
    "config": "%s"
  }
}`, namespace, name, strings.Replace(data, "\"", "\\\"", -1))
        cr = strings.Replace(cr, "\n", "", -1)
        cr = strings.Replace(cr, "\t", "", -1)
        f.nets[fmt.Sprintf("/apis/k8s.cni.cncf.io/v1/namespaces/%s/network-attachment-definitions/%s", namespace, name)] = cr
}

// AddNetFile puts config file as net-attach-def
func (f *FakeClient) AddNetFile(namespace, name, filePath, fileData string) {
        cr := fmt.Sprintf(`{
  "apiVersion": "k8s.cni.cncf.io/v1",
  "kind": "Network",
  "metadata": {
    "namespace": "%s",
    "name": "%s"
  }
}`, namespace, name)
        f.nets[fmt.Sprintf("/apis/k8s.cni.cncf.io/v1/namespaces/%s/network-attachment-definitions/%s", namespace, name)] = cr

        err := ioutil.WriteFile(filePath, []byte(fileData), 0600)
        gomega.Expect(err).NotTo(gomega.HaveOccurred())
}

// AddPod adds pod into fake client
func (f *FakeClient) AddPod(pod *v1.Pod) {
        key := fmt.Sprintf("%s/%s", pod.ObjectMeta.Namespace, pod.ObjectMeta.Name)
        f.pods[key] = pod
}

// DeletePod remove pod from fake client
func (f *FakeClient) DeletePod(pod *v1.Pod) {
        key := fmt.Sprintf("%s/%s", pod.ObjectMeta.Namespace, pod.ObjectMeta.Name)
        delete(f.pods, key)
}

// NewFakePod creates fake Pod object
func NewFakePod(name string, netAnnotation string, defaultNetAnnotation string) *v1.Pod {
        pod := &v1.Pod{
                ObjectMeta: metav1.ObjectMeta{
                        Name:      name,
                        Namespace: "test",
                },
                Spec: v1.PodSpec{
                        Containers: []v1.Container{
                                {Name: "ctr1", Image: "image"},
                        },
                },
        }
        annotations := make(map[string]string)

        if netAnnotation != "" {
                netAnnotation = strings.Replace(netAnnotation, "\n", "", -1)
                netAnnotation = strings.Replace(netAnnotation, "\t", "", -1)
                annotations["k8s.v1.cni.cncf.io/networks"] = netAnnotation
        }

        if defaultNetAnnotation != "" {
                annotations["v1.multus-cni.io/default-network"] = defaultNetAnnotation
        }

        pod.ObjectMeta.Annotations = annotations
        return pod
}

// EnsureCIDR parses/verify CIDR ip string and convert to net.IPNet
func EnsureCIDR(cidr string) *net.IPNet {
        ip, net, err := net.ParseCIDR(cidr)
        gomega.Expect(err).NotTo(gomega.HaveOccurred())
        net.IP = ip
        return net
}
