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

package utils

import (
	"github.com/containernetworking/cni/pkg/skel"
	nptypes "github.com/intel/multus-cni/pkg/types"
        cnitypes "github.com/containernetworking/cni/pkg/types"
)

// GetCNIArgs gets k8s related args from CNI args
func GetCNIArgs (args *skel.CmdArgs) (*nptypes.K8sCNIArgs, error) {
        k8sArgs := &nptypes.K8sCNIArgs{}

        err := cnitypes.LoadArgs(args.Args, k8sArgs)
        if err != nil {
                return nil, err
        }

        return k8sArgs, nil
}
