// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 The Falco Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package unit

const (
	// ReleaseName is the name of the release we expect in the rendered resources.
	ReleaseName = "rendered-resources"
	// PatternK8sMetacollectorFiles is the regex pattern we expect to find in the rendered resources.
	PatternK8sMetacollectorFiles = `# Source: falco/charts/k8s-metacollector/templates/([^\n]+)`
	// K8sMetaPluginName is the name of the k8smeta plugin we expect in the falco configuration.
	K8sMetaPluginName = "k8smeta"
	// ContainerPluginName name of the container plugin we expect in the falco configuration.
	ContainerPluginName = "container"
	// ChartPath is the path to the chart.
	ChartPath = "../../.."
)
