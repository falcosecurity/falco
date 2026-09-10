// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Falco Authors
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

package falcoTemplates

import (
	"path/filepath"
	"testing"

	"github.com/falcosecurity/falco/chart/falco/tests/unit"
	"github.com/gruntwork-io/terratest/modules/helm"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
)

// TestConfigDVolume checks that the Falco container always mounts an emptyDir
// at /etc/falco/config.d, regardless of the driver loader being enabled. The
// Falco image ships configuration snippets in that directory
// (falco.container_plugin.yaml sets load_plugins: [container]); when they are
// visible they get merged on top of the chart configuration and Falco aborts
// with "found another plugin with name container".
func TestConfigDVolume(t *testing.T) {
	t.Parallel()

	helmChartPath, err := filepath.Abs(unit.ChartPath)
	require.NoError(t, err)

	testCases := []struct {
		name       string
		controller string
		values     map[string]string
	}{
		{
			name:       "defaultValues",
			controller: "daemonset",
		},
		{
			name:       "modernEbpfWithoutFalcoctl",
			controller: "daemonset",
			values: map[string]string{
				"driver.kind":                       "modern_ebpf",
				"falcoctl.artifact.install.enabled": "false",
				"falcoctl.artifact.follow.enabled":  "false",
			},
		},
		{
			name:       "loaderDisabledWithoutFalcoctl",
			controller: "daemonset",
			values: map[string]string{
				"driver.loader.enabled":             "false",
				"falcoctl.artifact.install.enabled": "false",
				"falcoctl.artifact.follow.enabled":  "false",
			},
		},
		{
			name:       "driverDisabledDeployment",
			controller: "deployment",
			values: map[string]string{
				"driver.enabled":  "false",
				"controller.kind": "deployment",
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			options := &helm.Options{SetValues: testCase.values}
			output := helm.RenderTemplate(t, options, helmChartPath, unit.ReleaseName, []string{"templates/" + testCase.controller + ".yaml"})

			var podSpec corev1.PodSpec
			if testCase.controller == "daemonset" {
				var ds appsv1.DaemonSet
				helm.UnmarshalK8SYaml(t, output, &ds)
				podSpec = ds.Spec.Template.Spec
			} else {
				var deployment appsv1.Deployment
				helm.UnmarshalK8SYaml(t, output, &deployment)
				podSpec = deployment.Spec.Template.Spec
			}

			volume := findVolume("specialized-falco-configs", podSpec.Volumes)
			require.NotNil(t, volume)
			require.NotNil(t, volume.EmptyDir)

			falcoContainer := findContainer("falco", podSpec.Containers)
			require.NotNil(t, falcoContainer)
			mount := findVolumeMount("specialized-falco-configs", falcoContainer.VolumeMounts)
			require.NotNil(t, mount)
			require.Equal(t, "/etc/falco/config.d", mount.MountPath)
		})
	}
}
