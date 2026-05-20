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

func TestProcfsMount(t *testing.T) {
	t.Parallel()

	helmChartPath, err := filepath.Abs(unit.ChartPath)
	require.NoError(t, err)

	testCases := []struct {
		name              string
		values            map[string]string
		expectVolumeMount bool
		expectVolume      bool
	}{
		{
			name:              "defaultValues",
			values:            nil,
			expectVolumeMount: true,
			expectVolume:      true,
		},
		{
			name: "driver.disabled_pluginsHostinfo.enabled",
			values: map[string]string{
				"driver.enabled":         "false",
				"falco.plugins_hostinfo": "true",
			},
			expectVolumeMount: true,
			expectVolume:      true,
		},
		{
			name: "driver.disabled_pluginsHostinfo.disabled",
			values: map[string]string{
				"driver.enabled":         "false",
				"falco.plugins_hostinfo": "false",
			},
			expectVolumeMount: false,
			expectVolume:      false,
		},
		{
			name: "driver.enabled_pluginsHostinfo.disabled",
			values: map[string]string{
				"driver.enabled":         "true",
				"falco.plugins_hostinfo": "false",
			},
			expectVolumeMount: true,
			expectVolume:      true,
		},
	}

	for _, testCase := range testCases {
		testCase := testCase

		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			options := &helm.Options{SetValues: testCase.values}
			output := helm.RenderTemplate(t, options, helmChartPath, unit.ReleaseName, []string{"templates/daemonset.yaml"})

			var ds appsv1.DaemonSet
			helm.UnmarshalK8SYaml(t, output, &ds)

			falcoContainer := findContainer("falco", ds.Spec.Template.Spec.Containers)
			require.NotNil(t, falcoContainer)

			procMount := findVolumeMount("proc-fs", falcoContainer.VolumeMounts)
			procVolume := findVolume("proc-fs", ds.Spec.Template.Spec.Volumes)

			if testCase.expectVolumeMount {
				require.NotNil(t, procMount)
				require.Equal(t, "/host/proc", procMount.MountPath)
			} else {
				require.Nil(t, procMount)
			}

			if testCase.expectVolume {
				require.NotNil(t, procVolume)
				require.NotNil(t, procVolume.HostPath)
				require.Equal(t, "/proc", procVolume.HostPath.Path)
			} else {
				require.Nil(t, procVolume)
			}
		})
	}
}

func findContainer(name string, containers []corev1.Container) *corev1.Container {
	for _, container := range containers {
		if container.Name == name {
			return &container
		}
	}
	return nil
}

func findVolumeMount(name string, volumeMounts []corev1.VolumeMount) *corev1.VolumeMount {
	for _, volumeMount := range volumeMounts {
		if volumeMount.Name == name {
			return &volumeMount
		}
	}
	return nil
}

func findVolume(name string, volumes []corev1.Volume) *corev1.Volume {
	for _, volume := range volumes {
		if volume.Name == name {
			return &volume
		}
	}
	return nil
}
