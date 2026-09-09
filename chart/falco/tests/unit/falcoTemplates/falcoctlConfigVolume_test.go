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

func TestFalcoctlConfigVolume(t *testing.T) {
	t.Parallel()

	helmChartPath, err := filepath.Abs(unit.ChartPath)
	require.NoError(t, err)

	testCases := []struct {
		name          string
		values        map[string]string
		expectVolume  bool
		expectInstall bool
		expectFollow  bool
	}{
		{
			name:          "defaultValues",
			expectVolume:  true,
			expectInstall: true,
			expectFollow:  true,
		},
		{
			name: "installOnly",
			values: map[string]string{
				"falcoctl.artifact.follow.enabled": "false",
			},
			expectVolume:  true,
			expectInstall: true,
		},
		{
			name: "followOnly",
			values: map[string]string{
				"falcoctl.artifact.install.enabled": "false",
			},
			expectVolume: true,
			expectFollow: true,
		},
		{
			name: "falcoctlArtifactsDisabled",
			values: map[string]string{
				"falcoctl.artifact.install.enabled": "false",
				"falcoctl.artifact.follow.enabled":  "false",
			},
		},
	}

	for _, controller := range []string{"daemonset", "deployment"} {
		t.Run(controller, func(t *testing.T) {
			t.Parallel()

			for _, testCase := range testCases {
				t.Run(testCase.name, func(t *testing.T) {
					t.Parallel()

					values := map[string]string{"controller.kind": controller}
					for name, value := range testCase.values {
						values[name] = value
					}
					options := &helm.Options{SetValues: values}
					output := helm.RenderTemplate(t, options, helmChartPath, unit.ReleaseName, []string{"templates/" + controller + ".yaml"})

					var podSpec corev1.PodSpec
					if controller == "daemonset" {
						var ds appsv1.DaemonSet
						helm.UnmarshalK8SYaml(t, output, &ds)
						podSpec = ds.Spec.Template.Spec
					} else {
						var deployment appsv1.Deployment
						helm.UnmarshalK8SYaml(t, output, &deployment)
						podSpec = deployment.Spec.Template.Spec
					}

					volume := findVolume("falcoctl-config-volume", podSpec.Volumes)
					if testCase.expectVolume {
						require.NotNil(t, volume)
						require.NotNil(t, volume.ConfigMap)
						configMapOutput := helm.RenderTemplate(t, options, helmChartPath, unit.ReleaseName, []string{"templates/falcoctl-configmap.yaml"})
						var configMap corev1.ConfigMap
						helm.UnmarshalK8SYaml(t, configMapOutput, &configMap)
						require.Equal(t, configMap.Name, volume.ConfigMap.Name)
						require.Contains(t, configMap.Data, "falcoctl.yaml")
						require.Equal(t, []corev1.KeyToPath{{Key: "falcoctl.yaml", Path: "falcoctl.yaml"}}, volume.ConfigMap.Items)
					} else {
						require.Nil(t, volume)
					}

					for _, consumer := range []struct {
						name      string
						container *corev1.Container
						enabled   bool
					}{
						{"install", findContainer("falcoctl-artifact-install", podSpec.InitContainers), testCase.expectInstall},
						{"follow", findContainer("falcoctl-artifact-follow", podSpec.Containers), testCase.expectFollow},
					} {
						if consumer.enabled {
							require.NotNil(t, consumer.container, consumer.name)
							mount := findVolumeMount("falcoctl-config-volume", consumer.container.VolumeMounts)
							require.NotNil(t, mount, consumer.name)
							require.Equal(t, "/etc/falcoctl", mount.MountPath, consumer.name)
						} else {
							require.Nil(t, consumer.container, consumer.name)
						}
					}
				})
			}
		})
	}
}
