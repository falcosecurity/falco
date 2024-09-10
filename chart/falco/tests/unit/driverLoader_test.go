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

import (
	"path/filepath"
	"testing"

	v1 "k8s.io/api/core/v1"

	"github.com/gruntwork-io/terratest/modules/helm"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
)

var (
	namespaceEnvVar = v1.EnvVar{
		Name: "FALCOCTL_DRIVER_CONFIG_NAMESPACE",
		ValueFrom: &v1.EnvVarSource{
			FieldRef: &v1.ObjectFieldSelector{
				APIVersion: "",
				FieldPath:  "metadata.namespace",
			},
		}}

	configmapEnvVar = v1.EnvVar{
		Name:  "FALCOCTL_DRIVER_CONFIG_CONFIGMAP",
		Value: releaseName + "-falco",
	}

	updateConfigMapEnvVar = v1.EnvVar{
		Name:  "FALCOCTL_DRIVER_CONFIG_UPDATE_FALCO",
		Value: "false",
	}
)

// TestDriverLoaderEnabled tests the helper that enables the driver loader based on the configuration.
func TestDriverLoaderEnabled(t *testing.T) {
	t.Parallel()

	helmChartPath, err := filepath.Abs(chartPath)
	require.NoError(t, err)

	testCases := []struct {
		name     string
		values   map[string]string
		expected func(t *testing.T, initContainer any)
	}{
		{
			"defaultValues",
			nil,
			func(t *testing.T, initContainer any) {
				container, ok := initContainer.(v1.Container)
				require.True(t, ok)

				require.Contains(t, container.Args, "auto")
				require.True(t, *container.SecurityContext.Privileged)
				require.Contains(t, container.Env, namespaceEnvVar)
				require.Contains(t, container.Env, configmapEnvVar)
				require.NotContains(t, container.Env, updateConfigMapEnvVar)

				// Check that the expected volumes are there.
				volumeMounts(t, container.VolumeMounts)
			},
		},
		{
			"driver.kind=modern-bpf",
			map[string]string{
				"driver.kind": "modern-bpf",
			},
			func(t *testing.T, initContainer any) {
				require.Equal(t, initContainer, nil)
			},
		},
		{
			"driver.kind=modern_ebpf",
			map[string]string{
				"driver.kind": "modern_ebpf",
			},
			func(t *testing.T, initContainer any) {
				require.Equal(t, initContainer, nil)
			},
		},
		{
			"driver.kind=gvisor",
			map[string]string{
				"driver.kind": "gvisor",
			},
			func(t *testing.T, initContainer any) {
				require.Equal(t, initContainer, nil)
			},
		},
		{
			"driver.disabled",
			map[string]string{
				"driver.enabled": "false",
			},
			func(t *testing.T, initContainer any) {
				require.Equal(t, initContainer, nil)
			},
		},
		{
			"driver.loader.disabled",
			map[string]string{
				"driver.loader.enabled": "false",
			},
			func(t *testing.T, initContainer any) {
				require.Equal(t, initContainer, nil)
			},
		},
		{
			"driver.kind=kmod",
			map[string]string{
				"driver.kind": "kmod",
			},
			func(t *testing.T, initContainer any) {
				container, ok := initContainer.(v1.Container)
				require.True(t, ok)

				require.Contains(t, container.Args, "kmod")
				require.True(t, *container.SecurityContext.Privileged)
				require.NotContains(t, container.Env, namespaceEnvVar)
				require.NotContains(t, container.Env, configmapEnvVar)
				require.Contains(t, container.Env, updateConfigMapEnvVar)

				// Check that the expected volumes are there.
				volumeMounts(t, container.VolumeMounts)
			},
		},
		{
			"driver.kind=module",
			map[string]string{
				"driver.kind": "module",
			},
			func(t *testing.T, initContainer any) {
				container, ok := initContainer.(v1.Container)
				require.True(t, ok)

				require.Contains(t, container.Args, "kmod")
				require.True(t, *container.SecurityContext.Privileged)
				require.NotContains(t, container.Env, namespaceEnvVar)
				require.NotContains(t, container.Env, configmapEnvVar)
				require.Contains(t, container.Env, updateConfigMapEnvVar)

				// Check that the expected volumes are there.
				volumeMounts(t, container.VolumeMounts)
			},
		},
		{
			"driver.kind=ebpf",
			map[string]string{
				"driver.kind": "ebpf",
			},
			func(t *testing.T, initContainer any) {
				container, ok := initContainer.(v1.Container)
				require.True(t, ok)

				require.Contains(t, container.Args, "ebpf")
				require.Nil(t, container.SecurityContext)
				require.NotContains(t, container.Env, namespaceEnvVar)
				require.Contains(t, container.Env, updateConfigMapEnvVar)
				require.NotContains(t, container.Env, configmapEnvVar)

				// Check that the expected volumes are there.
				volumeMounts(t, container.VolumeMounts)
			},
		},
		{
			"driver.kind=kmod&driver.loader.disabled",
			map[string]string{
				"driver.kind":           "kmod",
				"driver.loader.enabled": "false",
			},
			func(t *testing.T, initContainer any) {
				require.Equal(t, initContainer, nil)
			},
		},
	}

	for _, testCase := range testCases {
		testCase := testCase

		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			options := &helm.Options{SetValues: testCase.values}
			output := helm.RenderTemplate(t, options, helmChartPath, releaseName, []string{"templates/daemonset.yaml"})

			var ds appsv1.DaemonSet
			helm.UnmarshalK8SYaml(t, output, &ds)
			for i := range ds.Spec.Template.Spec.InitContainers {
				if ds.Spec.Template.Spec.InitContainers[i].Name == "falco-driver-loader" {
					testCase.expected(t, ds.Spec.Template.Spec.InitContainers[i])
					return
				}
			}
			testCase.expected(t, nil)
		})
	}
}

// volumenMounts checks that the expected volume mounts have been configured.
func volumeMounts(t *testing.T, volumeMounts []v1.VolumeMount) {
	rootFalcoFS := v1.VolumeMount{
		Name:      "root-falco-fs",
		ReadOnly:  false,
		MountPath: "/root/.falco",
	}
	require.Contains(t, volumeMounts, rootFalcoFS)

	procFS := v1.VolumeMount{
		Name:      "proc-fs",
		ReadOnly:  true,
		MountPath: "/host/proc",
	}
	require.Contains(t, volumeMounts, procFS)

	bootFS := v1.VolumeMount{
		Name:      "boot-fs",
		ReadOnly:  true,
		MountPath: "/host/boot",
	}
	require.Contains(t, volumeMounts, bootFS)

	libModulesFS := v1.VolumeMount{
		Name:      "lib-modules",
		ReadOnly:  false,
		MountPath: "/host/lib/modules",
	}
	require.Contains(t, volumeMounts, libModulesFS)

	usrFS := v1.VolumeMount{
		Name:      "usr-fs",
		ReadOnly:  true,
		MountPath: "/host/usr",
	}
	require.Contains(t, volumeMounts, usrFS)

	etcFS := v1.VolumeMount{
		Name:      "etc-fs",
		ReadOnly:  true,
		MountPath: "/host/etc",
	}
	require.Contains(t, volumeMounts, etcFS)

	specializedFalcoConfigs := v1.VolumeMount{
		Name:      "specialized-falco-configs",
		ReadOnly:  false,
		MountPath: "/etc/falco/config.d",
	}
	require.Contains(t, volumeMounts, specializedFalcoConfigs)
}
