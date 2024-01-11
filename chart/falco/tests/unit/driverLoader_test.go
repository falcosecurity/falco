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

	"github.com/gruntwork-io/terratest/modules/helm"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
)

// TestDriverLoaderEnabled tests the helper that enables the driver loader based on the configuration.
func TestDriverLoaderEnabled(t *testing.T) {
	t.Parallel()

	helmChartPath, err := filepath.Abs(chartPath)
	require.NoError(t, err)

	testCases := []struct {
		name     string
		values   map[string]string
		expected bool
	}{
		{
			"defaultValues",
			nil,
			true,
		},
		{
			"driver.kind=modern-bpf",
			map[string]string{
				"driver.kind": "modern-bpf",
			},
			false,
		},
		{
			"driver.kind=modern_ebpf",
			map[string]string{
				"driver.kind": "modern_ebpf",
			},
			false,
		},
		{
			"driver.kind=gvisor",
			map[string]string{
				"driver.kind": "gvisor",
			},
			false,
		},
		{
			"driver.disabled",
			map[string]string{
				"driver.enabled": "false",
			},
			false,
		},
		{
			"driver.loader.disabled",
			map[string]string{
				"driver.loader.enabled": "false",
			},
			false,
		},
		{
			"driver.kind=kmod",
			map[string]string{
				"driver.kind": "kmod",
			},
			true,
		},
		{
			"driver.kind=module",
			map[string]string{
				"driver.kind": "module",
			},
			true,
		},
		{
			"driver.kind=ebpf",
			map[string]string{
				"driver.kind": "ebpf",
			},
			true,
		},
		{
			"driver.kind=kmod&driver.loader.disabled",
			map[string]string{
				"driver.kind":           "kmod",
				"driver.loader.enabled": "false",
			},
			false,
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
			found := false
			for i := range ds.Spec.Template.Spec.InitContainers {
				if ds.Spec.Template.Spec.InitContainers[i].Name == "falco-driver-loader" {
					found = true
				}
			}

			require.Equal(t, testCase.expected, found)
		})
	}
}
