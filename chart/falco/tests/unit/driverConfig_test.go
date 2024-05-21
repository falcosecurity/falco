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
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gruntwork-io/terratest/modules/helm"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
)

func TestDriverConfigInFalcoConfig(t *testing.T) {
	t.Parallel()

	helmChartPath, err := filepath.Abs(chartPath)
	require.NoError(t, err)

	testCases := []struct {
		name     string
		values   map[string]string
		expected func(t *testing.T, config any)
	}{
		{
			"defaultValues",
			nil,
			func(t *testing.T, config any) {
				require.Len(t, config, 4, "should have four items")
				kind, bufSizePreset, dropFailedExit, err := getKmodConfig(config)
				require.NoError(t, err)
				require.Equal(t, "modern_ebpf", kind)
				require.Equal(t, float64(4), bufSizePreset)
				require.False(t, dropFailedExit)
			},
		},
		{
			"kind=kmod",
			map[string]string{
				"driver.kind": "kmod",
			},
			func(t *testing.T, config any) {
				require.Len(t, config, 2, "should have only two items")
				kind, bufSizePreset, dropFailedExit, err := getKmodConfig(config)
				require.NoError(t, err)
				require.Equal(t, "kmod", kind)
				require.Equal(t, float64(4), bufSizePreset)
				require.False(t, dropFailedExit)
			},
		},
		{
			"kind=module(alias)",
			map[string]string{
				"driver.kind": "module",
			},
			func(t *testing.T, config any) {
				require.Len(t, config, 2, "should have only two items")
				kind, bufSizePreset, dropFailedExit, err := getKmodConfig(config)
				require.NoError(t, err)
				require.Equal(t, "kmod", kind)
				require.Equal(t, float64(4), bufSizePreset)
				require.False(t, dropFailedExit)
			},
		},
		{
			"kmod=config",
			map[string]string{
				"driver.kmod.bufSizePreset":  "6",
				"driver.kmod.dropFailedExit": "true",
				"driver.kind":                "module",
			},
			func(t *testing.T, config any) {
				require.Len(t, config, 2, "should have only two items")
				kind, bufSizePreset, dropFailedExit, err := getKmodConfig(config)
				require.NoError(t, err)
				require.Equal(t, "kmod", kind)
				require.Equal(t, float64(6), bufSizePreset)
				require.True(t, dropFailedExit)
			},
		},
		{
			"ebpf=config",
			map[string]string{
				"driver.kind":                "ebpf",
				"driver.ebpf.bufSizePreset":  "6",
				"driver.ebpf.dropFailedExit": "true",
				"driver.ebpf.path":           "testing/Path/ebpf",
			},
			func(t *testing.T, config any) {
				require.Len(t, config, 2, "should have only two items")
				kind, path, bufSizePreset, dropFailedExit, err := getEbpfConfig(config)
				require.NoError(t, err)
				require.Equal(t, "ebpf", kind)
				require.Equal(t, "testing/Path/ebpf", path)
				require.Equal(t, float64(6), bufSizePreset)
				require.True(t, dropFailedExit)
			},
		},
		{
			"kind=ebpf",
			map[string]string{
				"driver.kind": "ebpf",
			},
			func(t *testing.T, config any) {
				require.Len(t, config, 2, "should have only two items")
				kind, path, bufSizePreset, dropFailedExit, err := getEbpfConfig(config)
				require.NoError(t, err)
				require.Equal(t, "ebpf", kind)
				require.Equal(t, "${HOME}/.falco/falco-bpf.o", path)
				require.Equal(t, float64(4), bufSizePreset)
				require.False(t, dropFailedExit)
			},
		},
		{
			"kind=modern_ebpf",
			map[string]string{
				"driver.kind": "modern_ebpf",
			},
			func(t *testing.T, config any) {
				require.Len(t, config, 2, "should have only two items")
				kind, bufSizePreset, cpusForEachBuffer, dropFailedExit, err := getModernEbpfConfig(config)
				require.NoError(t, err)
				require.Equal(t, "modern_ebpf", kind)
				require.Equal(t, float64(4), bufSizePreset)
				require.Equal(t, float64(2), cpusForEachBuffer)
				require.False(t, dropFailedExit)
			},
		},
		{
			"kind=modern-bpf(alias)",
			map[string]string{
				"driver.kind": "modern-bpf",
			},
			func(t *testing.T, config any) {
				require.Len(t, config, 2, "should have only two items")
				kind, bufSizePreset, cpusForEachBuffer, dropFailedExit, err := getModernEbpfConfig(config)
				require.NoError(t, err)
				require.Equal(t, "modern_ebpf", kind)
				require.Equal(t, float64(4), bufSizePreset)
				require.Equal(t, float64(2), cpusForEachBuffer)
				require.False(t, dropFailedExit)
			},
		},
		{
			"modernEbpf=config",
			map[string]string{
				"driver.kind":                         "modern-bpf",
				"driver.modernEbpf.bufSizePreset":     "6",
				"driver.modernEbpf.dropFailedExit":    "true",
				"driver.modernEbpf.cpusForEachBuffer": "8",
			},
			func(t *testing.T, config any) {
				require.Len(t, config, 2, "should have only two items")
				kind, bufSizePreset, cpusForEachBuffer, dropFailedExit, err := getModernEbpfConfig(config)
				require.NoError(t, err)
				require.Equal(t, "modern_ebpf", kind)
				require.Equal(t, float64(6), bufSizePreset)
				require.Equal(t, float64(8), cpusForEachBuffer)
				require.True(t, dropFailedExit)
			},
		},
		{
			"kind=gvisor",
			map[string]string{
				"driver.kind": "gvisor",
			},
			func(t *testing.T, config any) {
				require.Len(t, config, 2, "should have only two items")
				kind, config, root, err := getGvisorConfig(config)
				require.NoError(t, err)
				require.Equal(t, "gvisor", kind)
				require.Equal(t, "/gvisor-config/pod-init.json", config)
				require.Equal(t, "/host/run/containerd/runsc/k8s.io", root)
			},
		},
		{
			"gvisor=config",
			map[string]string{
				"driver.kind":              "gvisor",
				"driver.gvisor.runsc.root": "/my/root/test",
			},
			func(t *testing.T, config any) {
				require.Len(t, config, 2, "should have only two items")
				kind, config, root, err := getGvisorConfig(config)
				require.NoError(t, err)
				require.Equal(t, "gvisor", kind)
				require.Equal(t, "/gvisor-config/pod-init.json", config)
				require.Equal(t, "/host/my/root/test/k8s.io", root)
			},
		},
		{
			"kind=auto",
			map[string]string{
				"driver.kind": "auto",
			},
			func(t *testing.T, config any) {
				require.Len(t, config, 4, "should have four items")
				// Check that configuration for kmod has been set.
				kind, bufSizePreset, dropFailedExit, err := getKmodConfig(config)
				require.NoError(t, err)
				require.Equal(t, "modern_ebpf", kind)
				require.Equal(t, float64(4), bufSizePreset)
				require.False(t, dropFailedExit)
				// Check that configuration for ebpf has been set.
				kind, path, bufSizePreset, dropFailedExit, err := getEbpfConfig(config)
				require.NoError(t, err)
				require.Equal(t, "modern_ebpf", kind)
				require.Equal(t, "${HOME}/.falco/falco-bpf.o", path)
				require.Equal(t, float64(4), bufSizePreset)
				require.False(t, dropFailedExit)
				// Check that configuration for modern_ebpf has been set.
				kind, bufSizePreset, cpusForEachBuffer, dropFailedExit, err := getModernEbpfConfig(config)
				require.NoError(t, err)
				require.Equal(t, "modern_ebpf", kind)
				require.Equal(t, float64(4), bufSizePreset)
				require.Equal(t, float64(2), cpusForEachBuffer)
				require.False(t, dropFailedExit)
			},
		},
	}

	for _, testCase := range testCases {
		testCase := testCase

		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			options := &helm.Options{SetValues: testCase.values}
			output := helm.RenderTemplate(t, options, helmChartPath, releaseName, []string{"templates/configmap.yaml"})

			var cm corev1.ConfigMap
			helm.UnmarshalK8SYaml(t, output, &cm)
			var config map[string]interface{}

			helm.UnmarshalK8SYaml(t, cm.Data["falco.yaml"], &config)
			engine := config["engine"]
			testCase.expected(t, engine)
		})
	}
}

func TestDriverConfigWithUnsupportedDriver(t *testing.T) {
	t.Parallel()

	helmChartPath, err := filepath.Abs(chartPath)
	require.NoError(t, err)

	values := map[string]string{
		"driver.kind": "notExisting",
	}
	options := &helm.Options{SetValues: values}
	_, err = helm.RenderTemplateE(t, options, helmChartPath, releaseName, []string{"templates/configmap.yaml"})
	require.Error(t, err)
	require.True(t, strings.Contains(err.Error(),
		"unsupported driver kind: \"notExisting\". Supported drivers [kmod ebpf modern_ebpf gvisor auto], alias [module modern-bpf]"))
}

func getKmodConfig(config interface{}) (kind string, bufSizePreset float64, dropFailedExit bool, err error) {
	configMap, ok := config.(map[string]interface{})
	if !ok {
		err = fmt.Errorf("can't assert type of config")
		return
	}

	kind = configMap["kind"].(string)
	kmod := configMap["kmod"].(map[string]interface{})
	bufSizePreset = kmod["buf_size_preset"].(float64)
	dropFailedExit = kmod["drop_failed_exit"].(bool)

	return
}

func getEbpfConfig(config interface{}) (kind, path string, bufSizePreset float64, dropFailedExit bool, err error) {
	configMap, ok := config.(map[string]interface{})
	if !ok {
		err = fmt.Errorf("can't assert type of config")
		return
	}

	kind = configMap["kind"].(string)
	ebpf := configMap["ebpf"].(map[string]interface{})
	bufSizePreset = ebpf["buf_size_preset"].(float64)
	dropFailedExit = ebpf["drop_failed_exit"].(bool)
	path = ebpf["probe"].(string)

	return
}

func getModernEbpfConfig(config interface{}) (kind string, bufSizePreset, cpusForEachBuffer float64, dropFailedExit bool, err error) {
	configMap, ok := config.(map[string]interface{})
	if !ok {
		err = fmt.Errorf("can't assert type of config")
		return
	}

	kind = configMap["kind"].(string)
	modernEbpf := configMap["modern_ebpf"].(map[string]interface{})
	bufSizePreset = modernEbpf["buf_size_preset"].(float64)
	dropFailedExit = modernEbpf["drop_failed_exit"].(bool)
	cpusForEachBuffer = modernEbpf["cpus_for_each_buffer"].(float64)

	return
}

func getGvisorConfig(cfg interface{}) (kind, config, root string, err error) {
	configMap, ok := cfg.(map[string]interface{})
	if !ok {
		err = fmt.Errorf("can't assert type of config")
		return
	}

	kind = configMap["kind"].(string)
	gvisor := configMap["gvisor"].(map[string]interface{})
	config = gvisor["config"].(string)
	root = gvisor["root"].(string)

	return
}
