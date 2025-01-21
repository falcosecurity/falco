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

	"gopkg.in/yaml.v3"

	"github.com/gruntwork-io/terratest/modules/helm"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
)

type Config struct {
	ContainerEngines ContainerEngines `yaml:"container_engines"`
}

type ContainerEngines struct {
	Docker     EngineConfig `yaml:"docker"`
	Cri        CriConfig    `yaml:"cri"`
	Podman     EngineConfig `yaml:"podman"`
	Lxc        EngineConfig `yaml:"lxc"`
	LibvirtLxc EngineConfig `yaml:"libvirt_lxc"`
	Bpm        EngineConfig `yaml:"bpm"`
}

type EngineConfig struct {
	Enabled bool `yaml:"enabled"`
}

type CriConfig struct {
	Enabled      bool     `yaml:"enabled"`
	Sockets      []string `yaml:"sockets"`
	DisableAsync bool     `yaml:"disable_async"`
}

func TestContainerEnginesConfig(t *testing.T) {
	t.Parallel()

	helmChartPath, err := filepath.Abs(chartPath)
	require.NoError(t, err)

	testCases := []struct {
		name     string
		values   map[string]string
		expected func(t *testing.T, engines ContainerEngines)
	}{
		{
			"defaultValues",
			nil,
			func(t *testing.T, engines ContainerEngines) {
				require.True(t, engines.Docker.Enabled)
				require.True(t, engines.Cri.Enabled)
				require.False(t, engines.Cri.DisableAsync)
				require.Contains(t, engines.Cri.Sockets, "/run/crio/crio.sock")
				require.Contains(t, engines.Cri.Sockets, "/run/containerd/containerd.sock")
				require.False(t, engines.Podman.Enabled)
				require.False(t, engines.Lxc.Enabled)
				require.False(t, engines.LibvirtLxc.Enabled)
				require.False(t, engines.Bpm.Enabled)
			},
		},
		{
			"collectors disabled",
			map[string]string{
				"collectors.enabled": "false",
			},
			func(t *testing.T, engines ContainerEngines) {
				require.False(t, engines.Docker.Enabled)
				require.False(t, engines.Cri.Enabled)
				require.False(t, engines.Cri.DisableAsync)
				require.Contains(t, engines.Cri.Sockets, "/run/crio/crio.sock")
				require.Contains(t, engines.Cri.Sockets, "/run/containerd/containerd.sock")
				require.False(t, engines.Podman.Enabled)
				require.False(t, engines.Lxc.Enabled)
				require.False(t, engines.LibvirtLxc.Enabled)
				require.False(t, engines.Bpm.Enabled)
			},
		},
		{
			"Disable containerd",
			map[string]string{
				"collectors.containerd.enabled": "false",
			},
			func(t *testing.T, engines ContainerEngines) {
				require.True(t, engines.Docker.Enabled)
				require.True(t, engines.Cri.Enabled)
				require.False(t, engines.Cri.DisableAsync)
				require.Len(t, engines.Cri.Sockets, 1)
				require.Contains(t, engines.Cri.Sockets, "/run/crio/crio.sock")
				require.NotContains(t, engines.Cri.Sockets, "/run/containerd/containerd.sock")
				require.False(t, engines.Podman.Enabled)
				require.False(t, engines.Lxc.Enabled)
				require.False(t, engines.LibvirtLxc.Enabled)
				require.False(t, engines.Bpm.Enabled)
			},
		},
		{
			"Customize containerd socket",
			map[string]string{
				"collectors.containerd.socket": "/var/run/containerd/my.socket",
			},
			func(t *testing.T, engines ContainerEngines) {
				require.True(t, engines.Docker.Enabled)
				require.True(t, engines.Cri.Enabled)
				require.False(t, engines.Cri.DisableAsync)
				require.Len(t, engines.Cri.Sockets, 2)
				require.Contains(t, engines.Cri.Sockets, "/run/crio/crio.sock")
				require.Contains(t, engines.Cri.Sockets, "/var/run/containerd/my.socket")
				require.False(t, engines.Podman.Enabled)
				require.False(t, engines.Lxc.Enabled)
				require.False(t, engines.LibvirtLxc.Enabled)
				require.False(t, engines.Bpm.Enabled)
			},
		},
		{
			"Disable docker",
			map[string]string{
				"collectors.docker.enabled": "false",
			},
			func(t *testing.T, engines ContainerEngines) {
				require.False(t, engines.Docker.Enabled)
				require.True(t, engines.Cri.Enabled)
				require.False(t, engines.Cri.DisableAsync)
				require.Len(t, engines.Cri.Sockets, 2)
				require.Contains(t, engines.Cri.Sockets, "/run/crio/crio.sock")
				require.Contains(t, engines.Cri.Sockets, "/run/containerd/containerd.sock")
				require.False(t, engines.Podman.Enabled)
				require.False(t, engines.Lxc.Enabled)
				require.False(t, engines.LibvirtLxc.Enabled)
				require.False(t, engines.Bpm.Enabled)
			},
		},
		{
			"Disable crio",
			map[string]string{
				"collectors.crio.enabled": "false",
			},
			func(t *testing.T, engines ContainerEngines) {
				require.True(t, engines.Docker.Enabled)
				require.True(t, engines.Cri.Enabled)
				require.False(t, engines.Cri.DisableAsync)
				require.Len(t, engines.Cri.Sockets, 1)
				require.NotContains(t, engines.Cri.Sockets, "/run/crio/crio.sock")
				require.Contains(t, engines.Cri.Sockets, "/run/containerd/containerd.sock")
				require.False(t, engines.Podman.Enabled)
				require.False(t, engines.Lxc.Enabled)
				require.False(t, engines.LibvirtLxc.Enabled)
				require.False(t, engines.Bpm.Enabled)
			},
		},
		{
			"Customize crio socket",
			map[string]string{
				"collectors.crio.socket": "/run/crio/my.socket",
			},
			func(t *testing.T, engines ContainerEngines) {
				require.True(t, engines.Docker.Enabled)
				require.True(t, engines.Cri.Enabled)
				require.False(t, engines.Cri.DisableAsync)
				require.Len(t, engines.Cri.Sockets, 2)
				require.Contains(t, engines.Cri.Sockets, "/run/crio/my.socket")
				require.Contains(t, engines.Cri.Sockets, "/run/containerd/containerd.sock")
				require.False(t, engines.Podman.Enabled)
				require.False(t, engines.Lxc.Enabled)
				require.False(t, engines.LibvirtLxc.Enabled)
				require.False(t, engines.Bpm.Enabled)
			},
		},
		{
			"Disable crio and containerd",
			map[string]string{
				"collectors.crio.enabled":       "false",
				"collectors.containerd.enabled": "false",
			},
			func(t *testing.T, engines ContainerEngines) {
				require.True(t, engines.Docker.Enabled)
				require.False(t, engines.Cri.Enabled)
				require.False(t, engines.Cri.DisableAsync)
				require.Len(t, engines.Cri.Sockets, 0)
				require.NotContains(t, engines.Cri.Sockets, "/run/crio/my.socket")
				require.NotContains(t, engines.Cri.Sockets, "/run/containerd/containerd.sock")
				require.False(t, engines.Podman.Enabled)
				require.False(t, engines.Lxc.Enabled)
				require.False(t, engines.LibvirtLxc.Enabled)
				require.False(t, engines.Bpm.Enabled)
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
			engineConfigString := config["container_engines"]
			engineConfigBytes, err := yaml.Marshal(engineConfigString)

			var containerEngines ContainerEngines
			err = yaml.Unmarshal(engineConfigBytes, &containerEngines)
			require.NoError(t, err)

			testCase.expected(t, containerEngines)
		})
	}
}
