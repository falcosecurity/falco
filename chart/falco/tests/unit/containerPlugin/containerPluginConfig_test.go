package containerPlugin

import (
	"path/filepath"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"

	"gopkg.in/yaml.v3"
	corev1 "k8s.io/api/core/v1"

	"github.com/falcosecurity/charts/charts/falco/tests/unit"
	"github.com/gruntwork-io/terratest/modules/helm"
)

func TestContainerPluginConfiguration(t *testing.T) {
	t.Parallel()
	helmChartPath, err := filepath.Abs(unit.ChartPath)
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
				plugin := config.(map[string]interface{})
				initConfig, ok := plugin["init_config"]
				require.True(t, ok)

				initConfigMap := initConfig.(map[string]interface{})

				// Check engines configurations.
				engines, ok := initConfigMap["engines"].(map[string]interface{})
				require.True(t, ok, "checking if engines section exists")
				require.Len(t, engines, 7, "checking number of engines")
				var engineConfig ContainerEngineConfig
				// Unmarshal the engines configuration.
				data, err := yaml.Marshal(engines)
				require.NoError(t, err)
				err = yaml.Unmarshal(data, &engineConfig)
				require.NoError(t, err)
				// Check the default values for each engine.
				require.True(t, engineConfig.Docker.Enabled)
				require.Equal(t, []string{"/var/run/docker.sock"}, engineConfig.Docker.Sockets)

				require.True(t, engineConfig.Podman.Enabled)
				require.Equal(t, []string{"/run/podman/podman.sock"}, engineConfig.Podman.Sockets)

				require.True(t, engineConfig.Containerd.Enabled)
				require.Equal(t, []string{"/run/host-containerd/containerd.sock"}, engineConfig.Containerd.Sockets)

				require.True(t, engineConfig.CRI.Enabled)
				require.Equal(t, []string{"/run/containerd/containerd.sock", "/run/crio/crio.sock", "/run/k3s/containerd/containerd.sock", "/run/host-containerd/containerd.sock"}, engineConfig.CRI.Sockets)

				require.True(t, engineConfig.LXC.Enabled)
				require.True(t, engineConfig.LibvirtLXC.Enabled)
				require.True(t, engineConfig.BPM.Enabled)
			},
		},
		{
			name: "changeDockerSocket",
			values: map[string]string{
				"collectors.containerEngine.engines.docker.enabled":    "true",
				"collectors.containerEngine.engines.docker.sockets[0]": "/custom/docker.sock",
			},
			expected: func(t *testing.T, config any) {
				plugin := config.(map[string]interface{})
				initConfig, ok := plugin["init_config"]
				require.True(t, ok)

				initConfigMap := initConfig.(map[string]interface{})
				engines, ok := initConfigMap["engines"].(map[string]interface{})
				require.True(t, ok)

				var engineConfig ContainerEngineConfig
				data, err := yaml.Marshal(engines)
				require.NoError(t, err)
				err = yaml.Unmarshal(data, &engineConfig)
				require.NoError(t, err)

				require.True(t, engineConfig.Docker.Enabled)
				require.Equal(t, []string{"/custom/docker.sock"}, engineConfig.Docker.Sockets)
			},
		},
		{
			name: "changeCriSocket",
			values: map[string]string{
				"collectors.containerEngine.engines.cri.enabled":    "true",
				"collectors.containerEngine.engines.cri.sockets[0]": "/custom/cri.sock",
			},
			expected: func(t *testing.T, config any) {
				plugin := config.(map[string]interface{})
				initConfig, ok := plugin["init_config"]
				require.True(t, ok)

				initConfigMap := initConfig.(map[string]interface{})
				engines, ok := initConfigMap["engines"].(map[string]interface{})
				require.True(t, ok)

				var engineConfig ContainerEngineConfig
				data, err := yaml.Marshal(engines)
				require.NoError(t, err)
				err = yaml.Unmarshal(data, &engineConfig)
				require.NoError(t, err)

				require.True(t, engineConfig.CRI.Enabled)
				require.Equal(t, []string{"/custom/cri.sock"}, engineConfig.CRI.Sockets)
			},
		},
		{
			name: "disableDockerSocket",
			values: map[string]string{
				"collectors.containerEngine.engines.docker.enabled": "false",
			},
			expected: func(t *testing.T, config any) {
				plugin := config.(map[string]interface{})
				initConfig, ok := plugin["init_config"]
				require.True(t, ok)

				initConfigMap := initConfig.(map[string]interface{})
				engines, ok := initConfigMap["engines"].(map[string]interface{})
				require.True(t, ok)

				var engineConfig ContainerEngineConfig
				data, err := yaml.Marshal(engines)
				require.NoError(t, err)
				err = yaml.Unmarshal(data, &engineConfig)
				require.NoError(t, err)

				require.False(t, engineConfig.Docker.Enabled)
			},
		},
		{
			name: "disableCriSocket",
			values: map[string]string{
				"collectors.containerEngine.engines.cri.enabled": "false",
			},
			expected: func(t *testing.T, config any) {
				plugin := config.(map[string]interface{})
				initConfig, ok := plugin["init_config"]
				require.True(t, ok)

				initConfigMap := initConfig.(map[string]interface{})
				engines, ok := initConfigMap["engines"].(map[string]interface{})
				require.True(t, ok)

				var engineConfig ContainerEngineConfig
				data, err := yaml.Marshal(engines)
				require.NoError(t, err)
				err = yaml.Unmarshal(data, &engineConfig)
				require.NoError(t, err)

				require.False(t, engineConfig.CRI.Enabled)
			},
		},
		{
			name: "changeContainerdSocket",
			values: map[string]string{
				"collectors.containerEngine.engines.containerd.enabled":    "true",
				"collectors.containerEngine.engines.containerd.sockets[0]": "/custom/containerd.sock",
			},
			expected: func(t *testing.T, config any) {
				plugin := config.(map[string]interface{})
				initConfig, ok := plugin["init_config"]
				require.True(t, ok)

				initConfigMap := initConfig.(map[string]interface{})
				engines, ok := initConfigMap["engines"].(map[string]interface{})
				require.True(t, ok)

				var engineConfig ContainerEngineConfig
				data, err := yaml.Marshal(engines)
				require.NoError(t, err)
				err = yaml.Unmarshal(data, &engineConfig)
				require.NoError(t, err)

				require.True(t, engineConfig.Containerd.Enabled)
				require.Equal(t, []string{"/custom/containerd.sock"}, engineConfig.Containerd.Sockets)
			},
		},
		{
			name: "disableContainerdSocket",
			values: map[string]string{
				"collectors.containerEngine.engines.containerd.enabled": "false",
			},
			expected: func(t *testing.T, config any) {
				plugin := config.(map[string]interface{})
				initConfig, ok := plugin["init_config"]
				require.True(t, ok)

				initConfigMap := initConfig.(map[string]interface{})
				engines, ok := initConfigMap["engines"].(map[string]interface{})
				require.True(t, ok)

				var engineConfig ContainerEngineConfig
				data, err := yaml.Marshal(engines)
				require.NoError(t, err)
				err = yaml.Unmarshal(data, &engineConfig)
				require.NoError(t, err)

				require.False(t, engineConfig.Containerd.Enabled)
			},
		},
		{
			name:   "defaultContainerEngineConfig",
			values: map[string]string{},
			expected: func(t *testing.T, config any) {
				plugin := config.(map[string]interface{})
				initConfig, ok := plugin["init_config"]
				require.True(t, ok)

				initConfigMap := initConfig.(map[string]interface{})
				require.Equal(t, float64(100), initConfigMap["label_max_len"])
				require.False(t, initConfigMap["with_size"].(bool))

				hooks := initConfigMap["hooks"].([]interface{})
				require.Len(t, hooks, 1)
				require.Contains(t, hooks, "create")

				engines := initConfigMap["engines"].(map[string]interface{})
				var engineConfig ContainerEngineConfig
				data, err := yaml.Marshal(engines)
				require.NoError(t, err)
				err = yaml.Unmarshal(data, &engineConfig)
				require.NoError(t, err)

				// Check default engine configurations
				require.True(t, engineConfig.Docker.Enabled)
				require.Equal(t, []string{"/var/run/docker.sock"}, engineConfig.Docker.Sockets)

				require.True(t, engineConfig.Podman.Enabled)
				require.Equal(t, []string{"/run/podman/podman.sock"}, engineConfig.Podman.Sockets)

				require.True(t, engineConfig.Containerd.Enabled)
				require.Equal(t, []string{"/run/host-containerd/containerd.sock"}, engineConfig.Containerd.Sockets)

				require.True(t, engineConfig.CRI.Enabled)
				require.Equal(t, []string{"/run/containerd/containerd.sock", "/run/crio/crio.sock", "/run/k3s/containerd/containerd.sock", "/run/host-containerd/containerd.sock"}, engineConfig.CRI.Sockets)

				require.True(t, engineConfig.LXC.Enabled)
				require.True(t, engineConfig.LibvirtLXC.Enabled)
				require.True(t, engineConfig.BPM.Enabled)
			},
		},
		{
			name: "customContainerEngineConfig",
			values: map[string]string{
				"collectors.docker.enabled":                                "false",
				"collectors.containerd.enabled":                            "false",
				"collectors.crio.enabled":                                  "false",
				"collectors.containerEngine.enabled":                       "true",
				"collectors.containerEngine.labelMaxLen":                   "200",
				"collectors.containerEngine.withSize":                      "true",
				"collectors.containerEngine.hooks[0]":                      "create",
				"collectors.containerEngine.hooks[1]":                      "start",
				"collectors.containerEngine.engines.docker.enabled":        "false",
				"collectors.containerEngine.engines.podman.enabled":        "false",
				"collectors.containerEngine.engines.containerd.sockets[0]": "/custom/containerd.sock",
				"collectors.containerEngine.engines.cri.sockets[0]":        "/custom/crio.sock",
				"collectors.containerEngine.engines.lxc.enabled":           "false",
				"collectors.containerEngine.engines.libvirt_lxc.enabled":   "false",
				"collectors.containerEngine.engines.bpm.enabled":           "false",
			},
			expected: func(t *testing.T, config any) {
				plugin := config.(map[string]interface{})
				initConfig, ok := plugin["init_config"]
				require.True(t, ok)

				initConfigMap := initConfig.(map[string]interface{})
				require.Equal(t, float64(200), initConfigMap["label_max_len"])
				require.True(t, initConfigMap["with_size"].(bool))

				hooks := initConfigMap["hooks"].([]interface{})
				require.Len(t, hooks, 2)
				require.Contains(t, hooks, "create")
				require.Contains(t, hooks, "start")

				engines := initConfigMap["engines"].(map[string]interface{})
				var engineConfig ContainerEngineConfig
				data, err := yaml.Marshal(engines)
				require.NoError(t, err)
				err = yaml.Unmarshal(data, &engineConfig)
				require.NoError(t, err)

				// Check custom engine configurations
				require.False(t, engineConfig.Docker.Enabled)
				require.False(t, engineConfig.Podman.Enabled)

				require.True(t, engineConfig.Containerd.Enabled)
				require.Equal(t, []string{"/custom/containerd.sock"}, engineConfig.Containerd.Sockets)

				require.True(t, engineConfig.CRI.Enabled)
				require.Equal(t, []string{"/custom/crio.sock"}, engineConfig.CRI.Sockets)

				require.False(t, engineConfig.LXC.Enabled)
				require.False(t, engineConfig.LibvirtLXC.Enabled)
				require.False(t, engineConfig.BPM.Enabled)
			},
		},
		{
			name: "customDockerEngineConfigInContainerEngine",
			values: map[string]string{
				"collectors.docker.enabled":                            "false",
				"collectors.containerd.enabled":                        "false",
				"collectors.crio.enabled":                              "false",
				"collectors.containerEngine.enabled":                   "true",
				"collectors.containerEngine.engines.docker.enabled":    "false",
				"collectors.containerEngine.engines.docker.sockets[0]": "/custom/docker.sock",
				"collectors.containerEngine.engines.docker.sockets[1]": "/custom/docker.sock2",
			},
			expected: func(t *testing.T, config any) {
				plugin := config.(map[string]interface{})
				initConfig, ok := plugin["init_config"]
				require.True(t, ok)

				initConfigMap := initConfig.(map[string]interface{})
				engines, ok := initConfigMap["engines"].(map[string]interface{})
				require.True(t, ok)

				var engineConfig ContainerEngineConfig
				data, err := yaml.Marshal(engines)
				require.NoError(t, err)
				err = yaml.Unmarshal(data, &engineConfig)
				require.NoError(t, err)

				// Check Docker engine configuration
				require.False(t, engineConfig.Docker.Enabled)
				require.Equal(t, []string{"/custom/docker.sock", "/custom/docker.sock2"}, engineConfig.Docker.Sockets)
			},
		},
		{
			name: "customContainerdEngineConfigInContainerEngine",
			values: map[string]string{
				"collectors.docker.enabled":                                "false",
				"collectors.containerd.enabled":                            "false",
				"collectors.crio.enabled":                                  "false",
				"collectors.containerEngine.enabled":                       "true",
				"collectors.containerEngine.engines.containerd.enabled":    "false",
				"collectors.containerEngine.engines.containerd.sockets[0]": "/custom/containerd.sock",
				"collectors.containerEngine.engines.containerd.sockets[1]": "/custom/containerd.sock2",
			},
			expected: func(t *testing.T, config any) {
				plugin := config.(map[string]interface{})
				initConfig, ok := plugin["init_config"]
				require.True(t, ok)

				initConfigMap := initConfig.(map[string]interface{})
				engines, ok := initConfigMap["engines"].(map[string]interface{})
				require.True(t, ok)

				var engineConfig ContainerEngineConfig
				data, err := yaml.Marshal(engines)
				require.NoError(t, err)
				err = yaml.Unmarshal(data, &engineConfig)
				require.NoError(t, err)

				// Check Containerd engine configuration
				require.False(t, engineConfig.Containerd.Enabled)
				require.Equal(t, []string{"/custom/containerd.sock", "/custom/containerd.sock2"}, engineConfig.Containerd.Sockets)
			},
		},
		{
			name: "customPodmanEngineConfigInContainerEngine",
			values: map[string]string{
				"collectors.docker.enabled":                            "false",
				"collectors.containerd.enabled":                        "false",
				"collectors.crio.enabled":                              "false",
				"collectors.containerEngine.enabled":                   "true",
				"collectors.containerEngine.engines.podman.enabled":    "true",
				"collectors.containerEngine.engines.podman.sockets[0]": "/custom/podman.sock",
				"collectors.containerEngine.engines.podman.sockets[1]": "/custom/podman.sock2",
			},
			expected: func(t *testing.T, config any) {
				plugin := config.(map[string]interface{})
				initConfig, ok := plugin["init_config"]
				require.True(t, ok)

				initConfigMap := initConfig.(map[string]interface{})
				engines, ok := initConfigMap["engines"].(map[string]interface{})
				require.True(t, ok)

				var engineConfig ContainerEngineConfig
				data, err := yaml.Marshal(engines)
				require.NoError(t, err)
				err = yaml.Unmarshal(data, &engineConfig)
				require.NoError(t, err)

				// Check Podman engine configuration
				require.True(t, engineConfig.Podman.Enabled)
				require.Equal(t, []string{"/custom/podman.sock", "/custom/podman.sock2"}, engineConfig.Podman.Sockets)
			},
		},
		{
			name: "customCRIEngineConfigInContainerEngine",
			values: map[string]string{
				"collectors.docker.enabled":                         "false",
				"collectors.containerd.enabled":                     "false",
				"collectors.crio.enabled":                           "false",
				"collectors.containerEngine.enabled":                "true",
				"collectors.containerEngine.engines.cri.enabled":    "true",
				"collectors.containerEngine.engines.cri.sockets[0]": "/custom/cri.sock",
				"collectors.containerEngine.engines.cri.sockets[1]": "/custom/cri.sock2",
			},
			expected: func(t *testing.T, config any) {
				plugin := config.(map[string]interface{})
				initConfig, ok := plugin["init_config"]
				require.True(t, ok)

				initConfigMap := initConfig.(map[string]interface{})
				engines, ok := initConfigMap["engines"].(map[string]interface{})
				require.True(t, ok)

				var engineConfig ContainerEngineConfig
				data, err := yaml.Marshal(engines)
				require.NoError(t, err)
				err = yaml.Unmarshal(data, &engineConfig)
				require.NoError(t, err)

				// Check CRI engine configuration
				require.True(t, engineConfig.CRI.Enabled)
				require.Equal(t, []string{"/custom/cri.sock", "/custom/cri.sock2"}, engineConfig.CRI.Sockets)
			},
		},
		{
			name: "customLXCEngineConfigInContainerEngine",
			values: map[string]string{
				"collectors.docker.enabled":                      "false",
				"collectors.containerd.enabled":                  "false",
				"collectors.crio.enabled":                        "false",
				"collectors.containerEngine.enabled":             "true",
				"collectors.containerEngine.engines.lxc.enabled": "true",
			},
			expected: func(t *testing.T, config any) {
				plugin := config.(map[string]interface{})
				initConfig, ok := plugin["init_config"]
				require.True(t, ok)

				initConfigMap := initConfig.(map[string]interface{})
				engines, ok := initConfigMap["engines"].(map[string]interface{})
				require.True(t, ok)

				var engineConfig ContainerEngineConfig
				data, err := yaml.Marshal(engines)
				require.NoError(t, err)
				err = yaml.Unmarshal(data, &engineConfig)
				require.NoError(t, err)

				// Check LXC engine configuration
				require.True(t, engineConfig.LXC.Enabled)
			},
		},
		{
			name: "customLibvirtLXCEngineConfigInContainerEngine",
			values: map[string]string{
				"collectors.docker.enabled":                              "false",
				"collectors.containerd.enabled":                          "false",
				"collectors.crio.enabled":                                "false",
				"collectors.containerEngine.enabled":                     "true",
				"collectors.containerEngine.engines.libvirt_lxc.enabled": "true",
			},
			expected: func(t *testing.T, config any) {
				plugin := config.(map[string]interface{})
				initConfig, ok := plugin["init_config"]
				require.True(t, ok)

				initConfigMap := initConfig.(map[string]interface{})
				engines, ok := initConfigMap["engines"].(map[string]interface{})
				require.True(t, ok)

				var engineConfig ContainerEngineConfig
				data, err := yaml.Marshal(engines)
				require.NoError(t, err)
				err = yaml.Unmarshal(data, &engineConfig)
				require.NoError(t, err)

				// Check LibvirtLXC engine configuration
				require.True(t, engineConfig.LibvirtLXC.Enabled)
			},
		},
		{
			name: "customBPMEngineConfigInContainerEngine",
			values: map[string]string{
				"collectors.docker.enabled":                      "false",
				"collectors.containerd.enabled":                  "false",
				"collectors.crio.enabled":                        "false",
				"collectors.containerEngine.enabled":             "true",
				"collectors.containerEngine.engines.bpm.enabled": "true",
			},
			expected: func(t *testing.T, config any) {
				plugin := config.(map[string]interface{})
				initConfig, ok := plugin["init_config"]
				require.True(t, ok)

				initConfigMap := initConfig.(map[string]interface{})
				engines, ok := initConfigMap["engines"].(map[string]interface{})
				require.True(t, ok)

				var engineConfig ContainerEngineConfig
				data, err := yaml.Marshal(engines)
				require.NoError(t, err)
				err = yaml.Unmarshal(data, &engineConfig)
				require.NoError(t, err)

				// Check BPM engine configuration
				require.True(t, engineConfig.BPM.Enabled)
			},
		},
		{
			name: "allCollectorsDisabled",
			values: map[string]string{
				"collectors.docker.enabled":          "false",
				"collectors.containerd.enabled":      "false",
				"collectors.crio.enabled":            "false",
				"collectors.containerEngine.enabled": "false",
			},
			expected: func(t *testing.T, config any) {
				// When config is nil, it means the plugin wasn't found in the configuration
				require.Nil(t, config, "container plugin should not be present in configuration when all collectors are disabled")

				// If somehow the config exists (which it shouldn't), verify there are no engine configurations
				if config != nil {
					plugin := config.(map[string]interface{})
					initConfig, ok := plugin["init_config"]
					if ok {
						initConfigMap := initConfig.(map[string]interface{})
						engines, ok := initConfigMap["engines"]
						if ok {
							engineMap := engines.(map[string]interface{})
							require.Empty(t, engineMap, "engines configuration should be empty when all collectors are disabled")
						}
					}
				}
			},
		},
		{
			name: "allCollectorsDisabledTopLevel",
			values: map[string]string{
				"collectors.enabled": "false",
			},
			expected: func(t *testing.T, config any) {
				// When config is nil, it means the plugin wasn't found in the configuration
				require.Nil(t, config, "container plugin should not be present in configuration when all collectors are disabled")

				// If somehow the config exists (which it shouldn't), verify there are no engine configurations
				if config != nil {
					plugin := config.(map[string]interface{})
					initConfig, ok := plugin["init_config"]
					if ok {
						initConfigMap := initConfig.(map[string]interface{})
						engines, ok := initConfigMap["engines"]
						if ok {
							engineMap := engines.(map[string]interface{})
							require.Empty(t, engineMap, "engines configuration should be empty when all collectors are disabled")
						}
					}
				}
			},
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			options := &helm.Options{SetValues: testCase.values}
			// Render the chart with the given options.
			output := helm.RenderTemplate(t, options, helmChartPath, unit.ReleaseName, []string{"templates/configmap.yaml"})

			var cm corev1.ConfigMap
			// Unmarshal the output into a ConfigMap object.
			helm.UnmarshalK8SYaml(t, output, &cm)

			// Unmarshal the data field of the ConfigMap into a map.
			var config map[string]interface{}
			helm.UnmarshalK8SYaml(t, cm.Data["falco.yaml"], &config)

			// Extract the container plugin configuration.
			plugins, ok := config["plugins"]
			require.True(t, ok, "checking if plugins section exists")
			pluginsList := plugins.([]interface{})
			found := false

			// Get the container plugin configuration.
			for _, plugin := range pluginsList {
				if name, ok := plugin.(map[string]interface{})["name"]; ok && name == unit.ContainerPluginName {
					testCase.expected(t, plugin)
					found = true
				}
			}

			if found {
				// Check that the plugin has been added to the ones that are enabled.
				loadPlugins := config["load_plugins"]
				require.True(t, slices.Contains(loadPlugins.([]interface{}), unit.ContainerPluginName))
			} else {
				testCase.expected(t, nil)
				loadPlugins := config["load_plugins"]
				require.False(t, slices.Contains(loadPlugins.([]interface{}), unit.ContainerPluginName))
			}
		})
	}
}

func TestInvalidCollectorConfiguration(t *testing.T) {
	t.Parallel()

	helmChartPath, err := filepath.Abs(unit.ChartPath)
	require.NoError(t, err)

	testCases := []struct {
		name        string
		values      map[string]string
		expectedErr string
	}{
		{
			name: "dockerAndContainerEngine",
			values: map[string]string{
				"collectors.docker.enabled":          "true",
				"collectoars.containerd.enabled":     "false",
				"collectors.crio.enabled":            "false",
				"collectors.containerEngine.enabled": "true",
			},
			expectedErr: "You can not enable any of the [docker, containerd, crio] collectors configuration and the containerEngine configuration at the same time. Please use the containerEngine configuration since the old configurations are deprecated.",
		},
		{
			name: "containerdAndContainerEngine",
			values: map[string]string{
				"collectors.docker.enabled":          "false",
				"collectors.containerd.enabled":      "true",
				"collectors.crio.enabled":            "false",
				"collectors.containerEngine.enabled": "true",
			},
			expectedErr: "You can not enable any of the [docker, containerd, crio] collectors configuration and the containerEngine configuration at the same time. Please use the containerEngine configuration since the old configurations are deprecated.",
		},
		{
			name: "crioAndContainerEngine",
			values: map[string]string{
				"collectors.docker.enabled":          "false",
				"collectoars.containerd.enabled":     "false",
				"collectors.crio.enabled":            "true",
				"collectors.containerEngine.enabled": "true",
			},
			expectedErr: "You can not enable any of the [docker, containerd, crio] collectors configuration and the containerEngine configuration at the same time. Please use the containerEngine configuration since the old configurations are deprecated.",
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			options := &helm.Options{
				SetValues: tc.values,
			}

			// Attempt to render the template, expect an error
			_, err := helm.RenderTemplateE(t, options, helmChartPath, unit.ReleaseName, []string{"templates/configmap.yaml"})
			require.Error(t, err)
			require.Contains(t, err.Error(), tc.expectedErr)
		})
	}
}

// Test that the helper does not overwrite user's configuration.
// And that the container reference is added to the configmap.
func TestFalcoctlRefs(t *testing.T) {
	t.Parallel()

	refShouldBeSet := func(t *testing.T, config any) {
		// Get artifact configuration map.
		configMap := config.(map[string]interface{})
		artifactConfig := (configMap["artifact"]).(map[string]interface{})
		// Test allowed types.
		allowedTypes := artifactConfig["allowedTypes"]
		require.Len(t, allowedTypes, 2)
		require.True(t, slices.Contains(allowedTypes.([]interface{}), "plugin"))
		require.True(t, slices.Contains(allowedTypes.([]interface{}), "rulesfile"))
		// Test plugin reference.
		refs := artifactConfig["install"].(map[string]interface{})["refs"].([]interface{})
		require.Len(t, refs, 2)
		require.True(t, slices.Contains(refs, "falco-rules:4"))
		require.True(t, slices.Contains(refs, "ghcr.io/falcosecurity/plugins/plugin/container:0.3.3"))
	}

	refShouldNotBeSet := func(t *testing.T, config any) {
		// Get artifact configuration map.
		configMap := config.(map[string]interface{})
		artifactConfig := (configMap["artifact"]).(map[string]interface{})
		// Test allowed types.
		allowedTypes := artifactConfig["allowedTypes"]
		require.Len(t, allowedTypes, 2)
		require.True(t, slices.Contains(allowedTypes.([]interface{}), "plugin"))
		require.True(t, slices.Contains(allowedTypes.([]interface{}), "rulesfile"))
		// Test plugin reference.
		refs := artifactConfig["install"].(map[string]interface{})["refs"].([]interface{})
		require.Len(t, refs, 1)
		require.True(t, slices.Contains(refs, "falco-rules:4"))
		require.False(t, slices.Contains(refs, "ghcr.io/falcosecurity/plugins/plugin/container:0.3.3"))
	}

	testCases := []struct {
		name     string
		values   map[string]string
		expected func(t *testing.T, config any)
	}{
		{
			"defaultValues",
			nil,
			refShouldBeSet,
		},
		{
			"setPluginConfiguration",
			map[string]string{
				"collectors.enabled": "false",
			},
			refShouldNotBeSet,
		},
		{
			"driver disabled",
			map[string]string{
				"driver.enabled": "false",
			},
			refShouldNotBeSet,
		},
	}

	helmChartPath, err := filepath.Abs(unit.ChartPath)
	require.NoError(t, err)

	for _, testCase := range testCases {
		testCase := testCase

		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			options := &helm.Options{SetValues: testCase.values}
			output := helm.RenderTemplate(t, options, helmChartPath, unit.ReleaseName, []string{"templates/falcoctl-configmap.yaml"})

			var cm corev1.ConfigMap
			helm.UnmarshalK8SYaml(t, output, &cm)
			var config map[string]interface{}
			helm.UnmarshalK8SYaml(t, cm.Data["falcoctl.yaml"], &config)
			testCase.expected(t, config)
		})
	}
}

type ContainerEngineSocket struct {
	Enabled bool     `yaml:"enabled"`
	Sockets []string `yaml:"sockets,omitempty"`
}

type ContainerEngineConfig struct {
	Docker     ContainerEngineSocket `yaml:"docker"`
	Podman     ContainerEngineSocket `yaml:"podman"`
	Containerd ContainerEngineSocket `yaml:"containerd"`
	CRI        ContainerEngineSocket `yaml:"cri"`
	LXC        ContainerEngineSocket `yaml:"lxc"`
	LibvirtLXC ContainerEngineSocket `yaml:"libvirt_lxc"`
	BPM        ContainerEngineSocket `yaml:"bpm"`
}
