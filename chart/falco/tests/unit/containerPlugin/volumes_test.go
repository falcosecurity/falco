package containerPlugin

import (
	"path/filepath"
	"slices"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"

	"github.com/falcosecurity/charts/charts/falco/tests/unit"
	"github.com/gruntwork-io/terratest/modules/helm"
	"github.com/stretchr/testify/require"
)

func TestContainerPluginVolumes(t *testing.T) {
	t.Parallel()
	helmChartPath, err := filepath.Abs(unit.ChartPath)
	require.NoError(t, err)

	testCases := []struct {
		name     string
		values   map[string]string
		expected func(t *testing.T, volumes []corev1.Volume)
	}{
		{
			name:   "defaultValues",
			values: nil,
			expected: func(t *testing.T, volumes []corev1.Volume) {
				require.Len(t, volumes, 3)
				require.Equal(t, "docker-socket", volumes[0].Name)
				require.Equal(t, "/var/run/docker.sock", volumes[0].HostPath.Path)
				require.Equal(t, "crio-socket", volumes[1].Name)
				require.Equal(t, "/run/crio/crio.sock", volumes[1].HostPath.Path)
				require.Equal(t, "containerd-socket", volumes[2].Name)
				require.Equal(t, "/run/containerd/containerd.sock", volumes[2].HostPath.Path)
			},
		},
		{
			name: "defaultDockerVolume",
			values: map[string]string{
				"collectors.docker.enabled":     "true",
				"collectors.containerd.enabled": "false",
				"collectors.crio.enabled":       "false",
			},
			expected: func(t *testing.T, volumes []corev1.Volume) {
				require.Len(t, volumes, 1)
				require.Equal(t, "docker-socket", volumes[0].Name)
				require.Equal(t, "/var/run/docker.sock", volumes[0].HostPath.Path)
			},
		},
		{
			name: "customDockerSocket",
			values: map[string]string{
				"collectors.docker.enabled":     "true",
				"collectors.docker.socket":      "/custom/docker.sock",
				"collectors.containerd.enabled": "false",
				"collectors.crio.enabled":       "false",
			},
			expected: func(t *testing.T, volumes []corev1.Volume) {
				require.Len(t, volumes, 1)
				require.Equal(t, "docker-socket", volumes[0].Name)
				require.Equal(t, "/custom/docker.sock", volumes[0].HostPath.Path)
			},
		},
		{
			name: "defaultCrioVolume",
			values: map[string]string{
				"collectors.docker.enabled":     "false",
				"collectors.containerd.enabled": "false",
				"collectors.crio.enabled":       "true",
			},
			expected: func(t *testing.T, volumes []corev1.Volume) {
				require.Len(t, volumes, 1)
				require.Equal(t, "crio-socket", volumes[0].Name)
				require.Equal(t, "/run/crio/crio.sock", volumes[0].HostPath.Path)
			},
		},
		{
			name: "customCrioSocket",
			values: map[string]string{
				"collectors.docker.enabled":     "false",
				"collectors.containerd.enabled": "false",
				"collectors.crio.enabled":       "true",
				"collectors.crio.socket":        "/custom/crio.sock",
			},
			expected: func(t *testing.T, volumes []corev1.Volume) {
				require.Len(t, volumes, 1)
				require.Equal(t, "crio-socket", volumes[0].Name)
				require.Equal(t, "/custom/crio.sock", volumes[0].HostPath.Path)
			},
		},
		{
			name: "defaultContainerdVolume",
			values: map[string]string{
				"collectors.docker.enabled":     "false",
				"collectors.containerd.enabled": "true",
				"collectors.crio.enabled":       "false",
			},
			expected: func(t *testing.T, volumes []corev1.Volume) {
				require.Len(t, volumes, 1)
				require.Equal(t, "containerd-socket", volumes[0].Name)
				require.Equal(t, "/run/containerd/containerd.sock", volumes[0].HostPath.Path)
			},
		},
		{
			name: "customContainerdSocket",
			values: map[string]string{
				"collectors.docker.enabled":     "false",
				"collectors.containerd.enabled": "true",
				"collectors.containerd.socket":  "/custom/containerd.sock",
				"collectors.crio.enabled":       "false",
			},
			expected: func(t *testing.T, volumes []corev1.Volume) {
				require.Len(t, volumes, 1)
				require.Equal(t, "containerd-socket", volumes[0].Name)
				require.Equal(t, "/custom/containerd.sock", volumes[0].HostPath.Path)
			},
		},

		{
			name: "ContainerEnginesDefaultValues",
			values: map[string]string{
				"collectors.docker.enabled":          "false",
				"collectors.containerd.enabled":      "false",
				"collectors.crio.enabled":            "false",
				"collectors.containerEngine.enabled": "true",
			},
			expected: func(t *testing.T, volumes []corev1.Volume) {
				require.Len(t, volumes, 4)

				dockerV := findVolume("docker-socket-0", volumes)
				require.NotNil(t, dockerV)
				require.Equal(t, "/var/run/docker.sock", dockerV.HostPath.Path)
				podmanV := findVolume("podman-socket-0", volumes)
				require.NotNil(t, podmanV)
				require.Equal(t, "/run/podman/podman.sock", podmanV.HostPath.Path)
				containerdV := findVolume("containerd-socket-0", volumes)
				require.NotNil(t, containerdV)
				require.Equal(t, "/run/containerd/containerd.sock", containerdV.HostPath.Path)
				crioV := findVolume("cri-socket-0", volumes)
				require.NotNil(t, crioV)
				require.Equal(t, "/run/crio/crio.sock", crioV.HostPath.Path)
			},
		},
		{
			name: "ContainerEnginesDockerWithMultipleSockets",
			values: map[string]string{
				"collectors.docker.enabled":                             "false",
				"collectors.containerd.enabled":                         "false",
				"collectors.crio.enabled":                               "false",
				"collectors.containerEngine.enabled":                    "true",
				"collectors.containerEngine.engines.docker.enabled":     "true",
				"collectors.containerEngine.engines.docker.sockets[0]":  "/var/run/docker.sock",
				"collectors.containerEngine.engines.docker.sockets[1]":  "/custom/docker.sock",
				"collectors.containerEngine.engines.containerd.enabled": "false",
				"collectors.containerEngine.engines.cri.enabled":        "false",
				"collectors.containerEngine.engines.podman.enabled":     "false",
			},
			expected: func(t *testing.T, volumes []corev1.Volume) {
				require.Len(t, volumes, 2)

				dockerV0 := findVolume("docker-socket-0", volumes)
				require.NotNil(t, dockerV0)
				require.Equal(t, "/var/run/docker.sock", dockerV0.HostPath.Path)

				dockerV1 := findVolume("docker-socket-1", volumes)
				require.NotNil(t, dockerV1)
				require.Equal(t, "/custom/docker.sock", dockerV1.HostPath.Path)
			},
		},
		{
			name: "ContainerEnginesCrioWithMultipleSockets",
			values: map[string]string{
				"collectors.docker.enabled":                             "false",
				"collectors.containerd.enabled":                         "false",
				"collectors.crio.enabled":                               "false",
				"collectors.containerEngine.enabled":                    "true",
				"collectors.containerEngine.engines.docker.enabled":     "false",
				"collectors.containerEngine.engines.containerd.enabled": "false",
				"collectors.containerEngine.engines.cri.enabled":        "true",
				"collectors.containerEngine.engines.cri.sockets[0]":     "/run/crio/crio.sock",
				"collectors.containerEngine.engines.cri.sockets[1]":     "/custom/crio.sock",
				"collectors.containerEngine.engines.podman.enabled":     "false",
			},
			expected: func(t *testing.T, volumes []corev1.Volume) {
				require.Len(t, volumes, 2)

				crioV0 := findVolume("cri-socket-0", volumes)
				require.NotNil(t, crioV0)
				require.Equal(t, "/run/crio/crio.sock", crioV0.HostPath.Path)

				crioV1 := findVolume("cri-socket-1", volumes)
				require.NotNil(t, crioV1)
				require.Equal(t, "/custom/crio.sock", crioV1.HostPath.Path)
			},
		},
		{
			name: "ContainerEnginesPodmanWithMultipleSockets",
			values: map[string]string{
				"collectors.docker.enabled":                             "false",
				"collectors.containerd.enabled":                         "false",
				"collectors.crio.enabled":                               "false",
				"collectors.containerEngine.enabled":                    "true",
				"collectors.containerEngine.engines.docker.enabled":     "false",
				"collectors.containerEngine.engines.containerd.enabled": "false",
				"collectors.containerEngine.engines.cri.enabled":        "false",
				"collectors.containerEngine.engines.podman.enabled":     "true",
				"collectors.containerEngine.engines.podman.sockets[0]":  "/run/podman/podman.sock",
				"collectors.containerEngine.engines.podman.sockets[1]":  "/custom/podman.sock",
			},
			expected: func(t *testing.T, volumes []corev1.Volume) {
				require.Len(t, volumes, 2)

				podmanV0 := findVolume("podman-socket-0", volumes)
				require.NotNil(t, podmanV0)
				require.Equal(t, "/run/podman/podman.sock", podmanV0.HostPath.Path)

				podmanV1 := findVolume("podman-socket-1", volumes)
				require.NotNil(t, podmanV1)
				require.Equal(t, "/custom/podman.sock", podmanV1.HostPath.Path)
			},
		},
		{
			name: "ContainerEnginesContainerdWithMultipleSockets",
			values: map[string]string{
				"collectors.docker.enabled":                                "false",
				"collectors.containerd.enabled":                            "false",
				"collectors.crio.enabled":                                  "false",
				"collectors.containerEngine.enabled":                       "true",
				"collectors.containerEngine.engines.docker.enabled":        "false",
				"collectors.containerEngine.engines.containerd.enabled":    "true",
				"collectors.containerEngine.engines.containerd.sockets[0]": "/run/containerd/containerd.sock",
				"collectors.containerEngine.engines.containerd.sockets[1]": "/custom/containerd.sock",
				"collectors.containerEngine.engines.cri.enabled":           "false",
				"collectors.containerEngine.engines.podman.enabled":        "false",
			},
			expected: func(t *testing.T, volumes []corev1.Volume) {
				require.Len(t, volumes, 2)

				containerdV0 := findVolume("containerd-socket-0", volumes)
				require.NotNil(t, containerdV0)
				require.Equal(t, "/run/containerd/containerd.sock", containerdV0.HostPath.Path)

				containerdV1 := findVolume("containerd-socket-1", volumes)
				require.NotNil(t, containerdV1)
				require.Equal(t, "/custom/containerd.sock", containerdV1.HostPath.Path)
			},
		},
		{
			name: "ContainerEnginesMultipleWithCustomSockets",
			values: map[string]string{
				"collectors.docker.enabled":                             "false",
				"collectors.containerd.enabled":                         "false",
				"collectors.crio.enabled":                               "false",
				"collectors.containerEngine.enabled":                    "true",
				"collectors.containerEngine.engines.docker.enabled":     "true",
				"collectors.containerEngine.engines.docker.sockets[0]":  "/custom/docker/socket.sock",
				"collectors.containerEngine.engines.containerd.enabled": "true",
				"collectors.containerEngine.engines.cri.enabled":        "true",
				"collectors.containerEngine.engines.cri.sockets[0]":     "/var/custom/crio.sock",
				"collectors.containerEngine.engines.podman.enabled":     "true",
				"collectors.containerEngine.engines.podman.sockets[0]":  "/run/podman/podman.sock",
			},
			expected: func(t *testing.T, volumes []corev1.Volume) {
				require.Len(t, volumes, 4)

				dockerV0 := findVolume("docker-socket-0", volumes)
				require.NotNil(t, dockerV0)
				require.Equal(t, "/custom/docker/socket.sock", dockerV0.HostPath.Path)

				containerdV0 := findVolume("containerd-socket-0", volumes)
				require.NotNil(t, containerdV0)
				require.Equal(t, "/run/containerd/containerd.sock", containerdV0.HostPath.Path)

				crioV0 := findVolume("cri-socket-0", volumes)
				require.NotNil(t, crioV0)
				require.Equal(t, "/var/custom/crio.sock", crioV0.HostPath.Path)

				podmanV0 := findVolume("podman-socket-0", volumes)
				require.NotNil(t, podmanV0)
				require.Equal(t, "/run/podman/podman.sock", podmanV0.HostPath.Path)
			},
		},
		{
			name: "noVolumesWhenCollectorsDisabled",
			values: map[string]string{
				"collectors.enabled": "false",
			},
			expected: func(t *testing.T, volumes []corev1.Volume) {
				require.Len(t, volumes, 0)
			},
		},
		{
			name: "noVolumesWhenDriverDisabled",
			values: map[string]string{
				"driver.enabled": "false",
			},
			expected: func(t *testing.T, volumes []corev1.Volume) {
				require.Len(t, volumes, 0)
			},
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			options := &helm.Options{
				SetValues: tc.values,
			}

			// Render the template
			output := helm.RenderTemplate(t, options, helmChartPath, unit.ReleaseName, []string{"templates/daemonset.yaml"})

			// Parse the YAML output
			var daemonset appsv1.DaemonSet
			helm.UnmarshalK8SYaml(t, output, &daemonset)

			// Find volumes that match our container plugin pattern
			var pluginVolumes []corev1.Volume
			for _, volume := range daemonset.Spec.Template.Spec.Volumes {
				// Check if the volume is for container sockets
				if volume.HostPath != nil && slices.Contains(volumeNames, volume.Name) {
					pluginVolumes = append(pluginVolumes, volume)
				}
			}

			// Run the test case's assertions
			tc.expected(t, pluginVolumes)
		})
	}
}

func TestInvalidVolumeConfiguration(t *testing.T) {
	t.Parallel()
	helmChartPath, err := filepath.Abs(unit.ChartPath)
	require.NoError(t, err)

	testCases := []struct {
		name        string
		values      map[string]string
		expectedErr string
	}{
		{
			name: "bothOldAndNewConfigEnabled",
			values: map[string]string{
				"collectors.docker.enabled":          "true",
				"collectors.containerEngine.enabled": "true",
			},
			expectedErr: "You can not enable one of the [docker, containerd, crio] collectors configuration and the containerEngine configuration at the same time",
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
			_, err := helm.RenderTemplateE(t, options, helmChartPath, unit.ReleaseName, []string{"templates/daemonset.yaml"})
			require.Error(t, err)
			require.Contains(t, err.Error(), tc.expectedErr)
		})
	}
}

func findVolume(name string, volumes []corev1.Volume) *corev1.Volume {
	for _, v := range volumes {
		if v.Name == name {
			return &v
		}
	}
	return nil
}
