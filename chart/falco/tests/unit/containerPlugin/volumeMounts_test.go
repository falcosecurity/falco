package containerPlugin

import (
	"path/filepath"
	"slices"
	"testing"

	"github.com/falcosecurity/falco/chart/falco/tests/unit"
	"github.com/gruntwork-io/terratest/modules/helm"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
)

func TestContainerPluginVolumeMounts(t *testing.T) {
	t.Parallel()
	helmChartPath, err := filepath.Abs(unit.ChartPath)
	require.NoError(t, err)

	testCases := []struct {
		name     string
		values   map[string]string
		expected func(t *testing.T, volumeMounts []corev1.VolumeMount)
	}{
		{
			name:   "defaultValues",
			values: nil,
			expected: func(t *testing.T, volumeMounts []corev1.VolumeMount) {
				require.Len(t, volumeMounts, 6)
				require.Equal(t, "container-engine-socket-0", volumeMounts[0].Name)
				require.Equal(t, "/host/var/run", volumeMounts[0].MountPath)
				require.Equal(t, "container-engine-socket-1", volumeMounts[1].Name)
				require.Equal(t, "/host/run/podman", volumeMounts[1].MountPath)
				require.Equal(t, "container-engine-socket-2", volumeMounts[2].Name)
				require.Equal(t, "/host/run/host-containerd", volumeMounts[2].MountPath)
				require.Equal(t, "container-engine-socket-3", volumeMounts[3].Name)
				require.Equal(t, "/host/run/containerd", volumeMounts[3].MountPath)
				require.Equal(t, "container-engine-socket-4", volumeMounts[4].Name)
				require.Equal(t, "/host/run/crio", volumeMounts[4].MountPath)
				require.Equal(t, "container-engine-socket-5", volumeMounts[5].Name)
				require.Equal(t, "/host/run/k3s/containerd", volumeMounts[5].MountPath)
			},
		},
		{
			name: "defaultDockerVolumeMount",
			values: map[string]string{
				"collectors.containerEngine.engines.docker.enabled":     "true",
				"collectors.containerEngine.engines.containerd.enabled": "false",
				"collectors.containerEngine.engines.cri.enabled":        "false",
				"collectors.containerEngine.engines.podman.enabled":     "false",
			},
			expected: func(t *testing.T, volumeMounts []corev1.VolumeMount) {
				require.Len(t, volumeMounts, 1)
				require.Equal(t, "container-engine-socket-0", volumeMounts[0].Name)
				require.Equal(t, "/host/var/run", volumeMounts[0].MountPath)
			},
		},
		{
			name: "customDockerSocket",
			values: map[string]string{
				"collectors.containerEngine.engines.docker.enabled":     "true",
				"collectors.containerEngine.engines.docker.sockets[0]":  "/custom/docker.sock",
				"collectors.containerEngine.engines.containerd.enabled": "false",
				"collectors.containerEngine.engines.cri.enabled":        "false",
				"collectors.containerEngine.engines.podman.enabled":     "false",
			},
			expected: func(t *testing.T, volumeMounts []corev1.VolumeMount) {
				require.Len(t, volumeMounts, 1)
				require.Equal(t, "container-engine-socket-0", volumeMounts[0].Name)
				require.Equal(t, "/host/custom", volumeMounts[0].MountPath)
			},
		},
		{
			name: "defaultCriVolumeMount",
			values: map[string]string{
				"collectors.containerEngine.engines.docker.enabled":     "false",
				"collectors.containerEngine.engines.containerd.enabled": "false",
				"collectors.containerEngine.engines.cri.enabled":        "true",
				"collectors.containerEngine.engines.podman.enabled":     "false",
			},
			expected: func(t *testing.T, volumeMounts []corev1.VolumeMount) {
				require.Len(t, volumeMounts, 4)
				require.Equal(t, "container-engine-socket-0", volumeMounts[0].Name)
				require.Equal(t, "/host/run/containerd", volumeMounts[0].MountPath)
				require.Equal(t, "container-engine-socket-1", volumeMounts[1].Name)
				require.Equal(t, "/host/run/crio", volumeMounts[1].MountPath)
				require.Equal(t, "container-engine-socket-2", volumeMounts[2].Name)
				require.Equal(t, "/host/run/k3s/containerd", volumeMounts[2].MountPath)
				require.Equal(t, "container-engine-socket-3", volumeMounts[3].Name)
				require.Equal(t, "/host/run/host-containerd", volumeMounts[3].MountPath)
			},
		},
		{
			name: "customCriSocket",
			values: map[string]string{
				"collectors.containerEngine.engines.cri.enabled":        "true",
				"collectors.containerEngine.engines.cri.sockets[0]":     "/custom/crio.sock",
				"collectors.containerEngine.engines.containerd.enabled": "false",
				"collectors.containerEngine.engines.docker.enabled":     "false",
				"collectors.containerEngine.engines.podman.enabled":     "false",
			},
			expected: func(t *testing.T, volumeMounts []corev1.VolumeMount) {
				require.Len(t, volumeMounts, 1)
				require.Equal(t, "container-engine-socket-0", volumeMounts[0].Name)
				require.Equal(t, "/host/custom", volumeMounts[0].MountPath)
			},
		},
		{
			name: "defaultContainerdVolumeMount",
			values: map[string]string{
				"collectors.containerEngine.engines.docker.enabled":     "false",
				"collectors.containerEngine.engines.containerd.enabled": "true",
				"collectors.containerEngine.engines.cri.enabled":        "false",
				"collectors.containerEngine.engines.podman.enabled":     "false",
			},
			expected: func(t *testing.T, volumeMounts []corev1.VolumeMount) {
				require.Len(t, volumeMounts, 1)
				require.Equal(t, "container-engine-socket-0", volumeMounts[0].Name)
				require.Equal(t, "/host/run/host-containerd", volumeMounts[0].MountPath)
			},
		},
		{
			name: "customContainerdSocket",
			values: map[string]string{
				"collectors.containerEngine.engines.containerd.enabled":    "true",
				"collectors.containerEngine.engines.containerd.sockets[0]": "/custom/containerd.sock",
				"collectors.containerEngine.engines.cri.enabled":           "false",
				"collectors.containerEngine.engines.docker.enabled":        "false",
				"collectors.containerEngine.engines.podman.enabled":        "false",
			},
			expected: func(t *testing.T, volumeMounts []corev1.VolumeMount) {
				require.Len(t, volumeMounts, 1)
				require.Equal(t, "container-engine-socket-0", volumeMounts[0].Name)
				require.Equal(t, "/host/custom", volumeMounts[0].MountPath)
			},
		},
		{
			name:   "ContainerEnginesDefaultValues",
			values: map[string]string{},
			expected: func(t *testing.T, volumeMounts []corev1.VolumeMount) {
				require.Len(t, volumeMounts, 6)

				// dockerV := findVolumeMount("docker-socket-0", volumeMounts)
				// require.NotNil(t, dockerV)
				// require.Equal(t, "/host/var/run", dockerV.MountPath)

				// podmanV := findVolumeMount("podman-socket-0", volumeMounts)
				// require.NotNil(t, podmanV)
				// require.Equal(t, "/host/run/podman", podmanV.MountPath)

				// containerdV := findVolumeMount("containerd-socket-0", volumeMounts)
				// require.NotNil(t, containerdV)
				// require.Equal(t, "/host/run/host-containerd", containerdV.MountPath)

				// crioV0 := findVolumeMount("cri-socket-0", volumeMounts)
				// require.NotNil(t, crioV0)
				// require.Equal(t, "/host/run/containerd", crioV0.MountPath)

				// crioV1 := findVolumeMount("cri-socket-1", volumeMounts)
				// require.NotNil(t, crioV1)
				// require.Equal(t, "/host/run/crio", crioV1.MountPath)

				// crioV2 := findVolumeMount("cri-socket-2", volumeMounts)
				// require.NotNil(t, crioV2)
				// require.Equal(t, "/host/run/k3s/containerd", crioV2.MountPath)
			},
		},
		{
			name: "ContainerEnginesDockerWithMultipleSockets",
			values: map[string]string{
				"collectors.containerEngine.engines.docker.enabled":     "true",
				"collectors.containerEngine.engines.docker.sockets[0]":  "/var/run/docker.sock",
				"collectors.containerEngine.engines.docker.sockets[1]":  "/custom/docker.sock",
				"collectors.containerEngine.engines.containerd.enabled": "false",
				"collectors.containerEngine.engines.cri.enabled":        "false",
				"collectors.containerEngine.engines.podman.enabled":     "false",
			},
			expected: func(t *testing.T, volumeMounts []corev1.VolumeMount) {
				require.Len(t, volumeMounts, 2)

				dockerV0 := findVolumeMount("container-engine-socket-0", volumeMounts)
				require.NotNil(t, dockerV0)
				require.Equal(t, "/host/var/run", dockerV0.MountPath)

				dockerV1 := findVolumeMount("container-engine-socket-1", volumeMounts)
				require.NotNil(t, dockerV1)
				require.Equal(t, "/host/custom", dockerV1.MountPath)
			},
		},
		{
			name: "ContainerEnginesCrioWithMultipleSockets",
			values: map[string]string{
				"collectors.containerEngine.engines.docker.enabled":     "false",
				"collectors.containerEngine.engines.containerd.enabled": "false",
				"collectors.containerEngine.engines.cri.enabled":        "true",
				"collectors.containerEngine.engines.cri.sockets[0]":     "/run/crio/crio.sock",
				"collectors.containerEngine.engines.cri.sockets[1]":     "/custom/crio.sock",
				"collectors.containerEngine.engines.podman.enabled":     "false",
			},
			expected: func(t *testing.T, volumeMounts []corev1.VolumeMount) {
				require.Len(t, volumeMounts, 2)

				crioV0 := findVolumeMount("container-engine-socket-0", volumeMounts)
				require.NotNil(t, crioV0)
				require.Equal(t, "/host/run/crio", crioV0.MountPath)

				crioV1 := findVolumeMount("container-engine-socket-1", volumeMounts)
				require.NotNil(t, crioV1)
				require.Equal(t, "/host/custom", crioV1.MountPath)
			},
		},
		{
			name: "ContainerEnginesSocketsInSameDirectoryShareOneVolumeMount",
			values: map[string]string{
				"collectors.containerEngine.engines.docker.enabled":     "false",
				"collectors.containerEngine.engines.containerd.enabled": "false",
				"collectors.containerEngine.engines.cri.enabled":        "true",
				"collectors.containerEngine.engines.cri.sockets[0]":     "/run/containerd/containerd.sock",
				"collectors.containerEngine.engines.cri.sockets[1]":     "/run/containerd/other.sock",
				"collectors.containerEngine.engines.podman.enabled":     "false",
			},
			expected: func(t *testing.T, volumeMounts []corev1.VolumeMount) {
				require.Len(t, volumeMounts, 1)
				require.Equal(t, "container-engine-socket-0", volumeMounts[0].Name)
				require.Equal(t, "/host/run/containerd", volumeMounts[0].MountPath)
			},
		},
		{
			name: "noVolumeMountsWhenCollectorsDisabled",
			values: map[string]string{
				"collectors.enabled": "false",
			},
			expected: func(t *testing.T, volumeMounts []corev1.VolumeMount) {
				require.Len(t, volumeMounts, 0)
			},
		},
		{
			name: "noVolumeMountsWhenDriverDisabled",
			values: map[string]string{
				"driver.enabled": "false",
			},
			expected: func(t *testing.T, volumeMounts []corev1.VolumeMount) {
				require.Len(t, volumeMounts, 0)
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

			// Find volumeMounts in the falco container
			var pluginVolumeMounts []corev1.VolumeMount
			for _, container := range daemonset.Spec.Template.Spec.Containers {
				if container.Name == "falco" {
					for _, volumeMount := range container.VolumeMounts {
						if slices.Contains(volumeNames, volumeMount.Name) {
							pluginVolumeMounts = append(pluginVolumeMounts, volumeMount)
						}
					}
				}
			}

			// Run the test case's assertions
			tc.expected(t, pluginVolumeMounts)
		})
	}
}

func findVolumeMount(name string, volumeMounts []corev1.VolumeMount) *corev1.VolumeMount {
	for _, v := range volumeMounts {
		if v.Name == name {
			return &v
		}
	}
	return nil
}
