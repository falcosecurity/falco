package unit

import (
	"path/filepath"
	"testing"

	"github.com/gruntwork-io/terratest/modules/helm"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
)

func TestContainerEngineSocketMounts(t *testing.T) {
	helmChartPath, err := filepath.Abs(chartPath)
	require.NoError(t, err)

	testCases := []struct {
		name     string
		values   map[string]string
		expected func(t *testing.T, volumes []v1.Volume, volumeMounts []v1.VolumeMount)
	}{
		{
			"defaultValues",
			nil,
			func(t *testing.T, volumes []v1.Volume, volumeMounts []v1.VolumeMount) {
				require.Contains(t, volumes, volume("crio-socket", "/run/crio/crio.sock"))
				require.Contains(t, volumes, volume("containerd-socket", "/run/containerd/containerd.sock"))
				require.Contains(t, volumes, volume("docker-socket", "/var/run/docker.sock"))
				require.Contains(t, volumeMounts, volumeMount("crio-socket", "/host/run/crio/crio.sock"))
				require.Contains(t, volumeMounts, volumeMount("containerd-socket", "/host/run/containerd/containerd.sock"))
				require.Contains(t, volumeMounts, volumeMount("docker-socket", "/host/var/run/docker.sock"))
			},
		},
		{
			"disableCrioSocket",
			map[string]string{"collectors.crio.enabled": "false"},
			func(t *testing.T, volumes []v1.Volume, volumeMounts []v1.VolumeMount) {
				require.NotContains(t, volumes, volume("crio-socket", "/run/crio/crio.sock"))
				require.Contains(t, volumes, volume("containerd-socket", "/run/containerd/containerd.sock"))
				require.Contains(t, volumes, volume("docker-socket", "/var/run/docker.sock"))
				require.NotContains(t, volumeMounts, volumeMount("crio-socket", "/host/run/crio/crio.sock"))
				require.Contains(t, volumeMounts, volumeMount("containerd-socket", "/host/run/containerd/containerd.sock"))
				require.Contains(t, volumeMounts, volumeMount("docker-socket", "/host/var/run/docker.sock"))
			},
		},
		{
			"disableContainerdSocket",
			map[string]string{"collectors.containerd.enabled": "false"},
			func(t *testing.T, volumes []v1.Volume, volumeMounts []v1.VolumeMount) {
				require.Contains(t, volumes, volume("crio-socket", "/run/crio/crio.sock"))
				require.NotContains(t, volumes, volume("containerd-socket", "/run/containerd/containerd.sock"))
				require.Contains(t, volumes, volume("docker-socket", "/var/run/docker.sock"))
				require.Contains(t, volumeMounts, volumeMount("crio-socket", "/host/run/crio/crio.sock"))
				require.NotContains(t, volumeMounts, volumeMount("containerd-socket", "/host/run/containerd/containerd.sock"))
				require.Contains(t, volumeMounts, volumeMount("docker-socket", "/host/var/run/docker.sock"))
			},
		},
		{
			"disableDockerSocket",
			map[string]string{"collectors.docker.enabled": "false"},
			func(t *testing.T, volumes []v1.Volume, volumeMounts []v1.VolumeMount) {
				require.Contains(t, volumes, volume("crio-socket", "/run/crio/crio.sock"))
				require.Contains(t, volumes, volume("containerd-socket", "/run/containerd/containerd.sock"))
				require.NotContains(t, volumes, volume("docker-socket", "/var/run/docker.sock"))
				require.Contains(t, volumeMounts, volumeMount("crio-socket", "/host/run/crio/crio.sock"))
				require.Contains(t, volumeMounts, volumeMount("containerd-socket", "/host/run/containerd/containerd.sock"))
				require.NotContains(t, volumeMounts, volumeMount("docker-socket", "/host/var/run/docker.sock"))
			},
		},
		{
			"disableAllCollectors",
			map[string]string{"collectors.enabled": "false"},
			func(t *testing.T, volumes []v1.Volume, volumeMounts []v1.VolumeMount) {
				require.NotContains(t, volumes, volume("crio-socket", "/run/crio/crio.sock"))
				require.NotContains(t, volumes, volume("containerd-socket", "/run/containerd/containerd.sock"))
				require.NotContains(t, volumes, volume("docker-socket", "/var/run/docker.sock"))
				require.NotContains(t, volumeMounts, volumeMount("crio-socket", "/host/run/crio/crio.sock"))
				require.NotContains(t, volumeMounts, volumeMount("containerd-socket", "/host/run/containerd/containerd.sock"))
				require.NotContains(t, volumeMounts, volumeMount("docker-socket", "/host/var/run/docker.sock"))
			},
		},
		{
			"customCrioSocketPath",
			map[string]string{"collectors.crio.socket": "/custom/path/crio.sock"},
			func(t *testing.T, volumes []v1.Volume, volumeMounts []v1.VolumeMount) {
				require.Contains(t, volumes, volume("crio-socket", "/custom/path/crio.sock"))
				require.Contains(t, volumes, volume("containerd-socket", "/run/containerd/containerd.sock"))
				require.Contains(t, volumes, volume("docker-socket", "/var/run/docker.sock"))
				require.Contains(t, volumeMounts, volumeMount("crio-socket", "/host/custom/path/crio.sock"))
				require.Contains(t, volumeMounts, volumeMount("containerd-socket", "/host/run/containerd/containerd.sock"))
				require.Contains(t, volumeMounts, volumeMount("docker-socket", "/host/var/run/docker.sock"))
			},
		},
		{
			"customContainerdSocketPath",
			map[string]string{"collectors.containerd.socket": "/custom/path/containerd.sock"},
			func(t *testing.T, volumes []v1.Volume, volumeMounts []v1.VolumeMount) {
				require.Contains(t, volumes, volume("crio-socket", "/run/crio/crio.sock"))
				require.Contains(t, volumes, volume("containerd-socket", "/custom/path/containerd.sock"))
				require.Contains(t, volumes, volume("docker-socket", "/var/run/docker.sock"))
				require.Contains(t, volumeMounts, volumeMount("crio-socket", "/host/run/crio/crio.sock"))
				require.Contains(t, volumeMounts, volumeMount("containerd-socket", "/host/custom/path/containerd.sock"))
				require.Contains(t, volumeMounts, volumeMount("docker-socket", "/host/var/run/docker.sock"))
			},
		},
		{
			"customDockerSocketPath",
			map[string]string{"collectors.docker.socket": "/custom/path/docker.sock"},
			func(t *testing.T, volumes []v1.Volume, volumeMounts []v1.VolumeMount) {
				require.Contains(t, volumes, volume("crio-socket", "/run/crio/crio.sock"))
				require.Contains(t, volumes, volume("containerd-socket", "/run/containerd/containerd.sock"))
				require.Contains(t, volumes, volume("docker-socket", "/custom/path/docker.sock"))
				require.Contains(t, volumeMounts, volumeMount("crio-socket", "/host/run/crio/crio.sock"))
				require.Contains(t, volumeMounts, volumeMount("containerd-socket", "/host/run/containerd/containerd.sock"))
				require.Contains(t, volumeMounts, volumeMount("docker-socket", "/host/custom/path/docker.sock"))
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
			for i := range ds.Spec.Template.Spec.Containers {
				if ds.Spec.Template.Spec.Containers[i].Name == "falco" {
					testCase.expected(t, ds.Spec.Template.Spec.Volumes, ds.Spec.Template.Spec.Containers[i].VolumeMounts)
					return
				}
			}
		})
	}
}

func volume(name, path string) v1.Volume {
	return v1.Volume{
		Name: name,
		VolumeSource: v1.VolumeSource{
			HostPath: &v1.HostPathVolumeSource{
				Path: filepath.Dir(path),
				Type: nil,
			},
			EmptyDir:              nil,
			GCEPersistentDisk:     nil,
			AWSElasticBlockStore:  nil,
			GitRepo:               nil,
			Secret:                nil,
			NFS:                   nil,
			ISCSI:                 nil,
			Glusterfs:             nil,
			PersistentVolumeClaim: nil,
			RBD:                   nil,
			FlexVolume:            nil,
			Cinder:                nil,
			CephFS:                nil,
			Flocker:               nil,
			DownwardAPI:           nil,
			FC:                    nil,
			AzureFile:             nil,
			ConfigMap:             nil,
			VsphereVolume:         nil,
			Quobyte:               nil,
			AzureDisk:             nil,
			PhotonPersistentDisk:  nil,
			Projected:             nil,
			PortworxVolume:        nil,
			ScaleIO:               nil,
			StorageOS:             nil,
			CSI:                   nil,
			Ephemeral:             nil,
		},
	}
}

func volumeMount(name, path string) v1.VolumeMount {
	return v1.VolumeMount{
		Name:             name,
		ReadOnly:         false,
		MountPath:        filepath.Dir(path),
		SubPath:          "",
		MountPropagation: nil,
		SubPathExpr:      "",
	}
}
