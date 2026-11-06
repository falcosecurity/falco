package falcoTemplates

import (
	"github.com/falcosecurity/falco/chart/falco/tests/unit"
	"github.com/gruntwork-io/terratest/modules/helm"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"path/filepath"
	"testing"
)

func TestFalcoctlCACertSecret(t *testing.T) {
	t.Parallel()

	helmChartPath, err := filepath.Abs(unit.ChartPath)
	require.NoError(t, err)

	options := &helm.Options{
		SetValues: map[string]string{
			"extra.registryCustomCaCert.enabled": "true",
			"extra.registryCustomCaCert.cacert":  "-----BEGIN CERTIFICATE-----test-----END CERTIFICATE-----",

			// Conditions externes du template
			"falcoctl.artifact.install.enabled": "true",
			"falcoctl.artifact.follow.enabled":  "true",
		},
	}

	output, err := helm.RenderTemplateE(
		t,
		options,
		helmChartPath,
		unit.ReleaseName,
		[]string{
			"templates/falcoctl-cacert-secret.yaml",
		},
	)
	require.NoError(t, err)

	var secret corev1.Secret
	helm.UnmarshalK8SYaml(t, output, &secret)

	require.Equal(t, "Secret", secret.Kind)
	require.Equal(t, "rendered-resources-falco-custom-ca", secret.Name)

	require.Empty(t, secret.StringData)

	certificate, found := secret.Data["registry-cacert.pem"]
	require.True(t, found)
	require.Equal(
		t,
		"-----BEGIN CERTIFICATE-----test-----END CERTIFICATE-----",
		string(certificate),
	)
}