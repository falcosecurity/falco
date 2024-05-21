package unit

import (
	"github.com/gruntwork-io/terratest/modules/helm"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"path/filepath"
	"strings"
	"testing"
)

func TestServiceAccount(t *testing.T) {
	t.Parallel()

	helmChartPath, err := filepath.Abs(chartPath)
	require.NoError(t, err)

	testCases := []struct {
		name     string
		values   map[string]string
		expected func(t *testing.T, sa *corev1.ServiceAccount)
	}{
		{
			"defaultValues",
			nil,
			func(t *testing.T, sa *corev1.ServiceAccount) {
				require.Equal(t, sa.Name, "rendered-resources-falco")
			},
		},
		{
			"kind=auto",
			map[string]string{
				"serviceAccount.create": "false",
			},
			func(t *testing.T, sa *corev1.ServiceAccount) {
				require.Equal(t, sa.Name, "")
			},
		},
	}

	for _, testCase := range testCases {
		testCase := testCase

		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			options := &helm.Options{SetValues: testCase.values}
			output, err := helm.RenderTemplateE(t, options, helmChartPath, releaseName, []string{"templates/serviceaccount.yaml"})
			if err != nil {
				require.True(t, strings.Contains(err.Error(), "Error: could not find template templates/serviceaccount.yaml in chart"))
			}

			var sa corev1.ServiceAccount
			helm.UnmarshalK8SYaml(t, output, &sa)

			testCase.expected(t, &sa)
		})
	}
}
