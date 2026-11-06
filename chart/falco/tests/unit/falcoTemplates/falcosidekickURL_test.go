// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Falco Authors
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

package falcoTemplates

import (
	"path/filepath"
	"testing"

	"github.com/falcosecurity/falco/chart/falco/tests/unit"
	"github.com/gruntwork-io/terratest/modules/helm"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
)

func TestFalcosidekickHTTPOutputURL(t *testing.T) {
	t.Parallel()

	helmChartPath, err := filepath.Abs(unit.ChartPath)
	require.NoError(t, err)

	testCases := []struct {
		name     string
		values   map[string]string
		expected string
	}{
		{
			name:     "defaultPort",
			values:   map[string]string{},
			expected: "http://rendered-resources-falco-falcosidekick:2801",
		},
		{
			name:     "listenPort",
			values:   map[string]string{"falcosidekick.listenPort": "2802"},
			expected: "http://rendered-resources-falco-falcosidekick:2802",
		},
		{
			name: "listenPortWithFullFQDN",
			values: map[string]string{
				"falcosidekick.listenPort": "2802",
				"falcosidekick.fullfqdn":   "true",
			},
			expected: "http://rendered-resources-falco-falcosidekick.default.svc.cluster.local:2802",
		},
		{
			name:     "legacyLowercaseListenport",
			values:   map[string]string{"falcosidekick.listenport": "2803"},
			expected: "http://rendered-resources-falco-falcosidekick:2803",
		},
		{
			name: "explicitURL",
			values: map[string]string{
				"falcosidekick.listenPort": "2802",
				"falco.http_output.url":    "http://example.com:9999",
			},
			expected: "http://example.com:9999",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			values := map[string]string{"falcosidekick.enabled": "true"}
			for k, v := range testCase.values {
				values[k] = v
			}
			options := &helm.Options{SetValues: values}
			output := helm.RenderTemplate(t, options, helmChartPath, unit.ReleaseName, []string{"templates/configmap.yaml"})

			var cm corev1.ConfigMap
			helm.UnmarshalK8SYaml(t, output, &cm)
			var config map[string]interface{}
			helm.UnmarshalK8SYaml(t, cm.Data["falco.yaml"], &config)

			httpOutput, ok := config["http_output"].(map[string]interface{})
			require.True(t, ok, "http_output section should be present")
			require.Equal(t, true, httpOutput["enabled"])
			require.Equal(t, testCase.expected, httpOutput["url"])
		})
	}
}
