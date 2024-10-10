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
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gruntwork-io/terratest/modules/helm"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	corev1 "k8s.io/api/core/v1"
)

type grafanaDashboardsTemplateTest struct {
	suite.Suite
	chartPath   string
	releaseName string
	namespace   string
	templates   []string
}

func TestGrafanaDashboardsTemplate(t *testing.T) {
	t.Parallel()

	chartFullPath, err := filepath.Abs(chartPath)
	require.NoError(t, err)

	suite.Run(t, &grafanaDashboardsTemplateTest{
		Suite:       suite.Suite{},
		chartPath:   chartFullPath,
		releaseName: "falco-test-dashboard",
		namespace:   "falco-test-dashboard",
		templates:   []string{"templates/falco-dashboard-grafana.yaml"},
	})
}

func (g *grafanaDashboardsTemplateTest) TestCreationDefaultValues() {
	// Render the dashboard configmap and check that it has not been rendered.
	_, err := helm.RenderTemplateE(g.T(), &helm.Options{}, g.chartPath, g.releaseName, g.templates, fmt.Sprintf("--namespace=%s", g.namespace))
	g.Error(err, "should error")
	g.Equal("error while running command: exit status 1; Error: could not find template templates/falco-dashboard-grafana.yaml in chart", err.Error())
}

func (g *grafanaDashboardsTemplateTest) TestConfig() {
	testCases := []struct {
		name     string
		values   map[string]string
		expected func(cm *corev1.ConfigMap)
	}{
		{"dashboard enabled",
			map[string]string{
				"grafana.dashboards.enabled": "true",
			},
			func(cm *corev1.ConfigMap) {
				// Check that the name is the expected one.
				g.Equal("falco-grafana-dashboard", cm.Name)
				// Check the namespace.
				g.Equal(g.namespace, cm.Namespace)
				g.Nil(cm.Annotations)
			},
		},
		{"namespace",
			map[string]string{
				"grafana.dashboards.enabled":                    "true",
				"grafana.dashboards.configMaps.falco.namespace": "custom-namespace",
			},
			func(cm *corev1.ConfigMap) {
				// Check that the name is the expected one.
				g.Equal("falco-grafana-dashboard", cm.Name)
				// Check the namespace.
				g.Equal("custom-namespace", cm.Namespace)
				g.Nil(cm.Annotations)
			},
		},
		{"folder",
			map[string]string{
				"grafana.dashboards.enabled":                 "true",
				"grafana.dashboards.configMaps.falco.folder": "custom-folder",
			},
			func(cm *corev1.ConfigMap) {
				// Check that the name is the expected one.
				g.Equal("falco-grafana-dashboard", cm.Name)
				g.NotNil(cm.Annotations)
				g.Len(cm.Annotations, 2)
				// Check sidecar annotation.
				val, ok := cm.Annotations["k8s-sidecar-target-directory"]
				g.True(ok)
				g.Equal("/tmp/dashboards/custom-folder", val)
				// Check grafana annotation.
				val, ok = cm.Annotations["grafana_dashboard_folder"]
				g.True(ok)
				g.Equal("custom-folder", val)
			},
		},
	}

	for _, testCase := range testCases {
		testCase := testCase

		g.Run(testCase.name, func() {
			subT := g.T()
			subT.Parallel()

			options := &helm.Options{SetValues: testCase.values}

			// Render the configmap unmarshal it.
			output, err := helm.RenderTemplateE(subT, options, g.chartPath, g.releaseName, g.templates, "--namespace="+g.namespace)
			g.NoError(err, "should succeed")
			var cfgMap corev1.ConfigMap
			helm.UnmarshalK8SYaml(subT, output, &cfgMap)

			// Common checks
			// Check that contains the right label.
			g.Contains(cfgMap.Labels, "grafana_dashboard")
			// Check that the dashboard is contained in the config map.
			file, err := os.Open("../../dashboards/falco-dashboard.json")
			g.NoError(err)
			content, err := io.ReadAll(file)
			g.NoError(err)
			cfgData, ok := cfgMap.Data["falco-dashboard.json"]
			g.True(ok)
			g.Equal(strings.TrimRight(string(content), "\n"), cfgData)
			testCase.expected(&cfgMap)
		})
	}
}
