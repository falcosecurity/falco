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
	"encoding/json"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/gruntwork-io/terratest/modules/helm"
	monitoringv1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type serviceMonitorTemplateTest struct {
	suite.Suite
	chartPath   string
	releaseName string
	namespace   string
	templates   []string
}

func TestServiceMonitorTemplate(t *testing.T) {
	t.Parallel()

	chartFullPath, err := filepath.Abs(chartPath)
	require.NoError(t, err)

	suite.Run(t, &serviceMonitorTemplateTest{
		Suite:       suite.Suite{},
		chartPath:   chartFullPath,
		releaseName: "falco-test",
		namespace:   "falco-namespace-test",
		templates:   []string{"templates/serviceMonitor.yaml"},
	})
}

func (s *serviceMonitorTemplateTest) TestCreationDefaultValues() {
	// Render the servicemonitor and check that it has not been rendered.
	_, err := helm.RenderTemplateE(s.T(), &helm.Options{}, s.chartPath, s.releaseName, s.templates)
	s.Error(err, "should error")
	s.Equal("error while running command: exit status 1; Error: could not find template templates/serviceMonitor.yaml in chart", err.Error())
}

func (s *serviceMonitorTemplateTest) TestEndpoint() {
	defaultEndpointsJSON := `[
    {
        "port": "metrics",
        "interval": "15s",
        "scrapeTimeout": "10s",
        "honorLabels": true,
        "path": "/metrics",
        "scheme": "http"
    }
]`
	var defaultEndpoints []monitoringv1.Endpoint
	err := json.Unmarshal([]byte(defaultEndpointsJSON), &defaultEndpoints)
	s.NoError(err)

	options := &helm.Options{SetValues: map[string]string{"serviceMonitor.create": "true"}}
	output := helm.RenderTemplate(s.T(), options, s.chartPath, s.releaseName, s.templates)

	var svcMonitor monitoringv1.ServiceMonitor
	helm.UnmarshalK8SYaml(s.T(), output, &svcMonitor)

	s.Len(svcMonitor.Spec.Endpoints, 1, "should have only one endpoint")
	s.True(reflect.DeepEqual(svcMonitor.Spec.Endpoints[0], defaultEndpoints[0]))
}

func (s *serviceMonitorTemplateTest) TestNamespaceSelector() {
	selectorsLabelJson := `{
			"app.kubernetes.io/instance": "my-falco",
			"foo": "bar"
		}`
	options := &helm.Options{SetValues: map[string]string{"serviceMonitor.create": "true"},
		SetJsonValues: map[string]string{"serviceMonitor.selector": selectorsLabelJson}}
	output := helm.RenderTemplate(s.T(), options, s.chartPath, s.releaseName, s.templates)

	var svcMonitor monitoringv1.ServiceMonitor
	helm.UnmarshalK8SYaml(s.T(), output, &svcMonitor)
	s.Len(svcMonitor.Spec.NamespaceSelector.MatchNames, 1)
	s.Equal("default", svcMonitor.Spec.NamespaceSelector.MatchNames[0])
}

func (s *serviceMonitorTemplateTest) TestServiceMonitorSelector() {
	testCases := []struct {
		name     string
		values   string
		expected map[string]string
	}{
		{
			"defaultValues",
			"",
			map[string]string{
				"app.kubernetes.io/instance": "falco-test",
				"app.kubernetes.io/name":     "falco",
				"type":                       "falco-metrics",
			},
		},
		{
			"customValues",
			`{
			"foo": "bar"
		}`,
			map[string]string{
				"app.kubernetes.io/instance": "falco-test",
				"app.kubernetes.io/name":     "falco",
				"foo":                        "bar",
				"type":                       "falco-metrics",
			},
		},
		{
			"overwriteDefaultValues",
			`{
			"app.kubernetes.io/instance": "falco-overwrite",
			"foo": "bar"
		}`,
			map[string]string{
				"app.kubernetes.io/instance": "falco-overwrite",
				"app.kubernetes.io/name":     "falco",
				"foo":                        "bar",
				"type":                       "falco-metrics",
			},
		},
	}

	for _, testCase := range testCases {
		testCase := testCase

		s.Run(testCase.name, func() {
			subT := s.T()
			subT.Parallel()

			options := &helm.Options{SetValues: map[string]string{"serviceMonitor.create": "true"},
				SetJsonValues: map[string]string{"serviceMonitor.selector": testCase.values}}
			output := helm.RenderTemplate(s.T(), options, s.chartPath, s.releaseName, s.templates)

			var svcMonitor monitoringv1.ServiceMonitor
			helm.UnmarshalK8SYaml(s.T(), output, &svcMonitor)

			s.Equal(testCase.expected, svcMonitor.Spec.Selector.MatchLabels, "should be the same")
		})
	}
}
