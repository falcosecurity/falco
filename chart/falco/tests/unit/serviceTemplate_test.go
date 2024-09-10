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
	"path/filepath"
	"testing"

	"github.com/gruntwork-io/terratest/modules/helm"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	corev1 "k8s.io/api/core/v1"
)

type serviceTemplateTest struct {
	suite.Suite
	chartPath   string
	releaseName string
	namespace   string
	templates   []string
}

func TestServiceTemplate(t *testing.T) {
	t.Parallel()

	chartFullPath, err := filepath.Abs(chartPath)
	require.NoError(t, err)

	suite.Run(t, &serviceTemplateTest{
		Suite:       suite.Suite{},
		chartPath:   chartFullPath,
		releaseName: "falco-test",
		namespace:   "falco-namespace-test",
		templates:   []string{"templates/service.yaml"},
	})
}

func (s *serviceTemplateTest) TestCreationDefaultValues() {
	// Render the service and check that it has not been rendered.
	_, err := helm.RenderTemplateE(s.T(), &helm.Options{}, s.chartPath, s.releaseName, s.templates)
	s.Error(err, "should error")
	s.Equal("error while running command: exit status 1; Error: could not find template templates/service.yaml in chart", err.Error())
}

func (s *serviceTemplateTest) TestDefaultLabelsValues() {
	options := &helm.Options{SetValues: map[string]string{"metrics.enabled": "true"}}
	output, err := helm.RenderTemplateE(s.T(), options, s.chartPath, s.releaseName, s.templates)
	s.NoError(err, "should render template")

	cInfo, err := chartInfo(s.T(), s.chartPath)
	s.NoError(err)
	// Get app version.
	appVersion, found := cInfo["appVersion"]
	s.True(found, "should find app version in chart info")
	appVersion = appVersion.(string)
	// Get chart version.
	chartVersion, found := cInfo["version"]
	s.True(found, "should find chart version in chart info")
	// Get chart name.
	chartName, found := cInfo["name"]
	s.True(found, "should find chart name in chart info")
	chartName = chartName.(string)
	expectedLabels := map[string]string{
		"helm.sh/chart":                fmt.Sprintf("%s-%s", chartName, chartVersion),
		"app.kubernetes.io/name":       chartName.(string),
		"app.kubernetes.io/instance":   s.releaseName,
		"app.kubernetes.io/version":    appVersion.(string),
		"app.kubernetes.io/managed-by": "Helm",
		"type":                         "falco-metrics",
	}
	var svc corev1.Service
	helm.UnmarshalK8SYaml(s.T(), output, &svc)
	labels := svc.GetLabels()
	for key, value := range labels {
		expectedVal := expectedLabels[key]
		s.Equal(expectedVal, value)
	}

	for key, value := range expectedLabels {
		expectedVal := labels[key]
		s.Equal(expectedVal, value)
	}
}


func (s *serviceTemplateTest) TestCustomLabelsValues() {
	options := &helm.Options{SetValues: map[string]string{"metrics.enabled": "true",
		"metrics.service.labels.customLabel": "customLabelValues"}}
	output, err := helm.RenderTemplateE(s.T(), options, s.chartPath, s.releaseName, s.templates)


	s.NoError(err, "should render template")

	cInfo, err := chartInfo(s.T(), s.chartPath)
	s.NoError(err)
	// Get app version.
	appVersion, found := cInfo["appVersion"]
	s.True(found, "should find app version in chart info")
	appVersion = appVersion.(string)
	// Get chart version.
	chartVersion, found := cInfo["version"]
	s.True(found, "should find chart version in chart info")
	// Get chart name.
	chartName, found := cInfo["name"]
	s.True(found, "should find chart name in chart info")
	chartName = chartName.(string)
	expectedLabels := map[string]string{
		"helm.sh/chart":                fmt.Sprintf("%s-%s", chartName, chartVersion),
		"app.kubernetes.io/name":       chartName.(string),
		"app.kubernetes.io/instance":   s.releaseName,
		"app.kubernetes.io/version":    appVersion.(string),
		"app.kubernetes.io/managed-by": "Helm",
		"type":                         "falco-metrics",
		"customLabel":                  "customLabelValues",
	}
	var svc corev1.Service
	helm.UnmarshalK8SYaml(s.T(), output, &svc)
	labels := svc.GetLabels()
	for key, value := range labels {
		expectedVal := expectedLabels[key]
		s.Equal(expectedVal, value)
	}

	for key, value := range expectedLabels {
		expectedVal := labels[key]
		s.Equal(expectedVal, value)
	}
 
}

func (s *serviceTemplateTest) TestDefaultAnnotationsValues() {
	options := &helm.Options{SetValues: map[string]string{"metrics.enabled": "true"}}
	output, err := helm.RenderTemplateE(s.T(), options, s.chartPath, s.releaseName, s.templates)

	s.NoError(err)

	var svc corev1.Service
 	helm.UnmarshalK8SYaml(s.T(), output, &svc)
	s.Nil(svc.Annotations, "should be nil")
}

func (s *serviceTemplateTest) TestCustomAnnotationsValues() {
	values := map[string]string{
		"metrics.enabled":                         "true",
		"metrics.service.annotations.annotation1": "customAnnotation1",
		"metrics.service.annotations.annotation2": "customAnnotation2",
	}
	annotations := map[string]string{
		"annotation1": "customAnnotation1",
		"annotation2": "customAnnotation2",
	}
	options := &helm.Options{SetValues: values}
	output, err := helm.RenderTemplateE(s.T(), options, s.chartPath, s.releaseName, s.templates)
	s.NoError(err)

	var svc corev1.Service
	helm.UnmarshalK8SYaml(s.T(), output, &svc)
	s.Len(svc.Annotations, 2)

	for key, value := range svc.Annotations {
		expectedVal := annotations[key]
		s.Equal(expectedVal, value)
	}
}