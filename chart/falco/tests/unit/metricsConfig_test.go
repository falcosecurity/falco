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
	"path/filepath"
	"testing"

	"github.com/gruntwork-io/terratest/modules/helm"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
	corev1 "k8s.io/api/core/v1"
)

type metricsConfig struct {
	Enabled                          bool   `yaml:"enabled"`
	ConvertMemoryToMB                bool   `yaml:"convert_memory_to_mb"`
	IncludeEmptyValues               bool   `yaml:"include_empty_values"`
	KernelEventCountersEnabled       bool   `yaml:"kernel_event_counters_enabled"`
	KernelEventCountersPerCPUEnabled bool   `yaml:"kernel_event_counters_per_cpu_enabled"`
	ResourceUtilizationEnabled       bool   `yaml:"resource_utilization_enabled"`
	RulesCountersEnabled             bool   `yaml:"rules_counters_enabled"`
	LibbpfStatsEnabled               bool   `yaml:"libbpf_stats_enabled"`
	OutputRule                       bool   `yaml:"output_rule"`
	StateCountersEnabled             bool   `yaml:"state_counters_enabled"`
	Interval                         string `yaml:"interval"`
}

type webServerConfig struct {
	Enabled                  bool   `yaml:"enabled"`
	K8sHealthzEndpoint       string `yaml:"k8s_healthz_endpoint"`
	ListenPort               string `yaml:"listen_port"`
	PrometheusMetricsEnabled bool   `yaml:"prometheus_metrics_enabled"`
	SSLCertificate           string `yaml:"ssl_certificate"`
	SSLEnabled               bool   `yaml:"ssl_enabled"`
	Threadiness              int    `yaml:"threadiness"`
}

func TestMetricsConfigInFalcoConfig(t *testing.T) {
	t.Parallel()

	helmChartPath, err := filepath.Abs(chartPath)
	require.NoError(t, err)

	testCases := []struct {
		name     string
		values   map[string]string
		expected func(t *testing.T, metricsConfig, webServerConfig any)
	}{
		{
			"defaultValues",
			nil,
			func(t *testing.T, metricsConfig, webServerConfig any) {
				require.Len(t, metricsConfig, 11, "should have ten items")

				metrics, err := getMetricsConfig(metricsConfig)
				require.NoError(t, err)
				require.NotNil(t, metrics)
				require.True(t, metrics.ConvertMemoryToMB)
				require.False(t, metrics.Enabled)
				require.False(t, metrics.IncludeEmptyValues)
				require.True(t, metrics.KernelEventCountersEnabled)
				require.True(t, metrics.ResourceUtilizationEnabled)
				require.True(t, metrics.RulesCountersEnabled)
				require.Equal(t, "1h", metrics.Interval)
				require.True(t, metrics.LibbpfStatsEnabled)
				require.True(t, metrics.OutputRule)
				require.True(t, metrics.StateCountersEnabled)
				require.False(t, metrics.KernelEventCountersPerCPUEnabled)

				webServer, err := getWebServerConfig(webServerConfig)
				require.NoError(t, err)
				require.NotNil(t, webServer)
				require.True(t, webServer.Enabled)
				require.False(t, webServer.PrometheusMetricsEnabled)
			},
		},
		{
			"metricsEnabled",
			map[string]string{
				"metrics.enabled": "true",
			},
			func(t *testing.T, metricsConfig, webServerConfig any) {
				require.Len(t, metricsConfig, 11, "should have ten items")

				metrics, err := getMetricsConfig(metricsConfig)
				require.NoError(t, err)
				require.NotNil(t, metrics)
				require.True(t, metrics.ConvertMemoryToMB)
				require.True(t, metrics.Enabled)
				require.False(t, metrics.IncludeEmptyValues)
				require.True(t, metrics.KernelEventCountersEnabled)
				require.True(t, metrics.ResourceUtilizationEnabled)
				require.True(t, metrics.RulesCountersEnabled)
				require.Equal(t, "1h", metrics.Interval)
				require.True(t, metrics.LibbpfStatsEnabled)
				require.False(t, metrics.OutputRule)
				require.True(t, metrics.StateCountersEnabled)
				require.False(t, metrics.KernelEventCountersPerCPUEnabled)

				webServer, err := getWebServerConfig(webServerConfig)
				require.NoError(t, err)
				require.NotNil(t, webServer)
				require.True(t, webServer.Enabled)
				require.True(t, webServer.PrometheusMetricsEnabled)
			},
		},
		{
			"Flip/Change Values",
			map[string]string{
				"metrics.enabled":                          "true",
				"metrics.convertMemoryToMB":                "false",
				"metrics.includeEmptyValues":               "true",
				"metrics.kernelEventCountersEnabled":       "false",
				"metrics.resourceUtilizationEnabled":       "false",
				"metrics.rulesCountersEnabled":             "false",
				"metrics.libbpfStatsEnabled":               "false",
				"metrics.outputRule":                       "false",
				"metrics.stateCountersEnabled":             "false",
				"metrics.interval":                         "1s",
				"metrics.kernelEventCountersPerCPUEnabled": "true",
			},
			func(t *testing.T, metricsConfig, webServerConfig any) {
				require.Len(t, metricsConfig, 11, "should have ten items")

				metrics, err := getMetricsConfig(metricsConfig)
				require.NoError(t, err)
				require.NotNil(t, metrics)
				require.False(t, metrics.ConvertMemoryToMB)
				require.True(t, metrics.Enabled)
				require.True(t, metrics.IncludeEmptyValues)
				require.False(t, metrics.KernelEventCountersEnabled)
				require.False(t, metrics.ResourceUtilizationEnabled)
				require.False(t, metrics.RulesCountersEnabled)
				require.Equal(t, "1s", metrics.Interval)
				require.False(t, metrics.LibbpfStatsEnabled)
				require.False(t, metrics.OutputRule)
				require.False(t, metrics.StateCountersEnabled)
				require.True(t, metrics.KernelEventCountersPerCPUEnabled)

				webServer, err := getWebServerConfig(webServerConfig)
				require.NoError(t, err)
				require.NotNil(t, webServer)
				require.True(t, webServer.Enabled)
				require.True(t, webServer.PrometheusMetricsEnabled)
			},
		},
	}

	for _, testCase := range testCases {
		testCase := testCase

		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			options := &helm.Options{SetValues: testCase.values}
			output := helm.RenderTemplate(t, options, helmChartPath, releaseName, []string{"templates/configmap.yaml"})

			var cm corev1.ConfigMap
			helm.UnmarshalK8SYaml(t, output, &cm)
			var config map[string]interface{}

			helm.UnmarshalK8SYaml(t, cm.Data["falco.yaml"], &config)
			metrics := config["metrics"]
			webServer := config["webserver"]
			testCase.expected(t, metrics, webServer)
		})
	}
}

func getMetricsConfig(config any) (*metricsConfig, error) {
	var metrics metricsConfig

	metricsByte, err := yaml.Marshal(config)
	if err != nil {
		return nil, err
	}

	if err := yaml.Unmarshal(metricsByte, &metrics); err != nil {
		return nil, err
	}

	return &metrics, nil
}

func getWebServerConfig(config any) (*webServerConfig, error) {
	var webServer webServerConfig
	webServerByte, err := yaml.Marshal(config)
	if err != nil {
		return nil, err
	}
	if err := yaml.Unmarshal(webServerByte, &webServer); err != nil {
		return nil, err
	}
	return &webServer, nil
}
