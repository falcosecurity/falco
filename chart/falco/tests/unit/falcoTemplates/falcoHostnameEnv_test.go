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

package falcoTemplates

import (
	"path/filepath"
	"testing"

	"github.com/falcosecurity/charts/charts/falco/tests/unit"
	"github.com/gruntwork-io/terratest/modules/helm"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
)

// findEnvVars returns every env entry on the falco container with the given name.
// `env[].name` is the strategic-merge-patch merge key in Kubernetes; producing
// more than one entry with the same name is the exact bug this feature guards
// against, so callers assert on the slice length explicitly.
func findEnvVars(envs []corev1.EnvVar, name string) []corev1.EnvVar {
	var out []corev1.EnvVar
	for _, e := range envs {
		if e.Name == name {
			out = append(out, e)
		}
	}
	return out
}

// falcoContainer returns the primary falco container from a rendered DaemonSet.
// The container is named after the chart (`falco`) in pod-template.tpl.
func falcoContainer(t *testing.T, ds appsv1.DaemonSet) corev1.Container {
	for _, c := range ds.Spec.Template.Spec.Containers {
		if c.Name == "falco" {
			return c
		}
	}
	t.Fatalf("falco container not found in rendered DaemonSet")
	return corev1.Container{}
}

func TestFalcoHostnameEnv(t *testing.T) {
	t.Parallel()

	helmChartPath, err := filepath.Abs(unit.ChartPath)
	require.NoError(t, err)

	testCases := []struct {
		name     string
		values   map[string]string
		expected func(t *testing.T, env []corev1.EnvVar)
	}{
		{
			"default",
			nil,
			func(t *testing.T, env []corev1.EnvVar) {
				matches := findEnvVars(env, "FALCO_HOSTNAME")
				require.Len(t, matches, 1, "expected exactly one FALCO_HOSTNAME entry")
				require.Empty(t, matches[0].Value, "default form must not set a literal value")
				require.NotNil(t, matches[0].ValueFrom, "default form must use valueFrom")
				require.NotNil(t, matches[0].ValueFrom.FieldRef)
				require.Equal(t, "spec.nodeName", matches[0].ValueFrom.FieldRef.FieldPath)
			},
		},
		{
			"extraEnvOverride",
			map[string]string{
				"extra.env[0].name":  "FALCO_HOSTNAME",
				"extra.env[0].value": "custom-host",
			},
			func(t *testing.T, env []corev1.EnvVar) {
				matches := findEnvVars(env, "FALCO_HOSTNAME")
				require.Len(t, matches, 1,
					"chart-default must be suppressed when extra.env supplies FALCO_HOSTNAME (otherwise SMP collision on UPDATE)")
				require.Equal(t, "custom-host", matches[0].Value)
				require.Nil(t, matches[0].ValueFrom, "user override must not carry valueFrom")
			},
		},
		{
			"disabled",
			map[string]string{
				"falcoHostnameEnv": "false",
			},
			func(t *testing.T, env []corev1.EnvVar) {
				matches := findEnvVars(env, "FALCO_HOSTNAME")
				require.Empty(t, matches, "FALCO_HOSTNAME must not be emitted when falcoHostnameEnv=false")
			},
		},
	}

	for _, testCase := range testCases {
		testCase := testCase

		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			options := &helm.Options{SetValues: testCase.values}
			output := helm.RenderTemplate(t, options, helmChartPath, unit.ReleaseName, []string{"templates/daemonset.yaml"})

			var ds appsv1.DaemonSet
			helm.UnmarshalK8SYaml(t, output, &ds)

			testCase.expected(t, falcoContainer(t, ds).Env)
		})
	}
}

// TestFalcoHostnameEnvNotInFalcoConfig asserts the chart-only toggle does not
// leak into the rendered falco.yaml runtime config. The toggle controls
// container env injection, not Falco process behavior, so it must not appear
// in the config consumed by the Falco binary.
func TestFalcoHostnameEnvNotInFalcoConfig(t *testing.T) {
	t.Parallel()

	helmChartPath, err := filepath.Abs(unit.ChartPath)
	require.NoError(t, err)

	output := helm.RenderTemplate(t, &helm.Options{}, helmChartPath, unit.ReleaseName, []string{"templates/configmap.yaml"})

	var cm corev1.ConfigMap
	helm.UnmarshalK8SYaml(t, output, &cm)

	var config map[string]interface{}
	helm.UnmarshalK8SYaml(t, cm.Data["falco.yaml"], &config)

	_, leak := config["falcoHostnameEnv"]
	require.False(t, leak, "falcoHostnameEnv must not appear in rendered falco.yaml")
}
