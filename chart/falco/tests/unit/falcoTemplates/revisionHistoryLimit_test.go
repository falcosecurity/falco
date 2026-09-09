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
	appsv1 "k8s.io/api/apps/v1"
)

func TestRevisionHistoryLimit(t *testing.T) {
	t.Parallel()

	helmChartPath, err := filepath.Abs(unit.ChartPath)
	require.NoError(t, err)

	testCases := []struct {
		name       string
		value      string
		configured bool
		expected   int32
	}{
		{name: "unset"},
		{name: "null", value: "null"},
		{name: "zero", value: "0", configured: true, expected: 0},
		{name: "positive", value: "3", configured: true, expected: 3},
	}

	for _, kind := range []string{"daemonset", "deployment"} {
		for _, testCase := range testCases {
			t.Run(kind+"/"+testCase.name, func(t *testing.T) {
				t.Parallel()

				values := map[string]string{"controller.kind": kind}
				if testCase.value != "" {
					values["controller."+kind+".revisionHistoryLimit"] = testCase.value
				}
				options := &helm.Options{SetValues: values}
				output := helm.RenderTemplate(t, options, helmChartPath, unit.ReleaseName, []string{"templates/" + kind + ".yaml"})

				var revisionHistoryLimit *int32
				if kind == "daemonset" {
					var ds appsv1.DaemonSet
					helm.UnmarshalK8SYaml(t, output, &ds)
					revisionHistoryLimit = ds.Spec.RevisionHistoryLimit
				} else {
					var deployment appsv1.Deployment
					helm.UnmarshalK8SYaml(t, output, &deployment)
					revisionHistoryLimit = deployment.Spec.RevisionHistoryLimit
				}

				if testCase.configured {
					require.NotNil(t, revisionHistoryLimit)
					require.Equal(t, testCase.expected, *revisionHistoryLimit)
				} else {
					require.Nil(t, revisionHistoryLimit)
					require.NotContains(t, output, "revisionHistoryLimit:")
				}
			})
		}
	}
}
