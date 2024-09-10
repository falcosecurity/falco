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
	"testing"

	"github.com/gruntwork-io/terratest/modules/helm"
	"gopkg.in/yaml.v3"
)

func chartInfo(t *testing.T, chartPath string) (map[string]interface{}, error) {
	// Get chart info.
	output, err := helm.RunHelmCommandAndGetOutputE(t, &helm.Options{}, "show", "chart", chartPath)
	if err != nil {
		return nil, err
	}
	chartInfo := map[string]interface{}{}
	err = yaml.Unmarshal([]byte(output), &chartInfo)
	return chartInfo, err
}
