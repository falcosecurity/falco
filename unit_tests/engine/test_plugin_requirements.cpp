// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2023 The Falco Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include <memory>
#include <engine/falco_engine.h>
#include <gtest/gtest.h>

static bool check_requirements(std::string& err,
			       const std::vector<falco_engine::plugin_version_requirement>& plugins,
			       const std::string& ruleset_content)
{
	falco_engine e;
	falco::load_result::rules_contents_t c = {{"test", ruleset_content}};

	auto res = e.load_rules(c.begin()->second, c.begin()->first);
	if(!res->successful())
	{
		return false;
	}
	return e.check_plugin_requirements(plugins, err);
}

TEST(PluginRequirements, check_plugin_requirements_success)
{
	std::string error;

	/* No requirement */
	ASSERT_TRUE(check_requirements(error, {{"k8saudit", "0.1.0"}}, "")) << error << std::endl;

	/* Single plugin */
	ASSERT_TRUE(check_requirements(error, {{"k8saudit", "0.1.0"}}, R"(
- required_plugin_versions:
  - name: k8saudit
    version: 0.1.0
        )")) << error
	     << std::endl;

	/* Single plugin newer version */
	ASSERT_TRUE(check_requirements(error, {{"k8saudit", "0.2.0"}}, R"(
- required_plugin_versions:
  - name: k8saudit
    version: 0.1.0
        )")) << error
	     << std::endl;

	/* Multiple plugins */
	ASSERT_TRUE(check_requirements(error, {{"k8saudit", "0.1.0"}, {"json", "0.3.0"}}, R"(
- required_plugin_versions:
  - name: k8saudit
    version: 0.1.0
  - name: json
    version: 0.3.0
        )")) << error
	     << std::endl;

	/* Single plugin multiple versions */
	ASSERT_TRUE(check_requirements(error, {{"k8saudit", "0.2.0"}}, R"(
- required_plugin_versions:
  - name: k8saudit
    version: 0.1.0
- required_plugin_versions:
  - name: k8saudit
    version: 0.2.0
        )")) << error
	     << std::endl;

	/* Single plugin with alternatives */
	ASSERT_TRUE(check_requirements(error, {{"k8saudit-other", "0.5.0"}}, R"(
- required_plugin_versions:
  - name: k8saudit
    version: 0.1.0
    alternatives:
      - name: k8saudit-other
        version: 0.4.0
        )")) << error
	     << std::endl;

	/* Multiple plugins with alternatives */
	ASSERT_TRUE(check_requirements(error, {{"k8saudit-other", "0.5.0"}, {"json2", "0.5.0"}}, R"(
- required_plugin_versions:
  - name: k8saudit
    version: 0.1.0
    alternatives:
      - name: k8saudit-other
        version: 0.4.0
  - name: json
    version: 0.3.0
    alternatives:
      - name: json2
        version: 0.1.0
        )")) << error
	     << std::endl;

	/* Multiple plugins with alternatives with multiple versions */
	ASSERT_TRUE(check_requirements(error, {{"k8saudit-other", "0.7.0"}, {"json2", "0.5.0"}}, R"(
- required_plugin_versions:
  - name: k8saudit
    version: 0.1.0
    alternatives:
      - name: k8saudit-other
        version: 0.4.0
  - name: json
    version: 0.3.0
    alternatives:
      - name: json2
        version: 0.1.0
- required_plugin_versions:
  - name: k8saudit
    version: 1.0.0
    alternatives:
      - name: k8saudit-other
        version: 0.7.0
        )")) << error
	     << std::endl;
}

TEST(PluginRequirements, check_plugin_requirements_reject)
{
	std::string error;

	/* No plugin loaded */
	ASSERT_FALSE(check_requirements(error, {}, R"(
- required_plugin_versions:
  - name: k8saudit
    version: 0.1.0
        )")) << error
	     << std::endl;

	/* Single plugin wrong name */
	ASSERT_FALSE(check_requirements(error, {{"k8saudit", "0.1.0"}}, R"(
- required_plugin_versions:
  - name: k8saudit2
    version: 0.1.0
        )")) << error
	     << std::endl;

	/* Single plugin wrong version */
	ASSERT_FALSE(check_requirements(error, {{"k8saudit", "0.1.0"}}, R"(
- required_plugin_versions:
  - name: k8saudit
    version: 0.2.0
        )")) << error
	     << std::endl;

	/* Multiple plugins */
	ASSERT_FALSE(check_requirements(error, {{"k8saudit", "0.1.0"}}, R"(
- required_plugin_versions:
  - name: k8saudit
    version: 0.1.0
  - name: json
    version: 0.3.0
        )")) << error
	     << std::endl;

	/* Single plugin multiple versions */
	ASSERT_FALSE(check_requirements(error, {{"k8saudit", "0.1.0"}}, R"(
- required_plugin_versions:
  - name: k8saudit
    version: 0.1.0
- required_plugin_versions:
  - name: k8saudit
    version: 0.2.0
        )")) << error
	     << std::endl;

	/* Single plugin with alternatives */
	ASSERT_FALSE(check_requirements(error, {{"k8saudit2", "0.5.0"}}, R"(
- required_plugin_versions:
  - name: k8saudit
    version: 0.1.0
    alternatives:
      - name: k8saudit-other
        version: 0.4.0
        )")) << error
	     << std::endl;

	/* Single plugin with overlapping alternatives */
	ASSERT_FALSE(check_requirements(error, {{"k8saudit", "0.5.0"}}, R"(
- required_plugin_versions:
  - name: k8saudit
    version: 0.1.0
    alternatives:
      - name: k8saudit
        version: 0.4.0
        )")) << error
	     << std::endl;

	/* Multiple plugins with alternatives */
	ASSERT_FALSE(check_requirements(error, {{"k8saudit-other", "0.5.0"}, {"json3", "0.5.0"}}, R"(
- required_plugin_versions:
  - name: k8saudit
    version: 0.1.0
    alternatives:
      - name: k8saudit-other
        version: 0.4.0
  - name: json
    version: 0.3.0
    alternatives:
      - name: json2
        version: 0.1.0
        )")) << error
	     << std::endl;

	/* Multiple plugins with alternatives with multiple versions */
	ASSERT_FALSE(check_requirements(error, {{"k8saudit", "0.7.0"}, {"json2", "0.5.0"}}, R"(
- required_plugin_versions:
  - name: k8saudit
    version: 0.4.0
    alternatives:
      - name: k8saudit-other
        version: 0.4.0
  - name: json
    version: 0.3.0
    alternatives:
      - name: json2
        version: 0.1.0
- required_plugin_versions:
  - name: k8saudit
    version: 1.0.0
    alternatives:
      - name: k8saudit-other
        version: 0.7.0
        )")) << error
	     << std::endl;
}
