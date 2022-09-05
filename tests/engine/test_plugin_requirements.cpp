/*
Copyright (C) 2022 The Falco Authors.

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
#include <catch.hpp>
#include "falco_engine.h"

static void check_requirements(
        bool expect_success,
        const std::vector<falco_engine::plugin_version_requirement>& plugins,
        const std::string& ruleset_content)
{
    std::string err;
    std::unique_ptr<falco_engine> e(new falco_engine());
    falco::load_result::rules_contents_t c = {{"test", ruleset_content}};

    auto res = e->load_rules(c.begin()->second, c.begin()->first);
    if (!res->successful())
    {
        if (expect_success)
        {
            FAIL(res->as_string(false, c));
        }
        return;
    }

    if (!e->check_plugin_requirements(plugins, err))
    {
        if (expect_success)
        {
            FAIL(err);
        }
    }
    else if (!expect_success)
    {
        FAIL("unexpected successful plugin requirements check");
    }
}

TEST_CASE("check_plugin_requirements must accept", "[rule_loader]")
{
    SECTION("no requirement")
    {
        check_requirements(true, {{"k8saudit", "0.1.0"}}, "");
    }

    SECTION("single plugin")
    {
        check_requirements(true, {{"k8saudit", "0.1.0"}}, R"(
- required_plugin_versions:
  - name: k8saudit
    version: 0.1.0
        )");
    }

    SECTION("single plugin newer version")
    {
        check_requirements(true, {{"k8saudit", "0.2.0"}}, R"(
- required_plugin_versions:
  - name: k8saudit
    version: 0.1.0
        )");
    }

    SECTION("multiple plugins")
    {
        check_requirements(true, {{"k8saudit", "0.1.0"}, {"json", "0.3.0"}}, R"(
- required_plugin_versions:
  - name: k8saudit
    version: 0.1.0
  - name: json
    version: 0.3.0
        )");
    }

    SECTION("single plugin multiple versions")
    {
        check_requirements(true, {{"k8saudit", "0.2.0"}}, R"(
- required_plugin_versions:
  - name: k8saudit
    version: 0.1.0
- required_plugin_versions:
  - name: k8saudit
    version: 0.2.0
        )");
    }

    SECTION("single plugin with alternatives")
    {
        check_requirements(true, {{"k8saudit-other", "0.5.0"}}, R"(
- required_plugin_versions:
  - name: k8saudit
    version: 0.1.0
    alternatives:
      - name: k8saudit-other
        version: 0.4.0
        )");
    }

    SECTION("multiple plugins with alternatives")
    {
        check_requirements(true, {{"k8saudit-other", "0.5.0"}, {"json2", "0.5.0"}}, R"(
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
        )");
    }

    SECTION("multiple plugins with alternatives with multiple versions")
    {
        check_requirements(true, {{"k8saudit-other", "0.7.0"}, {"json2", "0.5.0"}}, R"(
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
        )");
    }
}

TEST_CASE("check_plugin_requirements must reject", "[rule_loader]")
{
    SECTION("no plugin loaded")
    {
        check_requirements(false, {}, R"(
- required_plugin_versions:
  - name: k8saudit
    version: 0.1.0
        )");
    }
    
    SECTION("single plugin wrong name")
    {
        check_requirements(false, {{"k8saudit", "0.1.0"}}, R"(
- required_plugin_versions:
  - name: k8saudit2
    version: 0.1.0
        )");
    }

    SECTION("single plugin wrong version")
    {
        check_requirements(false, {{"k8saudit", "0.1.0"}}, R"(
- required_plugin_versions:
  - name: k8saudit
    version: 0.2.0
        )");
    }

    SECTION("multiple plugins")
    {
        check_requirements(false, {{"k8saudit", "0.1.0"}}, R"(
- required_plugin_versions:
  - name: k8saudit
    version: 0.1.0
  - name: json
    version: 0.3.0
        )");
    }

    SECTION("single plugin multiple versions")
    {
        check_requirements(false, {{"k8saudit", "0.1.0"}}, R"(
- required_plugin_versions:
  - name: k8saudit
    version: 0.1.0
- required_plugin_versions:
  - name: k8saudit
    version: 0.2.0
        )");
    }

    SECTION("single plugin with alternatives")
    {
        check_requirements(false, {{"k8saudit2", "0.5.0"}}, R"(
- required_plugin_versions:
  - name: k8saudit
    version: 0.1.0
    alternatives:
      - name: k8saudit-other
        version: 0.4.0
        )");
    }

    SECTION("single plugin with overlapping alternatives")
    {
        check_requirements(false, {{"k8saudit", "0.5.0"}}, R"(
- required_plugin_versions:
  - name: k8saudit
    version: 0.1.0
    alternatives:
      - name: k8saudit
        version: 0.4.0
        )");
    }

    SECTION("multiple plugins with alternatives")
    {
        check_requirements(false, {{"k8saudit-other", "0.5.0"}, {"json3", "0.5.0"}}, R"(
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
        )");
    }

    SECTION("multiple plugins with alternatives with multiple versions")
    {
        check_requirements(false, {{"k8saudit", "0.7.0"}, {"json2", "0.5.0"}}, R"(
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
        )");
    }
}
