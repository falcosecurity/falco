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

#include <falco_engine.h>
#include <falco/app/app.h>
#include "engine_helper.h"
#include <gtest/gtest.h>

static std::shared_ptr<falco_engine> mock_engine()
{
	// Create a mock Falco engine
	std::shared_ptr<falco_engine> engine(new falco_engine());
	auto filter_factory = std::shared_ptr<gen_event_filter_factory>(
			new sinsp_filter_factory(nullptr));
	auto formatter_factory = std::shared_ptr<gen_event_formatter_factory>(
			new sinsp_evt_formatter_factory(nullptr));
	engine->add_source("syscall", filter_factory, formatter_factory);
	return engine;
}

auto engine = mock_engine();

TEST(RuleLoaderReader, append_override_enabled)
{
    engine->load_rules_file("../unit_tests/falco_rules_test1.yaml");
    auto rules = engine->get_rules();
    std::unordered_set<std::string> rules_names = {};
    std::unordered_set<std::string> expected_rules_names = {"Dummy Rule 0", "Dummy Rule 1", "Dummy Rule 2"};
    ASSERT_EQ(rules.size(), N_TEST_RULES_FALCO_RULES_TEST_YAML);

    for(const auto& r : rules)
    {
        rules_names.insert(r.name);
        if (r.name.compare(std::string("Dummy Rule 0")) == 0)
        {
            // Test condition where we append to tags, cond and output
            ASSERT_TRUE(r.enabled);
            std::set<std::string> some_desired_tags = {"test1", "test2"};
            ASSERT_CONTAINS(r.tags, some_desired_tags);
            ASSERT_STRING_EQUAL(r.cond, std::string("evt.type in (execve, execveat) and proc.name=cat and proc.cmdline contains test"));
            ASSERT_STRING_EQUAL(r.output, std::string("%evt.type %evt.num %proc.aname[5] %proc.name %proc.tty %proc.exepath %fd.name proc_exeline=%proc.exeline proc_exepath=%proc.exepath"));
        }
        else if (r.name.compare(std::string("Dummy Rule 1")) == 0)
        {
            ASSERT_TRUE(r.enabled);
        }
        else if (r.name.compare(std::string("Dummy Rule 2")) == 0)
        {
            // Test where we have overridden a rule to NOT be enabled
            ASSERT_FALSE(r.enabled);
        }
    }
    ASSERT_CONTAINS(rules_names, expected_rules_names);
}
