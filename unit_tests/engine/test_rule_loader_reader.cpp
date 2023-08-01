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

TEST(RuleLoaderReader, append_merge_override_enabled)
{
    auto engine1 = mock_engine();
    engine1->load_rules_file("../unit_tests/falco_rules_test1.yaml");
    auto rules1 = engine1->get_rules();
    std::unordered_set<std::string> rules_names = {};
    std::unordered_set<std::string> expected_rules_names = {"Dummy Rule 0", "Dummy Rule 1", "Dummy Rule 2", "Dummy Rule 4 Disabled"};
    std::unordered_set<std::string> not_expected_rules_names = {"Dummy Rule 3 Invalid"};
    ASSERT_EQ(rules1.size(), N_VALID_TEST_RULES_FALCO_RULES_TEST_YAML);

    for(const auto& r : rules1)
    {
        rules_names.insert(r.name);
        if (r.name.compare(std::string("Dummy Rule 0")) == 0)
        {
            // Test condition where we append to tags, cond and output
            ASSERT_TRUE(r.enabled);
            std::set<std::string> some_desired_tags = {"maturity_stable", "test1", "test2"};
            ASSERT_CONTAINS(r.tags, some_desired_tags);
            ASSERT_STRING_EQUAL(r.cond, std::string("evt.type in (execve, execveat) and proc.name=cat and proc.cmdline contains test"));
            ASSERT_STRING_EQUAL(r.output, std::string("%evt.type %evt.num %proc.aname[5] %proc.name %proc.tty %proc.exepath %fd.name proc_exeline=%proc.exeline proc_exepath=%proc.exepath"));
            ASSERT_EQ(r.priority, falco_common::priority_type::PRIORITY_CRITICAL);
        }
        else if (r.name.compare(std::string("Dummy Rule 1")) == 0)
        {
            // Test rules merging aka override only re-defined keys, else keep old keys
            std::set<std::string> some_desired_tags = {"maturity_incubating", "host", "container"};  // ensure prev definition
            ASSERT_STRING_EQUAL(r.desc, std::string("My test desc 1"));  // ensure prev definition
            ASSERT_EQ(r.priority, falco_common::priority_type::PRIORITY_CRITICAL);  // ensure prev definition
            ASSERT_CONTAINS(r.tags, some_desired_tags);
            ASSERT_STRING_EQUAL(r.cond, std::string("evt.type in (ptrace)"));  // ensure new definition
            ASSERT_STRING_EQUAL(r.output, std::string("%evt.type %evt.num"));  // ensure new definition
            ASSERT_FALSE(r.enabled);  // ensure new definition
        }
        else if (r.name.compare(std::string("Dummy Rule 2")) == 0)
        {
            // Test where we have overridden a rule to ONLY NOT be enabled
            ASSERT_EQ(r.priority, falco_common::priority_type::PRIORITY_NOTICE);
            ASSERT_FALSE(r.enabled);
        }
        else if (r.name.compare(std::string("Dummy Rule 4 Disabled")) == 0)
        {
            // Test if entire rule defined just once is disabled
            ASSERT_FALSE(r.enabled);
        }
    }
    ASSERT_CONTAINS(rules_names, expected_rules_names);
    ASSERT_NOT_CONTAINS(rules_names, not_expected_rules_names);
}
