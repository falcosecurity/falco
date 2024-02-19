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

#include <gtest/gtest.h>

#include <falco_engine.h>
#include <evttype_index_ruleset.h>

static std::string syscall_source_name = "syscall";

// A variant of evttype_index_ruleset_factory that uses a singleton
// for the underlying ruleset. This allows testing of
// ruleset_for_source

namespace
{
class test_ruleset_factory : public evttype_index_ruleset_factory
{
public:
	explicit test_ruleset_factory(std::shared_ptr<sinsp_filter_factory> factory):
		evttype_index_ruleset_factory(factory)
	{
		ruleset = evttype_index_ruleset_factory::new_ruleset();
	}

	virtual ~test_ruleset_factory() = default;

	inline std::shared_ptr<filter_ruleset> new_ruleset() override
	{
		return ruleset;
	}

	std::shared_ptr<filter_ruleset> ruleset;
};
}; // namespace

TEST(AddSource, basic)
{
	falco_engine engine;
	sinsp inspector;
	sinsp_filter_check_list filterchecks;

	auto filter_factory = std::make_shared<sinsp_filter_factory>(&inspector, filterchecks);
	auto formatter_factory = std::make_shared<sinsp_evt_formatter_factory>(&inspector, filterchecks);
	auto ruleset_factory = std::make_shared<test_ruleset_factory>(filter_factory);

	falco_source syscall_source;
	syscall_source.name = syscall_source_name;
	syscall_source.ruleset = ruleset_factory->new_ruleset();
	syscall_source.ruleset_factory = ruleset_factory;
	syscall_source.filter_factory = filter_factory;
	syscall_source.formatter_factory = formatter_factory;

	size_t source_idx = engine.add_source(syscall_source_name,
					      filter_factory,
					      formatter_factory,
					      ruleset_factory);

	ASSERT_TRUE(engine.is_source_valid(syscall_source_name));

	ASSERT_EQ(engine.filter_factory_for_source(syscall_source_name), filter_factory);
	ASSERT_EQ(engine.filter_factory_for_source(source_idx), filter_factory);

	ASSERT_EQ(engine.formatter_factory_for_source(syscall_source_name), formatter_factory);
	ASSERT_EQ(engine.formatter_factory_for_source(source_idx), formatter_factory);

	ASSERT_EQ(engine.ruleset_factory_for_source(syscall_source_name), ruleset_factory);
	ASSERT_EQ(engine.ruleset_factory_for_source(source_idx), ruleset_factory);

	ASSERT_EQ(engine.ruleset_for_source(syscall_source_name), ruleset_factory->ruleset);
	ASSERT_EQ(engine.ruleset_for_source(source_idx), ruleset_factory->ruleset);
}
