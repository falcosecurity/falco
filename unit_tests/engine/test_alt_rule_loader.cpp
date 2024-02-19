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

#include <string>

#include <gtest/gtest.h>

#include <sinsp.h>
#include <filter_check_list.h>
#include <filter.h>
#include <eventformatter.h>

#include <falco_engine.h>
#include "indexed_vector.h"
#include "evttype_index_ruleset.h"

#include "rule_loader_reader.h"
#include "rule_loader_collector.h"
#include "rule_loader_compiler.h"

namespace
{

struct test_object_info
{
	std::string name;
	std::string property;
};

struct test_compile_output : public rule_loader::compile_output
{
	test_compile_output() = default;
	~test_compile_output() = default;

	std::set<std::string> defined_test_properties;
};

class test_compiler : public rule_loader::compiler
{
public:
	test_compiler() = default;
	virtual ~test_compiler() = default;

	std::unique_ptr<rule_loader::compile_output> new_compile_output() override
	{
		return std::make_unique<test_compile_output>();
	}

	void compile(
		rule_loader::configuration& cfg,
		const rule_loader::collector& col,
		rule_loader::compile_output& out) const override;
};

class test_collector : public rule_loader::collector
{
public:
	test_collector() = default;
	virtual ~test_collector() = default;

	indexed_vector<test_object_info> test_object_infos;
};

class test_reader : public rule_loader::reader
{
public:
	test_reader() = default;
	virtual ~test_reader() = default;

protected:
	rule_loader::context create_context(const YAML::Node& item,
					    const rule_loader::context& parent)
	{
		return rule_loader::context(item,
					    rule_loader::context::EXTENSION_ITEM,
					    "test object",
					    parent);
	};

	void read_item(rule_loader::configuration& cfg,
		       rule_loader::collector& collector,
		       const YAML::Node& item,
		       const rule_loader::context& parent) override
	{
		test_collector& test_col =
			dynamic_cast<test_collector&>(collector);

		if(item["test_object"].IsDefined())
		{
			rule_loader::context tmp = create_context(item, parent);
			test_object_info obj;
			std::string name;
			std::string property;

			decode_val(item, "test_object", name, tmp);
			decode_val(item, "property", property, tmp);

			obj.name = name;
			obj.property = property;

			test_col.test_object_infos.insert(obj, obj.name);
		}
		else
		{
			rule_loader::reader::read_item(cfg, collector, item, parent);
		}
	};
};

class test_ruleset : public evttype_index_ruleset
{
public:
	explicit test_ruleset(std::shared_ptr<sinsp_filter_factory> factory):
		evttype_index_ruleset(factory){};
	virtual ~test_ruleset() = default;

	void add_compile_output(
		const rule_loader::compile_output& compile_output,
		falco_common::priority_type min_priority,
		const std::string& source)
	{

		evttype_index_ruleset::add_compile_output(compile_output,
							  min_priority,
							  source);

		std::shared_ptr<filter_ruleset> ruleset;
		get_engine_state().get_ruleset(source, ruleset);
		EXPECT_EQ(this, ruleset.get());

		const test_compile_output& test_output =
			dynamic_cast<const test_compile_output&>(compile_output);

		defined_properties = test_output.defined_test_properties;
	};

	std::set<std::string> defined_properties;
};

class test_ruleset_factory : public filter_ruleset_factory
{
public:
	explicit test_ruleset_factory(std::shared_ptr<sinsp_filter_factory> factory):
		m_filter_factory(factory)
	{
	}

	virtual ~test_ruleset_factory() = default;

	inline std::shared_ptr<filter_ruleset> new_ruleset() override
	{
		return std::make_shared<test_ruleset>(m_filter_factory);
	}

	std::shared_ptr<sinsp_filter_factory> m_filter_factory;
};
}; // namespace

void test_compiler::compile(
	rule_loader::configuration& cfg,
	const rule_loader::collector& col,
	rule_loader::compile_output& out) const
{
	rule_loader::compiler::compile(cfg, col, out);

	const test_collector& test_col =
		dynamic_cast<const test_collector&>(col);

	test_compile_output& test_output =
		dynamic_cast<test_compile_output&>(out);

	for(auto& test_obj : test_col.test_object_infos)
	{
		test_output.defined_test_properties.insert(test_obj.property);
	}
}

static std::string content = R"END(

- test_object: test
  property: my-value

- test_object: test2
  property: other-value

- list: shell_binaries
  items: [sh, bash]

- macro: spawned_process
  condition: evt.type=execve and proc.name in (shell_binaries)

- rule: test info rule
  desc: A test info rule
  condition: spawned_process
  output: A test info rule matched (evt.type=%evt.type proc.name=%proc.name)
  priority: INFO
  source: syscall
  tags: [process]

- rule: test k8s_audit rule
  desc: A k8s audit test rule
  condition: ka.target.resource=deployments
  output: A k8s audit rule matched (ka.verb=%ka.verb resource=%ka.target.resource)
  priority: INFO
  source: k8s_audit
  tags: [process]

- rule: test debug rule
  desc: A test debug rule
  condition: spawned_process and proc.name="bash"
  output: A test debug rule matched (evt.type=%evt.type proc.name=%proc.name)
  priority: DEBUG
  source: syscall
  tags: [process]
)END";

static std::string syscall_source_name = "syscall";

static std::shared_ptr<rule_loader::configuration> create_configuration(sinsp& inspector,
									sinsp_filter_check_list& filterchecks,
									indexed_vector<falco_source>& sources)
{
	auto filter_factory = std::make_shared<sinsp_filter_factory>(&inspector, filterchecks);
	auto formatter_factory = std::make_shared<sinsp_evt_formatter_factory>(&inspector, filterchecks);
	auto ruleset_factory = std::make_shared<evttype_index_ruleset_factory>(filter_factory);

	falco_source syscall_source;
	syscall_source.name = syscall_source_name;
	syscall_source.ruleset = ruleset_factory->new_ruleset();
	syscall_source.ruleset_factory = ruleset_factory;
	syscall_source.filter_factory = filter_factory;
	syscall_source.formatter_factory = formatter_factory;

	sources.insert(syscall_source, syscall_source_name);

	return std::make_shared<rule_loader::configuration>(content,
	                                                    sources,
	                                                    "test configuration");
}

static void load_rules(sinsp& inspector,
		       sinsp_filter_check_list& filterchecks,
		       std::unique_ptr<rule_loader::compile_output>& compile_output,
		       indexed_vector<falco_source>& sources)
{
	std::shared_ptr<rule_loader::configuration> cfg = create_configuration(inspector, filterchecks, sources);

	rule_loader::reader reader;
	rule_loader::collector collector;
	rule_loader::compiler compiler;

	EXPECT_TRUE(reader.read(*(cfg.get()), collector));

	compile_output = compiler.new_compile_output();

	compiler.compile(*(cfg.get()), collector, *(compile_output.get()));
}

TEST(engine_loader_alt_loader, load_rules)
{
	sinsp inspector;
	sinsp_filter_check_list filterchecks;
	std::unique_ptr<rule_loader::compile_output> compile_output;
	indexed_vector<falco_source> sources;

	load_rules(inspector, filterchecks, compile_output, sources);

	// Note that the k8s_audit rule will be skipped as load_rules
	// only adds a syscall source.
	EXPECT_EQ(compile_output->lists.size(), 1);
	EXPECT_TRUE(compile_output->lists.at("shell_binaries") != nullptr);

	EXPECT_EQ(compile_output->macros.size(), 1);
	EXPECT_TRUE(compile_output->macros.at("spawned_process") != nullptr);

	EXPECT_EQ(compile_output->rules.size(), 2);
	EXPECT_TRUE(compile_output->rules.at("test info rule") != nullptr);
	EXPECT_TRUE(compile_output->rules.at("test debug rule") != nullptr);
}

TEST(engine_loader_alt_loader, pass_compile_output_to_ruleset)
{
	sinsp inspector;
	sinsp_filter_check_list filterchecks;
	std::unique_ptr<rule_loader::compile_output> compile_output;
	indexed_vector<falco_source> sources;

	load_rules(inspector, filterchecks, compile_output, sources);

	std::shared_ptr<filter_ruleset> ruleset = sources.at(syscall_source_name)->ruleset;

	ruleset->add_compile_output(*(compile_output.get()),
				    falco_common::PRIORITY_INFORMATIONAL,
				    syscall_source_name);

	// Enable all rules for a ruleset id. Because the compile
	// output contained one rule with priority >= INFO, that rule
	// should be enabled.
	bool match_exact = true;
	uint16_t ruleset_id = 0;
	ruleset->enable("", match_exact, ruleset_id);

	EXPECT_EQ(ruleset->enabled_count(ruleset_id), 1);
}

TEST(engine_loader_alt_loader, falco_engine_alternate_loader)
{
	falco_engine engine;
	sinsp inspector;
	sinsp_filter_check_list filterchecks;

	auto filter_factory = std::make_shared<sinsp_filter_factory>(&inspector, filterchecks);
	auto formatter_factory = std::make_shared<sinsp_evt_formatter_factory>(&inspector, filterchecks);
	auto ruleset_factory = std::make_shared<test_ruleset_factory>(filter_factory);

	engine.add_source(syscall_source_name, filter_factory, formatter_factory, ruleset_factory);

	auto reader = std::make_shared<test_reader>();
	auto collector = std::make_shared<test_collector>();
	auto compiler = std::make_shared<test_compiler>();

	engine.set_rule_reader(reader);
	engine.set_rule_collector(collector);
	engine.set_rule_compiler(compiler);

	EXPECT_EQ(reader, engine.get_rule_reader());
	EXPECT_EQ(collector, engine.get_rule_collector());
	EXPECT_EQ(compiler, engine.get_rule_compiler());

	engine.load_rules(content, "test_rules.yaml");

	EXPECT_EQ(collector->test_object_infos.size(), 2);

	std::shared_ptr<filter_ruleset> ruleset = engine.ruleset_for_source(syscall_source_name);
	std::set<std::string>& defined_properties = std::dynamic_pointer_cast<test_ruleset>(ruleset)->defined_properties;

	EXPECT_TRUE(defined_properties.find("my-value") != defined_properties.end());
	EXPECT_TRUE(defined_properties.find("other-value") != defined_properties.end());
	EXPECT_TRUE(defined_properties.find("not-exists-value") == defined_properties.end());
};
