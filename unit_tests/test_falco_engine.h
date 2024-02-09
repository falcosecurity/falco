#pragma once

#include <gtest/gtest.h>

#include "falco_engine.h"
#include "rule_loader_reader.h"
#include "rule_loader_compiler.h"
#include "rule_loading_messages.h"

class test_falco_engine : public ::testing::Test {
protected:
	void SetUp() override
	{
		m_sample_ruleset = "sample-ruleset";
		m_sample_source = falco_common::syscall_source;

		// create a falco engine ready to load the ruleset
		m_inspector.reset(new sinsp());
		m_engine.reset(new falco_engine());
		m_filter_factory = std::shared_ptr<sinsp_filter_factory>(
			new sinsp_filter_factory(m_inspector.get(), m_filterlist));
		m_formatter_factory = std::shared_ptr<sinsp_evt_formatter_factory>(
			new sinsp_evt_formatter_factory(m_inspector.get(), m_filterlist));
		m_engine->add_source(m_sample_source, m_filter_factory, m_formatter_factory);
	}

	void TearDown() override
	{

	}

	bool load_rules(std::string rules_content, std::string rules_filename)
	{
		bool ret = false;
		falco::load_result::rules_contents_t rc = {{rules_filename, rules_content}};
		m_load_result = m_engine->load_rules(rules_content, rules_filename);
		m_load_result_string = m_load_result->as_string(true, rc);
		m_load_result_json = m_load_result->as_json(rc);
		ret = m_load_result->successful();

		if (ret)
		{
			m_engine->enable_rule("", true, m_sample_ruleset);
		}

		return ret;
	}

	// This must be kept in line with the (private) falco_engine::s_default_ruleset
	uint64_t num_rules_for_ruleset(std::string ruleset = "falco-default-ruleset")
	{
		return m_engine->num_rules_for_ruleset(ruleset);
	}

	bool has_warnings()
	{
		return m_load_result->has_warnings();
	}

	bool check_warning_message(std::string warning_msg)
	{
		if(!m_load_result->has_warnings())
		{
			return false;
		}

		for(auto &warn : m_load_result_json["warnings"])
		{
			std::string msg = warn["message"];
			// Debug:
			// printf("msg: %s\n", msg.c_str());
			if(msg.find(warning_msg) != std::string::npos)
			{
				return true;
			}
		}

		return false;
	}

	bool check_error_message(std::string error_msg)
	{
		// if the loading is successful there are no errors
		if(m_load_result->successful())
		{
			return false;
		}

		for(auto &err : m_load_result_json["errors"])
		{
			std::string msg = err["message"];
			// Debug:
			// printf("msg: %s\n", msg.c_str());
			if(msg.find(error_msg) != std::string::npos)
			{
				return true;
			}
		}

		return false;
	}

	std::string get_compiled_rule_condition(std::string rule_name = "")
	{
		auto rule_description = m_engine->describe_rule(&rule_name, {});
		return rule_description["rules"][0]["details"]["condition_compiled"].template get<std::string>();
	}

	std::string m_sample_ruleset;
	std::string m_sample_source;
	sinsp_filter_check_list m_filterlist;
	std::shared_ptr<sinsp_filter_factory> m_filter_factory;
	std::shared_ptr<sinsp_evt_formatter_factory> m_formatter_factory;
	std::unique_ptr<falco_engine> m_engine;
	std::unique_ptr<falco::load_result> m_load_result;
	std::string m_load_result_string;
	nlohmann::json m_load_result_json;
	std::unique_ptr<sinsp> m_inspector;
};
