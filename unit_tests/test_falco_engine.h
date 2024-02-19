#pragma once

#include "falco_engine.h"
#include "rule_loader_reader.h"
#include "rule_loader_compiler.h"
#include "rule_loading_messages.h"

#include <gtest/gtest.h>

class test_falco_engine : public testing::Test
{
protected:
	test_falco_engine();

	bool load_rules(const std::string& rules_content, const std::string& rules_filename);
	// This must be kept in line with the (private) falco_engine::s_default_ruleset
	uint64_t num_rules_for_ruleset(const std::string& ruleset = "falco-default-ruleset");
	bool has_warnings() const;
	bool check_warning_message(const std::string& warning_msg) const;
	bool check_error_message(const std::string& error_msg) const;
	std::string get_compiled_rule_condition(std::string rule_name = "") const;

	std::string m_sample_ruleset = "sample-ruleset";
	std::string m_sample_source = falco_common::syscall_source;
	sinsp m_inspector;
	sinsp_filter_check_list m_filterlist;
	std::shared_ptr<sinsp_filter_factory> m_filter_factory;
	std::shared_ptr<sinsp_evt_formatter_factory> m_formatter_factory;
	std::shared_ptr<falco_engine> m_engine;
	std::unique_ptr<falco::load_result> m_load_result;
	std::string m_load_result_string;
	nlohmann::json m_load_result_json;
};
