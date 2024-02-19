#include "test_falco_engine.h"

test_falco_engine::test_falco_engine()
{
	// create a falco engine ready to load the ruleset
	m_filter_factory = std::make_shared<sinsp_filter_factory>(&m_inspector, m_filterlist);
	m_formatter_factory = std::make_shared<sinsp_evt_formatter_factory>(&m_inspector, m_filterlist);
	m_engine = std::make_shared<falco_engine>();
	m_engine->add_source(m_sample_source, m_filter_factory, m_formatter_factory);
}

bool test_falco_engine::load_rules(const std::string& rules_content, const std::string& rules_filename)
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
uint64_t test_falco_engine::num_rules_for_ruleset(const std::string& ruleset)
{
	return m_engine->num_rules_for_ruleset(ruleset);
}

bool test_falco_engine::has_warnings() const
{
	return m_load_result->has_warnings();
}

bool test_falco_engine::check_warning_message(const std::string& warning_msg) const
{
	if(!m_load_result->has_warnings())
	{
		return false;
	}

	for(const auto &warn : m_load_result_json["warnings"])
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

bool test_falco_engine::check_error_message(const std::string& error_msg) const
{
	// if the loading is successful there are no errors
	if(m_load_result->successful())
	{
		return false;
	}

	for(const auto &err : m_load_result_json["errors"])
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

std::string test_falco_engine::get_compiled_rule_condition(std::string rule_name) const
{
	auto rule_description = m_engine->describe_rule(&rule_name, {});
	return rule_description["rules"][0]["details"]["condition_compiled"].template get<std::string>();
}
