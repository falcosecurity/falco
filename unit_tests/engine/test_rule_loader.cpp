#include <gtest/gtest.h>

#include "falco_engine.h"
#include "rule_loader_reader.h"
#include "rule_loader_compiler.h"

class engine_loader_test : public ::testing::Test {
protected:
	void SetUp() override
	{
		m_sample_ruleset = "sample-ruleset";
		m_sample_source = falco_common::syscall_source;

		// create a falco engine ready to load the ruleset
		m_inspector.reset(new sinsp());
		m_engine.reset(new falco_engine());
		m_filter_factory = std::shared_ptr<gen_event_filter_factory>(
			new sinsp_filter_factory(m_inspector.get(), m_filterlist));
		m_formatter_factory = std::shared_ptr<gen_event_formatter_factory>(
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

	std::string m_sample_ruleset;
	std::string m_sample_source;
	sinsp_filter_check_list m_filterlist;
	std::shared_ptr<gen_event_filter_factory> m_filter_factory;
	std::shared_ptr<gen_event_formatter_factory> m_formatter_factory;
	std::unique_ptr<falco_engine> m_engine;
	std::unique_ptr<falco::load_result> m_load_result;
	std::string m_load_result_string;
	nlohmann::json m_load_result_json;
	std::unique_ptr<sinsp> m_inspector;
};

std::string s_sample_ruleset = "sample-ruleset";
std::string s_sample_source = falco_common::syscall_source;

TEST_F(engine_loader_test, list_append)
{
    std::string rules_content = R"END(
- list: shell_binaries
  items: [ash, bash, csh, ksh, sh, tcsh, zsh, dash]

- rule: legit_rule
  desc: legit rule description
  condition: evt.type=open and proc.name in (shell_binaries)
  output: user=%user.name command=%proc.cmdline file=%fd.name
  priority: INFO

- list: shell_binaries
  items: [pwsh]
  override:
    items: append
)END";

	std::string rule_name = "legit_rule";
	ASSERT_TRUE(load_rules(rules_content, "legit_rules.yaml")) << m_load_result_string;

	auto rule_description = m_engine->describe_rule(&rule_name, {});
	ASSERT_EQ(rule_description["rules"][0]["details"]["condition_compiled"].template get<std::string>(),
		"(evt.type = open and proc.name in (ash, bash, csh, ksh, sh, tcsh, zsh, dash, pwsh))");
}

TEST_F(engine_loader_test, condition_append)
{
    std::string rules_content = R"END(
- macro: interactive
  condition: >
    ((proc.aname=sshd and proc.name != sshd) or
    proc.name=systemd-logind or proc.name=login)

- rule: legit_rule
  desc: legit rule description
  condition: evt.type=open and interactive
  output: user=%user.name command=%proc.cmdline file=%fd.name
  priority: INFO

- macro: interactive
  condition: or proc.name = ssh
  override:
    condition: append
)END";

	std::string rule_name = "legit_rule";
	ASSERT_TRUE(load_rules(rules_content, "legit_rules.yaml")) << m_load_result_string;

	auto rule_description = m_engine->describe_rule(&rule_name, {});
	ASSERT_EQ(rule_description["rules"][0]["details"]["condition_compiled"].template get<std::string>(),
		"(evt.type = open and (((proc.aname = sshd and proc.name != sshd) or proc.name = systemd-logind or proc.name = login) or proc.name = ssh))");
}

TEST_F(engine_loader_test, rule_override_append)
{
    std::string rules_content = R"END(
- rule: legit_rule
  desc: legit rule description
  condition: evt.type=open
  output: user=%user.name command=%proc.cmdline file=%fd.name
  priority: INFO

- rule: legit_rule
  desc: with append
  condition: and proc.name = cat
  output: proc=%proc.name
  override:
    desc: append
    condition: append
    output: append
)END";

	std::string rule_name = "legit_rule";
	ASSERT_TRUE(load_rules(rules_content, "legit_rules.yaml")) << m_load_result_string;

	auto rule_description = m_engine->describe_rule(&rule_name, {});
	ASSERT_EQ(rule_description["rules"][0]["info"]["condition"].template get<std::string>(),
	 	"evt.type=open and proc.name = cat");

	ASSERT_EQ(rule_description["rules"][0]["info"]["output"].template get<std::string>(),
	 	"user=%user.name command=%proc.cmdline file=%fd.name proc=%proc.name");

	ASSERT_EQ(rule_description["rules"][0]["info"]["description"].template get<std::string>(),
	 	"legit rule description with append");
}


TEST_F(engine_loader_test, rule_append)
{
    std::string rules_content = R"END(
- rule: legit_rule
  desc: legit rule description
  condition: evt.type=open
  output: user=%user.name command=%proc.cmdline file=%fd.name
  priority: INFO

- rule: legit_rule
  condition: and proc.name = cat
  append: true
)END";

	std::string rule_name = "legit_rule";
	ASSERT_TRUE(load_rules(rules_content, "legit_rules.yaml")) << m_load_result_string;

	auto rule_description = m_engine->describe_rule(&rule_name, {});
	ASSERT_EQ(rule_description["rules"][0]["details"]["condition_compiled"].template get<std::string>(),
	 	"(evt.type = open and proc.name = cat)");
}


TEST_F(engine_loader_test, rule_override_replace)
{
    std::string rules_content = R"END(
- rule: legit_rule
  desc: legit rule description
  condition: evt.type=open
  output: user=%user.name command=%proc.cmdline file=%fd.name
  priority: INFO

- rule: legit_rule
  desc: a replaced legit description
  condition: evt.type = close
  override:
    desc: replace
    condition: replace
)END";

	std::string rule_name = "legit_rule";
	ASSERT_TRUE(load_rules(rules_content, "legit_rules.yaml")) << m_load_result_string;

	auto rule_description = m_engine->describe_rule(&rule_name, {});
	ASSERT_EQ(rule_description["rules"][0]["info"]["condition"].template get<std::string>(),
	 	"evt.type = close");

	ASSERT_EQ(rule_description["rules"][0]["info"]["output"].template get<std::string>(),
	 	"user=%user.name command=%proc.cmdline file=%fd.name");

	ASSERT_EQ(rule_description["rules"][0]["info"]["description"].template get<std::string>(),
	 	"a replaced legit description");
}

TEST_F(engine_loader_test, rule_override_append_replace)
{
    std::string rules_content = R"END(
- rule: legit_rule
  desc: legit rule description
  condition: evt.type = close
  output: user=%user.name command=%proc.cmdline file=%fd.name
  priority: INFO

- rule: legit_rule
  desc: a replaced legit description
  condition: and proc.name = cat
  priority: WARNING
  override:
    desc: replace
    condition: append
    priority: replace
)END";

	std::string rule_name = "legit_rule";
	ASSERT_TRUE(load_rules(rules_content, "legit_rules.yaml")) << m_load_result_string;

	auto rule_description = m_engine->describe_rule(&rule_name, {});
	ASSERT_EQ(rule_description["rules"][0]["info"]["condition"].template get<std::string>(),
	 	"evt.type = close and proc.name = cat");

	ASSERT_EQ(rule_description["rules"][0]["info"]["output"].template get<std::string>(),
	 	"user=%user.name command=%proc.cmdline file=%fd.name");

	ASSERT_EQ(rule_description["rules"][0]["info"]["description"].template get<std::string>(),
	 	"a replaced legit description");

	ASSERT_EQ(rule_description["rules"][0]["info"]["priority"].template get<std::string>(),
	 	"Warning");
}

TEST_F(engine_loader_test, rule_incorrect_override_type)
{
    std::string rules_content = R"END(
- rule: failing_rule
  desc: legit rule description
  condition: evt.type = close
  output: user=%user.name command=%proc.cmdline file=%fd.name
  priority: INFO

- rule: failing_rule
  desc: an appended incorrect field
  condition: and proc.name = cat
  priority: WARNING
  override:
    desc: replace
    condition: append
    priority: append
)END";

	std::string rule_name = "failing_rule";

	ASSERT_FALSE(load_rules(rules_content, "rules.yaml"));
	ASSERT_EQ(m_load_result_json["errors"][0]["message"], "Key 'priority' cannot be appended to, use 'replace' instead");
	ASSERT_TRUE(std::string(m_load_result_json["errors"][0]["context"]["snippet"]).find("priority: append") != std::string::npos);
}

TEST_F(engine_loader_test, rule_incorrect_append_override)
{
    std::string rules_content = R"END(
- rule: failing_rule
  desc: legit rule description
  condition: evt.type = close
  output: user=%user.name command=%proc.cmdline file=%fd.name
  priority: INFO

- rule: failing_rule
  desc: an appended incorrect field
  condition: and proc.name = cat
  append: true
  override:
    desc: replace
    condition: append
)END";

	std::string rule_name = "failing_rule";

	ASSERT_FALSE(load_rules(rules_content, "rules.yaml"));
	ASSERT_TRUE(std::string(m_load_result_json["errors"][0]["message"]).find("'override' and 'append: true' cannot be used together") != std::string::npos);
}

TEST_F(engine_loader_test, rule_override_without_rule)
{
    std::string rules_content = R"END(
- rule: failing_rule
  desc: an appended field
  condition: and proc.name = cat
  override:
    desc: replace
    condition: append
)END";

	std::string rule_name = "failing_rule";

	ASSERT_FALSE(load_rules(rules_content, "rules.yaml"));
	ASSERT_TRUE(std::string(m_load_result_json["errors"][0]["message"]).find("no rule by that name already exists") != std::string::npos);
}

TEST_F(engine_loader_test, rule_override_without_field)
{
    std::string rules_content = R"END(
- rule: failing_rule
  desc: legit rule description
  condition: evt.type = close
  output: user=%user.name command=%proc.cmdline file=%fd.name
  priority: INFO

- rule: failing_rule
  desc: an appended incorrect field
  override:
    desc: replace
    condition: append
)END";

	std::string rule_name = "failing_rule";

	ASSERT_FALSE(load_rules(rules_content, "rules.yaml"));
	ASSERT_EQ(m_load_result_json["errors"][0]["message"], "An append override for 'condition' was specified but 'condition' is not defined");
}

TEST_F(engine_loader_test, rule_override_extra_field)
{
    std::string rules_content = R"END(
- rule: failing_rule
  desc: legit rule description
  condition: evt.type = close
  output: user=%user.name command=%proc.cmdline file=%fd.name
  priority: INFO

- rule: failing_rule
  desc: an appended incorrect field
  condition: and proc.name = cat
  priority: WARNING
  override:
    desc: replace
    condition: append
)END";

	std::string rule_name = "failing_rule";

	ASSERT_FALSE(load_rules(rules_content, "rules.yaml"));
	ASSERT_TRUE(std::string(m_load_result_json["errors"][0]["message"]).find("Unexpected key 'priority'") != std::string::npos);
}
