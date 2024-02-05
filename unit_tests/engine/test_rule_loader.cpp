#include <gtest/gtest.h>

#include "falco_engine.h"
#include "rule_loader_reader.h"
#include "rule_loader_compiler.h"
#include "rule_loading_messages.h"

class engine_loader_test : public ::testing::Test {
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

	ASSERT_TRUE(load_rules(rules_content, "legit_rules.yaml")) << m_load_result_string;
	ASSERT_EQ(get_compiled_rule_condition("legit_rule"),"(evt.type = open and proc.name in (ash, bash, csh, ksh, sh, tcsh, zsh, dash, pwsh))");
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

	ASSERT_TRUE(load_rules(rules_content, "legit_rules.yaml")) << m_load_result_string;
	ASSERT_EQ(get_compiled_rule_condition("legit_rule"),"(evt.type = open and (((proc.aname = sshd and proc.name != sshd) or proc.name = systemd-logind or proc.name = login) or proc.name = ssh))");
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

	// Here we don't use the deprecated `append` flag, so we don't expect the warning.
	ASSERT_FALSE(check_warning_message(WARNING_APPEND));

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

	ASSERT_TRUE(load_rules(rules_content, "legit_rules.yaml")) << m_load_result_string;

	// We should have at least one warning because the 'append' flag is deprecated.
	ASSERT_TRUE(check_warning_message(WARNING_APPEND));

	ASSERT_EQ(get_compiled_rule_condition("legit_rule"),"(evt.type = open and proc.name = cat)");
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
	ASSERT_TRUE(check_error_message("Key 'priority' cannot be appended to, use 'replace' instead"));
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
	
	// We should have at least one warning because the 'append' flag is deprecated.
	ASSERT_TRUE(check_warning_message(WARNING_APPEND));
	
	ASSERT_TRUE(check_error_message(ERROR_OVERRIDE_APPEND));
}

TEST_F(engine_loader_test, macro_override_append_before_macro_definition)
{
    std::string rules_content = R"END(

- macro: open_simple
  condition: or evt.type = openat2
  override:
    condition: append

- macro: open_simple
  condition: evt.type in (open,openat)

- rule: test_rule
  desc: simple rule
  condition: open_simple
  output: command=%proc.cmdline
  priority: INFO

)END";

	// We cannot define a macro override before the macro definition.
	ASSERT_FALSE(load_rules(rules_content, "rules.yaml"));
	ASSERT_TRUE(check_error_message(ERROR_NO_PREVIOUS_MACRO));
}

TEST_F(engine_loader_test, macro_override_replace_before_macro_definition)
{
    std::string rules_content = R"END(

- macro: open_simple
  condition: or evt.type = openat2
  override:
    condition: replace

- macro: open_simple
  condition: evt.type in (open,openat)

- rule: test_rule
  desc: simple rule
  condition: open_simple
  output: command=%proc.cmdline
  priority: INFO

)END";

	// The first override defines a macro that is overridden by the second macro definition
	ASSERT_TRUE(load_rules(rules_content, "rules.yaml"));
	ASSERT_EQ(get_compiled_rule_condition("test_rule"),"evt.type in (open, openat)");	
}

TEST_F(engine_loader_test, macro_append_before_macro_definition)
{
    std::string rules_content = R"END(

- macro: open_simple
  condition: or evt.type = openat2
  append: true

- macro: open_simple
  condition: evt.type in (open,openat)

- rule: test_rule
  desc: simple rule
  condition: open_simple
  output: command=%proc.cmdline
  priority: INFO

)END";

	// We cannot define a macro override before the macro definition.
	ASSERT_FALSE(load_rules(rules_content, "rules.yaml"));
	ASSERT_TRUE(check_error_message(ERROR_NO_PREVIOUS_MACRO));
}

TEST_F(engine_loader_test, macro_override_append_after_macro_definition)
{
    std::string rules_content = R"END(

- macro: open_simple
  condition: evt.type in (open,openat)

- macro: open_simple
  condition: or evt.type = openat2
  override:
    condition: append

- rule: test_rule
  desc: simple rule
  condition: open_simple
  output: command=%proc.cmdline
  priority: INFO

)END";

	// We cannot define a macro override before the macro definition.
	ASSERT_TRUE(load_rules(rules_content, "rules.yaml"));
	ASSERT_EQ(get_compiled_rule_condition("test_rule"),"(evt.type in (open, openat) or evt.type = openat2)");
}

TEST_F(engine_loader_test, macro_append_after_macro_definition)
{
    std::string rules_content = R"END(

- macro: open_simple
  condition: evt.type in (open,openat)

- macro: open_simple
  condition: or evt.type = openat2
  append: true

- rule: test_rule
  desc: simple rule
  condition: open_simple
  output: command=%proc.cmdline
  priority: INFO

)END";

	// We cannot define a macro override before the macro definition.
	ASSERT_TRUE(load_rules(rules_content, "rules.yaml"));
	ASSERT_EQ(get_compiled_rule_condition("test_rule"),"(evt.type in (open, openat) or evt.type = openat2)");
}

TEST_F(engine_loader_test, rule_override_append_before_rule_definition)
{
    std::string rules_content = R"END(
- rule: test_rule
  condition: and proc.name = cat
  override:
    condition: append

- rule: test_rule
  desc: simple rule
  condition: evt.type in (open,openat)
  output: command=%proc.cmdline
  priority: INFO

)END";

	ASSERT_FALSE(load_rules(rules_content, "rules.yaml"));
	ASSERT_TRUE(check_error_message(ERROR_NO_PREVIOUS_RULE_APPEND));
}

TEST_F(engine_loader_test, rule_override_replace_before_rule_definition)
{
    std::string rules_content = R"END(
- rule: test_rule
  condition: and proc.name = cat
  override:
    condition: replace

- rule: test_rule
  desc: simple rule
  condition: evt.type in (open,openat)
  output: command=%proc.cmdline
  priority: INFO

)END";

	ASSERT_FALSE(load_rules(rules_content, "rules.yaml"));
	ASSERT_TRUE(check_error_message(ERROR_NO_PREVIOUS_RULE_REPLACE));
}

TEST_F(engine_loader_test, rule_append_before_rule_definition)
{
    std::string rules_content = R"END(
- rule: test_rule
  condition: and proc.name = cat
  append: true

- rule: test_rule
  desc: simple rule
  condition: evt.type in (open,openat)
  output: command=%proc.cmdline
  priority: INFO

)END";

	ASSERT_FALSE(load_rules(rules_content, "rules.yaml"));
	ASSERT_TRUE(check_error_message(ERROR_NO_PREVIOUS_RULE_APPEND));
}

TEST_F(engine_loader_test, rule_override_append_after_rule_definition)
{
    std::string rules_content = R"END(
- rule: test_rule
  desc: simple rule
  condition: evt.type in (open,openat)
  output: command=%proc.cmdline
  priority: INFO

- rule: test_rule
  condition: and proc.name = cat
  override:
    condition: append
)END";

	ASSERT_TRUE(load_rules(rules_content, "rules.yaml"));
	ASSERT_EQ(get_compiled_rule_condition("test_rule"),"(evt.type in (open, openat) and proc.name = cat)");
}

TEST_F(engine_loader_test, rule_append_after_rule_definition)
{
    std::string rules_content = R"END(
- rule: test_rule
  desc: simple rule
  condition: evt.type in (open,openat)
  output: command=%proc.cmdline
  priority: INFO

- rule: test_rule
  condition: and proc.name = cat
  append: true
)END";

	ASSERT_TRUE(load_rules(rules_content, "rules.yaml"));
	ASSERT_EQ(get_compiled_rule_condition("test_rule"),"(evt.type in (open, openat) and proc.name = cat)");
}

TEST_F(engine_loader_test, list_override_append_wrong_key)
{
	// todo: maybe we want to manage some non-existent keys
	// Please note how the non-existent key 'non-existent keys' is ignored.
    std::string rules_content = R"END(
- list: dev_creation_binaries
  items: ["csi-provisioner", "csi-attacher"]
  override_written_wrong:
    items: append

- list: dev_creation_binaries
  items: [blkid]

- rule: test_rule
  desc: simple rule
  condition: evt.type = execve and proc.name in (dev_creation_binaries)
  output: command=%proc.cmdline
  priority: INFO

)END";

	// Since there is a wrong key in the first list definition the `override` is not
	// considered. so in this situation, we are defining the list 2 times. The 
	// second one overrides the first one.
	ASSERT_TRUE(load_rules(rules_content, "rules.yaml"));
	ASSERT_EQ(get_compiled_rule_condition("test_rule"),"(evt.type = execve and proc.name in (blkid))");
}

TEST_F(engine_loader_test, list_override_append_before_list_definition)
{
    std::string rules_content = R"END(
- list: dev_creation_binaries
  items: ["csi-provisioner", "csi-attacher"]
  override:
    items: append

- list: dev_creation_binaries
  items: [blkid]

- rule: test_rule
  desc: simple rule
  condition: evt.type = execve and proc.name in (dev_creation_binaries)
  output: command=%proc.cmdline
  priority: INFO

)END";

	// We cannot define a list override before the list definition.
	ASSERT_FALSE(load_rules(rules_content, "rules.yaml"));
	ASSERT_TRUE(check_error_message(ERROR_NO_PREVIOUS_LIST));
}

TEST_F(engine_loader_test, list_override_replace_before_list_definition)
{
    std::string rules_content = R"END(
- list: dev_creation_binaries
  items: ["csi-provisioner", "csi-attacher"]
  override:
    items: replace

- list: dev_creation_binaries
  items: [blkid]

- rule: test_rule
  desc: simple rule
  condition: evt.type = execve and proc.name in (dev_creation_binaries)
  output: command=%proc.cmdline
  priority: INFO

)END";

	// With override replace we define a first list that then is overridden by the second one.
	ASSERT_TRUE(load_rules(rules_content, "rules.yaml"));
	ASSERT_EQ(get_compiled_rule_condition("test_rule"),"(evt.type = execve and proc.name in (blkid))");
}

TEST_F(engine_loader_test, list_append_before_list_definition)
{
    std::string rules_content = R"END(
- list: dev_creation_binaries
  items: ["csi-provisioner", "csi-attacher"]
  append: true

- list: dev_creation_binaries
  items: [blkid]

- rule: test_rule
  desc: simple rule
  condition: evt.type = execve and proc.name in (dev_creation_binaries)
  output: command=%proc.cmdline
  priority: INFO

)END";

	// We cannot define a list append before the list definition.
	ASSERT_FALSE(load_rules(rules_content, "rules.yaml"));
	ASSERT_TRUE(check_error_message(ERROR_NO_PREVIOUS_LIST));
}

TEST_F(engine_loader_test, list_override_append_after_list_definition)
{
    std::string rules_content = R"END(
- list: dev_creation_binaries
  items: [blkid]

- list: dev_creation_binaries
  items: ["csi-provisioner", "csi-attacher"]
  override:
    items: append

- rule: test_rule
  desc: simple rule
  condition: evt.type = execve and proc.name in (dev_creation_binaries)
  output: command=%proc.cmdline
  priority: INFO

)END";

	ASSERT_TRUE(load_rules(rules_content, "rules.yaml"));
	ASSERT_EQ(get_compiled_rule_condition("test_rule"),"(evt.type = execve and proc.name in (blkid, csi-provisioner, csi-attacher))");
}

TEST_F(engine_loader_test, list_append_after_list_definition)
{
    std::string rules_content = R"END(
- list: dev_creation_binaries
  items: [blkid]

- list: dev_creation_binaries
  items: ["csi-provisioner", "csi-attacher"]
  append: true

- rule: test_rule
  desc: simple rule
  condition: evt.type = execve and proc.name in (dev_creation_binaries)
  output: command=%proc.cmdline
  priority: INFO
)END";

	ASSERT_TRUE(load_rules(rules_content, "rules.yaml"));
	ASSERT_EQ(get_compiled_rule_condition("test_rule"),"(evt.type = execve and proc.name in (blkid, csi-provisioner, csi-attacher))");
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
	ASSERT_TRUE(check_error_message("An append override for 'condition' was specified but 'condition' is not defined"));
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
	ASSERT_TRUE(check_error_message("Unexpected key 'priority'"));
}

TEST_F(engine_loader_test, missing_enabled_key_with_override)
{
    std::string rules_content = R"END(
- rule: test_rule
  desc: test rule description
  condition: evt.type = close
  output: user=%user.name command=%proc.cmdline file=%fd.name
  priority: INFO
  enabled: false

- rule: test_rule
  desc: missing enabled key
  condition: and proc.name = cat
  override:
    desc: replace
    condition: append
    enabled: replace
)END";

	// In the rule override we miss `enabled: true`
	ASSERT_FALSE(load_rules(rules_content, "rules.yaml"));
	ASSERT_TRUE(check_error_message("'enabled' was specified but 'enabled' is not defined"));
}

TEST_F(engine_loader_test, rule_override_with_enabled)
{
    std::string rules_content = R"END(
- rule: test_rule
  desc: test rule description
  condition: evt.type = close
  output: user=%user.name command=%proc.cmdline file=%fd.name
  priority: INFO
  enabled: false

- rule: test_rule
  desc: correct override
  condition: and proc.name = cat
  enabled: true
  override:
    desc: replace
    condition: append
    enabled: replace
)END";

	ASSERT_TRUE(load_rules(rules_content, "rules.yaml"));
	ASSERT_FALSE(has_warnings());
	// The rule should be enabled at the end.
	EXPECT_EQ(num_rules_for_ruleset(), 1);
}

TEST_F(engine_loader_test, rule_not_enabled)
{
    std::string rules_content = R"END(
- rule: test_rule
  desc: rule not enabled
  condition: evt.type = close
  output: user=%user.name command=%proc.cmdline file=%fd.name
  priority: INFO
  enabled: false
)END";

	ASSERT_TRUE(load_rules(rules_content, "rules.yaml"));
	ASSERT_FALSE(has_warnings());
	EXPECT_EQ(num_rules_for_ruleset(), 0);
}

TEST_F(engine_loader_test, rule_enabled_warning)
{
    std::string rules_content = R"END(
- rule: test_rule
  desc: test rule description
  condition: evt.type = close
  output: user=%user.name command=%proc.cmdline file=%fd.name
  priority: INFO
  enabled: false

- rule: test_rule
  enabled: true
)END";

	ASSERT_TRUE(load_rules(rules_content, "rules.yaml"));
	ASSERT_TRUE(check_warning_message(WARNING_ENABLED));
	// The rule should be enabled at the end.
	EXPECT_EQ(num_rules_for_ruleset(), 1);
}

// todo!: Probably we shouldn't allow this syntax
TEST_F(engine_loader_test, rule_enabled_is_ignored_by_append)
{
    std::string rules_content = R"END(
- rule: test_rule
  desc: test rule description
  condition: evt.type = close
  output: user=%user.name command=%proc.cmdline file=%fd.name
  priority: INFO
  enabled: false

- rule: test_rule
  condition: and proc.name = cat
  append: true
  enabled: true
)END";

	// 'enabled' is ignored by the append, this syntax is not supported
	// so the rule is not enabled.
	ASSERT_TRUE(load_rules(rules_content, "rules.yaml"));
	EXPECT_EQ(num_rules_for_ruleset(), 0);
}

// todo!: Probably we shouldn't allow this syntax
TEST_F(engine_loader_test, rewrite_rule)
{
    std::string rules_content = R"END(
- rule: test_rule
  desc: test rule description
  condition: evt.type = close
  output: user=%user.name command=%proc.cmdline file=%fd.name
  priority: INFO
  enabled: false

- rule: test_rule
  desc: redefined rule syntax
  condition: proc.name = cat
  output: user=%user.name command=%proc.cmdline file=%fd.name
  priority: WARNING
  enabled: true
)END";

	// The above syntax is not supported, we cannot override the content
	// of a rule in this way.
	ASSERT_TRUE(load_rules(rules_content, "rules.yaml"));
	// In this case the rule is completely overridden but this syntax is not supported.
	EXPECT_EQ(num_rules_for_ruleset(), 1);
	ASSERT_EQ(get_compiled_rule_condition("test_rule"),"proc.name = cat");
}

TEST_F(engine_loader_test, required_engine_version_semver)
{
    std::string rules_content = R"END(
- required_engine_version: 0.26.0

- rule: test_rule
  desc: test rule description
  condition: evt.type = close
  output: user=%user.name command=%proc.cmdline file=%fd.name
  priority: INFO
  enabled: false

)END";

	ASSERT_TRUE(load_rules(rules_content, "rules.yaml"));
	ASSERT_FALSE(has_warnings());
}

TEST_F(engine_loader_test, required_engine_version_not_semver)
{
    std::string rules_content = R"END(
- required_engine_version: 26

- rule: test_rule
  desc: test rule description
  condition: evt.type = close
  output: user=%user.name command=%proc.cmdline file=%fd.name
  priority: INFO
  enabled: false

)END";

	ASSERT_TRUE(load_rules(rules_content, "rules.yaml"));
	ASSERT_FALSE(has_warnings());
}

TEST_F(engine_loader_test, required_engine_version_invalid)
{
    std::string rules_content = R"END(
- required_engine_version: seven

- rule: test_rule
  desc: test rule description
  condition: evt.type = close
  output: user=%user.name command=%proc.cmdline file=%fd.name
  priority: INFO
  enabled: false

)END";

	ASSERT_FALSE(load_rules(rules_content, "rules.yaml"));
	ASSERT_TRUE(check_error_message("Unable to parse engine version"));
}

// checks for issue described in https://github.com/falcosecurity/falco/pull/3028
TEST_F(engine_loader_test, list_value_with_escaping)
{
    std::string rules_content = R"END(
- list: my_list
  items: [non_escaped_val, "escaped val"]
)END";

	ASSERT_TRUE(load_rules(rules_content, "rules.yaml"));
	ASSERT_TRUE(m_load_result->successful());
  ASSERT_TRUE(m_load_result->has_warnings()); // a warning for the unused list

  auto rule_description = m_engine->describe_rule(nullptr, {});
  ASSERT_TRUE(m_load_result->successful());
  ASSERT_EQ(rule_description["rules"].size(), 0);
  ASSERT_EQ(rule_description["macros"].size(), 0);
  ASSERT_EQ(rule_description["lists"].size(), 1);

  // escaped values must not be interpreted as list refs by mistake
  ASSERT_EQ(rule_description["lists"][0]["details"]["lists"].size(), 0);

  // values should be escaped correctly
  ASSERT_EQ(rule_description["lists"][0]["details"]["items_compiled"].size(), 2);
  ASSERT_EQ(rule_description["lists"][0]["details"]["items_compiled"][0].template get<std::string>(), "non_escaped_val");
  ASSERT_EQ(rule_description["lists"][0]["details"]["items_compiled"][1].template get<std::string>(), "escaped val");
}