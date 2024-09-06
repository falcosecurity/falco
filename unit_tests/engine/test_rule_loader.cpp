#include <gtest/gtest.h>

#include "../test_falco_engine.h"
#include "yaml_helper.h"

#define ASSERT_VALIDATION_STATUS(status) ASSERT_TRUE(sinsp_utils::startswith(m_load_result->schema_validation(), status))

std::string s_sample_ruleset = "sample-ruleset";
std::string s_sample_source = falco_common::syscall_source;

TEST_F(test_falco_engine, list_append)
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
	ASSERT_VALIDATION_STATUS(yaml_helper::validation_ok) << m_load_result->schema_validation();
	ASSERT_EQ(get_compiled_rule_condition("legit_rule"),"(evt.type = open and proc.name in (ash, bash, csh, ksh, sh, tcsh, zsh, dash, pwsh))");
}

TEST_F(test_falco_engine, condition_append)
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
	ASSERT_VALIDATION_STATUS(yaml_helper::validation_ok) << m_load_result->schema_validation();
	ASSERT_EQ(get_compiled_rule_condition("legit_rule"),"(evt.type = open and (((proc.aname = sshd and proc.name != sshd) or proc.name = systemd-logind or proc.name = login) or proc.name = ssh))");
}

TEST_F(test_falco_engine, rule_override_append)
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
	ASSERT_VALIDATION_STATUS(yaml_helper::validation_ok) << m_load_result->schema_validation();

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

TEST_F(test_falco_engine, rule_append)
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
	ASSERT_VALIDATION_STATUS(yaml_helper::validation_ok) << m_load_result->schema_validation();

	// We should have at least one warning because the 'append' flag is deprecated.
	ASSERT_TRUE(check_warning_message(WARNING_APPEND));

	ASSERT_EQ(get_compiled_rule_condition("legit_rule"),"(evt.type = open and proc.name = cat)");
}

TEST_F(test_falco_engine, rule_override_replace)
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
	ASSERT_VALIDATION_STATUS(yaml_helper::validation_ok) << m_load_result->schema_validation();

	auto rule_description = m_engine->describe_rule(&rule_name, {});
	ASSERT_EQ(rule_description["rules"][0]["info"]["condition"].template get<std::string>(),
	 	"evt.type = close");

	ASSERT_EQ(rule_description["rules"][0]["info"]["output"].template get<std::string>(),
	 	"user=%user.name command=%proc.cmdline file=%fd.name");

	ASSERT_EQ(rule_description["rules"][0]["info"]["description"].template get<std::string>(),
	 	"a replaced legit description");
}

TEST_F(test_falco_engine, rule_override_append_replace)
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
	ASSERT_VALIDATION_STATUS(yaml_helper::validation_ok) << m_load_result->schema_validation();

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

TEST_F(test_falco_engine, rule_incorrect_override_type)
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

	ASSERT_FALSE(load_rules(rules_content, "rules.yaml"));
	ASSERT_VALIDATION_STATUS(yaml_helper::validation_ok) << m_load_result->schema_validation();
	ASSERT_TRUE(check_error_message("Key 'priority' cannot be appended to, use 'replace' instead"));
	ASSERT_TRUE(std::string(m_load_result_json["errors"][0]["context"]["snippet"]).find("priority: append") != std::string::npos);
}

TEST_F(test_falco_engine, rule_incorrect_append_override)
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

	ASSERT_FALSE(load_rules(rules_content, "rules.yaml"));
	ASSERT_VALIDATION_STATUS(yaml_helper::validation_ok) << m_load_result->schema_validation();
	
	// We should have at least one warning because the 'append' flag is deprecated.
	ASSERT_TRUE(check_warning_message(WARNING_APPEND));
	
	ASSERT_TRUE(check_error_message(ERROR_OVERRIDE_APPEND));
}

TEST_F(test_falco_engine, macro_override_append_before_macro_definition)
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
	ASSERT_VALIDATION_STATUS(yaml_helper::validation_ok) << m_load_result->schema_validation();
	ASSERT_TRUE(check_error_message(ERROR_NO_PREVIOUS_MACRO));
}

TEST_F(test_falco_engine, macro_override_replace_before_macro_definition)
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
	ASSERT_VALIDATION_STATUS(yaml_helper::validation_ok) << m_load_result->schema_validation();
	ASSERT_EQ(get_compiled_rule_condition("test_rule"),"evt.type in (open, openat)");	
}

TEST_F(test_falco_engine, macro_append_before_macro_definition)
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
	ASSERT_VALIDATION_STATUS(yaml_helper::validation_ok) << m_load_result->schema_validation();
	ASSERT_TRUE(check_error_message(ERROR_NO_PREVIOUS_MACRO));
}

TEST_F(test_falco_engine, macro_override_append_after_macro_definition)
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
	ASSERT_VALIDATION_STATUS(yaml_helper::validation_ok) << m_load_result->schema_validation();
	ASSERT_EQ(get_compiled_rule_condition("test_rule"),"(evt.type in (open, openat) or evt.type = openat2)");
}

TEST_F(test_falco_engine, macro_append_after_macro_definition)
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
	ASSERT_VALIDATION_STATUS(yaml_helper::validation_ok) << m_load_result->schema_validation();
	ASSERT_EQ(get_compiled_rule_condition("test_rule"),"(evt.type in (open, openat) or evt.type = openat2)");
}

TEST_F(test_falco_engine, rule_override_append_before_rule_definition)
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
	ASSERT_VALIDATION_STATUS(yaml_helper::validation_ok) << m_load_result->schema_validation();
	ASSERT_TRUE(check_error_message(ERROR_NO_PREVIOUS_RULE_APPEND));
}

TEST_F(test_falco_engine, rule_override_replace_before_rule_definition)
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
	ASSERT_VALIDATION_STATUS(yaml_helper::validation_ok) << m_load_result->schema_validation();
	ASSERT_TRUE(check_error_message(ERROR_NO_PREVIOUS_RULE_REPLACE));
}

TEST_F(test_falco_engine, rule_append_before_rule_definition)
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
	ASSERT_VALIDATION_STATUS(yaml_helper::validation_ok) << m_load_result->schema_validation();
	ASSERT_TRUE(check_error_message(ERROR_NO_PREVIOUS_RULE_APPEND));
}

TEST_F(test_falco_engine, rule_override_append_after_rule_definition)
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
	ASSERT_VALIDATION_STATUS(yaml_helper::validation_ok) << m_load_result->schema_validation();
	ASSERT_EQ(get_compiled_rule_condition("test_rule"),"(evt.type in (open, openat) and proc.name = cat)");
}

TEST_F(test_falco_engine, rule_append_after_rule_definition)
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
	ASSERT_VALIDATION_STATUS(yaml_helper::validation_ok) << m_load_result->schema_validation();
	ASSERT_EQ(get_compiled_rule_condition("test_rule"),"(evt.type in (open, openat) and proc.name = cat)");
}

TEST_F(test_falco_engine, list_override_append_wrong_key)
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
	ASSERT_VALIDATION_STATUS(yaml_helper::validation_failed) << m_load_result->schema_validation();
	ASSERT_EQ(get_compiled_rule_condition("test_rule"),"(evt.type = execve and proc.name in (blkid))");
}

TEST_F(test_falco_engine, list_override_append_before_list_definition)
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
	ASSERT_VALIDATION_STATUS(yaml_helper::validation_ok) << m_load_result->schema_validation();
	ASSERT_TRUE(check_error_message(ERROR_NO_PREVIOUS_LIST));
}

TEST_F(test_falco_engine, list_override_replace_before_list_definition)
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
	ASSERT_VALIDATION_STATUS(yaml_helper::validation_ok) << m_load_result->schema_validation();
	ASSERT_EQ(get_compiled_rule_condition("test_rule"),"(evt.type = execve and proc.name in (blkid))");
}

TEST_F(test_falco_engine, list_append_before_list_definition)
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
	ASSERT_VALIDATION_STATUS(yaml_helper::validation_ok) << m_load_result->schema_validation();
	ASSERT_TRUE(check_error_message(ERROR_NO_PREVIOUS_LIST));
}

TEST_F(test_falco_engine, list_override_append_after_list_definition)
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
	ASSERT_VALIDATION_STATUS(yaml_helper::validation_ok) << m_load_result->schema_validation();
	ASSERT_EQ(get_compiled_rule_condition("test_rule"),"(evt.type = execve and proc.name in (blkid, csi-provisioner, csi-attacher))");
}

TEST_F(test_falco_engine, list_append_after_list_definition)
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
	ASSERT_VALIDATION_STATUS(yaml_helper::validation_ok) << m_load_result->schema_validation();
	ASSERT_EQ(get_compiled_rule_condition("test_rule"),"(evt.type = execve and proc.name in (blkid, csi-provisioner, csi-attacher))");
}

TEST_F(test_falco_engine, rule_override_without_field)
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

	ASSERT_FALSE(load_rules(rules_content, "rules.yaml"));
	ASSERT_VALIDATION_STATUS(yaml_helper::validation_ok) << m_load_result->schema_validation();
	ASSERT_TRUE(check_error_message("An append override for 'condition' was specified but 'condition' is not defined"));
}

TEST_F(test_falco_engine, rule_override_extra_field)
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

	ASSERT_FALSE(load_rules(rules_content, "rules.yaml"));
	ASSERT_VALIDATION_STATUS(yaml_helper::validation_ok) << m_load_result->schema_validation();
	ASSERT_TRUE(check_error_message("Unexpected key 'priority'"));
}

TEST_F(test_falco_engine, missing_enabled_key_with_override)
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
	ASSERT_VALIDATION_STATUS(yaml_helper::validation_ok) << m_load_result->schema_validation();
	ASSERT_TRUE(check_error_message("'enabled' was specified but 'enabled' is not defined"));
}

TEST_F(test_falco_engine, rule_override_with_enabled)
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
	ASSERT_VALIDATION_STATUS(yaml_helper::validation_ok) << m_load_result->schema_validation();
	ASSERT_FALSE(has_warnings());
	// The rule should be enabled at the end.
	EXPECT_EQ(num_rules_for_ruleset(), 1);
}

TEST_F(test_falco_engine, rule_override_exceptions_required_fields)
{
    std::string rules_content = R"END(
- rule: test_rule
  desc: test rule description
  condition: evt.type = close
  output: user=%user.name command=%proc.cmdline file=%fd.name
  priority: INFO
  exceptions:
    - name: test_exception
      fields: proc.name
      comps: in
      values: ["cat"]

# when appending, it's fine to provide partial exception definitions
- rule: test_rule
  exceptions:
    - name: test_exception
      values: [echo]
  override:
    exceptions: append

# when replacing, we don't allow partial exception definitions
- rule: test_rule
  exceptions:
    - name: test_exception
      values: [id]
  override:
    exceptions: replace
)END";

	ASSERT_FALSE(load_rules(rules_content, "rules.yaml"));
	ASSERT_VALIDATION_STATUS(yaml_helper::validation_ok) << m_load_result->schema_validation();
	ASSERT_FALSE(has_warnings());
	ASSERT_TRUE(check_error_message("Item has no mapping for key 'fields'")) << m_load_result_json.dump();
}

TEST_F(test_falco_engine, rule_not_enabled)
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
	ASSERT_VALIDATION_STATUS(yaml_helper::validation_ok) << m_load_result->schema_validation();
	ASSERT_FALSE(has_warnings());
	EXPECT_EQ(num_rules_for_ruleset(), 0);
}

TEST_F(test_falco_engine, rule_enabled_warning)
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
	ASSERT_VALIDATION_STATUS(yaml_helper::validation_ok) << m_load_result->schema_validation();
	ASSERT_TRUE(check_warning_message(WARNING_ENABLED));
	// The rule should be enabled at the end.
	EXPECT_EQ(num_rules_for_ruleset(), 1);
}

// todo!: Probably we shouldn't allow this syntax
TEST_F(test_falco_engine, rule_enabled_is_ignored_by_append)
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
	ASSERT_VALIDATION_STATUS(yaml_helper::validation_ok) << m_load_result->schema_validation();
	EXPECT_EQ(num_rules_for_ruleset(), 0);
}

// todo!: Probably we shouldn't allow this syntax
TEST_F(test_falco_engine, rewrite_rule)
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
	ASSERT_VALIDATION_STATUS(yaml_helper::validation_ok) << m_load_result->schema_validation();
	// In this case the rule is completely overridden but this syntax is not supported.
	EXPECT_EQ(num_rules_for_ruleset(), 1);
	ASSERT_EQ(get_compiled_rule_condition("test_rule"),"proc.name = cat");
}

TEST_F(test_falco_engine, required_engine_version_semver)
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
	ASSERT_VALIDATION_STATUS(yaml_helper::validation_ok) << m_load_result->schema_validation();
	ASSERT_FALSE(has_warnings());
}

TEST_F(test_falco_engine, required_engine_version_not_semver)
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
	ASSERT_VALIDATION_STATUS(yaml_helper::validation_ok) << m_load_result->schema_validation();
	ASSERT_FALSE(has_warnings());
}

TEST_F(test_falco_engine, required_engine_version_invalid)
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
	ASSERT_VALIDATION_STATUS(yaml_helper::validation_ok) << m_load_result->schema_validation();
	ASSERT_TRUE(check_error_message("Unable to parse engine version"));
}

// checks for issue described in https://github.com/falcosecurity/falco/pull/3028
TEST_F(test_falco_engine, list_value_with_escaping)
{
    std::string rules_content = R"END(
- list: my_list
  items: [non_escaped_val, "escaped val"]
)END";

	ASSERT_TRUE(load_rules(rules_content, "rules.yaml"));
	ASSERT_VALIDATION_STATUS(yaml_helper::validation_ok) << m_load_result->schema_validation();
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

TEST_F(test_falco_engine, exceptions_condition)
{
    std::string rules_content = R"END(
- rule: test_rule
  desc: test rule
  condition: proc.cmdline contains curl or proc.cmdline contains wget
  output: command=%proc.cmdline
  priority: INFO
  exceptions:
    - name: test_exception
      fields: [proc.cmdline]
      comps: [contains]
      values:
        - [curl 127.0.0.1]
)END";

  ASSERT_TRUE(load_rules(rules_content, "rules.yaml"));
  ASSERT_VALIDATION_STATUS(yaml_helper::validation_ok) << m_load_result->schema_validation();
  ASSERT_EQ(get_compiled_rule_condition("test_rule"),"((proc.cmdline contains curl or proc.cmdline contains wget) and not proc.cmdline contains \"curl 127.0.0.1\")");
}

TEST_F(test_falco_engine, macro_name_invalid)
{
    std::string rules_content = R"END(
- macro: test-macro
  condition: evt.type = close
)END";

  ASSERT_TRUE(load_rules(rules_content, "rules.yaml"));
  ASSERT_VALIDATION_STATUS(yaml_helper::validation_ok) << m_load_result->schema_validation();
  ASSERT_TRUE(check_warning_message("Macro has an invalid name. Macro names should match a regular expression"));
}

TEST_F(test_falco_engine, list_name_invalid)
{
    std::string rules_content = R"END(
- list: test list
  items: [open, openat, openat2]

- rule: test_rule
  desc: test rule description
  condition: evt.type in (test list)
  output: user=%user.name command=%proc.cmdline file=%fd.name
  priority: INFO
  enabled: false

)END";

  ASSERT_TRUE(load_rules(rules_content, "rules.yaml"));
  ASSERT_VALIDATION_STATUS(yaml_helper::validation_ok) << m_load_result->schema_validation();
  ASSERT_TRUE(check_warning_message("List has an invalid name. List names should match a regular expression"));
}

// The appended exception has a purposely miswritten field (value),
// simulating a typo or an incorrect usage.
TEST_F(test_falco_engine, exceptions_append_no_values)
{
    std::string rules_content = R"END(
- rule: test_rule
  desc: test rule
  condition: proc.cmdline contains curl
  output: command=%proc.cmdline
  priority: INFO
  exceptions:
    - name: test_exception
      fields: [proc.cmdline]
      comps: [contains]
      values:
        - [curl 127.0.0.1]

- rule: test_rule
  exceptions:
    - name: test_exception
      value: curl 1.1.1.1
  append: true
)END";

  ASSERT_TRUE(load_rules(rules_content, "rules.yaml"));
  ASSERT_VALIDATION_STATUS(yaml_helper::validation_failed) << m_load_result->schema_validation();
  ASSERT_TRUE(check_warning_message("Overriding/appending exception with no values"));
}

TEST_F(test_falco_engine, exceptions_override_no_values)
{
    std::string rules_content = R"END(
- rule: test_rule
  desc: test rule
  condition: proc.cmdline contains curl
  output: command=%proc.cmdline
  priority: INFO
  exceptions:
    - name: test_exception
      fields: [proc.cmdline]
      comps: [contains]
      values:
        - [curl 127.0.0.1]

- rule: test_rule
  exceptions:
    - name: test_exception
      value: curl 1.1.1.1
  override:
    exceptions: append
)END";

  ASSERT_TRUE(load_rules(rules_content, "rules.yaml"));
  ASSERT_VALIDATION_STATUS(yaml_helper::validation_failed) << m_load_result->schema_validation();
  ASSERT_TRUE(check_warning_message("Overriding/appending exception with no values"));
}

TEST_F(test_falco_engine, exceptions_names_not_unique)
{
    std::string rules_content = R"END(
- rule: test_rule
  desc: test rule
  condition: proc.cmdline contains curl
  output: command=%proc.cmdline
  priority: INFO
  exceptions:
    - name: test_exception
      fields: [proc.cmdline]
      comps: [contains]
      values:
        - [curl 127.0.0.1]
    - name: test_exception
      fields: [proc.cmdline]
      comps: [endswith]
      values:
        - [curl 127.0.0.1]
)END";

  ASSERT_TRUE(load_rules(rules_content, "rules.yaml"));
  ASSERT_VALIDATION_STATUS(yaml_helper::validation_ok) << m_load_result->schema_validation();
  ASSERT_TRUE(check_warning_message("Multiple definitions of exception"));
}

static std::string s_exception_values_rule_base = R"END(
- rule: test_rule
  desc: test rule
  condition: evt.type = open
  output: command=%proc.cmdline
  priority: INFO
)END";

TEST_F(test_falco_engine, exceptions_values_rhs_field_ambiguous)
{
  auto rules_content = s_exception_values_rule_base + R"END(
  exceptions:
    - name: test_exception
      fields: [proc.name]
      comps: [=]
      values:
        - [proc.pname]
)END";

  ASSERT_TRUE(load_rules(rules_content, "rules.yaml"));
  ASSERT_VALIDATION_STATUS(yaml_helper::validation_ok) << m_load_result->schema_validation();
  EXPECT_EQ(get_compiled_rule_condition("test_rule"), "(evt.type = open and not proc.name = proc.pname)");
  EXPECT_TRUE(check_warning_message("'proc.pname' may be a valid field misused as a const string value"));
}

TEST_F(test_falco_engine, exceptions_values_rhs_field_ambiguous_quoted)
{
  auto rules_content = s_exception_values_rule_base + R"END(
  exceptions:
    - name: test_exception
      fields: [proc.name]
      comps: [=]
      values:
        - ["proc.pname"]
)END";

  ASSERT_TRUE(load_rules(rules_content, "rules.yaml"));
  ASSERT_VALIDATION_STATUS(yaml_helper::validation_ok) << m_load_result->schema_validation();
  EXPECT_EQ(get_compiled_rule_condition("test_rule"), "(evt.type = open and not proc.name = proc.pname)");
  EXPECT_TRUE(check_warning_message("'proc.pname' may be a valid field misused as a const string value"));
}

TEST_F(test_falco_engine, exceptions_values_rhs_field_ambiguous_space_quoted)
{
  auto rules_content = s_exception_values_rule_base + R"END(
  exceptions:
    - name: test_exception
      fields: [proc.name]
      comps: [=]
      values:
        - ["proc.pname "]
)END";

  ASSERT_TRUE(load_rules(rules_content, "rules.yaml"));
  ASSERT_VALIDATION_STATUS(yaml_helper::validation_ok) << m_load_result->schema_validation();
  EXPECT_EQ(get_compiled_rule_condition("test_rule"), "(evt.type = open and not proc.name = \"proc.pname \")");
  EXPECT_TRUE(check_warning_message("'proc.pname ' may be a valid field misused as a const string value"));
}

TEST_F(test_falco_engine, exceptions_values_rhs_transformer)
{
  auto rules_content = s_exception_values_rule_base + R"END(
  exceptions:
    - name: test_exception
      fields: [proc.name]
      comps: [=]
      values:
        - [toupper(proc.pname)]
)END";

  ASSERT_TRUE(load_rules(rules_content, "rules.yaml"));
  ASSERT_VALIDATION_STATUS(yaml_helper::validation_ok) << m_load_result->schema_validation();
  EXPECT_EQ(get_compiled_rule_condition("test_rule"), "(evt.type = open and not proc.name = toupper(proc.pname))");	
}

TEST_F(test_falco_engine, exceptions_values_transformer_value_quoted)
{
  auto rules_content = s_exception_values_rule_base + R"END(
  exceptions:
    - name: test_exception
      fields: [proc.name]
      comps: [=]
      values:
        - ["toupper(proc.pname)"]
)END";

  ASSERT_TRUE(load_rules(rules_content, "rules.yaml"));
  ASSERT_VALIDATION_STATUS(yaml_helper::validation_ok) << m_load_result->schema_validation();
  EXPECT_EQ(get_compiled_rule_condition("test_rule"), "(evt.type = open and not proc.name = toupper(proc.pname))");	
}

TEST_F(test_falco_engine, exceptions_values_transformer_space)
{
  auto rules_content = s_exception_values_rule_base + R"END(
  exceptions:
    - name: test_exception
      fields: [proc.name]
      comps: [=]
      values:
        - [toupper( proc.pname)]
)END";

  ASSERT_TRUE(load_rules(rules_content, "rules.yaml"));
  ASSERT_VALIDATION_STATUS(yaml_helper::validation_ok) << m_load_result->schema_validation();
  EXPECT_EQ(get_compiled_rule_condition("test_rule"), "(evt.type = open and not proc.name = \"toupper( proc.pname)\")");
  EXPECT_TRUE(check_warning_message("'toupper( proc.pname)' may be a valid field transformer misused as a const string value"));
}

TEST_F(test_falco_engine, exceptions_values_transformer_space_quoted)
{
  auto rules_content = s_exception_values_rule_base + R"END(
  exceptions:
    - name: test_exception
      fields: [proc.name]
      comps: [=]
      values:
        - ["toupper( proc.pname)"]
)END";

  ASSERT_TRUE(load_rules(rules_content, "rules.yaml"));
  ASSERT_VALIDATION_STATUS(yaml_helper::validation_ok) << m_load_result->schema_validation();
  EXPECT_EQ(get_compiled_rule_condition("test_rule"), "(evt.type = open and not proc.name = \"toupper( proc.pname)\")");
  EXPECT_TRUE(check_warning_message("'toupper( proc.pname)' may be a valid field transformer misused as a const string value"));
}

TEST_F(test_falco_engine, exceptions_fields_transformer)
{
  auto rules_content = s_exception_values_rule_base + R"END(
  exceptions:
    - name: test_exception
      fields: [tolower(proc.name)]
      comps: [=]
      values:
        - [test]
)END";

  ASSERT_TRUE(load_rules(rules_content, "rules.yaml"));
  ASSERT_VALIDATION_STATUS(yaml_helper::validation_ok) << m_load_result->schema_validation();
  EXPECT_FALSE(has_warnings());
  EXPECT_EQ(get_compiled_rule_condition("test_rule"), "(evt.type = open and not tolower(proc.name) = test)");
}

TEST_F(test_falco_engine, exceptions_fields_transformer_quoted)
{
  auto rules_content = s_exception_values_rule_base + R"END(
  exceptions:
    - name: test_exception
      fields: ["tolower(proc.name)"]
      comps: [=]
      values:
        - [test]
)END";

  ASSERT_TRUE(load_rules(rules_content, "rules.yaml"));
  ASSERT_VALIDATION_STATUS(yaml_helper::validation_ok) << m_load_result->schema_validation();
  ASSERT_FALSE(has_warnings());
  EXPECT_EQ(get_compiled_rule_condition("test_rule"), "(evt.type = open and not tolower(proc.name) = test)");
}

TEST_F(test_falco_engine, exceptions_fields_transformer_space_quoted)
{
  auto rules_content = s_exception_values_rule_base + R"END(
  exceptions:
    - name: test_exception
      fields: ["tolower( proc.name)"]
      comps: [=]
      values:
        - [test]
)END";

  ASSERT_TRUE(load_rules(rules_content, "rules.yaml"));
  ASSERT_VALIDATION_STATUS(yaml_helper::validation_ok) << m_load_result->schema_validation();
  ASSERT_FALSE(has_warnings());
  EXPECT_EQ(get_compiled_rule_condition("test_rule"), "(evt.type = open and not tolower(proc.name) = test)");
}
