// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2024 The Falco Authors.

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
#include <falco/configuration.h>

#include <stdexcept>
#include <string>

TEST(ConfigurationRuleOutputOptions, parse_yaml) {
	falco_configuration falco_config;
	ASSERT_NO_THROW(falco_config.init_from_content(R"(
append_output:
  - match:
      source: syscall
      tags: ["persistence"]
      rule: some rule name
    
    extra_output: "gparent=%proc.aname[2] ggparent=%proc.aname[3] gggparent=%proc.aname[4]"

  - match:
      tags: ["persistence", "execution"]
    extra_fields:
      - proc.aname[2]: "%proc.aname[2]"
      - proc.aname[3]: "%proc.aname[3]"
      - proc.aname[4]: "%proc.aname[4]"
    extra_output: "gparent=%proc.aname[2] ggparent=%proc.aname[3] gggparent=%proc.aname[4]"

  - match:
      source: k8s_audit
    extra_fields:
      - ka.verb
      - static_field: "static content"

	)",
	                                               {}));

	EXPECT_EQ(falco_config.m_append_output.size(), 3);

	EXPECT_EQ(falco_config.m_append_output[0].m_source, "syscall");
	EXPECT_EQ(falco_config.m_append_output[0].m_tags.size(), 1);
	EXPECT_EQ(falco_config.m_append_output[0].m_tags.count("persistence"), 1);
	EXPECT_EQ(falco_config.m_append_output[0].m_rule, "some rule name");
	EXPECT_EQ(falco_config.m_append_output[0].m_formatted_fields.size(), 0);
	EXPECT_EQ(falco_config.m_append_output[0].m_format,
	          "gparent=%proc.aname[2] ggparent=%proc.aname[3] gggparent=%proc.aname[4]");

	EXPECT_EQ(falco_config.m_append_output[1].m_tags.size(), 2);
	EXPECT_EQ(falco_config.m_append_output[1].m_tags.count("persistence"), 1);
	EXPECT_EQ(falco_config.m_append_output[1].m_tags.count("execution"), 1);
	EXPECT_EQ(falco_config.m_append_output[1].m_format,
	          "gparent=%proc.aname[2] ggparent=%proc.aname[3] gggparent=%proc.aname[4]");

	EXPECT_EQ(falco_config.m_append_output[1].m_formatted_fields.size(), 3);
	EXPECT_EQ(falco_config.m_append_output[1].m_formatted_fields["proc.aname[2]"],
	          "%proc.aname[2]");
	EXPECT_EQ(falco_config.m_append_output[1].m_formatted_fields["proc.aname[3]"],
	          "%proc.aname[3]");
	EXPECT_EQ(falco_config.m_append_output[1].m_formatted_fields["proc.aname[4]"],
	          "%proc.aname[4]");

	EXPECT_EQ(falco_config.m_append_output[2].m_source, "k8s_audit");

	EXPECT_EQ(falco_config.m_append_output[2].m_formatted_fields.size(), 1);
	EXPECT_EQ(falco_config.m_append_output[2].m_formatted_fields["static_field"], "static content");

	EXPECT_EQ(falco_config.m_append_output[2].m_raw_fields.size(), 1);
	EXPECT_EQ(falco_config.m_append_output[2].m_raw_fields.count("ka.verb"), 1);
}

TEST(ConfigurationRuleOutputOptions, cli_options) {
	falco_configuration falco_config;

	ASSERT_NO_THROW(falco_config.init_from_content(
	        "",
	        std::vector<std::string>{
	                R"(append_output[]={"match": {"source": "syscall", "tags": ["persistence"], "rule": "some rule name"}, "extra_output": "gparent=%proc.aname[2] ggparent=%proc.aname[3] gggparent=%proc.aname[4]"})",
	                R"(append_output[]={"match": {"tags": ["persistence", "execution"]}, "extra_fields": [{"proc.aname[2]": "%proc.aname[2]"}, {"proc.aname[3]": "%proc.aname[3]"}, {"proc.aname[4]": "%proc.aname[4]"}], "extra_output": "gparent=%proc.aname[2] ggparent=%proc.aname[3] gggparent=%proc.aname[4]"})",
	                R"(append_output[]={"match": {"source": "k8s_audit"}, "extra_fields": ["ka.verb", {"static_field": "static content"}]})"}));

	EXPECT_EQ(falco_config.m_append_output.size(), 3);

	EXPECT_EQ(falco_config.m_append_output[0].m_source, "syscall");
	EXPECT_EQ(falco_config.m_append_output[0].m_tags.size(), 1);
	EXPECT_EQ(falco_config.m_append_output[0].m_tags.count("persistence"), 1);
	EXPECT_EQ(falco_config.m_append_output[0].m_rule, "some rule name");
	EXPECT_EQ(falco_config.m_append_output[0].m_formatted_fields.size(), 0);
	EXPECT_EQ(falco_config.m_append_output[0].m_format,
	          "gparent=%proc.aname[2] ggparent=%proc.aname[3] gggparent=%proc.aname[4]");

	EXPECT_EQ(falco_config.m_append_output[1].m_tags.size(), 2);
	EXPECT_EQ(falco_config.m_append_output[1].m_tags.count("persistence"), 1);
	EXPECT_EQ(falco_config.m_append_output[1].m_tags.count("execution"), 1);
	EXPECT_EQ(falco_config.m_append_output[1].m_format,
	          "gparent=%proc.aname[2] ggparent=%proc.aname[3] gggparent=%proc.aname[4]");

	EXPECT_EQ(falco_config.m_append_output[1].m_formatted_fields.size(), 3);
	EXPECT_EQ(falco_config.m_append_output[1].m_formatted_fields["proc.aname[2]"],
	          "%proc.aname[2]");
	EXPECT_EQ(falco_config.m_append_output[1].m_formatted_fields["proc.aname[3]"],
	          "%proc.aname[3]");
	EXPECT_EQ(falco_config.m_append_output[1].m_formatted_fields["proc.aname[4]"],
	          "%proc.aname[4]");

	EXPECT_EQ(falco_config.m_append_output[2].m_source, "k8s_audit");

	EXPECT_EQ(falco_config.m_append_output[2].m_formatted_fields.size(), 1);
	EXPECT_EQ(falco_config.m_append_output[2].m_formatted_fields["static_field"], "static content");

	EXPECT_EQ(falco_config.m_append_output[2].m_raw_fields.size(), 1);
	EXPECT_EQ(falco_config.m_append_output[2].m_raw_fields.count("ka.verb"), 1);
}

TEST(ConfigurationHttpOutputOptions, parse_unix_socket_path) {
	falco_configuration falco_config;
	ASSERT_NO_THROW(falco_config.init_from_content(R"(
http_output:
  enabled: true
  url: "http://localhost/events"
  unix_socket_path: "/run/falco-consumer/events.sock"
)",
	                                               {}));

	ASSERT_EQ(falco_config.m_outputs.size(), 1);
	EXPECT_EQ(falco_config.m_outputs[0].name, "http");
	EXPECT_EQ(falco_config.m_outputs[0].options["url"], "http://localhost/events");
	EXPECT_EQ(falco_config.m_outputs[0].options["unix_socket_path"],
	          "/run/falco-consumer/events.sock");
}

TEST(ConfigurationHttpOutputOptions, unix_socket_path_defaults_to_empty) {
	falco_configuration falco_config;
	ASSERT_NO_THROW(falco_config.init_from_content(R"(
http_output:
  enabled: true
  url: "http://localhost/events"
)",
	                                               {}));

	ASSERT_EQ(falco_config.m_outputs.size(), 1);
	EXPECT_EQ(falco_config.m_outputs[0].options["unix_socket_path"], "");
}

TEST(ConfigurationHttpOutputOptions, rejects_relative_unix_socket_path) {
	falco_configuration falco_config;
	EXPECT_THROW(falco_config.init_from_content(R"(
http_output:
  enabled: true
  url: "http://localhost/events"
  unix_socket_path: "relative.sock"
)",
	                                            {}),
	             std::logic_error);
}

TEST(ConfigurationHttpOutputOptions, rejects_too_long_unix_socket_path) {
	falco_configuration falco_config;
	std::string config =
	        "http_output:\n"
	        "  enabled: true\n"
	        "  url: \"http://localhost/events\"\n"
	        "  unix_socket_path: \"/" +
	        std::string(200, 'a') + "\"\n";
	EXPECT_THROW(falco_config.init_from_content(config, {}), std::logic_error);
}
