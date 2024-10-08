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
#include <falco/configuration.h>
#include <falco_test_var.h>
#include <nlohmann/json.hpp>

#define EXPECT_VALIDATION_STATUS(res, status)                                                     \
	do {                                                                                          \
		for(const auto& pair : res) {                                                             \
			auto validation_status = pair.second;                                                 \
			EXPECT_TRUE(sinsp_utils::startswith(validation_status, status)) << validation_status; \
		}                                                                                         \
	} while(0)

// Read Falco config from current repo-path
TEST(Configuration, schema_validate_config) {
	falco_configuration falco_config;
	config_loaded_res res;

	if(!std::filesystem::exists(TEST_FALCO_CONFIG)) {
		GTEST_SKIP() << "Falco config not present under " << TEST_FALCO_CONFIG;
	}
	EXPECT_NO_THROW(res = falco_config.init_from_file(TEST_FALCO_CONFIG, {}));
	EXPECT_VALIDATION_STATUS(res, yaml_helper::validation_ok);
}

TEST(Configuration, schema_ok) {
	falco_configuration falco_config;
	config_loaded_res res;

	/* OK YAML */
	std::string config =
	        "falco_libs:\n"
	        "    thread_table_size: 50\n";

	EXPECT_NO_THROW(res = falco_config.init_from_content(config, {}));
	EXPECT_VALIDATION_STATUS(res, yaml_helper::validation_ok);
}

TEST(Configuration, schema_wrong_key) {
	falco_configuration falco_config;
	config_loaded_res res;

	/* Miss-typed key YAML */
	std::string config =
	        "falco_libss:\n"
	        "    thread_table_size: 50\n";

	EXPECT_NO_THROW(res = falco_config.init_from_content(config, {}));
	EXPECT_VALIDATION_STATUS(res, yaml_helper::validation_failed);
}

TEST(Configuration, schema_wrong_type) {
	falco_configuration falco_config;

	/* Wrong value type YAML */
	std::string config = "falco_libs: 512\n";

	// We expect an exception since `falco_configuration::load_yaml()`
	// will fail to parse `falco_libs` node.
	ASSERT_ANY_THROW(falco_config.init_from_content(config, {}));
}

TEST(Configuration, schema_wrong_embedded_key) {
	falco_configuration falco_config;
	config_loaded_res res;

	/* Miss-typed sub-key YAML */
	std::string config =
	        "falco_libs:\n"
	        "    thread_table_sizeee: 50\n";

	EXPECT_NO_THROW(res = falco_config.init_from_content(config, {}));
	EXPECT_VALIDATION_STATUS(res, yaml_helper::validation_failed);
}

TEST(Configuration, plugin_init_config) {
	falco_configuration falco_config;
	config_loaded_res res;

	std::string config = R"(
plugins:
  - name: k8saudit
    library_path: libk8saudit.so
    init_config:
      maxEventSize: 262144
      sslCertificate: /etc/falco/falco.pem
)";

	auto plugin_config_json = nlohmann::json::parse(
	        R"({"maxEventSize": 262144, "sslCertificate": "/etc/falco/falco.pem"})");

	EXPECT_NO_THROW(res = falco_config.init_from_content(config, {}));
	EXPECT_VALIDATION_STATUS(res, yaml_helper::validation_ok);
	auto parsed_init_config = nlohmann::json::parse(falco_config.m_plugins[0].m_init_config);
	EXPECT_EQ(parsed_init_config, plugin_config_json);

	config = R"(
plugins:
  - name: k8saudit
    library_path: libk8saudit.so
    init_config: '{"maxEventSize": 262144, "sslCertificate": "/etc/falco/falco.pem"}'
)";

	EXPECT_NO_THROW(res = falco_config.init_from_content(config, {}));
	EXPECT_VALIDATION_STATUS(res, yaml_helper::validation_ok);
	parsed_init_config = nlohmann::json::parse(falco_config.m_plugins[0].m_init_config);
	EXPECT_EQ(parsed_init_config, plugin_config_json);

	config = R"(
plugins:
  - name: k8saudit
    library_path: libk8saudit.so
    init_config: ""
)";

	EXPECT_NO_THROW(res = falco_config.init_from_content(config, {}));
	EXPECT_VALIDATION_STATUS(res, yaml_helper::validation_ok);
	EXPECT_EQ(falco_config.m_plugins[0].m_init_config, "");

	config = R"(
plugins:
  - name: k8saudit
    library_path: libk8saudit.so
    init_config: null
)";

	EXPECT_NO_THROW(res = falco_config.init_from_content(config, {}));
	EXPECT_VALIDATION_STATUS(res, yaml_helper::validation_ok);
	EXPECT_EQ(falco_config.m_plugins[0].m_init_config, "");
}

TEST(Configuration, schema_yaml_helper_validator) {
	yaml_helper conf;
	falco_configuration falco_config;

	/* Broken YAML */
	std::string sample_yaml =
	        "falco_libs:\n"
	        "    thread_table_size: 50\n";

	// Ok, we don't ask for any validation
	EXPECT_NO_THROW(conf.load_from_string(sample_yaml));

	// We pass a string variable but not a schema
	std::vector<std::string> validation;
	EXPECT_NO_THROW(conf.load_from_string(sample_yaml, nlohmann::json{}, &validation));
	EXPECT_EQ(validation[0], yaml_helper::validation_none);

	// We pass a schema but not a string storage for the validation; no validation takes place
	EXPECT_NO_THROW(conf.load_from_string(sample_yaml, falco_config.m_config_schema, nullptr));

	// We pass everything
	EXPECT_NO_THROW(conf.load_from_string(sample_yaml, falco_config.m_config_schema, &validation));
	EXPECT_EQ(validation[0], yaml_helper::validation_ok);
}
