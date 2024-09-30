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

#ifdef _WIN32
#define SET_ENV_VAR(env_var_name, env_var_value) _putenv_s(env_var_name, env_var_value)
#else
#define SET_ENV_VAR(env_var_name, env_var_value) setenv(env_var_name, env_var_value, 1)
#endif

TEST(Configuration, configuration_environment_variables) {
	// Set an environment variable for testing purposes
	std::string env_var_value = "envVarValue";
	std::string env_var_name = "ENV_VAR";
	SET_ENV_VAR(env_var_name.c_str(), env_var_value.c_str());

	std::string embedded_env_var_value = "${ENV_VAR}";
	std::string embedded_env_var_name = "ENV_VAR_EMBEDDED";
	SET_ENV_VAR(embedded_env_var_name.c_str(), embedded_env_var_value.c_str());

	std::string bool_env_var_value = "true";
	std::string bool_env_var_name = "ENV_VAR_BOOL";
	SET_ENV_VAR(bool_env_var_name.c_str(), bool_env_var_value.c_str());

	std::string int_env_var_value = "12";
	std::string int_env_var_name = "ENV_VAR_INT";
	SET_ENV_VAR(int_env_var_name.c_str(), int_env_var_value.c_str());

	std::string empty_env_var_value = "";
	std::string empty_env_var_name = "ENV_VAR_EMPTY";
	SET_ENV_VAR(empty_env_var_name.c_str(), empty_env_var_value.c_str());

	std::string default_value = "default";
	std::string env_var_sample_yaml =
	        "base_value:\n"
	        "    id: $ENV_VAR\n"
	        "    name: '${ENV_VAR}'\n"
	        "    string: my_string\n"
	        "    invalid: $${ENV_VAR}\n"
	        "    invalid_env: $$ENV_VAR\n"
	        "    invalid_double_env: $${ENV_VAR}$${ENV_VAR}\n"
	        "    invalid_embedded_env: $${${ENV_VAR}}\n"
	        "    invalid_valid_env: $${ENV_VAR}${ENV_VAR}\n"
	        "    escaped: \"${ENV_VAR}\"\n"
	        "    subvalue:\n"
	        "        subvalue2:\n"
	        "            boolean: ${UNSED_XX_X_X_VAR}\n"
	        "base_value_2:\n"
	        "    sample_list:\n"
	        "        - ${ENV_VAR}\n"
	        "        - ' ${ENV_VAR}'\n"
	        "        - '${ENV_VAR} '\n"
	        "        - $UNSED_XX_X_X_VAR\n"
	        "paths:\n"
	        "    - ${ENV_VAR}/foo\n"
	        "    - $ENV_VAR/foo\n"
	        "    - /foo/${ENV_VAR}/\n"
	        "    - /${ENV_VAR}/${ENV_VAR}${ENV_VAR}/foo\n"
	        "    - ${ENV_VAR_EMBEDDED}/foo\n"
	        "is_test: ${ENV_VAR_BOOL}\n"
	        "num_test: ${ENV_VAR_INT}\n"
	        "empty_test: ${ENV_VAR_EMPTY}\n"
	        "plugins:\n"
	        "  - name: k8saudit\n"
	        "    library_path: /foo/${ENV_VAR}/libk8saudit.so\n"
	        "    open_params: ${ENV_VAR_INT}\n";

	yaml_helper conf;
	conf.load_from_string(env_var_sample_yaml);

	/* Check if the base values are defined */
	ASSERT_TRUE(conf.is_defined("base_value"));
	ASSERT_TRUE(conf.is_defined("base_value_2"));
	ASSERT_TRUE(conf.is_defined("paths"));
	ASSERT_FALSE(conf.is_defined("unknown_base_value"));

	/* Test fetching of a regular string without any environment variable */
	auto base_value_string = conf.get_scalar<std::string>("base_value.string", default_value);
	ASSERT_EQ(base_value_string, "my_string");

	/* Test fetching of escaped environment variable format. Should return the string as-is after
	 * stripping the leading `$` */
	auto base_value_invalid = conf.get_scalar<std::string>("base_value.invalid", default_value);
	ASSERT_EQ(base_value_invalid, "${ENV_VAR}");

	/* Test fetching of invalid escaped environment variable format. Should return the string as-is
	 */
	auto base_value_invalid_env =
	        conf.get_scalar<std::string>("base_value.invalid_env", default_value);
	ASSERT_EQ(base_value_invalid_env, "$$ENV_VAR");

	/* Test fetching of 2 escaped environment variables side by side. Should return the string as-is
	 * after stripping the leading `$` */
	auto base_value_double_invalid =
	        conf.get_scalar<std::string>("base_value.invalid_double_env", default_value);
	ASSERT_EQ(base_value_double_invalid, "${ENV_VAR}${ENV_VAR}");

	/*
	 * Test fetching of escaped environment variable format with inside an env variable.
	 * Should return the string as-is after stripping the leading `$` with the resolved env variable
	 * within
	 */
	auto base_value_embedded_invalid =
	        conf.get_scalar<std::string>("base_value.invalid_embedded_env", default_value);
	ASSERT_EQ(base_value_embedded_invalid, "${" + env_var_value + "}");

	/*
	 * Test fetching of an escaped env variable plus an env variable side by side.
	 * Should return the escaped one trimming the leading `$` plus the second one resolved.
	 */
	auto base_value_valid_invalid =
	        conf.get_scalar<std::string>("base_value.invalid_valid_env", default_value);
	ASSERT_EQ(base_value_valid_invalid, "${ENV_VAR}" + env_var_value);

	/* Test fetching of strings that contain environment variables */
	auto base_value_id = conf.get_scalar<std::string>("base_value.id", default_value);
	ASSERT_EQ(base_value_id, "$ENV_VAR");  // Does not follow the `${VAR}` format, so it should be
	                                       // treated as a regular string

	auto base_value_name = conf.get_scalar<std::string>("base_value.name", default_value);
	ASSERT_EQ(base_value_name, env_var_value);  // Proper environment variable format

	auto base_value_escaped = conf.get_scalar<std::string>("base_value.escaped", default_value);
	ASSERT_EQ(base_value_escaped, env_var_value);  // Environment variable within quotes

	/* Test fetching of an undefined environment variable. Resolves to empty string. */
	auto unknown_boolean =
	        conf.get_scalar<std::string>("base_value.subvalue.subvalue2.boolean", default_value);
	ASSERT_EQ(unknown_boolean, "");

	/* Test fetching of environment variables from a list */
	auto base_value_2_list_0 =
	        conf.get_scalar<std::string>("base_value_2.sample_list[0]", default_value);
	ASSERT_EQ(base_value_2_list_0, env_var_value);  // Proper environment variable format

	auto base_value_2_list_1 =
	        conf.get_scalar<std::string>("base_value_2.sample_list[1]", default_value);
	ASSERT_EQ(base_value_2_list_1,
	          " " + env_var_value);  // Environment variable preceded by a space, still extracted
	                                 // env var with leading space

	auto base_value_2_list_2 =
	        conf.get_scalar<std::string>("base_value_2.sample_list[2]", default_value);
	ASSERT_EQ(base_value_2_list_2,
	          env_var_value + " ");  // Environment variable followed by a space, still extracted
	                                 // env var with trailing space

	auto base_value_2_list_3 =
	        conf.get_scalar<std::string>("base_value_2.sample_list[3]", default_value);
	ASSERT_EQ(base_value_2_list_3, "$UNSED_XX_X_X_VAR");  // Does not follow the `${VAR}` format, so
	                                                      // should be treated as a regular string

	/* Test expansion of environment variables within strings */
	auto path_list_0 = conf.get_scalar<std::string>("paths[0]", default_value);
	ASSERT_EQ(
	        path_list_0,
	        env_var_value + "/foo");  // Even if env var is part of bigger string, it gets expanded

	auto path_list_1 = conf.get_scalar<std::string>("paths[1]", default_value);
	ASSERT_EQ(path_list_1, "$ENV_VAR/foo");  // Does not follow the `${VAR}` format, so should be
	                                         // treated as a regular string

	auto path_list_2 = conf.get_scalar<std::string>("paths[2]", default_value);
	ASSERT_EQ(path_list_2,
	          "/foo/" + env_var_value +
	                  "/");  // Even when env var is in the middle of a string. it gets expanded

	auto path_list_3 = conf.get_scalar<std::string>("paths[3]", default_value);
	ASSERT_EQ(path_list_3,
	          "/" + env_var_value + "/" + env_var_value + env_var_value +
	                  "/foo");  // Even when the string contains multiple env vars they are
	                            // correctly expanded

	auto path_list_4 = conf.get_scalar<std::string>("paths[4]", default_value);
	ASSERT_EQ(path_list_4, env_var_value + "/foo");  // Even when the env var contains another env
	                                                 // var, it gets correctly double-expanded

	/* Check that variable expansion is type-aware */
	auto boolean = conf.get_scalar<bool>("is_test", false);
	ASSERT_EQ(boolean, true);  // `true` can be parsed to bool.

	auto boolean_as_str = conf.get_scalar<std::string>("is_test", "false");
	ASSERT_EQ(boolean_as_str, "true");  // `true` can be parsed to string.

	auto boolean_as_int = conf.get_scalar<int32_t>("is_test", 0);
	ASSERT_EQ(boolean_as_int, 0);  // `true` cannot be parsed to integer.

	auto integer = conf.get_scalar<int32_t>("num_test", -1);
	ASSERT_EQ(integer, 12);

	// An env var that resolves to an empty string returns ""
	auto empty_default_str = conf.get_scalar<std::string>("empty_test", default_value);
	ASSERT_EQ(empty_default_str, "");

	std::list<falco_configuration::plugin_config> plugins;
	conf.get_sequence<std::list<falco_configuration::plugin_config>>(plugins,
	                                                                 std::string("plugins"));
	std::vector<falco_configuration::plugin_config> m_plugins{
	        std::make_move_iterator(std::begin(plugins)),
	        std::make_move_iterator(std::end(plugins))};
	ASSERT_EQ(m_plugins[0].m_name, "k8saudit");
	ASSERT_EQ(m_plugins[0].m_library_path, "/foo/" + env_var_value + "/libk8saudit.so");
	ASSERT_EQ(m_plugins[0].m_open_params, "12");

	/* Clear the set environment variables after testing */
	SET_ENV_VAR(env_var_name.c_str(), "");
	SET_ENV_VAR(embedded_env_var_name.c_str(), "");
	SET_ENV_VAR(bool_env_var_name.c_str(), "");
	SET_ENV_VAR(int_env_var_name.c_str(), "");
	SET_ENV_VAR(empty_env_var_name.c_str(), "");
}
