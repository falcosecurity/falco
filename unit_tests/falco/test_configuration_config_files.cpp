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

TEST(Configuration, configuration_config_files_secondary_fail) {
	/* Test that a secondary config file is not able to include anything, triggering an exception.
	 */
	const std::string main_conf_yaml = yaml_helper::configs_key +
	                                   ":\n"
	                                   "  - conf_2.yaml\n"
	                                   "  - conf_3.yaml\n"
	                                   "foo: bar\n"
	                                   "base_value:\n"
	                                   "    id: 1\n"
	                                   "    name: foo\n";
	const std::string conf_yaml_2 = yaml_helper::configs_key +
	                                ":\n"
	                                "  - conf_4.yaml\n"
	                                "foo2: bar2\n"
	                                "base_value_2:\n"
	                                "    id: 2\n";

	std::ofstream outfile("main.yaml");
	outfile << main_conf_yaml;
	outfile.close();

	outfile.open("conf_2.yaml");
	outfile << conf_yaml_2;
	outfile.close();

	std::vector<std::string> cmdline_config_options;
	falco_configuration falco_config;
	ASSERT_ANY_THROW(falco_config.init_from_file("main.yaml", cmdline_config_options));

	std::filesystem::remove("main.yaml");
	std::filesystem::remove("conf_2.yaml");
}

TEST(Configuration, configuration_config_files_ok) {
	/* Test that every included config file was correctly parsed */
	const std::string main_conf_yaml = yaml_helper::configs_key +
	                                   ":\n"
	                                   "  - conf_2.yaml\n"
	                                   "  - conf_3.yaml\n"
	                                   "foo: bar\n"
	                                   "base_value:\n"
	                                   "    id: 1\n"
	                                   "    name: foo\n";
	const std::string conf_yaml_2 =
	        "foo2: bar2\n"
	        "base_value_2:\n"
	        "    id: 2\n";
	const std::string conf_yaml_3 =
	        "foo3: bar3\n"
	        "base_value_3:\n"
	        "    id: 3\n"
	        "    name: foo3\n";
	const std::string conf_yaml_4 =
	        "base_value_4:\n"
	        "    id: 4\n";

	std::ofstream outfile("main.yaml");
	outfile << main_conf_yaml;
	outfile.close();

	outfile.open("conf_2.yaml");
	outfile << conf_yaml_2;
	outfile.close();

	outfile.open("conf_3.yaml");
	outfile << conf_yaml_3;
	outfile.close();

	outfile.open("conf_4.yaml");
	outfile << conf_yaml_4;
	outfile.close();

	std::vector<std::string> cmdline_config_options;
	falco_configuration falco_config;
	config_loaded_res res;
	ASSERT_NO_THROW(res = falco_config.init_from_file("main.yaml", cmdline_config_options));

	// main + conf_2 + conf_3
	ASSERT_EQ(res.size(), 3);

	ASSERT_TRUE(falco_config.m_config.is_defined("foo"));
	ASSERT_EQ(falco_config.m_config.get_scalar<std::string>("foo", ""), "bar");
	ASSERT_TRUE(falco_config.m_config.is_defined("base_value.id"));
	ASSERT_EQ(falco_config.m_config.get_scalar<int>("base_value.id", 0), 1);
	ASSERT_TRUE(falco_config.m_config.is_defined("base_value.name"));
	ASSERT_EQ(falco_config.m_config.get_scalar<std::string>("base_value.name", ""), "foo");
	ASSERT_TRUE(falco_config.m_config.is_defined("foo2"));
	ASSERT_EQ(falco_config.m_config.get_scalar<std::string>("foo2", ""), "bar2");
	ASSERT_TRUE(falco_config.m_config.is_defined("base_value_2.id"));
	ASSERT_EQ(falco_config.m_config.get_scalar<int>("base_value_2.id", 0), 2);
	ASSERT_TRUE(falco_config.m_config.is_defined("foo3"));
	ASSERT_EQ(falco_config.m_config.get_scalar<std::string>("foo3", ""), "bar3");
	ASSERT_TRUE(falco_config.m_config.is_defined("base_value_3.id"));
	ASSERT_EQ(falco_config.m_config.get_scalar<int>("base_value_3.id", 0), 3);
	ASSERT_TRUE(falco_config.m_config.is_defined("base_value_3.name"));
	ASSERT_EQ(falco_config.m_config.get_scalar<std::string>("base_value_3.name", ""), "foo3");
	ASSERT_FALSE(falco_config.m_config.is_defined("base_value_4.id"));  // conf_4 is not included

	std::filesystem::remove("main.yaml");
	std::filesystem::remove("conf_2.yaml");
	std::filesystem::remove("conf_3.yaml");
	std::filesystem::remove("conf_4.yaml");
}

TEST(Configuration, configuration_config_files_relative_main) {
	/*
	 * Test that relative path are treated as relative to cwd and not to main config folder,
	 * and that absolute includes are ok too.
	 */
	const auto temp_main = std::filesystem::temp_directory_path() / "main.yaml";
	// So, conf_2 will be looked up in the same folder as main config file,
	// while conf_3, since is absolute, will be looked up in the absolute path (and found!).
	const std::string main_conf_yaml = yaml_helper::configs_key +
	                                   ":\n"
	                                   "  - conf_2.yaml\n"
	                                   "  - " +
	                                   std::filesystem::current_path().string() +
	                                   "/conf_3.yaml\n"
	                                   "foo: bar\n"
	                                   "base_value:\n"
	                                   "    id: 1\n"
	                                   "    name: foo\n";
	const std::string conf_yaml_2 =
	        "foo2: bar2\n"
	        "base_value_2:\n"
	        "    id: 2\n";
	const std::string conf_yaml_3 =
	        "foo3: bar3\n"
	        "base_value_3:\n"
	        "    id: 3\n"
	        "    name: foo3\n";

	std::ofstream outfile(temp_main.string());
	outfile << main_conf_yaml;
	outfile.close();

	outfile.open("conf_2.yaml");
	outfile << conf_yaml_2;
	outfile.close();

	outfile.open("conf_3.yaml");
	outfile << conf_yaml_3;
	outfile.close();

	std::vector<std::string> cmdline_config_options;
	falco_configuration falco_config;
	config_loaded_res res;
	ASSERT_NO_THROW(res = falco_config.init_from_file(temp_main.string(), cmdline_config_options));

	// main + conf_2 + conf_3
	ASSERT_EQ(res.size(), 3);

	ASSERT_TRUE(falco_config.m_config.is_defined("foo"));
	ASSERT_EQ(falco_config.m_config.get_scalar<std::string>("foo", ""), "bar");
	ASSERT_TRUE(falco_config.m_config.is_defined("base_value.id"));
	ASSERT_EQ(falco_config.m_config.get_scalar<int>("base_value.id", 0), 1);
	ASSERT_TRUE(falco_config.m_config.is_defined("base_value.name"));
	ASSERT_EQ(falco_config.m_config.get_scalar<std::string>("base_value.name", ""), "foo");
	ASSERT_TRUE(falco_config.m_config.is_defined("foo2"));
	ASSERT_EQ(falco_config.m_config.get_scalar<std::string>("foo2", ""), "bar2");
	ASSERT_TRUE(falco_config.m_config.is_defined("base_value_2"));
	ASSERT_EQ(falco_config.m_config.get_scalar<int>("base_value_2.id", 0), 2);
	ASSERT_TRUE(falco_config.m_config.is_defined("base_value_3.id"));
	ASSERT_EQ(falco_config.m_config.get_scalar<int>("base_value_3.id", 0), 3);

	std::filesystem::remove(temp_main.string());
	std::filesystem::remove("conf_2.yaml");
	std::filesystem::remove("conf_3.yaml");
}

TEST(Configuration, configuration_config_files_override) {
	/* Test that included config files are able to override configs from main file */
	const std::string main_conf_yaml = yaml_helper::configs_key +
	                                   ":\n"
	                                   "  - conf_2.yaml\n"
	                                   "  - conf_3.yaml\n"
	                                   "foo: bar\n"
	                                   "base_value:\n"
	                                   "    id: 1\n"
	                                   "    name: foo\n";
	const std::string conf_yaml_2 =
	        "foo2: bar2\n"
	        "base_value_2:\n"
	        "    id: 2\n";
	const std::string conf_yaml_3 =
	        "base_value:\n"
	        "    id: 3\n";

	std::ofstream outfile("main.yaml");
	outfile << main_conf_yaml;
	outfile.close();

	outfile.open("conf_2.yaml");
	outfile << conf_yaml_2;
	outfile.close();

	outfile.open("conf_3.yaml");
	outfile << conf_yaml_3;
	outfile.close();

	std::vector<std::string> cmdline_config_options;
	falco_configuration falco_config;
	config_loaded_res res;
	ASSERT_NO_THROW(res = falco_config.init_from_file("main.yaml", cmdline_config_options));

	// main + conf_2 + conf_3
	ASSERT_EQ(res.size(), 3);

	ASSERT_TRUE(falco_config.m_config.is_defined("foo"));
	ASSERT_EQ(falco_config.m_config.get_scalar<std::string>("foo", ""), "bar");
	ASSERT_TRUE(falco_config.m_config.is_defined("base_value.id"));
	ASSERT_EQ(falco_config.m_config.get_scalar<int>("base_value.id", 0), 3);  // overridden!
	ASSERT_FALSE(falco_config.m_config.is_defined(
	        "base_value.name"));  // no more present since entire `base_value` block was overridden
	ASSERT_TRUE(falco_config.m_config.is_defined("foo2"));
	ASSERT_EQ(falco_config.m_config.get_scalar<std::string>("foo2", ""), "bar2");
	ASSERT_TRUE(falco_config.m_config.is_defined("base_value_2.id"));
	ASSERT_EQ(falco_config.m_config.get_scalar<int>("base_value_2.id", 0), 2);
	ASSERT_FALSE(falco_config.m_config.is_defined("base_value_3.id"));  // not defined

	std::filesystem::remove("main.yaml");
	std::filesystem::remove("conf_2.yaml");
	std::filesystem::remove("conf_3.yaml");
}

TEST(Configuration, configuration_config_files_sequence_strategy_default) {
	const std::string main_conf_yaml = yaml_helper::configs_key +
	                                   ":\n"
	                                   "  - conf_2.yaml\n"  // default merge-strategy: append
	                                   "  - conf_3.yaml\n"
	                                   "foo: [ bar ]\n"
	                                   "base_value:\n"
	                                   "    id: 1\n"
	                                   "    name: foo\n";
	const std::string conf_yaml_2 =
	        "foo: [ bar2 ]\n"  // append to foo sequence
	        "base_value_2:\n"
	        "    id: 2\n";
	const std::string conf_yaml_3 =
	        "base_value:\n"  // override base_value
	        "    id: 3\n";

	std::ofstream outfile("main.yaml");
	outfile << main_conf_yaml;
	outfile.close();

	outfile.open("conf_2.yaml");
	outfile << conf_yaml_2;
	outfile.close();

	outfile.open("conf_3.yaml");
	outfile << conf_yaml_3;
	outfile.close();

	std::vector<std::string> cmdline_config_options;
	falco_configuration falco_config;
	config_loaded_res res;
	ASSERT_NO_THROW(res = falco_config.init_from_file("main.yaml", cmdline_config_options));

	// main + conf_2 + conf_3
	ASSERT_EQ(res.size(), 3);

	ASSERT_TRUE(falco_config.m_config.is_defined("foo"));
	std::vector<std::string> foos;
	auto expected_foos = std::vector<std::string>{"bar", "bar2"};
	ASSERT_NO_THROW(falco_config.m_config.get_sequence<std::vector<std::string>>(foos, "foo"));
	ASSERT_EQ(foos.size(), 2);  // 2 elements in `foo` sequence because we appended to it
	for(size_t i = 0; i < foos.size(); ++i) {
		EXPECT_EQ(foos[i], expected_foos[i])
		        << "Vectors foo's and expected_foo's differ at index " << i;
	}

	ASSERT_TRUE(falco_config.m_config.is_defined("base_value.id"));
	ASSERT_EQ(falco_config.m_config.get_scalar<int>("base_value.id", 0), 3);  // overridden!
	ASSERT_FALSE(falco_config.m_config.is_defined(
	        "base_value.name"));  // no more present since entire `base_value` block was overridden
	ASSERT_TRUE(falco_config.m_config.is_defined("base_value_2.id"));
	ASSERT_EQ(falco_config.m_config.get_scalar<int>("base_value_2.id", 0), 2);
	ASSERT_FALSE(falco_config.m_config.is_defined("base_value_3.id"));  // not defined

	std::filesystem::remove("main.yaml");
	std::filesystem::remove("conf_2.yaml");
	std::filesystem::remove("conf_3.yaml");
}

TEST(Configuration, configuration_config_files_sequence_strategy_append) {
	const std::string main_conf_yaml = yaml_helper::configs_key +
	                                   ":\n"
	                                   "  - path: conf_2.yaml\n"
	                                   "    strategy: append\n"
	                                   "  - conf_3.yaml\n"
	                                   "foo: [ bar ]\n"
	                                   "base_value:\n"
	                                   "    id: 1\n"
	                                   "    name: foo\n";
	const std::string conf_yaml_2 =
	        "foo: [ bar2 ]\n"  // append to foo sequence
	        "base_value_2:\n"
	        "    id: 2\n";
	const std::string conf_yaml_3 =
	        "base_value:\n"  // override base_value
	        "    id: 3\n";

	std::ofstream outfile("main.yaml");
	outfile << main_conf_yaml;
	outfile.close();

	outfile.open("conf_2.yaml");
	outfile << conf_yaml_2;
	outfile.close();

	outfile.open("conf_3.yaml");
	outfile << conf_yaml_3;
	outfile.close();

	std::vector<std::string> cmdline_config_options;
	falco_configuration falco_config;
	config_loaded_res res;
	ASSERT_NO_THROW(res = falco_config.init_from_file("main.yaml", cmdline_config_options));

	// main + conf_2 + conf_3
	ASSERT_EQ(res.size(), 3);

	ASSERT_TRUE(falco_config.m_config.is_defined("foo"));
	std::vector<std::string> foos;
	auto expected_foos = std::vector<std::string>{"bar", "bar2"};
	ASSERT_NO_THROW(falco_config.m_config.get_sequence<std::vector<std::string>>(foos, "foo"));
	ASSERT_EQ(foos.size(), 2);  // 2 elements in `foo` sequence because we appended to it
	for(size_t i = 0; i < foos.size(); ++i) {
		EXPECT_EQ(foos[i], expected_foos[i])
		        << "Vectors foo's and expected_foo's differ at index " << i;
	}

	ASSERT_TRUE(falco_config.m_config.is_defined("base_value.id"));
	ASSERT_EQ(falco_config.m_config.get_scalar<int>("base_value.id", 0), 3);  // overridden!
	ASSERT_FALSE(falco_config.m_config.is_defined(
	        "base_value.name"));  // no more present since entire `base_value` block was overridden
	ASSERT_TRUE(falco_config.m_config.is_defined("base_value_2.id"));
	ASSERT_EQ(falco_config.m_config.get_scalar<int>("base_value_2.id", 0), 2);
	ASSERT_FALSE(falco_config.m_config.is_defined("base_value_3.id"));  // not defined

	std::filesystem::remove("main.yaml");
	std::filesystem::remove("conf_2.yaml");
	std::filesystem::remove("conf_3.yaml");
}

TEST(Configuration, configuration_config_files_sequence_strategy_override) {
	const std::string main_conf_yaml = yaml_helper::configs_key +
	                                   ":\n"
	                                   "  - path: conf_2.yaml\n"
	                                   "    strategy: override\n"
	                                   "  - conf_3.yaml\n"
	                                   "foo: [ bar ]\n"
	                                   "base_value:\n"
	                                   "    id: 1\n"
	                                   "    name: foo\n";
	const std::string conf_yaml_2 =
	        "foo: [ bar2 ]\n"  // override foo sequence
	        "base_value_2:\n"
	        "    id: 2\n";
	const std::string conf_yaml_3 =
	        "base_value:\n"  // override base_value
	        "    id: 3\n";

	std::ofstream outfile("main.yaml");
	outfile << main_conf_yaml;
	outfile.close();

	outfile.open("conf_2.yaml");
	outfile << conf_yaml_2;
	outfile.close();

	outfile.open("conf_3.yaml");
	outfile << conf_yaml_3;
	outfile.close();

	std::vector<std::string> cmdline_config_options;
	falco_configuration falco_config;
	config_loaded_res res;
	ASSERT_NO_THROW(res = falco_config.init_from_file("main.yaml", cmdline_config_options));

	// main + conf_2 + conf_3
	ASSERT_EQ(res.size(), 3);

	ASSERT_TRUE(falco_config.m_config.is_defined("foo"));
	std::vector<std::string> foos;
	auto expected_foos = std::vector<std::string>{"bar2"};
	ASSERT_NO_THROW(falco_config.m_config.get_sequence<std::vector<std::string>>(foos, "foo"));
	ASSERT_EQ(foos.size(), 1);  // one element in `foo` sequence because we overrode it
	for(size_t i = 0; i < foos.size(); ++i) {
		EXPECT_EQ(foos[i], expected_foos[i])
		        << "Vectors foo's and expected_foo's differ at index " << i;
	}

	ASSERT_TRUE(falco_config.m_config.is_defined("base_value.id"));
	ASSERT_EQ(falco_config.m_config.get_scalar<int>("base_value.id", 0), 3);  // overridden!
	ASSERT_FALSE(falco_config.m_config.is_defined(
	        "base_value.name"));  // no more present since entire `base_value` block was overridden
	ASSERT_TRUE(falco_config.m_config.is_defined("base_value_2.id"));
	ASSERT_EQ(falco_config.m_config.get_scalar<int>("base_value_2.id", 0), 2);
	ASSERT_FALSE(falco_config.m_config.is_defined("base_value_3.id"));  // not defined

	std::filesystem::remove("main.yaml");
	std::filesystem::remove("conf_2.yaml");
	std::filesystem::remove("conf_3.yaml");
}

TEST(Configuration, configuration_config_files_sequence_strategy_addonly) {
	/* Test that included config files are able to override configs from main file */
	const std::string main_conf_yaml = yaml_helper::configs_key +
	                                   ":\n"
	                                   "  - path: conf_2.yaml\n"
	                                   "    strategy: add-only\n"
	                                   "  - conf_3.yaml\n"
	                                   "foo: [ bar ]\n"
	                                   "base_value:\n"
	                                   "    id: 1\n"
	                                   "    name: foo\n";
	const std::string conf_yaml_2 =
	        "foo: [ bar2 ]\n"  // ignored: add-only strategy
	        "base_value_2:\n"
	        "    id: 2\n";
	const std::string conf_yaml_3 =
	        "base_value:\n"  // override base_value
	        "    id: 3\n";

	std::ofstream outfile("main.yaml");
	outfile << main_conf_yaml;
	outfile.close();

	outfile.open("conf_2.yaml");
	outfile << conf_yaml_2;
	outfile.close();

	outfile.open("conf_3.yaml");
	outfile << conf_yaml_3;
	outfile.close();

	std::vector<std::string> cmdline_config_options;
	falco_configuration falco_config;
	config_loaded_res res;
	ASSERT_NO_THROW(res = falco_config.init_from_file("main.yaml", cmdline_config_options));

	// main + conf_2 + conf_3
	ASSERT_EQ(res.size(), 3);

	ASSERT_TRUE(falco_config.m_config.is_defined("foo"));
	std::vector<std::string> foos;
	auto expected_foos =
	        std::vector<std::string>{"bar"};  // bar2 is ignored because of merge-strategy: add-only
	ASSERT_NO_THROW(falco_config.m_config.get_sequence<std::vector<std::string>>(foos, "foo"));
	ASSERT_EQ(foos.size(), 1);  // one element in `foo` sequence because we overrode it
	for(size_t i = 0; i < foos.size(); ++i) {
		EXPECT_EQ(foos[i], expected_foos[i])
		        << "Vectors foo's and expected_foo's differ at index " << i;
	}

	ASSERT_TRUE(falco_config.m_config.is_defined("base_value.id"));
	ASSERT_EQ(falco_config.m_config.get_scalar<int>("base_value.id", 0), 3);  // overridden!
	ASSERT_FALSE(falco_config.m_config.is_defined(
	        "base_value.name"));  // no more present since entire `base_value` block was overridden
	ASSERT_TRUE(falco_config.m_config.is_defined("base_value_2.id"));
	ASSERT_EQ(falco_config.m_config.get_scalar<int>("base_value_2.id", 0), 2);
	ASSERT_FALSE(falco_config.m_config.is_defined("base_value_3.id"));  // not defined

	std::filesystem::remove("main.yaml");
	std::filesystem::remove("conf_2.yaml");
	std::filesystem::remove("conf_3.yaml");
}

TEST(Configuration, configuration_config_files_sequence_wrong_strategy) {
	const std::string main_conf_yaml = yaml_helper::configs_key +
	                                   ":\n"
	                                   "  - path: conf_2.yaml\n"
	                                   "    strategy: wrong\n"
	                                   "  - conf_3.yaml\n"
	                                   "foo: [ bar ]\n"
	                                   "base_value:\n"
	                                   "    id: 1\n"
	                                   "    name: foo\n";
	const std::string conf_yaml_2 =
	        "foo: [ bar2 ]\n"  // append to foo sequence
	        "base_value_2:\n"
	        "    id: 2\n";
	const std::string conf_yaml_3 =
	        "base_value:\n"  // override base_value
	        "    id: 3\n";

	std::ofstream outfile("main.yaml");
	outfile << main_conf_yaml;
	outfile.close();

	outfile.open("conf_2.yaml");
	outfile << conf_yaml_2;
	outfile.close();

	outfile.open("conf_3.yaml");
	outfile << conf_yaml_3;
	outfile.close();

	std::vector<std::string> cmdline_config_options;
	falco_configuration falco_config;
	config_loaded_res res;
	ASSERT_NO_THROW(res = falco_config.init_from_file("main.yaml", cmdline_config_options));

	// main
	ASSERT_EQ(res.size(), 3);
	auto validation = res["main.yaml"];
	// Since we are using a wrong strategy, the validation should fail
	// but the enforced strategy should be "append"
	ASSERT_NE(validation, yaml_helper::validation_ok);

	ASSERT_TRUE(falco_config.m_config.is_defined("foo"));
	std::vector<std::string> foos;
	auto expected_foos = std::vector<std::string>{"bar", "bar2"};
	ASSERT_NO_THROW(falco_config.m_config.get_sequence<std::vector<std::string>>(foos, "foo"));
	ASSERT_EQ(foos.size(), 2);  // 2 elements in `foo` sequence because we appended to it
	for(size_t i = 0; i < foos.size(); ++i) {
		EXPECT_EQ(foos[i], expected_foos[i])
		        << "Vectors foo's and expected_foo's differ at index " << i;
	}

	ASSERT_TRUE(falco_config.m_config.is_defined("base_value.id"));
	ASSERT_EQ(falco_config.m_config.get_scalar<int>("base_value.id", 0), 3);  // overridden!
	ASSERT_FALSE(falco_config.m_config.is_defined(
	        "base_value.name"));  // no more present since entire `base_value` block was overridden
	ASSERT_TRUE(falco_config.m_config.is_defined("base_value_2.id"));
	ASSERT_EQ(falco_config.m_config.get_scalar<int>("base_value_2.id", 0), 2);
	ASSERT_FALSE(falco_config.m_config.is_defined("base_value_3.id"));  // not defined

	std::filesystem::remove("main.yaml");
	std::filesystem::remove("conf_2.yaml");
	std::filesystem::remove("conf_3.yaml");
}

TEST(Configuration, configuration_config_files_unexistent) {
	/* Test that including an unexistent file just skips it */
	const std::string main_conf_yaml = yaml_helper::configs_key +
	                                   ":\n"
	                                   "  - conf_5.yaml\n"
	                                   "base_value:\n"
	                                   "    id: 1\n"
	                                   "    name: foo\n";

	std::ofstream outfile("main.yaml");
	outfile << main_conf_yaml;
	outfile.close();

	std::vector<std::string> cmdline_config_options;
	falco_configuration falco_config;
	config_loaded_res res;
	ASSERT_NO_THROW(res = falco_config.init_from_file("main.yaml", cmdline_config_options));

	// main
	ASSERT_EQ(res.size(), 1);

	ASSERT_TRUE(falco_config.m_config.is_defined("base_value.id"));
	ASSERT_EQ(falco_config.m_config.get_scalar<int>("base_value.id", 0), 1);
	ASSERT_TRUE(falco_config.m_config.is_defined("base_value.name"));
	ASSERT_EQ(falco_config.m_config.get_scalar<std::string>("base_value.name", ""), "foo");

	std::filesystem::remove("main.yaml");
}

TEST(Configuration, configuration_config_files_scalar_config_files) {
	/* Test that a single file can be included as a scalar (thanks to get_sequence_from_node magic)
	 */
	const std::string main_conf_yaml = yaml_helper::configs_key +
	                                   ": conf_2.yaml\n"
	                                   "foo: bar\n"
	                                   "base_value:\n"
	                                   "    id: 1\n"
	                                   "    name: foo\n";
	const std::string conf_yaml_2 =
	        "foo2: bar2\n"
	        "base_value_2:\n"
	        "    id: 2\n";

	std::ofstream outfile("main.yaml");
	outfile << main_conf_yaml;
	outfile.close();

	outfile.open("conf_2.yaml");
	outfile << conf_yaml_2;
	outfile.close();

	std::vector<std::string> cmdline_config_options;
	falco_configuration falco_config;
	config_loaded_res res;
	ASSERT_NO_THROW(res = falco_config.init_from_file("main.yaml", cmdline_config_options));

	// main + conf_2
	ASSERT_EQ(res.size(), 2);

	ASSERT_TRUE(falco_config.m_config.is_defined("foo"));
	ASSERT_EQ(falco_config.m_config.get_scalar<std::string>("foo", ""), "bar");
	ASSERT_TRUE(falco_config.m_config.is_defined("base_value.id"));
	ASSERT_EQ(falco_config.m_config.get_scalar<int>("base_value.id", 0), 1);
	ASSERT_TRUE(falco_config.m_config.is_defined("base_value.name"));
	ASSERT_EQ(falco_config.m_config.get_scalar<std::string>("base_value.name", ""), "foo");
	ASSERT_TRUE(falco_config.m_config.is_defined("foo2"));
	ASSERT_EQ(falco_config.m_config.get_scalar<std::string>("foo2", ""), "bar2");
	ASSERT_TRUE(falco_config.m_config.is_defined("base_value_2.id"));
	ASSERT_EQ(falco_config.m_config.get_scalar<int>("base_value_2.id", 0), 2);

	std::filesystem::remove("main.yaml");
	std::filesystem::remove("conf_2.yaml");
}

TEST(Configuration, configuration_config_files_empty_config_files) {
	/* Test that empty includes list is accepted */
	const std::string main_conf_yaml = yaml_helper::configs_key +
	                                   ":\n"
	                                   "foo: bar\n"
	                                   "base_value:\n"
	                                   "    id: 1\n"
	                                   "    name: foo\n";

	std::ofstream outfile("main.yaml");
	outfile << main_conf_yaml;
	outfile.close();

	std::vector<std::string> cmdline_config_options;
	falco_configuration falco_config;
	config_loaded_res res;
	ASSERT_NO_THROW(res = falco_config.init_from_file("main.yaml", cmdline_config_options));

	// main
	ASSERT_EQ(res.size(), 1);

	ASSERT_TRUE(falco_config.m_config.is_defined("foo"));
	ASSERT_EQ(falco_config.m_config.get_scalar<std::string>("foo", ""), "bar");
	ASSERT_TRUE(falco_config.m_config.is_defined("base_value.id"));
	ASSERT_EQ(falco_config.m_config.get_scalar<int>("base_value.id", 0), 1);
	ASSERT_TRUE(falco_config.m_config.is_defined("base_value.name"));
	ASSERT_EQ(falco_config.m_config.get_scalar<std::string>("base_value.name", ""), "foo");

	std::filesystem::remove("main.yaml");
}

TEST(Configuration, configuration_config_files_self) {
	/* Test that main config file cannot include itself */
	const std::string main_conf_yaml = yaml_helper::configs_key +
	                                   ": main.yaml\n"
	                                   "foo: bar\n"
	                                   "base_value:\n"
	                                   "    id: 1\n"
	                                   "    name: foo\n";

	std::ofstream outfile("main.yaml");
	outfile << main_conf_yaml;
	outfile.close();

	std::vector<std::string> cmdline_config_options;
	falco_configuration falco_config;
	ASSERT_ANY_THROW(falco_config.init_from_file("main.yaml", cmdline_config_options));

	std::filesystem::remove("main.yaml");
}

TEST(Configuration, configuration_config_files_directory) {
	/*
	 * Test that when main config file includes a config directory,
	 * the config directory is parsed in lexicographic order,
	 * and only regular files are parsed.
	 */
	// Main config includes whole temp directory
	const std::string main_conf_yaml = yaml_helper::configs_key + ": " +
	                                   std::filesystem::temp_directory_path().string() +
	                                   "/test\n"
	                                   "foo: bar\n"
	                                   "base_value:\n"
	                                   "    id: 1\n"
	                                   "    name: foo\n";
	const std::string conf_yaml_2 =
	        "foo2: bar2\n"
	        "base_value_2:\n"
	        "    id: 2\n";
	const std::string conf_yaml_3 =
	        "foo2: bar3\n"
	        "base_value_3:\n"
	        "    id: 3\n"
	        "    name: foo3\n";
	const std::string conf_yaml_4 = "foo4: bar4\n";

	std::filesystem::create_directory(std::filesystem::temp_directory_path() / "test");

	std::ofstream outfile("main.yaml");
	outfile << main_conf_yaml;
	outfile.close();

	outfile.open(std::filesystem::temp_directory_path() / "test/conf_2.yaml");
	outfile << conf_yaml_2;
	outfile.close();

	outfile.open(std::filesystem::temp_directory_path() / "test/conf_3.yaml");
	outfile << conf_yaml_3;
	outfile.close();

	// Create a directory and create a config inside it. We will later check that it was not parsed
	std::filesystem::create_directory(std::filesystem::temp_directory_path() / "test" / "foo");
	outfile.open(std::filesystem::temp_directory_path() / "test/foo/conf_4.yaml");
	outfile << conf_yaml_4;
	outfile.close();

	std::vector<std::string> cmdline_config_options;
	falco_configuration falco_config;
	config_loaded_res res;
	ASSERT_NO_THROW(res = falco_config.init_from_file("main.yaml", cmdline_config_options));

	// main + conf_2 + conf_3.
	// test/foo is not parsed.
	ASSERT_EQ(res.size(), 3);

	ASSERT_TRUE(falco_config.m_config.is_defined("foo"));
	ASSERT_EQ(falco_config.m_config.get_scalar<std::string>("foo", ""), "bar");
	ASSERT_TRUE(falco_config.m_config.is_defined("base_value.id"));
	ASSERT_EQ(falco_config.m_config.get_scalar<int>("base_value.id", 0), 1);
	ASSERT_TRUE(falco_config.m_config.is_defined("base_value.name"));
	ASSERT_EQ(falco_config.m_config.get_scalar<std::string>("base_value.name", ""), "foo");
	ASSERT_TRUE(falco_config.m_config.is_defined("base_value_2"));
	ASSERT_EQ(falco_config.m_config.get_scalar<int>("base_value_2.id", 0), 2);
	ASSERT_TRUE(falco_config.m_config.is_defined("base_value_3.id"));
	ASSERT_EQ(falco_config.m_config.get_scalar<int>("base_value_3.id", 0), 3);
	ASSERT_TRUE(falco_config.m_config.is_defined("foo2"));
	ASSERT_EQ(falco_config.m_config.get_scalar<std::string>("foo2", ""), "bar3");
	ASSERT_FALSE(falco_config.m_config.is_defined("foo4"));

	std::filesystem::remove("main");
	std::filesystem::remove_all(std::filesystem::temp_directory_path() / "test");
}

TEST(Configuration, configuration_config_files_cmdline) {
	/* Test that we support including configs files from cmdline option */
	const std::string main_conf_yaml =
	        "foo: bar\n"
	        "base_value:\n"
	        "    id: 1\n"
	        "    name: foo\n";
	const std::string conf_yaml_2 =
	        "foo2: bar2\n"
	        "base_value_2:\n"
	        "    id: 2\n";

	std::ofstream outfile("main.yaml");
	outfile << main_conf_yaml;
	outfile.close();

	outfile.open("conf_2.yaml");
	outfile << conf_yaml_2;
	outfile.close();

	// Pass "config_files=..." cmdline option
	std::vector<std::string> cmdline_config_options;
	cmdline_config_options.push_back((yaml_helper::configs_key + "=conf_2.yaml"));

	// Override foo2 value from cli
	cmdline_config_options.push_back(("foo2=bar22"));

	falco_configuration falco_config;
	config_loaded_res res;
	ASSERT_NO_THROW(res = falco_config.init_from_file("main.yaml", cmdline_config_options));

	// main + conf_2
	ASSERT_EQ(res.size(), 2);

	ASSERT_TRUE(falco_config.m_config.is_defined("foo"));
	ASSERT_EQ(falco_config.m_config.get_scalar<std::string>("foo", ""), "bar");
	ASSERT_TRUE(falco_config.m_config.is_defined("base_value.id"));
	ASSERT_EQ(falco_config.m_config.get_scalar<int>("base_value.id", 0), 1);
	ASSERT_TRUE(falco_config.m_config.is_defined("base_value.name"));
	ASSERT_EQ(falco_config.m_config.get_scalar<std::string>("base_value.name", ""), "foo");
	ASSERT_TRUE(falco_config.m_config.is_defined("foo2"));
	ASSERT_EQ(falco_config.m_config.get_scalar<std::string>("foo2", ""), "bar22");
	ASSERT_TRUE(falco_config.m_config.is_defined("base_value_2.id"));
	ASSERT_EQ(falco_config.m_config.get_scalar<int>("base_value_2.id", 0), 2);

	std::filesystem::remove("main.yaml");
	std::filesystem::remove("conf_2.yaml");
}
