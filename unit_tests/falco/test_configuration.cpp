/*
Copyright (C) 2023 The Falco Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless ASSERTd by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include <gtest/gtest.h>
#include <falco/configuration.h>

static std::string sample_yaml =
	"base_value:\n"
	"    id: 1\n"
	"    name: 'sample_name'\n"
	"    subvalue:\n"
	"      subvalue2:\n"
	"        boolean: true\n"
	"base_value_2:\n"
	"  sample_list:\n"
	"    - elem1\n"
	"    - elem2\n"
	"    - elem3\n";

TEST(Configuration, configuration_exceptions)
{
	yaml_helper conf;

	/* Broken YAML */
	std::string sample_broken_yaml = sample_yaml + " /  bad_symbol";
	EXPECT_ANY_THROW(conf.load_from_string(sample_broken_yaml));

	/* Right YAML */
	EXPECT_NO_THROW(conf.load_from_string(sample_yaml));
}

TEST(Configuration, configuration_reload)
{
	yaml_helper conf;

	/* Clear and reload config */
	conf.load_from_string(sample_yaml);
	ASSERT_TRUE(conf.is_defined("base_value"));
	conf.clear();
	ASSERT_FALSE(conf.is_defined("base_value"));
	conf.load_from_string(sample_yaml);
	ASSERT_TRUE(conf.is_defined("base_value"));
}

TEST(Configuration, read_yaml_fields)
{
	yaml_helper conf;
	conf.load_from_string(sample_yaml);

	/* is_defined */
	ASSERT_TRUE(conf.is_defined("base_value"));
	ASSERT_TRUE(conf.is_defined("base_value_2"));
	ASSERT_FALSE(conf.is_defined("unknown_base_value"));

	/* get some fields */
	ASSERT_EQ(conf.get_scalar<int>("base_value.id", -1), 1);
	ASSERT_STREQ(conf.get_scalar<std::string>("base_value.name", "none").c_str(), "sample_name");
	ASSERT_EQ(conf.get_scalar<bool>("base_value.subvalue.subvalue2.boolean", false), true);

	/* get list field elements */
	ASSERT_STREQ(conf.get_scalar<std::string>("base_value_2.sample_list[0]", "none").c_str(), "elem1");
	ASSERT_STREQ(conf.get_scalar<std::string>("base_value_2.sample_list[1]", "none").c_str(), "elem2");
	ASSERT_STREQ(conf.get_scalar<std::string>("base_value_2.sample_list[2]", "none").c_str(), "elem3");

	/* get sequence */
	std::vector<std::string> seq;
	conf.get_sequence(seq, "base_value_2.sample_list");
	ASSERT_EQ(seq.size(), 3);
	ASSERT_STREQ(seq[0].c_str(), "elem1");
	ASSERT_STREQ(seq[1].c_str(), "elem2");
	ASSERT_STREQ(seq[2].c_str(), "elem3");
}

TEST(Configuration, modify_yaml_fields)
{
	std::string key = "base_value.subvalue.subvalue2.boolean";
	yaml_helper conf;
	
    /* Get original value */
    conf.load_from_string(sample_yaml);
	ASSERT_EQ(conf.get_scalar<bool>(key, false), true);
	
    /* Modify the original value */
    conf.set_scalar<bool>(key, false);
	ASSERT_EQ(conf.get_scalar<bool>(key, true), false);
	
    /* Modify it again */
    conf.set_scalar<bool>(key, true);
	ASSERT_EQ(conf.get_scalar<bool>(key, false), true);
}
