/*
Copyright (C) 2019 Sysdig Inc.

This file is part of sysdig.

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

#include <gtest.h>
#include <cgroup_list_counter.h>

TEST(cgroup_list_counter_test, basic)
{
	libsinsp::cgroup_list_counter counter;
	ASSERT_EQ(8, counter("0-5,8,14"));
	ASSERT_EQ(1, counter("5"));
	ASSERT_EQ(6, counter("9-14"));
}

TEST(cgroup_list_counter_test, invalid_value)
{
	libsinsp::cgroup_list_counter counter;
	ASSERT_EQ(-1, counter(""));
	ASSERT_EQ(-1, counter(",1"));
}

TEST(cgroup_list_counter_test, invalid_range_missing_number)
{
	libsinsp::cgroup_list_counter counter;
	ASSERT_EQ(-1, counter("-5,8,14"));
	ASSERT_EQ(-1, counter("1,-5,8,14"));
	ASSERT_EQ(-1, counter("1,4-,14"));
	ASSERT_EQ(-1, counter("1,4-"));
}

TEST(cgroup_list_counter_test, invalid_range_double_dash)
{
	libsinsp::cgroup_list_counter counter;
	ASSERT_EQ(-1, counter("1,4-5-6,14"));
}

TEST(cgroup_list_counter_test, invalid_range_wrong_order)
{
	libsinsp::cgroup_list_counter counter;
	ASSERT_EQ(-1, counter("1,6-5,14"));
}

TEST(cgroup_list_counter_test, not_a_number)
{
	libsinsp::cgroup_list_counter counter;
	ASSERT_EQ(-1, counter("1,5-a,14"));
}


