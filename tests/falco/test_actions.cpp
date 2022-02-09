/*
Copyright (C) 2022 The Falco Authors.

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

#include "app_action_manager.h"

#include <catch.hpp>

// Test actions just record the order they were run (or skipped)
class test_action : public falco::app::runnable_action {
public:

	static std::list<std::string> s_actions_run;

	test_action(const std::string &name,
		    const std::list<std::string> &prerequsites,
		    run_result res)
		: m_name(name),
		  m_prerequsites(prerequsites),
		  m_res(res)
		{
		}

	~test_action()
		{
		}

	const std::string &name()
	{
		return m_name;
	}

	const std::list<std::string> &prerequsites()
	{
		return m_prerequsites;
	}

	run_result run()
	{
		s_actions_run.push_back(m_name);
		return m_res;
	}

private:
	std::string m_name;
	std::list<std::string> m_prerequsites;
	run_result m_res;
};

std::list<std::string> test_action::s_actions_run;

static std::list<std::string> empty;

std::list<std::string> prereq_first = {"first"};
std::list<std::string> prereq_third = {"third"};
std::list<std::string> prereq_fourth = {"fourth"};

static falco::app::runnable_action::run_result success_proceed{true, "", true};

static falco::app::runnable_action::run_result success_noproceed{true, "", false};

// No prereqs, succeeds with proceed=true
static std::shared_ptr<test_action> first = std::make_shared<test_action>(std::string("first"),
									  empty,
									  success_proceed);

static std::shared_ptr<test_action> first_noproceed = std::make_shared<test_action>(std::string("first"),
										    empty,
										    success_noproceed);

// Identical to first
static std::shared_ptr<test_action> second = std::make_shared<test_action>(std::string("second"),
									   empty,
									   success_proceed);

// Has first as prereq, succeeds with proceed=true
std::shared_ptr<test_action> third = std::make_shared<test_action>(std::string("third"),
								   prereq_first,
								   success_proceed);

std::shared_ptr<test_action> third_noproceed = std::make_shared<test_action>(std::string("third"),
									     prereq_first,
									     success_noproceed);

std::shared_ptr<test_action> third_depends_fourth = std::make_shared<test_action>(std::string("third"),
										  prereq_fourth,
										  success_noproceed);

// Depends on third
std::shared_ptr<test_action> fourth = std::make_shared<test_action>(std::string("fourth"),
								    prereq_third,
								    success_proceed);

std::shared_ptr<test_action> fourth_noproceed = std::make_shared<test_action>(std::string("fourth"),
									      prereq_third,
									      success_noproceed);

static std::list<std::string>::iterator find_action(const std::string &name,
						    std::list<std::string>::iterator begin = test_action::s_actions_run.begin())
{
	return std::find(begin,
			 test_action::s_actions_run.end(),
			 name);
}

static bool action_is_found(const std::string &name,
			    std::list<std::string>::iterator begin = test_action::s_actions_run.begin())
{
	auto it = find_action(name, begin);

	return (it != test_action::s_actions_run.end());
}

TEST_CASE("action manager can add and run actions", "[actions]")
{
	falco::app::action_manager amgr;

	SECTION("Two independent")
	{
		test_action::s_actions_run.clear();

		amgr.add(first);
		amgr.add(second);

		amgr.run();

		// Can't compare to any direct vector as order is not guaranteed
		REQUIRE(action_is_found(first->name()) == true);
		REQUIRE(action_is_found(second->name()) == true);
	}

	SECTION("Two dependent")
	{
		test_action::s_actions_run.clear();

		amgr.add(first);
		amgr.add(third);

		amgr.run();

		std::list<std::string> exp_actions_run = {"first", "third"};
		REQUIRE(test_action::s_actions_run == exp_actions_run);
	}

	SECTION("One independent, two dependent")
	{
		test_action::s_actions_run.clear();

		amgr.add(first);
		amgr.add(second);
		amgr.add(third);

		amgr.run();

		// Can't compare to any direct vector as order is not guaranteed
		REQUIRE(action_is_found(first->name()) == true);
		REQUIRE(action_is_found(second->name()) == true);
		REQUIRE(action_is_found(third->name()) == true);

		// Ensure that third appears *after* first
		auto it = find_action(first->name());
		REQUIRE(action_is_found(third->name(), it) == true);
	}

	SECTION("Two dependent, first does not proceed")
	{
		test_action::s_actions_run.clear();

		amgr.add(first_noproceed);
		amgr.add(third);

		amgr.run();

		std::list<std::string> exp_actions_run = {"first"};
		REQUIRE(test_action::s_actions_run == exp_actions_run);
	}

	SECTION("Two dependent, second does not proceed")
	{
		test_action::s_actions_run.clear();

		amgr.add(first);
		amgr.add(third_noproceed);

		amgr.run();

		std::list<std::string> exp_actions_run = {"first", "third"};
		REQUIRE(test_action::s_actions_run == exp_actions_run);
	}

	SECTION("Three dependent, first does not proceed")
	{
		test_action::s_actions_run.clear();

		amgr.add(first_noproceed);
		amgr.add(third);
		amgr.add(fourth);

		amgr.run();

		std::list<std::string> exp_actions_run = {"first"};
		REQUIRE(test_action::s_actions_run == exp_actions_run);
	}

	SECTION("Three dependent, second does not proceed")
	{
		test_action::s_actions_run.clear();

		amgr.add(first);
		amgr.add(third_noproceed);
		amgr.add(fourth);

		amgr.run();

		std::list<std::string> exp_actions_run = {"first", "third"};
		REQUIRE(test_action::s_actions_run == exp_actions_run);
	}

	SECTION("Prerequsites Cycle")
	{
		test_action::s_actions_run.clear();

		amgr.add(third_depends_fourth);
		amgr.add(fourth);

		REQUIRE_THROWS_WITH(amgr.run(), Catch::Matchers::Contains("Dependency cycle for actions") && Catch::Matchers::Contains("third") && Catch::Matchers::Contains("fourth"));
	}
}



