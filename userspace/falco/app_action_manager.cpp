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
#include "logger.h"
#include "falco_common.h"

#include <algorithm>
#include <list>
#include <memory>
#include <string>

namespace falco {
namespace app {

action_manager::action_manager()
{
}

action_manager::~action_manager()
{
}

void action_manager::add(std::shared_ptr<runnable_action> act)
{
	m_actions[act->name()] = act;
}

bool action_manager::run_after(const std::shared_ptr<runnable_action> &a, const std::shared_ptr<runnable_action> &b)
{
	// Check b's prerequsites recursively. If a is found return true.
	for(auto &prereq_name : b->prerequsites())
	{
		if(prereq_name == a->name())
		{
			return true;
		}

		auto it = m_actions.find(prereq_name);
		if(it == m_actions.end())
		{
			throw falco_exception("No action with name " + prereq_name + " exists?");
		}

		if(run_after(a, it->second))
		{
			fprintf(stderr, "a=%s b=%s A RUN AFTER B\n", a->name().c_str(), b->name().c_str());
			return true;
		}
	}

	fprintf(stderr, "a=%s b=%s A NOT RUN AFTER B\n", a->name().c_str(), b->name().c_str());
	return false;
}

bool action_manager::compare_actions(const std::shared_ptr<runnable_action> &a, const std::shared_ptr<runnable_action> &b)
{
	bool a_after_b = run_after(a, b);

	bool b_after_a = run_after(b, a);

	fprintf(stderr, "a=%s b=%s a_after_b=%d b_after_a=%d\n", a->name().c_str(), b->name().c_str(), (a_after_b ? 1 : 0), (b_after_a ? 1 : 0));
	// If both are prerequsites of each other, there is a cycle
	// and throw an exception.
	if(a_after_b && b_after_a)
	{
		throw falco_exception(std::string("Dependency cycle for actions ") + a->name() + " and " + b->name());
	}

	// If neither are, just sort on the name
	if(!a_after_b && !b_after_a)
	{
		return (a->name() < b->name());
	}

	// If b is a prereq of a, a is "less"
	if(b_after_a)
	{
		fprintf(stderr, "%s LESS %s\n", a->name().c_str(), b->name().c_str());
		return true;
	}

	fprintf(stderr, "%s NOT LESS %s\n", a->name().c_str(), b->name().c_str());
	// a must be a prereq of b. it is not less
	return false;
}


void action_manager::run()
{

	std::vector<std::shared_ptr<runnable_action>> actions_ordered;

	for(auto &pair : m_actions)
	{
		actions_ordered.push_back(pair.second);
	}

	auto compare = [this](const std::shared_ptr<runnable_action> &a,
			      const std::shared_ptr<runnable_action> &b) {
		return this->compare_actions(a, b);
	};

	// Order the actions according to precedence
	std::make_heap(actions_ordered.begin(), actions_ordered.end(), compare);

	for(auto &act : actions_ordered)
	{
		fprintf(stderr, "ACT %s\n", act->name().c_str());
	}

	for(auto &act : actions_ordered)
	{
		falco_logger::log(LOG_DEBUG, string("Initializing action ") + act->name());

		act->init();
	}

	for(auto &act : actions_ordered)
	{
		falco_logger::log(LOG_DEBUG, string("Running action ") + act->name());

		runnable_action::run_result res = act->run();

		if(!res.success)
		{
			fprintf(stderr, "Could not complete %s: %s\n", act->name().c_str(), res.errstr.c_str());
		}

		if(!res.proceed)
		{
			break;
		}
	}

	for(auto &act : actions_ordered)
	{
		falco_logger::log(LOG_DEBUG, string("Deinitializing action ") + act->name());

		act->deinit();
	}

	return;
}

}; // namespace application
}; // namespace falco
