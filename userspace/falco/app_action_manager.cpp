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

void action_manager::set_groups(std::list<std::string> &groups)
{
	m_groups = groups;
}

void action_manager::add(std::shared_ptr<runnable_action> act)
{
	m_actions[act->name()] = act;
}

bool action_manager::compare_actions(const std::shared_ptr<runnable_action> &a, const std::shared_ptr<runnable_action> &b)
{
	// Check b's prerequsites. If a is found return true.
	for(auto &prereq_name : b->prerequsites())
	{
		if(prereq_name == a->name())
		{
			return true;
		}
	}

	// Not a direct dependency. Check b's prerequsites recursively
	for(auto &prereq_name : b->prerequsites())
	{
		auto it = m_actions.find(prereq_name);
		if(it == m_actions.end())
		{
			throw falco_exception("No action with name " + prereq_name + " exists?");
		}

		if(compare_actions(a, it->second))
		{
			return true;
		}
	}

	return false;
}

void action_manager::run()
{
	for(auto &group : m_groups)
	{
		falco_logger::log(LOG_DEBUG, string("Running group ") + group);
		bool proceed = run_group(group);

		if(!proceed)
		{
			break;
		}
	}
}

bool action_manager::run_group(std::string &group)
{
	bool proceed = true;

	std::vector<std::shared_ptr<runnable_action>> actions_ordered;

	for(auto &pair : m_actions)
	{
		if(pair.second->group() == group)
		{
			actions_ordered.push_back(pair.second);
		}
	}

	auto compare = [this](const std::shared_ptr<runnable_action> &a,
			      const std::shared_ptr<runnable_action> &b) {
		return this->compare_actions(a, b);
	};

	// Order the actions according to precedence
	std::sort(actions_ordered.begin(), actions_ordered.end(), compare);

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
			proceed = false;
			break;
		}
	}

	for(auto &act : actions_ordered)
	{
		falco_logger::log(LOG_DEBUG, string("Deinitializing action ") + act->name());

		act->deinit();
	}

	return proceed;
}

}; // namespace application
}; // namespace falco
