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

#pragma once

#include "app_runnable_action.h"

#include <list>
#include <memory>
#include <map>
#include <string>
#include <vector>

namespace falco {
namespace app {

// This class manages a set of actions, ensuring that they run in an
// order that honors their dependencies, groups and their run results.

class action_manager {
public:
	action_manager();
	virtual ~action_manager();

	// Actions are organized into groups. All actions from a
	// given group are run before actions from another group.
	//
	// Example groups are "init", "run", etc.
	//
	// This specifies the order of groups.
	void set_groups(std::list<std::string> &groups);

	void add(std::shared_ptr<runnable_action> act);

	runnable_action::run_result run();

private:

	typedef std::vector<std::shared_ptr<runnable_action>> ordered_actions_t;

	void sort_groups();
	runnable_action::run_result run_groups();
	void deinit_groups();

	// Return true if a is less (e.g. a should run before b)
	bool compare_actions(const std::shared_ptr<runnable_action> &a, const std::shared_ptr<runnable_action> &b);

	std::list<std::string> m_groups;
	std::map<std::string, std::shared_ptr<runnable_action>> m_actions;
	std::map<std::string, ordered_actions_t> m_actions_ordered;
};

}; // namespace application
}; // namespace falco
