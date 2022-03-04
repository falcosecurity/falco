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

#include <memory>
#include <vector>
#include <map>

namespace falco {
namespace app {

// This class manages a set of actions, ensuring that they run in an
// order that honors their dependencies and their run results.

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

	void run();

private:

	void run_group(std::string &group);

	std::list<std::string> m_groups;

	// Return true if a is less (e.g. a should run before b)
	bool compare_actions(const std::shared_ptr<runnable_action> &a, const std::shared_ptr<runnable_action> &b);

	std::map<std::string, std::shared_ptr<runnable_action>> m_actions;
};

}; // namespace application
}; // namespace falco

