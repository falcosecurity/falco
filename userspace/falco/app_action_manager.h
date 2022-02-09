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

namespace falco {
namespace app {

// This class manages a set of actions, ensuring that they run in an
// order that honors their dependencies and their run results.

class action_manager {
public:
	action_manager();
	virtual ~action_manager();

	void add(std::shared_ptr<runnable_action> act);

	void run();

private:

	std::vector<std::shared_ptr<runnable_action>> m_actions;
};

}; // namespace application
}; // namespace falco

