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

#include <string>
#include <list>

namespace falco {
namespace app {

// Along with app_action.h, defines the interface for an application
// action. The split implementation allows for building tests for the
// action manager without bringing in all of the application related
// code (falco engine, outputs, webserver, etc.).
class runnable_action {
public:

	struct run_result {
		// If true, the action completed successfully.
		bool success;

		// If success==false, details on the error.
		std::string errstr;

		// If true, subsequent actions should be performed. If
		// false, subsequent actions should *not* be performed
		// and falco should tear down/exit.
		bool proceed;
	};

	runnable_action();
	virtual ~runnable_action();

	// Return the name of the action. Only used for logging
	// purposes and to use in prerequsites().
	virtual const std::string &name() = 0;

	// Actions are organized into groups. All actions from a
	// given group are run before actions from another group.
	//
	// The order of groups is passed to the action manager via
	// set_groups().
	virtual const std::string &group() = 0;

	// Return a list of action names that *must* run before this
	// action is run.
	virtual const std::list<std::string> &prerequsites() = 0;

	// Perform the action. The returned run_result holds the
	// result of the action and whether later actions should
	// procceed.
	virtual run_result run() = 0;

	// Destroy any state created while running the action. This is
	// called after all actions are run (or stopped due to a
	// proceed=false run_result).
	virtual void deinit();
};

}; // namespace application
}; // namespace falco
