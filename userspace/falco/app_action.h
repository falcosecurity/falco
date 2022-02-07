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

#include "application.h"
#include "app_runnable_action.h"

namespace falco {
namespace app {

// Current set of actions:
// One-offs:
//  - parse command line options
//  - display help
//  - print version info
//  - print ignored events
//  - list plugins
//  - list all fields/list source fields
//  - print support
//  - describe rule(s)

// "main" actions:
//  - setup signal handlers
//  - create/configure inspector
//  - load plugins
//  - create/configure falco engine
//  - validate rules files
//  - read config
//  - load rules files
//  - daemonize
//  - initialize outputs
//  - start grpc server
//  - set up signal handlers
//  - start webserver
//  - read events from source (trace or live), pass to falco engine

// This class represents an "action" e.g. a chunk of code to execute
// as a part of running the falco application. Examples of actions are:
//   - initializing/configuring the inspector
//   - loading/configuring plugins
//   - reading events from a trace file or live event source
//
// Actions also include "one off" actions for things like --help
// output, --list fields, etc.
//
// There's no attempt in this version to distribute state
// (e.g. inspectors, lists of plugins, etc) across actions. The
// expectation is that all state that needs to be used across actions
// is held in the provided application object and actions know which
// state they should create and destroy.

// The reason for a sublcass is to allow for building/running unit
// tests for the action manager without bringing in all of the falco
// application code (engine, outputs, grpc, etc).
class action : public runnable_action {
public:
	action(application &app);
	virtual ~action();

	application &app();

private:
	application &m_app;
};

}; // namespace application
}; // namespace falco

