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

// The falco "app" will eventually replace the monolithic code in
// falco.cpp. We expect it will be responsible for the following:
//  - Parsing/validating command line options
//  - Parsing/validing falco config
//  - Initialize prerequsites (inspector, falco engine, webserver, etc)
//  - Loading plugins
//  - Loading/validating rules
//  - Command/subcommand execution (e.g. --list/--list-fields, or
//    nothing specified to run "main" loop)

// For now, it is only responsible for command line options.
#pragma once

#include "app_cmdline_options.h"

#include <string>

namespace falco {
namespace app {

class application {
public:

	application();
	virtual ~application();

	cmdline_options &options();
	bool init(int argc, char **argv, std::string &errstr);

private:

	cmdline_options m_cmdline_options;
	bool m_initialized;
};

}; // namespace app
}; // namespace falco
