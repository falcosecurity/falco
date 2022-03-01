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

// The falco "app" holds application-level configuration and contains
// the implementation of any subcommand-like behaviors like --list, -i
// (print_ignored_events), etc.

// It also contains the code to initialize components like the
// inspector, falco engine, etc.

#include "application.h"
#include "defined_app_actions.h"
#include "falco_common.h"

namespace falco {
namespace app {

application::action_state::action_state()
	: restart(false),
	  terminate(false),
	  reopen_outputs(false)
{
}

application::action_state::~action_state()
{
}

application::application()
	: m_initialized(false)
{
}

application::~application()
{
}

application &application::get()
{
	static application instance;
	return instance;
}

cmdline_options &application::options()
{
	if(!m_initialized)
	{
		throw falco_exception("App init() not called yet");
	}

	return m_cmdline_options;
}

application::action_state &application::state()
{
	return m_state;
}

bool application::init(int argc, char **argv, std::string &errstr)
{
	if(!m_cmdline_options.parse(argc, argv, errstr))
	{
		return false;
	}

	m_action_manager.add(std::shared_ptr<runnable_action>(new act_print_help(*this)));
	m_action_manager.add(std::shared_ptr<runnable_action>(new act_print_version(*this)));
	m_action_manager.add(std::shared_ptr<runnable_action>(new act_create_signal_handlers(*this)));
	m_action_manager.add(std::shared_ptr<runnable_action>(new act_load_config(*this)));

	m_initialized = true;
	return true;
}

void application::run()
{
	m_action_manager.run();
}

}; // namespace app
}; // namespace falco
