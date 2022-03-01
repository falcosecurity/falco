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

#include <string.h>
#include <signal.h>

#include "create_signal_handlers.h"

static void signal_callback(int signal)
{
	falco::app::application::get().state().terminate = true;
}

static void reopen_outputs(int signal)
{
	falco::app::application::get().state().reopen_outputs = true;
}

static void restart_falco(int signal)
{
	falco::app::application::get().state().restart = true;
}

namespace falco {
namespace app {

act_create_signal_handlers::act_create_signal_handlers(application &app)
	: init_action(app), m_name("create signal handlers")
{
}

act_create_signal_handlers::~act_create_signal_handlers()
{
}

const std::string &act_create_signal_handlers::name()
{
	return m_name;
}

const std::list<std::string> &act_create_signal_handlers::prerequsites()
{
	return m_prerequsites;
}

runnable_action::run_result act_create_signal_handlers::run()
{
	run_result ret = {true, "", true};

	if(! create_handler(SIGINT, signal_callback, ret) ||
	   ! create_handler(SIGTERM, signal_callback, ret) ||
	   ! create_handler(SIGUSR1, reopen_outputs, ret) ||
	   ! create_handler(SIGHUP, restart_falco, ret))
	{
		return ret;
	}

	return ret;
}

bool act_create_signal_handlers::create_handler(int sig, void (*func)(int), run_result &ret)
{
	if(signal(sig, func) == SIG_ERR)
	{
		char errbuf[1024];

		if (strerror_r(errno, errbuf, sizeof(errbuf)) != 0)
		{
			snprintf(errbuf, sizeof(errbuf)-1, "Errno %d", errno);
		}

		ret.success = false;
		ret.errstr = std::string("Could not create signal handler for ") +
			   strsignal(sig) +
			   ": " +
			   errbuf;

		ret.proceed = false;
	}

	return ret.success;
}

}; // namespace application
}; // namespace falco

