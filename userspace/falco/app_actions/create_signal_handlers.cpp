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

#include <functional>

#include <string.h>
#include <signal.h>
#include <sys/inotify.h>
#include <fcntl.h>

#include "application.h"

using namespace falco::app;

// This is initially set to a dummy application. When
// create_signal_handlers is called, it will be rebound to the
// provided application, and in unregister_signal_handlers it will be
// rebound back to the dummy application.

static application dummy;
static std::reference_wrapper<application> s_app = dummy;
static int inot_fd;

static void signal_callback(int signal)
{
	s_app.get().terminate();
}

static void reopen_outputs(int signal)
{
	s_app.get().reopen_outputs();
}

static void restart_falco(int signal)
{
	s_app.get().restart();
}

bool application::create_handler(int sig, void (*func)(int), run_result &ret)
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

application::run_result application::create_signal_handlers()
{
	run_result ret;

	if(! create_handler(SIGINT, ::signal_callback, ret) ||
	   ! create_handler(SIGTERM, ::signal_callback, ret) ||
	   ! create_handler(SIGUSR1, ::reopen_outputs, ret) ||
	   ! create_handler(SIGHUP, ::restart_falco, ret))
	{
		return ret;
	}

	s_app = *this;

	return ret;
}

application::run_result application::attach_inotify_signals()
{
	run_result ret;
        if (m_state->config->m_watch_config_files)
	{
		ret.proceed = false;
		ret.success = false;
		inot_fd = inotify_init();
		if (inot_fd == -1)
		{
			ret.errstr = std::string("Could not create inotify handler.");
			return ret;
		}

		struct sigaction sa;
		sigemptyset(&sa.sa_mask);
		sa.sa_flags = SA_RESTART;
		sa.sa_handler = restart_falco;
		if (sigaction(SIGIO, &sa, NULL) == -1)
		{
			ret.errstr = std::string("Failed to link SIGIO to inotify handler.");
			return ret;
		}

		/* Set owner process that is to receive "I/O possible" signal */
		if (fcntl(inot_fd, F_SETOWN, getpid()) == -1)
		{
			ret.errstr = std::string("Failed to setting owner on inotify handler.");
			return ret;
		}

		/*
		 * Enable "I/O possible" signaling and make I/O nonblocking
		 *  for file descriptor
		 */
		int flags = fcntl(inot_fd, F_GETFL);
		if (fcntl(inot_fd, F_SETFL, flags | O_ASYNC | O_NONBLOCK) == -1)
		{
			ret.errstr = std::string("Failed to setting flags on inotify handler.");
			return ret;
		}

		/* Add watchers */
		int wd = inotify_add_watch(inot_fd, m_options.conf_filename.c_str(), IN_CLOSE_WRITE);
		if (wd == -1)
		{
			ret.errstr = std::string("Failed to watch conf file.");
			return ret;
		}
		falco_logger::log(LOG_DEBUG, "Watching " + m_options.conf_filename +"\n");

		for (const auto &rule : m_state->config->m_rules_filenames) {
			wd = inotify_add_watch(inot_fd, rule.c_str(), IN_CLOSE_WRITE);
			if (wd == -1)
			{
				ret.errstr = std::string("Failed to watch rule file: ") + rule;
				return ret;
			}
			falco_logger::log(LOG_DEBUG, "Watching " + rule +"\n");
		}
		ret.success = true;
		ret.proceed = true;
	}
	return ret;
}

bool application::unregister_signal_handlers(std::string &errstr)
{
	run_result ret;

	close(inot_fd);

	if(! create_handler(SIGINT, SIG_DFL, ret) ||
	   ! create_handler(SIGTERM, SIG_DFL, ret) ||
	   ! create_handler(SIGUSR1, SIG_DFL, ret) ||
	   ! create_handler(SIGHUP, SIG_DFL, ret))
	{
		errstr = ret.errstr;
		return false;
	}

	s_app = dummy;

	return true;
}
