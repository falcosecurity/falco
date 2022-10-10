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

static int inot_fd;

static void terminate_signal_handler(int signal)
{
	ASSERT(falco::app::g_terminate.is_lock_free());
	falco::app::g_terminate.store(APP_SIGNAL_SET, std::memory_order_seq_cst);
}

static void reopen_outputs_signal_handler(int signal)
{
	ASSERT(falco::app::g_reopen_outputs.is_lock_free());
	falco::app::g_reopen_outputs.store(APP_SIGNAL_SET, std::memory_order_seq_cst);
}

static void restart_signal_handler(int signal)
{
	ASSERT(falco::app::g_restart.is_lock_free());
	falco::app::g_restart.store(APP_SIGNAL_SET, std::memory_order_seq_cst);
}

bool application::create_handler(int sig, void (*func)(int), run_result &ret)
{
	ret = run_result::ok();
	if(signal(sig, func) == SIG_ERR)
	{
		char errbuf[1024];
		if (strerror_r(errno, errbuf, sizeof(errbuf)) != 0)
		{
			snprintf(errbuf, sizeof(errbuf)-1, "Errno %d", errno);
		}

		ret = run_result::fatal(std::string("Could not create signal handler for ") +
			   strsignal(sig) +
			   ": " +
			   errbuf);
	}

	return ret.success;
}

application::run_result application::create_signal_handlers()
{
	falco::app::g_terminate.store(APP_SIGNAL_NOT_SET, std::memory_order_seq_cst);
	falco::app::g_restart.store(APP_SIGNAL_NOT_SET, std::memory_order_seq_cst);
	falco::app::g_reopen_outputs.store(APP_SIGNAL_NOT_SET, std::memory_order_seq_cst);
	
	if (!g_terminate.is_lock_free()
		|| !g_restart.is_lock_free()
		|| !g_reopen_outputs.is_lock_free())
	{
		falco_logger::log(LOG_WARNING, "Bundled atomics implementation is not lock-free, signal handlers may be unstable\n");
	}

	// we use the if just to make sure we return at the first failed statement
	run_result ret;
	if(! create_handler(SIGINT, ::terminate_signal_handler, ret) ||
	   ! create_handler(SIGTERM, ::terminate_signal_handler, ret) ||
	   ! create_handler(SIGUSR1, ::reopen_outputs_signal_handler, ret) ||
	   ! create_handler(SIGHUP, ::restart_signal_handler, ret));
	return ret;
}

application::run_result application::attach_inotify_signals()
{
    if (m_state->config->m_watch_config_files)
	{
		inot_fd = inotify_init();
		if (inot_fd == -1)
		{
			return run_result::fatal("Could not create inotify handler");
		}

		struct sigaction sa;
		sigemptyset(&sa.sa_mask);
		sa.sa_flags = SA_RESTART;
		sa.sa_handler = restart_signal_handler;
		if (sigaction(SIGIO, &sa, NULL) == -1)
		{
			return run_result::fatal("Failed to link SIGIO to inotify handler");
		}

		/* Set owner process that is to receive "I/O possible" signal */
		if (fcntl(inot_fd, F_SETOWN, getpid()) == -1)
		{
			return run_result::fatal("Failed to setting owner on inotify handler");
		}

		/*
		 * Enable "I/O possible" signaling and make I/O nonblocking
		 *  for file descriptor
		 */
		int flags = fcntl(inot_fd, F_GETFL);
		if (fcntl(inot_fd, F_SETFL, flags | O_ASYNC | O_NONBLOCK) == -1)
		{
			return run_result::fatal("Failed to setting flags on inotify handler");
		}

		// Watch conf file
		int wd = inotify_add_watch(inot_fd, m_options.conf_filename.c_str(), IN_CLOSE_WRITE);
		if (wd == -1)
		{
			return run_result::fatal("Failed to watch conf file");
		}
		falco_logger::log(LOG_DEBUG, "Watching " + m_options.conf_filename +"\n");

		// Watch rules files
		for (const auto &rule : m_state->config->m_loaded_rules_filenames)
		{
			wd = inotify_add_watch(inot_fd, rule.c_str(), IN_CLOSE_WRITE | IN_ONESHOT);
			if (wd == -1)
			{
				return run_result::fatal("Failed to watch rule file: " + rule);
			}
			falco_logger::log(LOG_DEBUG, "Watching " + rule +"\n");
		}

		// Watch specified rules folders, if any:
		// any newly created/removed file within the folder
		// will trigger a Falco restart.
		for (const auto &fld : m_state->config->m_loaded_rules_folders)
		{
			// For folders, we watch if any file is created or destroyed within
			wd = inotify_add_watch(inot_fd, fld.c_str(), IN_CREATE | IN_DELETE | IN_ONESHOT);
			if (wd == -1)
			{
				return run_result::fatal("Failed to watch rule folder: " + fld);
			}
			falco_logger::log(LOG_DEBUG, "Watching " + fld +" folder\n");
		}
	}
	return run_result::ok();
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
	return true;
}
