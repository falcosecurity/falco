/*
Copyright (C) 2023 The Falco Authors.

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

#include "actions.h"
#include "../app.h"
#include "../signals.h"

#ifdef __linux__
#include <signal.h>
#endif // __linux__

using namespace falco::app;
using namespace falco::app::actions;

static std::shared_ptr<falco::app::restart_handler> s_restarter;

static void terminate_signal_handler(int signal)
{
	falco::app::g_terminate_signal.trigger();
}

static void reopen_outputs_signal_handler(int signal)
{
	falco::app::g_reopen_outputs_signal.trigger();
}

static void restart_signal_handler(int signal)
{
	if (s_restarter != nullptr)
	{
		s_restarter->trigger();
	}
}

bool create_handler(int sig, void (*func)(int), run_result &ret)
{
	ret = run_result::ok();
#ifdef __linux__
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
#endif
	return ret.success;
}

falco::app::run_result falco::app::actions::create_signal_handlers(falco::app::state& s)
{
	auto ret = run_result::ok();

#ifdef __linux__
	if (s.options.dry_run)
	{
		falco_logger::log(LOG_DEBUG, "Skipping signal handlers creation in dry-run\n");
		return run_result::ok();
	}

	falco::app::g_terminate_signal.reset();
	falco::app::g_restart_signal.reset();
	falco::app::g_reopen_outputs_signal.reset();

	if (!g_terminate_signal.is_lock_free()
		|| !g_restart_signal.is_lock_free()
		|| !g_reopen_outputs_signal.is_lock_free())
	{
		falco_logger::log(LOG_WARNING, "Bundled atomics implementation is not lock-free, signal handlers may be unstable\n");
	}

	if(! create_handler(SIGINT, ::terminate_signal_handler, ret) ||
	   ! create_handler(SIGTERM, ::terminate_signal_handler, ret) ||
	   ! create_handler(SIGUSR1, ::reopen_outputs_signal_handler, ret) ||
	   ! create_handler(SIGHUP, ::restart_signal_handler, ret))
	{
		return ret;
	}

	falco::app::restart_handler::watch_list_t files_to_watch;
	falco::app::restart_handler::watch_list_t dirs_to_watch;
	if (s.config->m_watch_config_files)
	{
		files_to_watch.push_back(s.options.conf_filename);
		files_to_watch.insert(
			files_to_watch.end(),
			s.config->m_loaded_rules_filenames.begin(),
			s.config->m_loaded_rules_filenames.end());
		dirs_to_watch.insert(
			dirs_to_watch.end(),
			s.config->m_loaded_rules_folders.begin(),
			s.config->m_loaded_rules_folders.end());
	}

	s.restarter = std::make_shared<falco::app::restart_handler>([&s]{
		bool tmp = false;
		bool success = false;
		std::string err;
		falco::app::state tmp_state(s.cmdline, s.options);
		tmp_state.options.dry_run = true;
		try
		{
			success = falco::app::run(tmp_state, tmp, err);
		}
		catch (std::exception& e)
		{
			err = e.what();
		}
		catch (...)
		{
			err = "unknown error";
		}

		if (!success && s.outputs != nullptr)
		{
			std::string rule = "Falco internal: hot restart failure";
			std::string msg = rule + ": " + err;
			auto fields = nlohmann::json::object();
			auto now = std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
			s.outputs->handle_msg(now, falco_common::PRIORITY_CRITICAL, msg, rule, fields);
		}

		return success;
	}, files_to_watch, dirs_to_watch);

	ret = run_result::ok();
	ret.success = s.restarter->start(ret.errstr);
	ret.proceed = ret.success;
	if (ret.success)
	{
		s_restarter = s.restarter;
	}
#endif

	return ret;
}

falco::app::run_result falco::app::actions::unregister_signal_handlers(falco::app::state& s)
{
#ifdef __linux__
	if (s.options.dry_run)
	{
		falco_logger::log(LOG_DEBUG, "Skipping unregistering signal handlers in dry-run\n");
		return run_result::ok();
	}

	s_restarter = nullptr;
	if (s.restarter != nullptr)
	{
		s.restarter->stop();
	}

	run_result ret;
	if(! create_handler(SIGINT, SIG_DFL, ret) ||
	   ! create_handler(SIGTERM, SIG_DFL, ret) ||
	   ! create_handler(SIGUSR1, SIG_DFL, ret) ||
	   ! create_handler(SIGHUP, SIG_DFL, ret))
	{
		return ret;
	}
#endif // __linux__

	return run_result::ok();
}
