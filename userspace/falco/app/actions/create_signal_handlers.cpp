// SPDX-License-Identifier: Apache-2.0
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
#include "compat.h"
#include "../app.h"
#include "../signals.h"
#include "../reload_state.h"

#ifdef __linux__
#include <signal.h>
#include <sys/eventfd.h>
#include <unistd.h>
#endif  // __linux__

using namespace falco::app;
using namespace falco::app::actions;

// Published before installing SIGHUP, never changed while the handler is live.
// Deliberately retained until process exit: closing it during teardown could
// make an in-flight signal write to a reused descriptor.
static int s_restart_signal_fd = -1;

int falco::app::restart_signal_fd() {
	return s_restart_signal_fd;
}

static void terminate_signal_handler(int signal) {
	falco::app::g_terminate_signal.trigger();
}

static void reopen_outputs_signal_handler(int signal) {
	falco::app::g_reopen_outputs_signal.trigger();
}

bool falco::app::request_reload() noexcept {
#ifdef __linux__
	if(s_restart_signal_fd < 0) {
		return false;
	}
	const int saved_errno = errno;
	g_reload_state.request();
	const uint64_t value = 1;
	ssize_t result;
	do {
		result = write(s_restart_signal_fd, &value, sizeof(value));
	} while(result < 0 && errno == EINTR);
	// EAGAIN means a wakeup is already pending. The request counter, not the
	// eventfd value, owns pending work.
	const bool notified =
	        result == static_cast<ssize_t>(sizeof(value)) || (result < 0 && errno == EAGAIN);
	errno = saved_errno;
	return notified;
#else
	return false;
#endif
}

static void restart_signal_handler(int signal) {
	(void)falco::app::request_reload();
}

bool create_handler(int sig, void (*func)(int), run_result& ret) {
	ret = run_result::ok();
#ifdef __linux__
	if(signal(sig, func) == SIG_ERR) {
		char errbuf[1024];
		const char* errstr = falco_strerror_r(errno, errbuf, sizeof(errbuf));

		ret = run_result::fatal(std::string("Could not create signal handler for ") +
		                        strsignal(sig) + ": " + errstr);
	}
#endif
	return ret.success;
}

bool falco::app::initialize_restart_signal_handler(std::string& err) {
	g_reload_state.initialize();
#ifdef __linux__
	if(s_restart_signal_fd >= 0) {
		return true;
	}
	if(!g_reload_state.is_lock_free()) {
		err = "SIGHUP handling requires lock-free reload request atomics";
		return false;
	}
	s_restart_signal_fd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
	if(s_restart_signal_fd < 0) {
		err = "could not initialize SIGHUP eventfd";
		return false;
	}
	run_result ret;
	if(!create_handler(SIGHUP, ::restart_signal_handler, ret)) {
		close(s_restart_signal_fd);
		s_restart_signal_fd = -1;
		err = ret.errstr;
		return false;
	}
#endif
	return true;
}

falco::app::run_result falco::app::actions::create_signal_handlers(falco::app::state& s) {
	auto ret = run_result::ok();

	if(s.options.dry_run) {
		falco_logger::log(falco_logger::level::DEBUG,
		                  "Skipping signal handlers creation in dry-run\n");
		return run_result::ok();
	}

	std::string err;
	if(!initialize_restart_signal_handler(err)) {
		return run_result::fatal(err);
	}

#ifdef __linux__
	falco::app::g_terminate_signal.reset();
	falco::app::g_restart_signal.reset();
	falco::app::g_reopen_outputs_signal.reset();

	if(!g_terminate_signal.is_lock_free() || !g_restart_signal.is_lock_free() ||
	   !g_reopen_outputs_signal.is_lock_free()) {
		falco_logger::log(falco_logger::level::WARNING,
		                  "Bundled atomics implementation is not lock-free, signal handlers may be "
		                  "unstable\n");
	}

	if(!create_handler(SIGINT, ::terminate_signal_handler, ret) ||
	   !create_handler(SIGTERM, ::terminate_signal_handler, ret) ||
	   !create_handler(SIGUSR1, ::reopen_outputs_signal_handler, ret)) {
		return ret;
	}

	falco::app::restart_handler::watch_list_t files_to_watch;
	falco::app::restart_handler::watch_list_t dirs_to_watch;
	if(s.config->m_watch_config_files) {
		files_to_watch.insert(files_to_watch.end(),
		                      s.config->m_loaded_configs_filenames.begin(),
		                      s.config->m_loaded_configs_filenames.end());
		dirs_to_watch.insert(dirs_to_watch.end(),
		                     s.config->m_loaded_configs_folders.begin(),
		                     s.config->m_loaded_configs_folders.end());
		files_to_watch.insert(files_to_watch.end(),
		                      s.config->m_loaded_rules_filenames.begin(),
		                      s.config->m_loaded_rules_filenames.end());
		dirs_to_watch.insert(dirs_to_watch.end(),
		                     s.config->m_loaded_rules_folders.begin(),
		                     s.config->m_loaded_rules_folders.end());
	}

	s.restarter = std::make_shared<falco::app::restart_handler>(
	        [&s] {
		        const auto attempt = g_reload_state.begin_check();
		        bool tmp = false;
		        bool success = false;
		        std::string err;
		        falco::app::state tmp_state(s.cmdline, s.options);
		        tmp_state.options.dry_run = true;
		        try {
			        success = falco::app::run(tmp_state, tmp, err);
		        } catch(std::exception& e) {
			        err = e.what();
		        } catch(...) {
			        err = "unknown error";
		        }

		        if(!success) {
			        g_reload_state.rejected(attempt);
		        }
		        if(!success && s.outputs != nullptr) {
			        std::string rule = "Falco internal: hot restart failure";
			        std::string msg = rule + ": " + err;
			        auto fields = nlohmann::json::object();
			        auto now = std::chrono::duration_cast<std::chrono::nanoseconds>(
			                           std::chrono::system_clock::now().time_since_epoch())
			                           .count();
			        s.outputs->handle_msg(now, falco_common::PRIORITY_CRITICAL, msg, rule, fields);
		        }

		        return success;
	        },
	        files_to_watch,
	        dirs_to_watch,
	        restart_signal_fd());

	ret = run_result::ok();
	ret.success = s.restarter->start(ret.errstr);
	ret.proceed = ret.success;
#endif

	return ret;
}

falco::app::run_result falco::app::actions::unregister_signal_handlers(falco::app::state& s) {
#ifdef __linux__
	if(s.options.dry_run) {
		falco_logger::log(falco_logger::level::DEBUG,
		                  "Skipping unregistering signal handlers in dry-run\n");
		return run_result::ok();
	}

	if(s.restarter != nullptr) {
		s.restarter->stop();
	}

	run_result ret;
	if(!create_handler(SIGINT, SIG_DFL, ret) || !create_handler(SIGTERM, SIG_DFL, ret) ||
	   !create_handler(SIGUSR1, SIG_DFL, ret)) {
		return ret;
	}
#endif  // __linux__

	return run_result::ok();
}
