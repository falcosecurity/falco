// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2026 The Falco Authors.

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

#include <gtest/gtest.h>

#if defined(__linux__) && defined(GTEST_HAS_DEATH_TEST) && GTEST_HAS_DEATH_TEST

#include <falco/app/actions/actions.h>
#include <falco/app/reload_state.h>
#include <falco/app/restart_handler.h>
#include <falco/app/signals.h>
#include <falco/app/state.h>

#include <fcntl.h>
#include <signal.h>
#include <unistd.h>

#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <future>
#include <limits>
#include <string>
#include <thread>

namespace {

namespace app = falco::app;

constexpr std::chrono::seconds s_deadline{5};
constexpr std::chrono::milliseconds s_poll{10};

// Child assertions must exit unsuccessfully so EXPECT_EXIT observes their failure.
void require_in_child(bool condition, const std::string& message) {
	if(!condition) {
		std::fprintf(stderr, "%s\n", message.c_str());
		_exit(1);
	}
}

void prepare_child() {
	// Bound failures that would otherwise block indefinitely while joining a worker.
	require_in_child(::signal(SIGALRM, SIG_DFL) != SIG_ERR,
	                 "could not restore default SIGALRM disposition");
	sigset_t signals;
	require_in_child(::sigemptyset(&signals) == 0, "sigemptyset failed");
	require_in_child(::sigaddset(&signals, SIGHUP) == 0, "sigaddset failed");
	require_in_child(::sigaddset(&signals, SIGALRM) == 0, "sigaddset failed");
	require_in_child(::sigprocmask(SIG_UNBLOCK, &signals, nullptr) == 0,
	                 "could not unblock test signals");
	::alarm(15);
}

void initialize_child() {
	prepare_child();
	std::string err;
	require_in_child(app::initialize_restart_signal_handler(err), err);
	require_in_child(app::restart_signal_fd() >= 0, "restart mailbox was not initialized");
	app::g_restart_signal.reset();
	app::g_reload_state.begin_run();
}

template<typename Predicate>
bool wait_until(Predicate predicate) {
	const auto end = std::chrono::steady_clock::now() + s_deadline;
	while(std::chrono::steady_clock::now() < end) {
		if(predicate()) {
			return true;
		}
		std::this_thread::sleep_for(s_poll);
	}
	return predicate();
}

}  // namespace

TEST(ReloadSignalsDeathTest, default_sighup_disposition_terminates_the_child) {
	EXPECT_EXIT(
	        {
		        prepare_child();
		        require_in_child(::signal(SIGHUP, SIG_DFL) != SIG_ERR,
		                         "could not restore default SIGHUP disposition");
		        ::raise(SIGHUP);
		        _exit(1);
	        },
	        ::testing::KilledBySignal(SIGHUP),
	        "");
}

TEST(ReloadSignalsDeathTest, unregister_preserves_sighup_reception_and_errno) {
	EXPECT_EXIT(
	        {
		        initialize_child();
		        app::state state;
		        state.options.dry_run = false;
		        const auto before = app::g_reload_state.requested();
		        // Force handler writes to fail with EAGAIN: errno must still be preserved.
		        const auto saturated = std::numeric_limits<uint64_t>::max() - 1;
		        require_in_child(::write(app::restart_signal_fd(), &saturated, sizeof(saturated)) ==
		                                 static_cast<ssize_t>(sizeof(saturated)),
		                         "could not saturate the signal mailbox");

		        errno = EDOM;
		        const auto first_result = ::raise(SIGHUP);
		        const auto first_errno = errno;
		        require_in_child(first_result == 0, "first SIGHUP could not be raised");
		        require_in_child(first_errno == EDOM, "SIGHUP changed errno");
		        require_in_child(app::g_reload_state.requested() == before + 1,
		                         "first SIGHUP was not recorded");

		        const auto result = app::actions::unregister_signal_handlers(state);
		        require_in_child(result.success, result.errstr);
		        errno = ERANGE;
		        const auto second_result = ::raise(SIGHUP);
		        const auto second_errno = errno;
		        require_in_child(second_result == 0, "second SIGHUP could not be raised");
		        require_in_child(second_errno == ERANGE, "SIGHUP after teardown changed errno");
		        require_in_child(app::g_reload_state.requested() == before + 2,
		                         "SIGHUP after teardown was not recorded");
		        _exit(0);
	        },
	        ::testing::ExitedWithCode(0),
	        "");
}

TEST(ReloadSignalsDeathTest, signal_before_worker_start_is_validated_without_file_watches) {
	EXPECT_EXIT(
	        {
		        initialize_child();
		        require_in_child(::raise(SIGHUP) == 0, "SIGHUP could not be raised");
		        std::atomic<int> checks{0};
		        app::restart_handler handler(
		                [&checks] {
			                app::g_reload_state.begin_check();
			                checks.fetch_add(1);
			                return true;
		                },
		                {},
		                {},
		                app::restart_signal_fd());
		        std::string err;
		        require_in_child(handler.start(err), err);
		        require_in_child(wait_until([] { return app::g_restart_signal.triggered(); }),
		                         "pending SIGHUP did not trigger a restart");
		        handler.stop();
		        require_in_child(checks.load() == 1, "pending SIGHUP was not validated once");
		        _exit(0);
	        },
	        ::testing::ExitedWithCode(0),
	        "");
}

TEST(ReloadSignalsDeathTest, signal_after_worker_exit_reaches_the_replacement_worker) {
	EXPECT_EXIT(
	        {
		        initialize_child();
		        const auto signal_fd = app::restart_signal_fd();
		        std::string err;
		        {
			        app::restart_handler retiring(
			                [] {
				                app::g_reload_state.begin_check();
				                return true;
			                },
			                {},
			                {},
			                signal_fd);
			        require_in_child(retiring.start(err), err);
			        require_in_child(::raise(SIGHUP) == 0, "first SIGHUP could not be raised");
			        require_in_child(wait_until([] { return app::g_restart_signal.triggered(); }),
			                         "retiring worker did not trigger a restart");
			        retiring.stop();
		        }
		        require_in_child(::fcntl(signal_fd, F_GETFD) >= 0,
		                         "retiring worker closed the process mailbox");
		        app::g_restart_signal.reset();
		        app::g_reload_state.begin_run();
		        const auto claimed = app::g_reload_state.covered();
		        require_in_child(claimed == app::g_reload_state.requested(),
		                         "replacement run did not claim the first request");

		        // The new run has started reading configuration, but has no worker yet.
		        require_in_child(::raise(SIGHUP) == 0, "second SIGHUP could not be raised");
		        require_in_child(app::g_reload_state.requested() > claimed,
		                         "SIGHUP between workers was not recorded");
		        std::atomic<int> checks{0};
		        app::restart_handler replacement(
		                [&checks] {
			                app::g_reload_state.begin_check();
			                checks.fetch_add(1);
			                return true;
		                },
		                {},
		                {},
		                signal_fd);
		        require_in_child(replacement.start(err), err);
		        require_in_child(wait_until([] { return app::g_restart_signal.triggered(); }),
		                         "replacement worker lost the pending SIGHUP");
		        replacement.stop();
		        require_in_child(checks.load() == 1,
		                         "replacement did not validate the pending request once");
		        _exit(0);
	        },
	        ::testing::ExitedWithCode(0),
	        "");
}

TEST(ReloadSignalsDeathTest, consumed_wakeup_does_not_erase_a_pending_signal) {
	EXPECT_EXIT(
	        {
		        initialize_child();
		        require_in_child(::raise(SIGHUP) == 0, "SIGHUP could not be raised");

		        // Model a retiring worker draining the mailbox, then stopping before validation.
		        uint64_t wakeups = 0;
		        const auto received = ::read(app::restart_signal_fd(), &wakeups, sizeof(wakeups));
		        require_in_child(received == static_cast<ssize_t>(sizeof(wakeups)) && wakeups > 0,
		                         "SIGHUP did not wake the process mailbox");
		        require_in_child(app::g_reload_state.requested() > app::g_reload_state.covered(),
		                         "draining the mailbox consumed the pending request");

		        std::atomic<int> checks{0};
		        app::restart_handler replacement(
		                [&checks] {
			                app::g_reload_state.begin_check();
			                checks.fetch_add(1);
			                return true;
		                },
		                {},
		                {},
		                app::restart_signal_fd());
		        std::string err;
		        require_in_child(replacement.start(err), err);
		        require_in_child(
		                wait_until([] { return app::g_restart_signal.triggered(); }),
		                "replacement relied on the consumed wakeup instead of the request");
		        replacement.stop();
		        require_in_child(checks.load() == 1, "pending request was not validated once");
		        _exit(0);
	        },
	        ::testing::ExitedWithCode(0),
	        "");
}

TEST(ReloadSignalsDeathTest, signal_during_rejected_validation_causes_another_check) {
	EXPECT_EXIT(
	        {
		        initialize_child();
		        std::promise<void> first_check_started;
		        auto entered = first_check_started.get_future();
		        std::promise<void> release_first_check;
		        auto released = release_first_check.get_future();
		        std::atomic<int> checks_started{0};
		        std::atomic<int> checks_completed{0};
		        app::restart_handler handler(
		                [&] {
			                const auto attempt = app::g_reload_state.begin_check();
			                if(checks_started.fetch_add(1) == 0) {
				                first_check_started.set_value();
				                released.wait();
			                }
			                app::g_reload_state.rejected(attempt);
			                checks_completed.fetch_add(1);
			                return false;
		                },
		                {},
		                {},
		                app::restart_signal_fd());
		        std::string err;
		        require_in_child(handler.start(err), err);
		        require_in_child(::raise(SIGHUP) == 0, "first SIGHUP could not be raised");
		        require_in_child(entered.wait_for(s_deadline) == std::future_status::ready,
		                         "first validation did not start");
		        require_in_child(::raise(SIGHUP) == 0, "second SIGHUP could not be raised");
		        release_first_check.set_value();
		        require_in_child(wait_until([&] { return checks_completed.load() >= 2; }),
		                         "SIGHUP during rejected validation was lost");
		        handler.stop();
		        require_in_child(checks_completed.load() == 2, "unexpected extra validation");
		        require_in_child(app::g_reload_state.covered() == app::g_reload_state.requested(),
		                         "second validation did not consume the pending request");
		        require_in_child(!app::g_restart_signal.triggered(),
		                         "rejected validation triggered a restart");
		        _exit(0);
	        },
	        ::testing::ExitedWithCode(0),
	        "");
}

#endif
