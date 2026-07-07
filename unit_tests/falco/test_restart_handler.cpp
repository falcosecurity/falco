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

#include <falco/app/restart_handler.h>
#include <falco/app/signals.h>

#include <gtest/gtest.h>

#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <fstream>
#include <string>
#include <thread>

namespace {

// deadlines sized for the watcher's 100ms cycle, with margin for slow CI
constexpr const std::chrono::seconds s_deadline{5};
constexpr const std::chrono::milliseconds s_poll{10};

bool wait_restart_triggered(std::chrono::seconds deadline) {
	auto end = std::chrono::steady_clock::now() + deadline;
	while(std::chrono::steady_clock::now() < end) {
		if(falco::app::g_restart_signal.triggered()) {
			return true;
		}
		std::this_thread::sleep_for(s_poll);
	}
	return falco::app::g_restart_signal.triggered();
}

bool wait_check_count(const std::atomic<int>& count, int expected, std::chrono::seconds deadline) {
	auto end = std::chrono::steady_clock::now() + deadline;
	while(count.load() < expected && std::chrono::steady_clock::now() < end) {
		std::this_thread::sleep_for(s_poll);
	}
	return count.load() >= expected;
}

// g_restart_signal is a process-wide global: reset it around each test
class RestartHandlerTest : public testing::Test {
protected:
	void SetUp() override { falco::app::g_restart_signal.reset(); }
	void TearDown() override { falco::app::g_restart_signal.reset(); }
};

}  // namespace

// a forced restart (SIGHUP/trigger()) must be served even with nothing to
// watch (watch_config_files=false)
TEST_F(RestartHandlerTest, forced_trigger_with_nothing_to_watch) {
	std::atomic<int> checks{0};
	falco::app::restart_handler handler([&checks] {
		checks.fetch_add(1);
		return true;
	});

	std::string err;
	ASSERT_TRUE(handler.start(err)) << err;

	handler.trigger();
	EXPECT_TRUE(wait_restart_triggered(s_deadline));
	EXPECT_GE(checks.load(), 1);
	handler.stop();
}

TEST_F(RestartHandlerTest, failed_check_does_not_restart_and_can_retry) {
	std::atomic<int> checks{0};
	falco::app::restart_handler handler([&checks] {
		checks.fetch_add(1);
		return false;
	});

	std::string err;
	ASSERT_TRUE(handler.start(err)) << err;

	// a failed dry-run check must not trigger a restart
	handler.trigger();
	EXPECT_TRUE(wait_check_count(checks, 1, s_deadline));
	EXPECT_FALSE(falco::app::g_restart_signal.triggered());

	// a new forced request must cause a new check
	handler.trigger();
	EXPECT_TRUE(wait_check_count(checks, 2, s_deadline));
	EXPECT_FALSE(falco::app::g_restart_signal.triggered());
	handler.stop();
}

TEST_F(RestartHandlerTest, stop_with_nothing_to_watch_joins_promptly) {
	falco::app::restart_handler handler([] { return true; });
	std::string err;
	ASSERT_TRUE(handler.start(err)) << err;
	// must not hang: the watcher wakes up at the next 100ms timeout
	handler.stop();
	EXPECT_FALSE(falco::app::g_restart_signal.triggered());
}

// guard for the watch=true path: an inotify event on a watched file must
// still produce a dry-run check and a restart trigger
TEST_F(RestartHandlerTest, watched_file_change_triggers_restart) {
	// note: pid-unique name so that parallel or leftover runs can't collide
	auto path = std::string(testing::TempDir()) + "falco_test_restart_handler_" +
	            std::to_string(getpid()) + ".yaml";
	{
		std::ofstream f(path);
		f << "a" << std::endl;
	}

	std::atomic<int> checks{0};
	falco::app::restart_handler handler(
	        [&checks] {
		        checks.fetch_add(1);
		        return true;
	        },
	        {path},
	        {});

	std::string err;
	ASSERT_TRUE(handler.start(err)) << err;

	// closing the file after writing fires IN_CLOSE_WRITE
	{
		std::ofstream f(path);
		f << "b" << std::endl;
	}

	EXPECT_TRUE(wait_restart_triggered(s_deadline));
	EXPECT_GE(checks.load(), 1);
	handler.stop();
	std::remove(path.c_str());
}
