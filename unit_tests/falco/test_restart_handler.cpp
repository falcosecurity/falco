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
#include <sys/select.h>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <filesystem>
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
	void SetUp() override {
		falco::app::g_restart_signal.reset();
		char path[] = "/tmp/falco-restart-handler-XXXXXX";
		const auto directory = ::mkdtemp(path);
		ASSERT_NE(directory, nullptr);
		m_directory = directory;
	}
	void TearDown() override {
		falco::app::g_restart_signal.reset();
		if(!m_directory.empty()) {
			std::error_code err;
			std::filesystem::remove_all(m_directory, err);
			EXPECT_FALSE(err) << err.message();
		}
	}
	std::string m_directory;
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

TEST_F(RestartHandlerTest, rejects_signal_descriptor_outside_select_capacity) {
	falco::app::restart_handler handler([] { return true; }, {}, {}, FD_SETSIZE);
	std::string err;
	EXPECT_FALSE(handler.start(err));
	EXPECT_EQ(err, "restart handler descriptor exceeds select capacity");
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

// No inotify watch exists when the deletion happens. Recovery must not need a
// second filesystem event or an external reload request.
TEST_F(RestartHandlerTest, removed_directory_member_requests_revalidation) {
	const auto path = m_directory + "/removed.yaml";
	const auto alias = m_directory + "/alias";
	std::filesystem::create_directory_symlink(m_directory, alias);
	for(const auto& directory :
	    {m_directory, m_directory + "/", alias, std::filesystem::relative(m_directory).string()}) {
		SCOPED_TRACE(directory);
		falco::app::g_restart_signal.reset();
		{ std::ofstream file(path); }
		ASSERT_TRUE(std::filesystem::remove(path));
		std::atomic<int> checks{0};
		falco::app::restart_handler handler(
		        [&checks] {
			        checks.fetch_add(1);
			        return true;
		        },
		        {path},
		        {directory});
		std::string err;
		ASSERT_TRUE(handler.start(err)) << err;
		EXPECT_TRUE(wait_restart_triggered(s_deadline));
		handler.stop();
		EXPECT_EQ(checks.load(), 1);
	}
}

TEST_F(RestartHandlerTest, multiple_removed_members_coalesce_into_one_check) {
	std::atomic<int> checks{0};
	falco::app::restart_handler handler(
	        [&checks] {
		        checks.fetch_add(1);
		        return true;
	        },
	        {m_directory + "/first.yaml", m_directory + "/second.yaml"},
	        {m_directory});
	std::string err;
	ASSERT_TRUE(handler.start(err)) << err;
	EXPECT_TRUE(wait_restart_triggered(s_deadline));
	handler.stop();
	EXPECT_EQ(checks.load(), 1);
}

TEST_F(RestartHandlerTest, removed_member_rejection_recovers_on_directory_change) {
	std::atomic<int> checks{0};
	std::atomic<bool> valid{false};
	const auto path = m_directory + "/removed.yaml";
	falco::app::restart_handler handler(
	        [&] {
		        const bool result = valid.load();
		        checks.fetch_add(1);
		        return result;
	        },
	        {path},
	        {m_directory});
	std::string err;
	ASSERT_TRUE(handler.start(err)) << err;
	ASSERT_TRUE(wait_check_count(checks, 1, s_deadline));
	// More than two debounce cycles: rejection must not turn into a retry loop.
	std::this_thread::sleep_for(std::chrono::milliseconds(400));
	EXPECT_EQ(checks.load(), 1);
	EXPECT_FALSE(falco::app::g_restart_signal.triggered());
	valid.store(true);
	{
		std::ofstream file(path);
		file << "repaired\n";
	}
	EXPECT_TRUE(wait_restart_triggered(s_deadline));
	handler.stop();
	// CREATE and CLOSE_WRITE can arrive in different debounce windows.
	EXPECT_GE(checks.load(), 2);
}

TEST_F(RestartHandlerTest, recreated_member_recovers_when_the_writer_finishes) {
	std::atomic<int> checks{0};
	std::atomic<bool> valid{false};
	const auto path = m_directory + "/removed.yaml";
	falco::app::restart_handler handler(
	        [&] {
		        const bool result = valid.load();
		        checks.fetch_add(1);
		        return result;
	        },
	        {path},
	        {m_directory});
	std::string err;
	ASSERT_TRUE(handler.start(err)) << err;
	ASSERT_TRUE(wait_check_count(checks, 1, s_deadline));
	std::ofstream file(path);
	ASSERT_TRUE(file.is_open());
	// Keep the writer open until the CREATE event has caused a rejected check.
	ASSERT_TRUE(wait_check_count(checks, 2, s_deadline));
	EXPECT_FALSE(falco::app::g_restart_signal.triggered());
	valid.store(true);
	file << "repaired\n";
	file.close();
	EXPECT_TRUE(wait_restart_triggered(s_deadline));
	handler.stop();
	EXPECT_EQ(checks.load(), 3);
}

TEST_F(RestartHandlerTest, missing_file_without_watched_parent_is_fatal) {
	std::filesystem::create_directory(m_directory + "/unwatched");
	for(const auto& dirs : {falco::app::restart_handler::watch_list_t{},
	                        falco::app::restart_handler::watch_list_t{m_directory}}) {
		const auto path = m_directory + "/unwatched/missing.yaml";
		falco::app::restart_handler handler([] { return true; }, {path}, dirs);
		std::string err;
		EXPECT_FALSE(handler.start(err));
		EXPECT_NE(err.find("could not watch file: " + path), std::string::npos);
	}
}

TEST_F(RestartHandlerTest, missing_directory_is_fatal) {
	const auto path = m_directory + "/missing";
	falco::app::restart_handler handler([] { return true; }, {}, {path});
	std::string err;
	EXPECT_FALSE(handler.start(err));
	EXPECT_NE(err.find("could not watch directory: " + path), std::string::npos);
}

TEST_F(RestartHandlerTest, other_file_watch_errors_remain_fatal) {
	const auto path = m_directory + "/loop.yaml";
	std::filesystem::create_symlink(path, path);
	falco::app::restart_handler handler([] { return true; }, {path}, {m_directory});
	std::string err;
	EXPECT_FALSE(handler.start(err));
	EXPECT_NE(err.find("could not watch file: " + path), std::string::npos);
}

TEST_F(RestartHandlerTest, unchanged_directory_member_does_not_request_reload) {
	const auto path = m_directory + "/present.yaml";
	{ std::ofstream file(path); }
	std::atomic<int> checks{0};
	falco::app::restart_handler handler(
	        [&checks] {
		        checks.fetch_add(1);
		        return true;
	        },
	        {path},
	        {m_directory});
	std::string err;
	ASSERT_TRUE(handler.start(err)) << err;
	std::this_thread::sleep_for(std::chrono::milliseconds(400));
	EXPECT_EQ(checks.load(), 0);
	EXPECT_FALSE(falco::app::g_restart_signal.triggered());
	{
		std::ofstream file(path);
		file << "changed\n";
	}
	EXPECT_TRUE(wait_restart_triggered(s_deadline));
	handler.stop();
	EXPECT_GE(checks.load(), 1);
}
