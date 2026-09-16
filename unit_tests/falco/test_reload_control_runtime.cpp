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

#include "reload_test_helpers.h"

#include <gtest/gtest.h>
#include <httplib.h>
#include <nlohmann/json.hpp>

#include <arpa/inet.h>
#include <fcntl.h>
#include <signal.h>
#include <spawn.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <memory>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

extern char** environ;

namespace {

using json = nlohmann::json;
using clock_type = std::chrono::steady_clock;
using namespace std::chrono_literals;
using falco::test::require;
using falco::test::scoped_fd;

// posix_spawn remains safe when other tests have started threads in this process.
class child_process {
public:
	child_process() = default;
	~child_process() { stop(); }
	child_process(const child_process&) = delete;
	child_process& operator=(const child_process&) = delete;

	void start(const std::string& config, const std::string& log) {
		require(m_pid < 0, "child already running");
		std::vector<std::string> environment;
		for(auto entry = environ; *entry; ++entry) {
			if(std::strncmp(*entry, "HOST_ROOT=", 10) != 0) {
				environment.emplace_back(*entry);
			}
		}
		environment.emplace_back("HOST_ROOT=/");
		std::vector<char*> env;
		for(auto& entry : environment) {
			env.push_back(entry.data());
		}
		env.push_back(nullptr);
		const char* arguments[] = {TEST_FALCO_BINARY, "-c", config.c_str(), nullptr};
		posix_spawn_file_actions_t actions;
		posix_spawnattr_t attributes;
		auto check = [](int err) { require(err == 0, std::strerror(err)); };
		check(::posix_spawn_file_actions_init(&actions));
		const auto attr_error = ::posix_spawnattr_init(&attributes);
		if(attr_error != 0) {
			::posix_spawn_file_actions_destroy(&actions);
			check(attr_error);
		}
		try {
			check(::posix_spawn_file_actions_addopen(&actions,
			                                         STDOUT_FILENO,
			                                         log.c_str(),
			                                         O_WRONLY | O_CREAT | O_APPEND,
			                                         0600));
			check(::posix_spawn_file_actions_adddup2(&actions, STDOUT_FILENO, STDERR_FILENO));
			sigset_t mask;
			::sigemptyset(&mask);
			check(::posix_spawnattr_setsigmask(&attributes, &mask));
			check(::posix_spawnattr_setflags(&attributes, POSIX_SPAWN_SETSIGMASK));
			pid_t pid = -1;
			check(::posix_spawn(&pid,
			                    TEST_FALCO_BINARY,
			                    &actions,
			                    &attributes,
			                    const_cast<char**>(arguments),
			                    env.data()));
			m_pid = pid;
			m_started = true;
			m_wait_error = false;
			m_status = 0;
		} catch(...) {
			::posix_spawnattr_destroy(&attributes);
			::posix_spawn_file_actions_destroy(&actions);
			throw;
		}
		::posix_spawnattr_destroy(&attributes);
		::posix_spawn_file_actions_destroy(&actions);
	}

	pid_t pid() const { return m_pid; }
	void check_running() {
		const auto pid = m_pid;
		require(pid > 0 && !reaped(),
		        "Falco exited (wait status " + std::to_string(m_status) + ")");
	}

	// All cleanup paths are bounded, including a child that fails to stop normally.
	bool stop() noexcept {
		if(m_pid < 0 || reaped()) {
			return exited_successfully();
		}
		::kill(m_pid, SIGTERM);
		if(wait_until(clock_type::now() + 5s)) {
			return exited_successfully();
		}
		::kill(m_pid, SIGKILL);
		wait_until(clock_type::now() + 2s);
		return false;
	}

private:
	bool exited_successfully() const noexcept {
		return !m_started || (!m_wait_error && WIFEXITED(m_status) && WEXITSTATUS(m_status) == 0);
	}
	bool reaped() noexcept {
		if(m_pid < 0) {
			return true;
		}
		const auto result = ::waitpid(m_pid, &m_status, WNOHANG);
		if(result == m_pid || (result < 0 && errno == ECHILD)) {
			m_wait_error = result < 0;
			m_pid = -1;
			return true;
		}
		return false;
	}
	bool wait_until(clock_type::time_point deadline) noexcept {
		do {
			if(reaped()) {
				return true;
			}
			std::this_thread::sleep_for(10ms);
		} while(clock_type::now() < deadline);
		return false;
	}
	pid_t m_pid = -1;
	int m_status = 0;
	bool m_started = false;
	bool m_wait_error = false;
};

class ReloadControlRuntimeTest : public testing::Test {
protected:
	void SetUp() override {
		char path[] = "/tmp/falco-reload-runtime-XXXXXX";
		const auto directory = ::mkdtemp(path);
		ASSERT_NE(directory, nullptr) << std::strerror(errno);
		m_directory = directory;
		ASSERT_EQ(::chmod(directory, 0750), 0) << std::strerror(errno);
		m_socket = m_directory + "/control.sock";
		m_config = m_directory + "/falco.yaml";
		m_rules = m_directory + "/rules.yaml";
		m_log = m_directory + "/falco.log";
	}

	void TearDown() override {
		EXPECT_TRUE(m_child.stop()) << "Falco did not exit successfully after SIGTERM";
		if(HasFailure()) {
			std::ifstream log(m_log);
			if(log) {
				std::cerr << "\nFalco child log (" << m_log << "):\n" << log.rdbuf();
			}
		}
		if(!m_directory.empty() && m_child.pid() < 0) {
			std::error_code err;
			std::filesystem::remove_all(m_directory, err);
			EXPECT_FALSE(err) << err.message();
		}
	}

	void write_file(const std::string& path, const std::string& contents) {
		const auto temporary = path + ".tmp";
		std::ofstream file(temporary);
		file.exceptions(std::ios::failbit | std::ios::badbit);
		file << contents;
		file.close();
		std::filesystem::rename(temporary, path);
	}
	void write_rules(int revision) {
		write_file(m_rules,
		           "- rule: Reload control regression\n"
		           "  desc: Real binary reload regression\n"
		           "  condition: evt.type = execve\n"
		           "  output: revision=" +
		                   std::to_string(revision) +
		                   " event=%evt.type\n"
		                   "  priority: DEBUG\n"
		                   "  enabled: false\n");
	}
	void write_config(bool watch,
	                  int port = 0,
	                  const std::string& health = "/health-before",
	                  const std::string& socket = "") {
		write_file(m_config,
		           "engine:\n  kind: nodriver\n"
		           "rules_files: [" +
		                   m_rules +
		                   "]\n"
		                   "config_files: []\nplugins: []\nload_plugins: []\n"
		                   "watch_config_files: " +
		                   std::string(watch ? "true" : "false") +
		                   "\n"
		                   "reload_control:\n  enabled: true\n  socket: " +
		                   (socket.empty() ? m_socket : socket) +
		                   "\n"
		                   "webserver:\n  enabled: " +
		                   std::string(port ? "true" : "false") +
		                   "\n"
		                   "  listen_address: 127.0.0.1\n  listen_port: " +
		                   std::to_string(port ? port : 8765) +
		                   "\n"
		                   "  k8s_healthz_endpoint: " +
		                   health +
		                   "\n"
		                   "metrics:\n  enabled: false\n"
		                   "log_level: info\nlog_stderr: true\nlog_syslog: false\n"
		                   "stdout_output:\n  enabled: true\n");
	}
	std::unique_ptr<httplib::Client> client() {
		auto client = std::make_unique<httplib::Client>(m_socket);
		client->set_address_family(AF_UNIX);
		client->set_connection_timeout(1);
		client->set_read_timeout(1);
		client->set_write_timeout(1);
		return client;
	}
	json state() {
		m_child.check_running();
		auto response = client()->Get("/reload");
		if(!response) {
			return nullptr;  // Startup and socket replacement can temporarily refuse connections.
		}
		require(response->status == 200, "GET /reload: HTTP " + std::to_string(response->status));
		const auto status = json::parse(response->body);
		require(status.at("instance_id").is_string() &&
		                !status.at("instance_id").get<std::string>().empty(),
		        "missing process identity: " + status.dump());
		for(const auto* field :
		    {"started_generation", "applied_generation", "rejected_generation"}) {
			require(status.at(field).is_number_unsigned(), "invalid generation: " + status.dump());
		}
		require(status.at("ready").is_boolean(), "invalid readiness: " + status.dump());
		require(m_instance.empty() || status.at("instance_id") == m_instance,
		        "process identity changed: " + status.dump());
		return status;
	}
	template<typename Predicate>
	json wait_state(Predicate predicate, const std::string& description) {
		const auto deadline = clock_type::now() + 20s;
		json latest;
		do {
			latest = state();
			if(!latest.is_null() && predicate(latest)) {
				return latest;
			}
			std::this_thread::sleep_for(20ms);
		} while(clock_type::now() < deadline);
		throw std::runtime_error("timed out " + description + ": " + latest.dump());
	}
	json start() {
		m_instance.clear();
		m_child.start(m_config, m_log);
		const auto initial = wait_state([](const json& value) { return value.at("ready") == true; },
		                                "waiting for initial readiness");
		require(initial.at("applied_generation").get<uint64_t>() > 0,
		        "initial runtime not applied");
		m_instance = initial.at("instance_id").get<std::string>();
		return initial;
	}
	uint64_t request() {
		const auto deadline = clock_type::now() + 20s;
		do {
			m_child.check_running();
			auto response = client()->Post("/reload");
			if(response) {
				require(response->status == 202,
				        "POST /reload: HTTP " + std::to_string(response->status));
				const auto accepted = json::parse(response->body);
				require(accepted.at("instance_id") == m_instance, "acceptance identity changed");
				return accepted.at("started_generation").get<uint64_t>();
			}
			// A concurrent native reload can close the listener before acceptance is received.
			std::this_thread::sleep_for(20ms);
		} while(clock_type::now() < deadline);
		throw std::runtime_error("timed out requesting reload");
	}
	json outcome(uint64_t baseline, bool reject = false) {
		return wait_state(
		        [=](const json& status) {
			        const auto applied = status.at("applied_generation").get<uint64_t>();
			        const auto rejected = status.at("rejected_generation").get<uint64_t>();
			        const bool failed = rejected > std::max(baseline, applied);
			        const bool succeeded =
			                status.at("ready") == true && applied > std::max(baseline, rejected);
			        require(!(reject ? succeeded : failed),
			                "unexpected reload outcome: " + status.dump());
			        return reject ? failed : succeeded;
		        },
		        "waiting for reload outcome after " + std::to_string(baseline));
	}
	size_t fd_count() {
		m_child.check_running();
		const auto path = "/proc/" + std::to_string(m_child.pid()) + "/fd";
		return std::distance(std::filesystem::directory_iterator(path),
		                     std::filesystem::directory_iterator());
	}

	child_process m_child;
	std::string m_directory, m_socket, m_config, m_rules, m_log, m_instance;
};

}  // namespace

TEST_F(ReloadControlRuntimeTest, unix_reload_converges_with_tcp_disabled_and_either_watch_mode) {
	for(const bool watch : {false, true}) {
		SCOPED_TRACE(watch ? "native watching enabled" : "native watching disabled");
		write_rules(1);
		write_config(watch);
		const auto initial = start();
		const auto pid = m_child.pid();
		write_rules(2);
		const auto baseline = request();
		EXPECT_GE(baseline, initial.at("started_generation").get<uint64_t>());
		const auto applied = outcome(baseline);
		EXPECT_GT(applied.at("applied_generation").get<uint64_t>(), baseline);
		EXPECT_EQ(m_child.pid(), pid);
		ASSERT_TRUE(m_child.stop());
		EXPECT_FALSE(std::filesystem::exists(m_socket));
	}
}

TEST_F(ReloadControlRuntimeTest,
       rejected_rules_leave_the_runtime_ready_and_recover_without_retrying) {
	write_rules(1);
	write_config(false);
	const auto initial = start();
	write_file(m_rules, "- rule: [invalid YAML\n");
	const auto rejected = outcome(request(), true);
	EXPECT_EQ(rejected.at("ready"), true);
	EXPECT_EQ(rejected.at("applied_generation"), initial.at("applied_generation"));
	// Observe a bounded quiet interval, rather than treating one rejection as proof of no retry
	// loop.
	const auto quiet_until = clock_type::now() + 750ms;
	do {
		EXPECT_EQ(state(), rejected);
		std::this_thread::sleep_for(20ms);
	} while(clock_type::now() < quiet_until);
	write_rules(2);
	const auto recovered = outcome(request());
	EXPECT_GT(recovered.at("applied_generation").get<uint64_t>(),
	          rejected.at("rejected_generation").get<uint64_t>());
}

TEST_F(ReloadControlRuntimeTest, invalid_socket_directories_leave_the_previous_runtime_active) {
	write_rules(1);
	write_config(false);
	const auto initial = start();
	const auto pid = m_child.pid();
	struct stat original = {};
	ASSERT_EQ(::lstat(m_socket.c_str(), &original), 0);
	const auto unsafe = m_directory + "/unsafe";
	ASSERT_EQ(::mkdir(unsafe.c_str(), 0700), 0);
	ASSERT_EQ(::chmod(unsafe.c_str(), 0770), 0);
	for(const auto& directory : {m_directory + "/missing", unsafe}) {
		SCOPED_TRACE(directory);
		const auto socket = directory + "/control.sock";
		write_config(false, 0, "/health-before", socket);
		const auto rejected = outcome(request(), true);
		EXPECT_EQ(rejected.at("ready"), true);
		EXPECT_EQ(rejected.at("applied_generation"), initial.at("applied_generation"));
		EXPECT_EQ(m_child.pid(), pid);
		struct stat current = {};
		ASSERT_EQ(::lstat(m_socket.c_str(), &current), 0);
		EXPECT_EQ(current.st_dev, original.st_dev);
		EXPECT_EQ(current.st_ino, original.st_ino);
		EXPECT_FALSE(std::filesystem::exists(socket));
	}
	write_config(false);
	const auto recovered = outcome(request());
	EXPECT_GT(recovered.at("applied_generation").get<uint64_t>(),
	          recovered.at("rejected_generation").get<uint64_t>());
	EXPECT_EQ(m_child.pid(), pid);
}

TEST_F(ReloadControlRuntimeTest, repeated_reloads_replace_the_socket_without_leaking_descriptors) {
	write_rules(1);
	write_config(false);
	start();
	// Wait until the readiness request's accepted descriptor has closed before taking a baseline.
	auto previous = fd_count();
	size_t baseline = previous;
	const auto settling_deadline = clock_type::now() + 5s;
	do {
		std::this_thread::sleep_for(100ms);
		baseline = fd_count();
		if(previous == baseline) {
			break;
		}
		previous = baseline;
	} while(clock_type::now() < settling_deadline);
	const auto pid = m_child.pid();
	for(int revision = 2; revision <= 4; ++revision) {
		SCOPED_TRACE(revision);
		// Pin the old inode: without this, immediate inode reuse makes identity assertions flaky.
		scoped_fd old_socket(::open(m_socket.c_str(), O_PATH | O_NOFOLLOW | O_CLOEXEC));
		ASSERT_GE(old_socket.get(), 0) << std::strerror(errno);
		struct stat old_info = {}, new_info = {};
		ASSERT_EQ(::fstat(old_socket.get(), &old_info), 0);
		write_rules(revision);
		outcome(request());
		ASSERT_EQ(::lstat(m_socket.c_str(), &new_info), 0);
		EXPECT_TRUE(old_info.st_dev != new_info.st_dev || old_info.st_ino != new_info.st_ino);
		EXPECT_EQ(m_child.pid(), pid);
		const auto deadline = clock_type::now() + 5s;
		size_t count;
		do {
			count = fd_count();
			if(count == baseline) {
				break;
			}
			std::this_thread::sleep_for(20ms);
		} while(clock_type::now() < deadline);
		EXPECT_EQ(count, baseline);
	}
	ASSERT_TRUE(m_child.stop());
	EXPECT_FALSE(std::filesystem::exists(m_socket));
}

TEST_F(ReloadControlRuntimeTest, tcp_is_read_only_and_reload_applies_the_new_health_route) {
	int port;
	{
		scoped_fd reservation(::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0));
		ASSERT_GE(reservation.get(), 0);
		sockaddr_in address = {};
		address.sin_family = AF_INET;
		address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		ASSERT_EQ(::bind(reservation.get(), reinterpret_cast<sockaddr*>(&address), sizeof(address)),
		          0);
		socklen_t length = sizeof(address);
		ASSERT_EQ(::getsockname(reservation.get(), reinterpret_cast<sockaddr*>(&address), &length),
		          0);
		port = ntohs(address.sin_port);
	}
	write_rules(1);
	write_config(false, port);
	start();
	httplib::Client tcp("127.0.0.1", port);
	tcp.set_connection_timeout(1);
	tcp.set_read_timeout(1);
	tcp.set_write_timeout(1);
	auto observation = tcp.Get("/reload");
	ASSERT_TRUE(observation) << httplib::to_string(observation.error());
	EXPECT_EQ(observation->status, 200);
	EXPECT_EQ(observation->get_header_value("Cache-Control"), "no-store");
	const auto observed = json::parse(observation->body);
	EXPECT_EQ(observed, state());
	auto mutation = tcp.Post("/reload");
	ASSERT_TRUE(mutation) << httplib::to_string(mutation.error());
	EXPECT_EQ(mutation->status, 404);
	EXPECT_EQ(state(), observed);
	auto before = tcp.Get("/health-before");
	ASSERT_TRUE(before);
	EXPECT_EQ(before->status, 200);
	write_config(false, port, "/health-after");
	outcome(request());
	m_child.check_running();
	auto old_route = tcp.Get("/health-before");
	auto new_route = tcp.Get("/health-after");
	ASSERT_TRUE(old_route);
	ASSERT_TRUE(new_route);
	EXPECT_EQ(old_route->status, 404);
	EXPECT_EQ(new_route->status, 200);
}
