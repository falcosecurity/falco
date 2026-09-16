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

#include <falco/reload_control.h>
#include <falco/app/reload_state.h>
#include <falco/app/signals.h>
#include <falco_common.h>

#include <gtest/gtest.h>
#include <httplib.h>
#include <nlohmann/json.hpp>

#include <endian.h>
#include <fcntl.h>
#include <grp.h>
#include <linux/posix_acl.h>
#include <linux/posix_acl_xattr.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/xattr.h>
#include <unistd.h>

#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <memory>
#include <string>
#include <vector>

namespace {

namespace app = falco::app;

using falco::test::require_in_child;
using falco::test::scoped_fd;

void initialize_backend() {
	std::string err;
	ASSERT_TRUE(app::initialize_restart_signal_handler(err)) << err;
}

std::unique_ptr<httplib::Client> make_client(const std::string& path) {
	auto client = std::make_unique<httplib::Client>(path);
	client->set_address_family(AF_UNIX);
	client->set_connection_timeout(1);
	client->set_read_timeout(1);
	client->set_write_timeout(1);
	return client;
}

void bind_stale_socket(const std::string& path) {
	struct sockaddr_un address = {};
	ASSERT_LT(path.size(), sizeof(address.sun_path));
	address.sun_family = AF_UNIX;
	std::memcpy(address.sun_path, path.c_str(), path.size() + 1);
	const auto fd = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	ASSERT_GE(fd, 0) << std::strerror(errno);
	const auto result = ::bind(fd, reinterpret_cast<const sockaddr*>(&address), sizeof(address));
	const auto saved_errno = errno;
	::close(fd);
	ASSERT_EQ(result, 0) << std::strerror(saved_errno);
}

size_t open_fd_count() {
	size_t count = 0;
	for(const auto& entry : std::filesystem::directory_iterator("/proc/self/fd")) {
		(void)entry;
		++count;
	}
	return count;
}

int install_extended_acl(const std::string& path, const char* attribute) {
	// A named user has read/search access while the visible mode remains 0750.
	// This specifically exercises ACL validation, rather than mode-bit rejection.
	const auto named_user = ::geteuid() == 65534 ? 65533 : 65534;
	const auto undefined_id = htole32(static_cast<uint32_t>(ACL_UNDEFINED_ID));
	const struct {
		posix_acl_xattr_header header;
		posix_acl_xattr_entry entries[5];
	} acl = {{htole32(POSIX_ACL_XATTR_VERSION)},
	         {{htole16(ACL_USER_OBJ), htole16(7), undefined_id},
	          {htole16(ACL_USER), htole16(5), htole32(named_user)},
	          {htole16(ACL_GROUP_OBJ), htole16(0), undefined_id},
	          {htole16(ACL_MASK), htole16(5), undefined_id},
	          {htole16(ACL_OTHER), htole16(0), undefined_id}}};
	return ::setxattr(path.c_str(), attribute, &acl, sizeof(acl), 0);
}

#if defined(GTEST_HAS_DEATH_TEST) && GTEST_HAS_DEATH_TEST
void initialize_child_backend() {
	require_in_child(::signal(SIGALRM, SIG_DFL) != SIG_ERR, "could not restore alarm disposition");
	sigset_t alarm_signal;
	require_in_child(::sigemptyset(&alarm_signal) == 0, "sigemptyset failed");
	require_in_child(::sigaddset(&alarm_signal, SIGALRM) == 0, "sigaddset failed");
	require_in_child(::sigprocmask(SIG_UNBLOCK, &alarm_signal, nullptr) == 0,
	                 "could not unblock alarm");
	::alarm(10);
	std::string err;
	const auto initialized = app::initialize_restart_signal_handler(err);
	require_in_child(initialized, err);
}
#endif

class ReloadControlTest : public testing::Test {
protected:
	void SetUp() override {
		char directory[] = "/tmp/falco-reload-control-XXXXXX";
		const auto created = ::mkdtemp(directory);
		ASSERT_NE(created, nullptr) << std::strerror(errno);
		m_directory = created;
		m_path = m_directory + "/control.sock";
	}

	void TearDown() override {
		if(!m_directory.empty()) {
			std::error_code err;
			std::filesystem::remove_all(m_directory, err);
			EXPECT_FALSE(err) << err.message();
		}
	}

	std::string m_directory;
	std::string m_path;
};

#if defined(GTEST_HAS_DEATH_TEST) && GTEST_HAS_DEATH_TEST
class ReloadControlDeathTest : public ReloadControlTest {};
#endif

}  // namespace

#if defined(GTEST_HAS_DEATH_TEST) && GTEST_HAS_DEATH_TEST
TEST_F(ReloadControlDeathTest, validation_requires_directory_write_and_search_access) {
	if(::geteuid() != 0) {
		GTEST_SKIP() << "dropping to another user requires root";
	}
	ASSERT_EQ(::chown(m_directory.c_str(), 65534, 65534), 0);
	EXPECT_EXIT(
	        {
		        require_in_child(::setgroups(0, nullptr) == 0,
		                         "could not drop supplementary groups");
		        require_in_child(::setgid(65534) == 0 && ::setuid(65534) == 0,
		                         "could not drop privileges");
		        const auto descriptors = open_fd_count();
		        for(const auto mode : {0500, 0600}) {
			        require_in_child(::chmod(m_directory.c_str(), mode) == 0,
			                         "could not change directory permissions");
			        bool rejected = false;
			        try {
				        falco_reload_control::validate_socket_directory(m_path);
			        } catch(const falco_exception&) {
				        rejected = true;
			        }
			        require_in_child(rejected, "inaccessible directory was accepted");
			        require_in_child(open_fd_count() == descriptors,
			                         "failed validation leaked descriptors");
		        }
		        require_in_child(::chmod(m_directory.c_str(), 0700) == 0,
		                         "could not restore directory permissions");
		        try {
			        falco_reload_control::validate_socket_directory(m_path);
		        } catch(const std::exception& err) {
			        std::fprintf(stderr, "%s\n", err.what());
			        _exit(1);
		        }
		        require_in_child(open_fd_count() == descriptors,
		                         "successful validation leaked descriptors");
		        _exit(0);
	        },
	        ::testing::ExitedWithCode(0),
	        "");
}

TEST_F(ReloadControlDeathTest, an_unrelated_user_cannot_connect_to_the_control_socket) {
	if(::geteuid() != 0) {
		GTEST_SKIP() << "dropping to another user requires root";
	}
	ASSERT_EQ(::chmod(m_directory.c_str(), 0750), 0);
	struct stat directory = {};
	ASSERT_EQ(::stat(m_directory.c_str(), &directory), 0);
	const gid_t denied_group = directory.st_gid == 65534 ? 65533 : 65534;

	EXPECT_EXIT(
	        {
		        initialize_child_backend();
		        falco_reload_control control;
		        try {
			        control.start(m_path);
		        } catch(const std::exception& err) {
			        std::fprintf(stderr, "%s\n", err.what());
			        _exit(1);
		        }
		        require_in_child(::setgroups(0, nullptr) == 0,
		                         "could not drop supplementary groups");
		        require_in_child(::setgid(denied_group) == 0, "could not drop group privileges");
		        require_in_child(::setuid(65534) == 0, "could not drop user privileges");
		        require_in_child(::geteuid() == 65534 && ::getegid() == denied_group &&
		                                 ::getgroups(0, nullptr) == 0,
		                         "untrusted identity was not established");

		        sockaddr_un address = {};
		        address.sun_family = AF_UNIX;
		        std::memcpy(address.sun_path, m_path.c_str(), m_path.size() + 1);
		        const auto fd = ::socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
		        require_in_child(fd >= 0, "could not create client socket");
		        const auto result =
		                ::connect(fd, reinterpret_cast<const sockaddr*>(&address), sizeof(address));
		        const auto error = errno;
		        ::close(fd);
		        require_in_child(result == -1 && error == EACCES,
		                         "unrelated user was not denied by filesystem permissions");
		        control.stop();
		        // The parent removes the socket: this user cannot unlink in its directory.
		        _exit(0);
	        },
	        ::testing::ExitedWithCode(0),
	        "");
}

TEST_F(ReloadControlDeathTest, stop_with_an_idle_client_is_bounded_and_releases_descriptors) {
	EXPECT_EXIT(
	        {
		        initialize_child_backend();
		        const auto descriptors = open_fd_count();
		        const auto requested = app::g_reload_state.requested();
		        {
			        falco_reload_control control;
			        try {
				        control.start(m_path);
			        } catch(const std::exception& err) {
				        std::fprintf(stderr, "%s\n", err.what());
				        _exit(1);
			        }
			        scoped_fd idle(
			                ::socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0));
			        require_in_child(idle.get() >= 0, "could not create idle client");
			        sockaddr_un address = {};
			        address.sun_family = AF_UNIX;
			        std::memcpy(address.sun_path, m_path.c_str(), m_path.size() + 1);
			        require_in_child(::connect(idle.get(),
			                                   reinterpret_cast<const sockaddr*>(&address),
			                                   sizeof(address)) == 0,
			                         "could not connect idle client");
			        const std::string partial = "POST /reload HTTP/1.1\r\nHost: localhost\r\n";
			        require_in_child(
			                ::send(idle.get(), partial.data(), partial.size(), MSG_NOSIGNAL) ==
			                        static_cast<ssize_t>(partial.size()),
			                "could not send incomplete request headers");
			        {
				        // A later accepted connection proves the idle one passed the listen queue.
				        auto observer = make_client(m_path);
				        const auto response = observer->Get("/reload");
				        require_in_child(response && response->status == 200,
				                         "listener did not accept the following observation");
			        }
			        char byte;
			        const auto peek = ::recv(idle.get(), &byte, 1, MSG_PEEK | MSG_DONTWAIT);
			        require_in_child(peek == -1 && (errno == EAGAIN || errno == EWOULDBLOCK),
			                         "idle client was already answered or closed before stop");
			        const auto started = std::chrono::steady_clock::now();
			        control.stop();
			        require_in_child(
			                std::chrono::steady_clock::now() - started < std::chrono::seconds(3),
			                "stop exceeded the bounded read timeout");
		        }
		        require_in_child(open_fd_count() == descriptors, "stop leaked descriptors");
		        require_in_child(app::g_reload_state.requested() == requested,
		                         "incomplete request unexpectedly queued a reload");
		        _exit(0);
	        },
	        ::testing::ExitedWithCode(0),
	        "");
}

TEST_F(ReloadControlDeathTest, permission_failure_after_bind_cleans_up_and_can_retry) {
	if(::geteuid() != 0) {
		GTEST_SKIP() << "preparing ownership and dropping to another user requires root";
	}
	ASSERT_EQ(::chown(m_directory.c_str(), 65534, 0), 0);
	ASSERT_EQ(::chmod(m_directory.c_str(), 0700), 0);

	EXPECT_EXIT(
	        {
		        require_in_child(::setgroups(0, nullptr) == 0,
		                         "could not drop supplementary groups");
		        require_in_child(::setgid(65534) == 0, "could not drop group privileges");
		        require_in_child(::setuid(65534) == 0, "could not drop user privileges");
		        require_in_child(::getuid() == 65534 && ::geteuid() == 65534 &&
		                                 ::getgid() == 65534 && ::getegid() == 65534 &&
		                                 ::getgroups(0, nullptr) == 0,
		                         "unprivileged directory owner was not established");
		        initialize_child_backend();
		        const auto descriptors = open_fd_count();
		        falco_reload_control control;
		        std::string failure;
		        try {
			        // Binding is permitted, but assigning the directory's unrelated
			        // group must fail before the listener thread starts.
			        control.start(m_path);
		        } catch(const std::exception& err) {
			        failure = err.what();
		        } catch(...) {
			        failure = "unexpected nonstandard exception";
		        }
		        require_in_child(
		                failure.find("cannot set socket ownership and permissions") !=
		                        std::string::npos,
		                failure.empty() ? "startup unexpectedly succeeded" : failure.c_str());
		        require_in_child(open_fd_count() == descriptors,
		                         "failed startup leaked a descriptor");
		        struct stat residual = {};
		        require_in_child(::lstat(m_path.c_str(), &residual) == -1 && errno == ENOENT,
		                         "failed startup left a socket path");

		        require_in_child(
		                ::chown(m_directory.c_str(), static_cast<uid_t>(-1), ::getegid()) == 0,
		                "directory owner could not adopt its own group");
		        try {
			        control.start(m_path);
		        } catch(const std::exception& err) {
			        std::fprintf(stderr, "%s\n", err.what());
			        _exit(1);
		        }
		        {
			        auto client = make_client(m_path);
			        const auto response = client->Get("/reload");
			        require_in_child(
			                response && response->status == 200,
			                "listener did not recover after correcting the directory group");
		        }
		        control.stop();
		        require_in_child(open_fd_count() == descriptors, "retry leaked a descriptor");
		        require_in_child(::lstat(m_path.c_str(), &residual) == -1 && errno == ENOENT,
		                         "retry cleanup left a socket path");
		        _exit(0);
	        },
	        ::testing::ExitedWithCode(0),
	        "");
}
#endif

TEST_F(ReloadControlTest, get_reports_state_without_requesting_or_starting_a_reload) {
	ASSERT_NO_FATAL_FAILURE(initialize_backend());
	falco_reload_control control;
	ASSERT_NO_THROW(control.start(m_path));
	auto client = make_client(m_path);
	const auto before = app::g_reload_state.get();
	const auto requested = app::g_reload_state.requested();
	const auto covered = app::g_reload_state.covered();
	const nlohmann::json expected = {{"instance_id", before.instance_id},
	                                 {"started_generation", before.started_generation},
	                                 {"applied_generation", before.applied_generation},
	                                 {"rejected_generation", before.rejected_generation},
	                                 {"ready", before.ready}};

	for(int i = 0; i < 2; ++i) {
		auto response = client->Get("/reload");
		ASSERT_TRUE(response) << httplib::to_string(response.error());
		EXPECT_EQ(response->status, 200);
		EXPECT_EQ(response->get_header_value("Cache-Control"), "no-store");
		EXPECT_EQ(nlohmann::json::parse(response->body), expected);
		EXPECT_EQ(app::g_reload_state.requested(), requested);
		EXPECT_EQ(app::g_reload_state.covered(), covered);
	}
}

TEST_F(ReloadControlTest, post_accepts_a_request_and_returns_a_pre_application_baseline) {
	ASSERT_NO_FATAL_FAILURE(initialize_backend());
	falco_reload_control control;
	ASSERT_NO_THROW(control.start(m_path));
	auto client = make_client(m_path);
	const auto before = app::g_reload_state.get();
	const auto requested = app::g_reload_state.requested();
	const auto covered = app::g_reload_state.covered();

	auto response = client->Post("/reload");
	ASSERT_TRUE(response) << httplib::to_string(response.error());
	EXPECT_EQ(response->status, 202);
	EXPECT_EQ(response->get_header_value("Location"), "/reload");
	EXPECT_EQ(response->get_header_value("Cache-Control"), "no-store");
	const auto body = nlohmann::json::parse(response->body);
	EXPECT_EQ(body.at("instance_id"), before.instance_id);
	EXPECT_EQ(body.at("started_generation"), before.started_generation);
	EXPECT_EQ(app::g_reload_state.requested(), requested + 1);
	EXPECT_EQ(app::g_reload_state.covered(), covered);
	auto observation = client->Get(response->get_header_value("Location"));
	ASSERT_TRUE(observation) << httplib::to_string(observation.error());
	EXPECT_EQ(observation->status, 200);
	EXPECT_EQ(nlohmann::json::parse(observation->body).at("instance_id"), before.instance_id);
	EXPECT_EQ(app::g_reload_state.requested(), requested + 1);

	// Acceptance alone cannot advance application state: no runtime worker is running.
	const auto after = app::g_reload_state.get();
	EXPECT_EQ(after.started_generation, before.started_generation);
	EXPECT_EQ(after.applied_generation, before.applied_generation);
	EXPECT_EQ(after.rejected_generation, before.rejected_generation);
	EXPECT_EQ(after.ready, before.ready);
}

TEST_F(ReloadControlTest, bodies_and_queries_are_rejected_without_requesting_reload) {
	ASSERT_NO_FATAL_FAILURE(initialize_backend());
	falco_reload_control control;
	ASSERT_NO_THROW(control.start(m_path));
	auto client = make_client(m_path);
	const auto requested = app::g_reload_state.requested();

	auto body_response = client->Post("/reload", "{}", "application/json");
	ASSERT_TRUE(body_response) << httplib::to_string(body_response.error());
	EXPECT_EQ(body_response->status, 400);
	EXPECT_EQ(app::g_reload_state.requested(), requested);
	for(const auto* path : {"/reload?force=true", "/reload?"}) {
		SCOPED_TRACE(path);
		auto response = client->Post(path);
		ASSERT_TRUE(response) << httplib::to_string(response.error());
		EXPECT_EQ(response->status, 400);
		EXPECT_EQ(app::g_reload_state.requested(), requested);
	}

	auto oversized = client->Post("/reload", std::string(64 * 1024, 'x'), "text/plain");
	ASSERT_TRUE(oversized) << httplib::to_string(oversized.error());
	EXPECT_EQ(oversized->status, 413);
	EXPECT_EQ(app::g_reload_state.requested(), requested);
}

TEST_F(ReloadControlTest, multipart_bodies_are_rejected_without_requesting_reload) {
	ASSERT_NO_FATAL_FAILURE(initialize_backend());
	falco_reload_control control;
	ASSERT_NO_THROW(control.start(m_path));
	auto client = make_client(m_path);
	const auto requested = app::g_reload_state.requested();

	const httplib::UploadFormDataItems parts = {
	        {"field", "value", "", "text/plain"},
	        {"file", "contents", "rules.yaml", "application/yaml"},
	        {"empty_field", "", "", "text/plain"},
	        {"empty_file", "", "rules.yaml", "application/yaml"}};
	for(const auto& part : parts) {
		SCOPED_TRACE(part.name);
		auto response = client->Post("/reload", httplib::UploadFormDataItems{part});
		ASSERT_TRUE(response) << httplib::to_string(response.error());
		EXPECT_EQ(response->status, 400);
		EXPECT_EQ(app::g_reload_state.requested(), requested);
	}
}

TEST_F(ReloadControlTest, other_methods_and_routes_do_not_request_reload) {
	ASSERT_NO_FATAL_FAILURE(initialize_backend());
	falco_reload_control control;
	ASSERT_NO_THROW(control.start(m_path));
	auto client = make_client(m_path);
	const auto requested = app::g_reload_state.requested();

	for(const auto* method : {"GET", "HEAD", "PUT", "PATCH", "DELETE", "OPTIONS"}) {
		SCOPED_TRACE(method);
		httplib::Request request;
		request.method = method;
		request.path = "/reload";
		auto response = client->send(request);
		ASSERT_TRUE(response) << httplib::to_string(response.error());
		EXPECT_NE(response->status, 202);
		EXPECT_EQ(app::g_reload_state.requested(), requested);
	}
	for(const auto* path : {"/reloadz", "/-/reload", "/reload/", "/unknown"}) {
		SCOPED_TRACE(path);
		for(const auto* method : {"GET", "POST"}) {
			SCOPED_TRACE(method);
			httplib::Request request;
			request.method = method;
			request.path = path;
			auto response = client->send(request);
			ASSERT_TRUE(response) << httplib::to_string(response.error());
			EXPECT_EQ(response->status, 404);
			EXPECT_EQ(app::g_reload_state.requested(), requested);
		}
	}
}

TEST_F(ReloadControlTest, validation_does_not_create_or_remove_sockets_or_leak_descriptors) {
	const auto descriptors = open_fd_count();
	for(int i = 0; i < 3; ++i) {
		ASSERT_NO_THROW(falco_reload_control::validate_socket_directory(m_path));
		EXPECT_FALSE(std::filesystem::exists(m_path));
		EXPECT_THROW(
		        falco_reload_control::validate_socket_directory(m_directory + "/missing/socket"),
		        falco_exception);
		EXPECT_EQ(open_fd_count(), descriptors);
	}
	ASSERT_NO_FATAL_FAILURE(bind_stale_socket(m_path));
	struct stat before = {}, after = {};
	ASSERT_EQ(::lstat(m_path.c_str(), &before), 0);
	ASSERT_NO_THROW(falco_reload_control::validate_socket_directory(m_path));
	ASSERT_EQ(::lstat(m_path.c_str(), &after), 0);
	EXPECT_EQ(after.st_dev, before.st_dev);
	EXPECT_EQ(after.st_ino, before.st_ino);
	EXPECT_EQ(open_fd_count(), descriptors);
}

TEST_F(ReloadControlTest, validation_preserves_the_live_listener_and_its_directory_lock) {
	ASSERT_NO_FATAL_FAILURE(initialize_backend());
	falco_reload_control control;
	ASSERT_NO_THROW(control.start(m_path));
	struct stat before = {}, after = {};
	ASSERT_EQ(::lstat(m_path.c_str(), &before), 0);
	const auto descriptors = open_fd_count();
	for(int i = 0; i < 3; ++i) {
		ASSERT_NO_THROW(falco_reload_control::validate_socket_directory(m_path));
		EXPECT_EQ(open_fd_count(), descriptors);
	}
	ASSERT_EQ(::lstat(m_path.c_str(), &after), 0);
	EXPECT_EQ(after.st_dev, before.st_dev);
	EXPECT_EQ(after.st_ino, before.st_ino);
	falco_reload_control competing;
	EXPECT_THROW(competing.start(m_path), falco_exception);
	auto response = make_client(m_path)->Get("/reload");
	ASSERT_TRUE(response) << httplib::to_string(response.error());
	EXPECT_EQ(response->status, 200);
}

TEST_F(ReloadControlTest, socket_permissions_and_group_follow_the_private_directory) {
	ASSERT_NO_FATAL_FAILURE(initialize_backend());
	ASSERT_EQ(::chmod(m_directory.c_str(), 0750), 0);
	// Exercise a different parent group whenever the current credentials permit it.
	const auto count = ::getgroups(0, nullptr);
	ASSERT_GE(count, 0);
	std::vector<gid_t> groups(count);
	ASSERT_EQ(::getgroups(count, groups.data()), count);
	auto directory_group = ::getegid();
	if(::geteuid() == 0) {
		directory_group = directory_group == 0 ? 1 : 0;
	} else {
		for(const auto group : groups) {
			if(group != directory_group) {
				directory_group = group;
				break;
			}
		}
	}
	ASSERT_EQ(::chown(m_directory.c_str(), static_cast<uid_t>(-1), directory_group), 0);
	falco_reload_control control;
	ASSERT_NO_THROW(control.start(m_path));
	struct stat status = {};
	ASSERT_EQ(::lstat(m_path.c_str(), &status), 0);
	EXPECT_TRUE(S_ISSOCK(status.st_mode));
	EXPECT_EQ(status.st_mode & 0777, 0660);
	EXPECT_EQ(status.st_uid, ::geteuid());
	EXPECT_EQ(status.st_gid, directory_group);
	auto client = make_client(m_path);
	auto response = client->Get("/reload");
	ASSERT_TRUE(response) << httplib::to_string(response.error());
	EXPECT_EQ(response->status, 200);
}

TEST_F(ReloadControlTest, stop_removes_the_socket_and_restart_releases_descriptors) {
	ASSERT_NO_FATAL_FAILURE(initialize_backend());
	const auto before = open_fd_count();
	{
		falco_reload_control control;
		for(int i = 0; i < 3; ++i) {
			ASSERT_NO_THROW(control.start(m_path));
			{
				auto client = make_client(m_path);
				auto response = client->Get("/reload");
				ASSERT_TRUE(response) << httplib::to_string(response.error());
				EXPECT_EQ(response->status, 200);
			}
			ASSERT_NO_THROW(control.stop());
			EXPECT_FALSE(std::filesystem::exists(m_path));
			ASSERT_NO_THROW(control.stop());
		}
	}
	EXPECT_EQ(open_fd_count(), before);
}

TEST_F(ReloadControlTest, another_listener_cannot_take_over_the_same_directory) {
	ASSERT_NO_FATAL_FAILURE(initialize_backend());
	falco_reload_control first;
	falco_reload_control second;
	ASSERT_NO_THROW(first.start(m_path));
	const auto other_path = m_directory + "/other.sock";
	EXPECT_THROW(second.start(m_path), falco_exception);
	EXPECT_THROW(second.start(other_path), falco_exception);
	EXPECT_FALSE(std::filesystem::exists(other_path));
	ASSERT_NO_THROW(second.stop());
	{
		auto client = make_client(m_path);
		auto response = client->Get("/reload");
		ASSERT_TRUE(response) << httplib::to_string(response.error());
		EXPECT_EQ(response->status, 200);
	}
	ASSERT_NO_THROW(first.stop());
	ASSERT_NO_THROW(second.start(m_path));
	auto client = make_client(m_path);
	auto response = client->Get("/reload");
	ASSERT_TRUE(response) << httplib::to_string(response.error());
	EXPECT_EQ(response->status, 200);
}

TEST_F(ReloadControlTest, an_owned_stale_socket_can_be_replaced) {
	ASSERT_NO_FATAL_FAILURE(initialize_backend());
	ASSERT_NO_FATAL_FAILURE(bind_stale_socket(m_path));
	falco_reload_control control;
	ASSERT_NO_THROW(control.start(m_path));
	auto client = make_client(m_path);
	auto response = client->Get("/reload");
	ASSERT_TRUE(response) << httplib::to_string(response.error());
	EXPECT_EQ(response->status, 200);
}

TEST_F(ReloadControlTest, an_active_socket_without_the_directory_lock_is_preserved) {
	ASSERT_NO_FATAL_FAILURE(initialize_backend());
	scoped_fd listener(::socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0));
	ASSERT_GE(listener.get(), 0) << std::strerror(errno);
	sockaddr_un address = {};
	address.sun_family = AF_UNIX;
	std::memcpy(address.sun_path, m_path.c_str(), m_path.size() + 1);
	ASSERT_EQ(::bind(listener.get(), reinterpret_cast<const sockaddr*>(&address), sizeof(address)),
	          0);
	ASSERT_EQ(::listen(listener.get(), 4), 0);
	struct stat original = {};
	ASSERT_EQ(::lstat(m_path.c_str(), &original), 0);
	falco_reload_control control;
	EXPECT_THROW(control.start(m_path), falco_exception);
	struct stat after = {};
	ASSERT_EQ(::lstat(m_path.c_str(), &after), 0);
	EXPECT_EQ(after.st_dev, original.st_dev);
	EXPECT_EQ(after.st_ino, original.st_ino);
	scoped_fd client(::socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0));
	ASSERT_GE(client.get(), 0) << std::strerror(errno);
	EXPECT_EQ(::connect(client.get(), reinterpret_cast<const sockaddr*>(&address), sizeof(address)),
	          0);
}

TEST_F(ReloadControlTest, regular_files_and_symlink_leaves_are_preserved) {
	ASSERT_NO_FATAL_FAILURE(initialize_backend());
	{
		std::ofstream file(m_path);
		file << "preserve this file";
		ASSERT_TRUE(file.good());
	}
	falco_reload_control control;
	EXPECT_THROW(control.start(m_path), falco_exception);
	ASSERT_TRUE(std::filesystem::is_regular_file(m_path));
	{
		std::ifstream file(m_path);
		std::string content;
		std::getline(file, content);
		EXPECT_EQ(content, "preserve this file");
	}
	const auto link = m_directory + "/linked.sock";
	ASSERT_EQ(::symlink(m_path.c_str(), link.c_str()), 0);
	EXPECT_THROW(control.start(link), falco_exception);
	struct stat status = {};
	ASSERT_EQ(::lstat(link.c_str(), &status), 0);
	EXPECT_TRUE(S_ISLNK(status.st_mode));
	EXPECT_TRUE(std::filesystem::is_regular_file(m_path));
}

TEST_F(ReloadControlTest, symlinked_directories_are_rejected) {
	ASSERT_NO_FATAL_FAILURE(initialize_backend());
	const auto directory = m_directory + "/real";
	const auto link = m_directory + "/alias";
	ASSERT_EQ(::mkdir(directory.c_str(), 0700), 0);
	ASSERT_EQ(::symlink(directory.c_str(), link.c_str()), 0);
	falco_reload_control control;
	EXPECT_THROW(falco_reload_control::validate_socket_directory(link + "/control.sock"),
	             falco_exception);
	EXPECT_THROW(control.start(link + "/control.sock"), falco_exception);
	EXPECT_FALSE(std::filesystem::exists(directory + "/control.sock"));
	EXPECT_TRUE(std::filesystem::is_symlink(link));
}

TEST_F(ReloadControlTest, relative_paths_and_missing_parent_directories_are_rejected) {
	ASSERT_NO_FATAL_FAILURE(initialize_backend());
	falco_reload_control control;
	EXPECT_THROW(falco_reload_control::validate_socket_directory("control.sock"), falco_exception);
	EXPECT_THROW(control.start("control.sock"), falco_exception);
	const auto missing = m_directory + "/missing";
	EXPECT_THROW(falco_reload_control::validate_socket_directory(missing + "/control.sock"),
	             falco_exception);
	EXPECT_THROW(control.start(missing + "/control.sock"), falco_exception);
	EXPECT_FALSE(std::filesystem::exists(missing));
}

TEST_F(ReloadControlTest, embedded_nul_dot_components_and_overlong_paths_are_rejected) {
	ASSERT_NO_FATAL_FAILURE(initialize_backend());
	const auto child = m_directory + "/child";
	ASSERT_EQ(::mkdir(child.c_str(), 0700), 0);
	auto embedded_nul = m_path;
	embedded_nul.push_back('\0');
	embedded_nul += "suffix";
	const std::vector<std::string> paths = {
	        embedded_nul,
	        m_directory + "/./control.sock",
	        child + "/../control.sock",
	        m_directory + "/" + std::string(sizeof(sockaddr_un::sun_path), 'x')};
	for(const auto& path : paths) {
		SCOPED_TRACE(path);
		falco_reload_control control;
		EXPECT_THROW(falco_reload_control::validate_socket_directory(path), falco_exception);
		EXPECT_THROW(control.start(path), falco_exception);
		EXPECT_FALSE(std::filesystem::exists(m_path));
	}
}

TEST_F(ReloadControlTest, unsafe_parent_permissions_and_writable_ancestors_are_rejected) {
	ASSERT_NO_FATAL_FAILURE(initialize_backend());
	for(const auto mode : {0770, 0701, 0755, 01777}) {
		SCOPED_TRACE(mode);
		ASSERT_EQ(::chmod(m_directory.c_str(), mode), 0);
		falco_reload_control control;
		EXPECT_THROW(falco_reload_control::validate_socket_directory(m_path), falco_exception);
		EXPECT_THROW(control.start(m_path), falco_exception);
		EXPECT_FALSE(std::filesystem::exists(m_path));
	}
	const auto nested = m_directory + "/private";
	ASSERT_EQ(::mkdir(nested.c_str(), 0700), 0);
	for(const auto mode : {0770, 0777}) {
		SCOPED_TRACE(mode);
		ASSERT_EQ(::chmod(m_directory.c_str(), mode), 0);
		falco_reload_control control;
		EXPECT_THROW(falco_reload_control::validate_socket_directory(nested + "/control.sock"),
		             falco_exception);
		EXPECT_THROW(control.start(nested + "/control.sock"), falco_exception);
		EXPECT_FALSE(std::filesystem::exists(nested + "/control.sock"));
	}
}

TEST_F(ReloadControlTest, extended_directory_access_acls_are_rejected) {
	ASSERT_NO_FATAL_FAILURE(initialize_backend());
	const auto* attribute = "system.posix_acl_access";
	const auto result = install_extended_acl(m_directory, attribute);
	const auto error = errno;
	if(result != 0 && error == ENOTSUP) {
		GTEST_SKIP() << "filesystem does not support POSIX ACLs";
	}
	ASSERT_EQ(result, 0) << std::strerror(error);
	ASSERT_GT(::getxattr(m_directory.c_str(), attribute, nullptr, 0), 0);
	struct stat directory = {};
	ASSERT_EQ(::stat(m_directory.c_str(), &directory), 0);
	ASSERT_EQ(directory.st_mode & 0777, 0750);
	falco_reload_control control;
	EXPECT_THROW(falco_reload_control::validate_socket_directory(m_path), falco_exception);
	EXPECT_THROW(control.start(m_path), falco_exception);
	EXPECT_FALSE(std::filesystem::exists(m_path));
	ASSERT_EQ(::removexattr(m_directory.c_str(), attribute), 0);
	ASSERT_NO_THROW(control.start(m_path));
}

TEST_F(ReloadControlTest, inherited_directory_default_acls_are_rejected) {
	ASSERT_NO_FATAL_FAILURE(initialize_backend());
	const auto* attribute = "system.posix_acl_default";
	const auto result = install_extended_acl(m_directory, attribute);
	const auto error = errno;
	if(result != 0 && error == ENOTSUP) {
		GTEST_SKIP() << "filesystem does not support POSIX ACLs";
	}
	ASSERT_EQ(result, 0) << std::strerror(error);
	ASSERT_GT(::getxattr(m_directory.c_str(), attribute, nullptr, 0), 0);
	struct stat directory = {};
	ASSERT_EQ(::stat(m_directory.c_str(), &directory), 0);
	ASSERT_EQ(directory.st_mode & 0777, 0700);
	falco_reload_control control;
	EXPECT_THROW(falco_reload_control::validate_socket_directory(m_path), falco_exception);
	EXPECT_THROW(control.start(m_path), falco_exception);
	EXPECT_FALSE(std::filesystem::exists(m_path));
	ASSERT_EQ(::removexattr(m_directory.c_str(), attribute), 0);
	ASSERT_NO_THROW(control.start(m_path));
}

TEST_F(ReloadControlTest, directories_and_stale_sockets_owned_by_another_user_are_preserved) {
	if(::geteuid() != 0) {
		GTEST_SKIP() << "creating paths owned by another user requires root";
	}
	ASSERT_NO_FATAL_FAILURE(initialize_backend());
	falco_reload_control control;
	ASSERT_EQ(::chown(m_directory.c_str(), 1, static_cast<gid_t>(-1)), 0);
	EXPECT_THROW(falco_reload_control::validate_socket_directory(m_path), falco_exception);
	EXPECT_THROW(control.start(m_path), falco_exception);
	EXPECT_FALSE(std::filesystem::exists(m_path));
	ASSERT_EQ(::chown(m_directory.c_str(), ::geteuid(), static_cast<gid_t>(-1)), 0);

	ASSERT_NO_FATAL_FAILURE(bind_stale_socket(m_path));
	ASSERT_EQ(::chown(m_path.c_str(), 1, static_cast<gid_t>(-1)), 0);
	struct stat original = {};
	ASSERT_EQ(::lstat(m_path.c_str(), &original), 0);
	EXPECT_THROW(control.start(m_path), falco_exception);
	struct stat after = {};
	ASSERT_EQ(::lstat(m_path.c_str(), &after), 0);
	EXPECT_EQ(after.st_uid, original.st_uid);
	EXPECT_EQ(after.st_dev, original.st_dev);
	EXPECT_EQ(after.st_ino, original.st_ino);
}

TEST_F(ReloadControlTest, stop_preserves_a_socket_replacing_its_original_path) {
	ASSERT_NO_FATAL_FAILURE(initialize_backend());
	falco_reload_control control;
	ASSERT_NO_THROW(control.start(m_path));
	const auto original = m_directory + "/retired.sock";
	ASSERT_EQ(::rename(m_path.c_str(), original.c_str()), 0);
	ASSERT_NO_FATAL_FAILURE(bind_stale_socket(m_path));
	struct stat replacement = {};
	ASSERT_EQ(::lstat(m_path.c_str(), &replacement), 0);

	ASSERT_NO_THROW(control.stop());
	struct stat after = {};
	ASSERT_EQ(::lstat(m_path.c_str(), &after), 0);
	EXPECT_TRUE(S_ISSOCK(after.st_mode));
	EXPECT_EQ(after.st_dev, replacement.st_dev);
	EXPECT_EQ(after.st_ino, replacement.st_ino);
}
