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

#include "reload_control.h"
#include "app/reload_state.h"
#include "app/signals.h"
#include "falco_common.h"
#include "logger.h"

#include <httplib.h>
#include <nlohmann/json.hpp>

#include <cerrno>
#include <cstring>
#include <filesystem>
#include <system_error>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/xattr.h>
#include <unistd.h>

namespace {

[[noreturn]] void fail(const std::string& reason) {
	throw falco_exception("reload_control: " + reason);
}

[[noreturn]] void fail_errno(const std::string& reason) {
	const auto error = errno;
	fail(reason + ": " + std::system_category().message(error));
}

bool same_socket(const struct stat& first, const struct stat& second) {
	return S_ISSOCK(second.st_mode) && first.st_dev == second.st_dev &&
	       first.st_ino == second.st_ino;
}

void remove_stale_socket(int directory_fd, const std::string& name, const std::string& path) {
	struct stat before {};
	if(fstatat(directory_fd, name.c_str(), &before, AT_SYMLINK_NOFOLLOW) != 0) {
		if(errno == ENOENT) {
			return;
		}
		fail_errno("cannot inspect existing socket");
	}
	if(!S_ISSOCK(before.st_mode) || before.st_uid != geteuid()) {
		fail("existing path is not a socket owned by Falco");
	}
	const int probe = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
	if(probe < 0) {
		fail_errno("cannot inspect existing listener");
	}
	sockaddr_un address{};
	address.sun_family = AF_UNIX;
	std::memcpy(address.sun_path, path.c_str(), path.size() + 1);
	const int result = connect(probe, reinterpret_cast<sockaddr*>(&address), sizeof(address));
	const int error = errno;
	close(probe);
	// A live listener or an indeterminate connection must never be unlinked.
	if(result == 0 || error != ECONNREFUSED) {
		fail("existing socket may have an active listener");
	}
	struct stat current {};
	if(fstatat(directory_fd, name.c_str(), &current, AT_SYMLINK_NOFOLLOW) != 0 ||
	   !same_socket(before, current)) {
		fail("socket changed while checking the existing listener");
	}
	if(unlinkat(directory_fd, name.c_str(), 0) != 0) {
		fail_errno("cannot remove stale socket");
	}
}

void check_directory(int fd, bool leaf) {
	struct stat info {};
	if(fstat(fd, &info) != 0) {
		fail_errno("cannot inspect socket directory");
	}
	if(leaf) {
		if(info.st_uid != geteuid() || (info.st_mode & (S_IWGRP | S_IRWXO)) != 0) {
			fail("socket directory must be owned by Falco, without group write or other access");
		}
		// Mode bits alone do not exclude named ACL users or inherited socket ACLs.
		for(const auto* attribute : {"system.posix_acl_access", "system.posix_acl_default"}) {
			if(fgetxattr(fd, attribute, nullptr, 0) >= 0) {
				fail("socket directory must not have extended or default POSIX ACLs");
			}
			if(errno != ENODATA && errno != ENOTSUP) {
				fail_errno("cannot inspect socket directory ACLs");
			}
		}
	} else if((info.st_uid != 0 && info.st_uid != geteuid()) ||
	          ((info.st_mode & (S_IWGRP | S_IWOTH)) != 0 &&
	           !(info.st_uid == 0 && (info.st_mode & S_ISVTX) != 0))) {
		// Root-owned sticky directories such as /tmp cannot be used to rename
		// Falco's child directory by another unprivileged UID.
		fail("socket directory has an untrusted writable ancestor");
	}
	if(faccessat(fd, ".", leaf ? W_OK | X_OK : X_OK, AT_EACCESS) != 0) {
		fail_errno("socket directory is not accessible to Falco");
	}
}

// The caller owns the returned descriptor. All failures close the current
// directory, including exceptions raised while walking the filesystem path.
int open_socket_directory(const std::string& socket_path) {
	const std::filesystem::path path(socket_path);
	if(!path.is_absolute() || path != path.lexically_normal() || path.filename().empty() ||
	   socket_path.find('\0') != std::string::npos ||
	   socket_path.size() >= sizeof(sockaddr_un::sun_path)) {
		fail("socket must be an absolute normalized path shorter than sun_path");
	}
	int fd = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if(fd < 0) {
		fail_errno("cannot open root directory");
	}
	try {
		for(const auto& component : path.parent_path().relative_path()) {
			check_directory(fd, false);
			const int next =
			        openat(fd, component.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
			if(next < 0) {
				fail_errno("cannot open socket directory");
			}
			close(fd);
			fd = next;
		}
		check_directory(fd, true);
		return fd;
	} catch(...) {
		close(fd);
		throw;
	}
}

}  // namespace

class falco_reload_control::server : public httplib::Server {
public:
	void prepare_shutdown() {
		m_accept_fd = svr_sock_.load();
		m_shutdown_fd = fcntl(m_accept_fd, F_DUPFD_CLOEXEC, 0);
		if(m_shutdown_fd < 0) {
			fail_errno("cannot retain listener for shutdown");
		}
	}

	void stop() {
		// httplib owns its accept descriptor and can close it on an accept error.
		// Shut down the independently owned duplicate, never a possibly reused fd.
		if(m_shutdown_fd >= 0) {
			// Let queued connections observe shutdown without waiting for keep-alive.
			svr_sock_.store(INVALID_SOCKET);
			shutdown(m_shutdown_fd, SHUT_RDWR);
		}
	}

	~server() override {
		// The owner has joined the listener before destruction. Also close a
		// bound-but-not-started listener on startup failure. httplib may leave
		// its closed accept fd's numeric value behind; the duplicate pins the
		// socket inode so a reused descriptor can never pass this identity check.
		const auto current = svr_sock_.exchange(INVALID_SOCKET);
		const auto fd = m_accept_fd >= 0 ? m_accept_fd : current;
		if(fd != INVALID_SOCKET) {
			struct stat original {};
			struct stat retained {};
			if(m_shutdown_fd < 0 ||
			   (fstat(fd, &original) == 0 && fstat(m_shutdown_fd, &retained) == 0 &&
			    same_socket(original, retained))) {
				close(fd);
			}
		}
		if(m_shutdown_fd >= 0) {
			close(m_shutdown_fd);
		}
	}

private:
	int m_accept_fd = -1;
	int m_shutdown_fd = -1;
};

falco_reload_control::falco_reload_control() = default;

falco_reload_control::~falco_reload_control() {
	stop();
}

void falco_reload_control::validate_socket_directory(const std::string& socket_path) {
	close(open_socket_directory(socket_path));
}

void falco_reload_control::start(const std::string& socket_path) {
	if(m_directory_fd >= 0) {
		fail("listener is already started");
	}
	if(falco::app::restart_signal_fd() < 0) {
		fail("reload request handling is not initialized");
	}
	m_name = std::filesystem::path(socket_path).filename().string();
	try {
		m_directory_fd = open_socket_directory(socket_path);
		// One listener per dedicated directory. Keep the lock through join and
		// unlink; unlike a lock file, the directory is never replaced by cleanup.
		if(flock(m_directory_fd, LOCK_EX | LOCK_NB) != 0) {
			fail_errno("socket directory is already in use");
		}
		struct stat directory {};
		if(fstat(m_directory_fd, &directory) != 0) {
			fail_errno("cannot inspect socket directory");
		}
		const auto anchored = "/proc/self/fd/" + std::to_string(m_directory_fd) + "/" + m_name;
		if(anchored.size() >= sizeof(sockaddr_un::sun_path)) {
			fail("socket filename is too long");
		}
		remove_stale_socket(m_directory_fd, m_name, anchored);

		m_server = std::make_unique<server>();
		m_server->set_address_family(AF_UNIX);
		m_server->set_read_timeout(1);
		m_server->set_write_timeout(1);
		m_server->set_keep_alive_max_count(1);
		m_server->set_payload_max_length(1024);
		m_server->new_task_queue = [] { return new httplib::ThreadPool(2, 16); };
		m_server->Get("/reload", [](const httplib::Request&, httplib::Response& res) {
			const auto status = falco::app::g_reload_state.get();
			nlohmann::json body = {{"instance_id", status.instance_id},
			                       {"started_generation", status.started_generation},
			                       {"applied_generation", status.applied_generation},
			                       {"rejected_generation", status.rejected_generation},
			                       {"ready", status.ready}};
			res.set_header("Cache-Control", "no-store");
			res.set_content(body.dump(), "application/json");
		});
		m_server->Post("/reload", [](const httplib::Request& req, httplib::Response& res) {
			res.set_header("Cache-Control", "no-store");
			// Multipart content is stored in req.form, leaving req.body empty.
			if(!req.body.empty() || req.is_multipart_form_data() ||
			   req.target.find('?') != std::string::npos) {
				res.status = 400;
				res.set_content("reload requests do not accept a body or query\n", "text/plain");
				return;
			}
			// Capture before publishing the request, as a worker can begin reading
			// immediately. Finish allocating the response before queuing work.
			const auto baseline = falco::app::g_reload_state.get();
			nlohmann::json body = {{"instance_id", baseline.instance_id},
			                       {"started_generation", baseline.started_generation}};
			res.set_content(body.dump(), "application/json");
			res.set_header("Location", "/reload");
			res.status = 202;
			if(!falco::app::request_reload()) {
				res.status = 503;
				res.set_content("reload notification unavailable\n", "text/plain");
			}
		});
		// AF_UNIX ignores this port; zero would request Internet port discovery.
		if(!m_server->bind_to_port(anchored, 80)) {
			fail_errno("cannot bind socket");
		}
		struct stat bound {};
		if(fstatat(m_directory_fd, m_name.c_str(), &bound, AT_SYMLINK_NOFOLLOW) != 0 ||
		   !S_ISSOCK(bound.st_mode)) {
			fail("cannot identify bound socket");
		}
		m_device = bound.st_dev;
		m_inode = bound.st_ino;
		m_owns_socket = true;
		if(fchownat(m_directory_fd, m_name.c_str(), -1, directory.st_gid, AT_SYMLINK_NOFOLLOW) !=
		           0 ||
		   fchmodat(m_directory_fd, m_name.c_str(), 0660, 0) != 0) {
			fail_errno("cannot set socket ownership and permissions");
		}
		m_server->prepare_shutdown();
		m_failed.store(false, std::memory_order_release);
		m_thread = std::thread([this] {
			try {
				m_server->listen_after_bind();
			} catch(const std::exception& e) {
				falco_logger::log(falco_logger::level::ERR,
				                  "reload_control: " + std::string(e.what()) + "\n");
			}
			m_failed.store(true, std::memory_order_release);
		});
		while(!m_server->is_running() && !m_failed.load(std::memory_order_acquire)) {
			std::this_thread::yield();
		}
		if(m_failed.load(std::memory_order_acquire)) {
			fail("could not start listener");
		}
	} catch(...) {
		stop();
		throw;
	}
}

void falco_reload_control::stop() {
	if(m_server) {
		m_server->stop();
	}
	if(m_thread.joinable()) {
		m_thread.join();
	}
	m_server.reset();
	if(m_owns_socket) {
		struct stat current {};
		if(fstatat(m_directory_fd, m_name.c_str(), &current, AT_SYMLINK_NOFOLLOW) == 0 &&
		   S_ISSOCK(current.st_mode) && current.st_dev == m_device && current.st_ino == m_inode) {
			unlinkat(m_directory_fd, m_name.c_str(), 0);
		}
		m_owns_socket = false;
	}
	if(m_directory_fd >= 0) {
		close(m_directory_fd);
		m_directory_fd = -1;
	}
}
