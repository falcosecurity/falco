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
#pragma once

#include <atomic>
#include <cstdint>
#include <memory>
#include <string>
#include <thread>

// Linux administrative HTTP listener. The owning application thread starts and
// stops it; request handlers access only process-owned reload state.
class falco_reload_control {
public:
	falco_reload_control();
	~falco_reload_control();
	falco_reload_control(const falco_reload_control&) = delete;
	falco_reload_control& operator=(const falco_reload_control&) = delete;
	// Read-only preflight. Does not lock the directory or touch an existing socket;
	// start() repeats these checks because the filesystem can change afterward.
	static void validate_socket_directory(const std::string& socket_path);
	void start(const std::string& socket_path);
	void stop();

private:
	class server;
	std::unique_ptr<server> m_server;
	std::thread m_thread;
	std::atomic<bool> m_failed{false};
	int m_directory_fd = -1;
	std::string m_name;
	uint64_t m_device = 0;
	uint64_t m_inode = 0;
	bool m_owns_socket = false;
};
