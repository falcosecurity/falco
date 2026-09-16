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

#include <cstdio>
#include <stdexcept>
#include <string>
#include <unistd.h>

namespace falco::test {

// Runtime checks throw so scoped resources are released on failure.
inline void require(bool condition, const std::string& message) {
	if(!condition) {
		throw std::runtime_error(message);
	}
}

// Child assertions must exit unsuccessfully so EXPECT_EXIT observes their failure.
inline void require_in_child(bool condition, const std::string& message) {
	if(!condition) {
		std::fprintf(stderr, "%s\n", message.c_str());
		_exit(1);
	}
}

class scoped_fd {
public:
	explicit scoped_fd(int fd): m_fd(fd) {}
	~scoped_fd() {
		if(m_fd >= 0) {
			::close(m_fd);
		}
	}
	scoped_fd(const scoped_fd&) = delete;
	scoped_fd& operator=(const scoped_fd&) = delete;
	int get() const { return m_fd; }

private:
	int m_fd;
};

}  // namespace falco::test
