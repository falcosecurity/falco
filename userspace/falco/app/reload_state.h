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
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <string>

namespace falco::app {

// Process-owned reload requests and observations. Unlike app::state, this object
// survives hot restarts. Signal delivery, validation and application are distinct.
class reload_state {
public:
	struct snapshot {
		std::string instance_id;
		uint64_t started_generation = 0;
		uint64_t applied_generation = 0;
		uint64_t rejected_generation = 0;
		bool ready = false;
	};

	struct check {
		uint64_t generation;
		uint64_t requests;
	};

	void initialize();
	bool is_lock_free() const { return m_requested.is_lock_free(); }
	// Only this operation is called from the OS signal handler.
	void request() noexcept { m_requested.fetch_add(1, std::memory_order_release); }
	uint64_t requested() const { return m_requested.load(std::memory_order_acquire); }
	uint64_t covered() const { return m_covered.load(std::memory_order_acquire); }

	// Call before reading any configuration. Standalone/dry-run app invocations
	// must not change the live runtime; supervised validation uses begin_check().
	void begin_run();
	check begin_check();
	void rejected(const check& attempt);
	void expect_sources(size_t count);
	void source_started();
	void stop();
	snapshot get() const;

private:
	std::atomic<uint64_t> m_requested{0};
	// Requests owned by the current runtime's load, or a rejected validation.
	// This is not an acknowledgment of successful application.
	std::atomic<uint64_t> m_covered{0};
	mutable std::mutex m_mutex;
	snapshot m_snapshot;
	uint64_t m_run_generation = 0;
	size_t m_expected_sources = 0;
	size_t m_started_sources = 0;
	bool m_stopped = true;
};

extern reload_state& g_reload_state;

}  // namespace falco::app
