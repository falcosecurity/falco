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

#include "reload_state.h"

#include <algorithm>
#include <iomanip>
#include <random>
#include <sstream>

void falco::app::reload_state::initialize() {
	std::lock_guard<std::mutex> lock(m_mutex);
	if(m_snapshot.instance_id.empty()) {
		std::random_device random;
		std::ostringstream id;
		for(int i = 0; i < 4; ++i) {
			id << std::hex << std::setfill('0') << std::setw(8) << static_cast<uint32_t>(random());
		}
		m_snapshot.instance_id = id.str();
	}
}

void falco::app::reload_state::begin_run() {
	std::lock_guard<std::mutex> lock(m_mutex);
	m_run_generation = ++m_snapshot.started_generation;
	m_covered.store(requested(), std::memory_order_release);
	m_snapshot.ready = false;
	m_expected_sources = 0;
	m_started_sources = 0;
	m_stopped = false;
}

falco::app::reload_state::check falco::app::reload_state::begin_check() {
	std::lock_guard<std::mutex> lock(m_mutex);
	return {++m_snapshot.started_generation, requested()};
}

void falco::app::reload_state::rejected(const check& attempt) {
	std::lock_guard<std::mutex> lock(m_mutex);
	m_snapshot.rejected_generation = std::max(m_snapshot.rejected_generation, attempt.generation);
	m_covered.store(std::max(covered(), attempt.requests), std::memory_order_release);
}

void falco::app::reload_state::expect_sources(size_t count) {
	std::lock_guard<std::mutex> lock(m_mutex);
	m_expected_sources = count;
}

void falco::app::reload_state::source_started() {
	std::lock_guard<std::mutex> lock(m_mutex);
	++m_started_sources;
	if(!m_stopped && m_expected_sources != 0 && m_started_sources == m_expected_sources) {
		m_snapshot.applied_generation = m_run_generation;
		m_snapshot.ready = true;
	}
}

void falco::app::reload_state::stop() {
	std::lock_guard<std::mutex> lock(m_mutex);
	m_stopped = true;
	m_snapshot.ready = false;
}

falco::app::reload_state::snapshot falco::app::reload_state::get() const {
	std::lock_guard<std::mutex> lock(m_mutex);
	return m_snapshot;
}
