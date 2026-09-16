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

void falco::app::reload_state::begin_run() {
	std::lock_guard<std::mutex> lock(m_mutex);
	m_covered.store(requested(), std::memory_order_release);
}

falco::app::reload_state::check falco::app::reload_state::begin_check() {
	std::lock_guard<std::mutex> lock(m_mutex);
	return {requested()};
}

void falco::app::reload_state::rejected(const check& attempt) {
	std::lock_guard<std::mutex> lock(m_mutex);
	m_covered.store(std::max(covered(), attempt.requests), std::memory_order_release);
}
