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

#include <gtest/gtest.h>

#include "falco/app/state.h"
#include "falco/falco_metrics.h"

#include <atomic>
#include <string>
#include <thread>

namespace {

void register_source(falco::app::state& state,
                     const std::string& name,
                     uint64_t initial_evts,
                     bool enabled) {
	falco::app::state::source_info info;
	info.inspector = std::make_shared<sinsp>();
	info.num_evts->store(initial_evts, std::memory_order_relaxed);
	state.source_infos.insert(info, name);
	state.loaded_sources.push_back(name);
	if(enabled) {
		state.enabled_sources.insert(name);
	}
}

}  // namespace

TEST(falco_metrics, exposes_num_evts_per_enabled_source) {
	falco::app::state state;
	register_source(state, "syscall", 1234, true);
	register_source(state, "k8s_audit", 56, true);
	register_source(state, "disabled_src", 999, false);

	const std::string out = falco_metrics::to_text_prometheus(state);

	EXPECT_NE(
	        out.find("# HELP falcosecurity_falco_num_evts_total https://falco.org/docs/metrics/\n"),
	        std::string::npos);
	EXPECT_NE(out.find("# TYPE falcosecurity_falco_num_evts_total counter\n"), std::string::npos);
	EXPECT_NE(out.find("falcosecurity_falco_num_evts_total{source=\"syscall\"} 1234\n"),
	          std::string::npos);
	EXPECT_NE(out.find("falcosecurity_falco_num_evts_total{source=\"k8s_audit\"} 56\n"),
	          std::string::npos);
	EXPECT_EQ(out.find("disabled_src"), std::string::npos);
}

TEST(falco_metrics, num_evts_reflects_live_atomic_updates) {
	falco::app::state state;
	register_source(state, "syscall", 0, true);

	const std::string initial = falco_metrics::to_text_prometheus(state);
	EXPECT_NE(initial.find("falcosecurity_falco_num_evts_total{source=\"syscall\"} 0\n"),
	          std::string::npos);

	auto counter = state.source_infos.at("syscall")->num_evts;
	std::atomic<bool> done{false};
	std::thread writer([&]() {
		for(uint64_t i = 1; i <= 5000; ++i) {
			counter->store(i, std::memory_order_relaxed);
		}
		done.store(true, std::memory_order_release);
	});

	while(!done.load(std::memory_order_acquire)) {
		const std::string mid = falco_metrics::to_text_prometheus(state);
		EXPECT_NE(mid.find("falcosecurity_falco_num_evts_total{source=\"syscall\"} "),
		          std::string::npos);
	}
	writer.join();

	const std::string final_out = falco_metrics::to_text_prometheus(state);
	EXPECT_NE(final_out.find("falcosecurity_falco_num_evts_total{source=\"syscall\"} 5000\n"),
	          std::string::npos);
}
