// SPDX-License-Identifier: Apache-2.0
/* Copyright (C) 2026 The Falco Authors. */

#include <gtest/gtest.h>

#include "falco/app/state.h"

#include <atomic>
#include <thread>

TEST(metrics_snapshot, copies_are_synchronized_between_writer_and_readers) {
	falco::app::state::source_info info;
	auto first = libs::metrics::libsinsp_metrics::new_metric("first",
	                                                         METRICS_V2_MISC,
	                                                         METRIC_VALUE_TYPE_U64,
	                                                         METRIC_VALUE_UNIT_COUNT,
	                                                         METRIC_VALUE_METRIC_TYPE_MONOTONIC,
	                                                         uint64_t{1});
	auto second = first;
	strlcpy(second.name, "second", sizeof(second.name));
	second.value.u64 = 2;

	std::atomic<bool> done{false};
	std::thread writer([&]() {
		for(size_t i = 0; i < 10000; ++i) {
			info.set_metrics_snapshot(i % 2 == 0 ? std::vector<metrics_v2>{first}
			                                     : std::vector<metrics_v2>{second});
		}
		done.store(true);
	});

	while(!done.load()) {
		auto snapshot = info.get_metrics_snapshot();
		if(!snapshot.empty()) {
			ASSERT_EQ(snapshot.size(), 1u);
			EXPECT_TRUE(snapshot[0].value.u64 == 1 || snapshot[0].value.u64 == 2);
		}
	}
	writer.join();
}
