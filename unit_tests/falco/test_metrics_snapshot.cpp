// SPDX-License-Identifier: Apache-2.0
/* Copyright (C) 2026 The Falco Authors. */

#include <gtest/gtest.h>

#include "falco/app/metrics_snapshot.h"
#include "falco/app/state.h"

#include <atomic>
#include <chrono>
#include <thread>

namespace {

metrics_v2 metric_with_value(uint64_t value) {
	return libs::metrics::libsinsp_metrics::new_metric("snapshot_seq",
	                                                   METRICS_V2_MISC,
	                                                   METRIC_VALUE_TYPE_U64,
	                                                   METRIC_VALUE_UNIT_COUNT,
	                                                   METRIC_VALUE_METRIC_TYPE_MONOTONIC,
	                                                   value);
}

}  // namespace

TEST(metrics_snapshot, collection_requires_live_metrics_and_webserver) {
	falco_configuration config;
	config.m_metrics_enabled = true;
	config.m_webserver_enabled = true;
	config.m_webserver_config.m_prometheus_metrics_enabled = true;

	EXPECT_TRUE(falco::app::prometheus_metrics_collection_enabled(config, false));
	EXPECT_FALSE(falco::app::prometheus_metrics_collection_enabled(config, true));

	config.m_metrics_enabled = false;
	EXPECT_FALSE(falco::app::prometheus_metrics_collection_enabled(config, false));
	config.m_metrics_enabled = true;

	config.m_webserver_enabled = false;
	EXPECT_FALSE(falco::app::prometheus_metrics_collection_enabled(config, false));
	config.m_webserver_enabled = true;

	config.m_webserver_config.m_prometheus_metrics_enabled = false;
	EXPECT_FALSE(falco::app::prometheus_metrics_collection_enabled(config, false));
}

TEST(metrics_snapshot, refreshes_on_bounded_steady_clock_cadence) {
	using namespace std::chrono_literals;
	using refresh = falco::app::prometheus_metrics_refresh;

	EXPECT_EQ(falco::app::prometheus_metrics_refresh_interval, 1s);

	refresh schedule(100ms);
	const refresh::time_point start{};
	int snapshots = 0;
	auto snapshot = [&]() { ++snapshots; };

	schedule.initialize(snapshot, start);
	EXPECT_EQ(snapshots, 1);

	EXPECT_FALSE(schedule.refresh_if_due(SCAP_TIMEOUT, snapshot, start + 99ms));
	EXPECT_FALSE(schedule.refresh_if_due(SCAP_EOF, snapshot, start + 100ms));
	EXPECT_TRUE(schedule.refresh_if_due(SCAP_TIMEOUT, snapshot, start + 100ms));
	EXPECT_EQ(snapshots, 2);

	EXPECT_FALSE(schedule.refresh_if_due(SCAP_SUCCESS, snapshot, start + 199ms));
	EXPECT_TRUE(schedule.refresh_if_due(SCAP_FILTERED_EVENT, snapshot, start + 200ms));
	EXPECT_TRUE(schedule.refresh_if_due(SCAP_SUCCESS, snapshot, start + 300ms));
	EXPECT_EQ(snapshots, 4);
}

#ifndef __EMSCRIPTEN__
TEST(metrics_snapshot, startup_and_timeout_refresh_are_safe_during_concurrent_scrapes) {
	using namespace std::chrono_literals;
	using refresh = falco::app::prometheus_metrics_refresh;

	falco::app::state::source_info info;
	refresh schedule(1ms);
	const refresh::time_point start{};
	uint64_t sequence = 0;
	auto snapshot = [&]() {
		info.set_metrics_snapshot(std::vector<metrics_v2>{metric_with_value(++sequence)});
	};

	// Production initializes the cache immediately after start_capture(), before
	// the first event or timeout is returned.
	schedule.initialize(snapshot, start);
	auto initial = info.get_metrics_snapshot();
	ASSERT_EQ(initial.size(), 1u);
	EXPECT_EQ(initial[0].value.u64, 1u);

	std::atomic<bool> done{false};
	std::atomic<bool> invalid_snapshot{false};
	std::thread scraper([&]() {
		while(!done.load(std::memory_order_relaxed)) {
			auto current = info.get_metrics_snapshot();
			if(current.size() != 1 || current[0].value.u64 == 0) {
				invalid_snapshot.store(true, std::memory_order_relaxed);
				break;
			}
		}
	});

	for(int i = 1; i <= 1000; ++i) {
		EXPECT_TRUE(schedule.refresh_if_due(SCAP_TIMEOUT, snapshot, start + i * 1ms));
	}
	done.store(true, std::memory_order_relaxed);
	scraper.join();

	EXPECT_FALSE(invalid_snapshot.load(std::memory_order_relaxed));
	auto final_snapshot = info.get_metrics_snapshot();
	ASSERT_EQ(final_snapshot.size(), 1u);
	EXPECT_EQ(final_snapshot[0].value.u64, 1001u);
}
#endif
