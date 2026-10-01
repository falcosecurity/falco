// SPDX-License-Identifier: Apache-2.0
/* Copyright (C) 2026 The Falco Authors. */

#pragma once

#include "../configuration.h"

#include <libscap/scap.h>

#include <chrono>
#include <cstdint>
#include <utility>

namespace falco::app {

// Refresh inspector-backed Prometheus metrics once per second: short enough for
// fresh scrapes while bounding expensive state/resource snapshots independently
// of metrics.interval, whose shipped default is one hour.
inline constexpr auto prometheus_metrics_refresh_interval = std::chrono::seconds(1);

inline bool prometheus_metrics_collection_enabled(const falco_configuration& config,
                                                  bool is_capture_mode) {
	return !is_capture_mode && config.m_metrics_enabled && config.m_webserver_enabled &&
	       config.m_webserver_config.m_prometheus_metrics_enabled;
}

class prometheus_metrics_refresh {
public:
	using clock = std::chrono::steady_clock;
	using time_point = clock::time_point;

	explicit prometheus_metrics_refresh(
	        clock::duration interval = prometheus_metrics_refresh_interval):
	        m_interval(interval) {}

	template<typename Snapshot>
	void initialize(Snapshot&& snapshot, time_point now = clock::now()) {
		std::forward<Snapshot>(snapshot)();
		m_next_refresh = now + m_interval;
		m_initialized = true;
	}

	template<typename Snapshot>
	bool refresh_if_due(int32_t rc, Snapshot&& snapshot, time_point now = clock::now()) {
		if(!m_initialized || !refreshable_result(rc) || now < m_next_refresh) {
			return false;
		}
		std::forward<Snapshot>(snapshot)();
		m_next_refresh = now + m_interval;
		return true;
	}

	static bool refreshable_result(int32_t rc) {
		return rc == SCAP_SUCCESS || rc == SCAP_TIMEOUT || rc == SCAP_FILTERED_EVENT;
	}

private:
	clock::duration m_interval;
	time_point m_next_refresh{};
	bool m_initialized = false;
};

}  // namespace falco::app
