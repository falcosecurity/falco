/*
Copyright (C) 2013-2018 Draios Inc dba Sysdig.

This file is part of sysdig.

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

#include "internal_metrics.h"

#ifdef GATHER_INTERNAL_STATS

//
// Processing stats class.
// Keeps a bunch of counters with key library performance metrics.
//
class SINSP_PUBLIC sinsp_stats : public internal_metrics::processor
{
public:
	void clear();
	void emit(FILE* f);
	internal_metrics::registry& get_metrics_registry()
	{
		return m_metrics_registry;
	}

	void process(internal_metrics::counter& metric);

	uint64_t m_n_seen_evts;
	uint64_t m_n_drops;
	uint64_t m_n_preemptions;
	uint64_t m_n_noncached_fd_lookups;
	uint64_t m_n_cached_fd_lookups;
	uint64_t m_n_failed_fd_lookups;
	uint64_t m_n_threads;
	uint64_t m_n_fds;
	uint64_t m_n_added_fds;
	uint64_t m_n_removed_fds;
	uint64_t m_n_stored_evts;
	uint64_t m_n_store_drops;
	uint64_t m_n_retrieved_evts;
	uint64_t m_n_retrieve_drops;

private:
	internal_metrics::registry m_metrics_registry;
	FILE* m_output_target;
};

#endif // GATHER_INTERNAL_STATS
