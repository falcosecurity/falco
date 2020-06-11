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

////////////////////////////////////////////////////////////////////////////
// Public definitions for the scap library
////////////////////////////////////////////////////////////////////////////
#include "sinsp.h"
#include "sinsp_int.h"

#ifdef GATHER_INTERNAL_STATS

void sinsp_stats::clear()
{
	m_n_seen_evts = 0;
	m_n_drops = 0;
	m_n_preemptions = 0;
	m_n_noncached_fd_lookups = 0;
	m_n_cached_fd_lookups = 0;
	m_n_failed_fd_lookups = 0;
	m_n_threads = 0;
	m_n_fds = 0;
	m_n_added_fds = 0;
	m_n_removed_fds = 0;
	m_n_stored_evts = 0;
	m_n_store_drops = 0;
	m_n_retrieved_evts = 0;
	m_n_retrieve_drops = 0;
	m_metrics_registry.clear_all_metrics();
}

void sinsp_stats::emit(FILE* f)
{
	m_output_target = f;

	fprintf(f, "evts seen by driver: %" PRIu64 "\n", m_n_seen_evts);
	fprintf(f, "drops: %" PRIu64 "\n", m_n_drops);
	fprintf(f, "preemptions: %" PRIu64 "\n", m_n_preemptions);
	fprintf(f, "fd lookups: %" PRIu64 "(%" PRIu64 " cached %" PRIu64 " noncached)\n", 
		m_n_noncached_fd_lookups + m_n_cached_fd_lookups,
		m_n_cached_fd_lookups,
		m_n_noncached_fd_lookups);
	fprintf(f, "failed fd lookups: %" PRIu64 "\n", m_n_failed_fd_lookups);
	fprintf(f, "n. threads: %" PRIu64 "\n", m_n_threads);
	fprintf(f, "n. fds: %" PRIu64 "\n", m_n_fds);
	fprintf(f, "added fds: %" PRIu64 "\n", m_n_added_fds);
	fprintf(f, "removed fds: %" PRIu64 "\n", m_n_removed_fds);
	fprintf(f, "stored evts: %" PRIu64 "\n", m_n_stored_evts);
	fprintf(f, "store drops: %" PRIu64 "\n", m_n_store_drops);
	fprintf(f, "retrieved evts: %" PRIu64 "\n", m_n_retrieved_evts);
	fprintf(f, "retrieve drops: %" PRIu64 "\n", m_n_retrieve_drops);

	for(internal_metrics::registry::metric_map_iterator_t it = m_metrics_registry.get_metrics().begin(); it != m_metrics_registry.get_metrics().end(); it++)
	{
		fprintf(f, "%s: ", it->first.get_description().c_str());
		it->second->process(*this);
	}
}

void sinsp_stats::process(internal_metrics::counter& metric)
{
	fprintf(m_output_target, "%" PRIu64 "\n", metric.get_value());
}

#endif // GATHER_INTERNAL_STATS
