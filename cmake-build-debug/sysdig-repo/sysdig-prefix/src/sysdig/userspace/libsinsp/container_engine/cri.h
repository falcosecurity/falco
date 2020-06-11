/*
Copyright (C) 2013-2019 Draios Inc dba Sysdig.

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

#include <string>
#include <stdint.h>

class sinsp_threadinfo;

#include "cgroup_limits.h"
#include "container_engine/container_engine_base.h"
#include "container_engine/sinsp_container_type.h"
#include "container_info.h"
#include <cri.h>

namespace runtime {
namespace v1alpha2 {
class ContainerStatusResponse;
}
}

namespace libsinsp {
namespace container_engine {

/**
 * Asynchronous metadata lookup for CRI containers
 *
 * There are two related reasons for asynchronous lookup:
 * 1. Not blocking the main event processing thread
 *
 * 2. Apparently CRI can fail to find a freshly created container
 * for a short while, so we should delay the query a bit.
 */
class cri_async_source : public sysdig::async_key_value_source<
        libsinsp::cgroup_limits::cgroup_limits_key,
        sinsp_container_info>
{
public:
	explicit cri_async_source(container_cache_interface *cache, ::libsinsp::cri::cri_interface *cri, uint64_t ttl_ms) :
		async_key_value_source(NO_WAIT_LOOKUP, ttl_ms),
		m_cache(cache),
		m_cri(cri)
	{
	}

	void quiesce() {
		async_key_value_source::stop();
	}

	bool lookup_sync(const libsinsp::cgroup_limits::cgroup_limits_key& key,
		    sinsp_container_info& value);

	bool parse_cri(sinsp_container_info& container, const libsinsp::cgroup_limits::cgroup_limits_key& key);
private:
	bool parse_containerd(const runtime::v1alpha2::ContainerStatusResponse& status, sinsp_container_info& container);
	void run_impl() override;

	container_cache_interface *m_cache;
	::libsinsp::cri::cri_interface *m_cri;
};

class cri : public container_engine_base
{
public:
	cri(container_cache_interface &cache);
	bool resolve(sinsp_threadinfo *tinfo, bool query_os_for_missing_info) override;
	void update_with_size(const std::string& container_id) override;
	void cleanup() override;
	static void set_cri_socket_path(const std::string& path);
	static void set_cri_timeout(int64_t timeout_ms);
	static void set_extra_queries(bool extra_queries);
	static void set_async(bool async_limits);
	static void set_cri_delay(uint64_t delay_ms);

private:
	std::unique_ptr<cri_async_source> m_async_source;
	std::unique_ptr<::libsinsp::cri::cri_interface> m_cri;
};
}
}
