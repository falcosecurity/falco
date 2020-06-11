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

#include <sys/types.h>
#if defined(_WIN64) || defined(WIN64) || defined(_WIN32) || defined(WIN32)
#include <WinSock2.h>
#else
#include <sys/socket.h>
#include <netdb.h>
#endif
#include <string>
#include <thread>
#include <chrono>
#include <future>
#include <mutex>
#if defined(HAS_CAPTURE) && !defined(CYGWING_AGENT)
#include "tbb/concurrent_unordered_map.h"
#endif
#include "sinsp.h"


struct sinsp_dns_resolver
{
	static void refresh(uint64_t erase_timeout, uint64_t base_refresh_timeout, uint64_t max_refresh_timeout, std::future<void> f_exit);
};

class sinsp_dns_manager
{
public:

	bool match(const char *name, int af, void *addr, uint64_t ts);
	string name_of(int af, void *addr, uint64_t ts);

	void cleanup();

        static sinsp_dns_manager& get()
        {
            static sinsp_dns_manager instance;
            return instance;
        };

	void set_erase_timeout(uint64_t ns)
	{
		m_erase_timeout = ns;
	};
	void set_base_refresh_timeout(uint64_t ns)
	{
		m_base_refresh_timeout = ns;
	};
	void set_max_refresh_timeout(uint64_t ns)
	{
		m_max_refresh_timeout = ns;
	};

	size_t size()
	{
#if defined(HAS_CAPTURE) && !defined(CYGWING_AGENT)
		return m_cache.size();
#else
		return 0;
#endif
	};

private:

	sinsp_dns_manager() :
		m_erase_timeout(3600 * ONE_SECOND_IN_NS),
		m_base_refresh_timeout(10 * ONE_SECOND_IN_NS),
		m_max_refresh_timeout(320 * ONE_SECOND_IN_NS)
	{};
        sinsp_dns_manager(sinsp_dns_manager const&) = delete;
        void operator=(sinsp_dns_manager const&) = delete;

#if defined(HAS_CAPTURE) && !defined(CYGWING_AGENT)
	struct dns_info
	{
		bool operator==(const dns_info &other) const
		{
			return m_v4_addrs == other.m_v4_addrs && m_v6_addrs == other.m_v6_addrs;
		};
		bool operator!=(const dns_info &other) const
		{
			return !operator==(other);
		};

		uint64_t m_timeout;
		uint64_t m_last_resolve_ts;
		uint64_t m_last_used_ts;
		std::set<uint32_t> m_v4_addrs;
		std::set<ipv6addr> m_v6_addrs;
	};

	static inline dns_info resolve(const std::string &name, uint64_t ts);

	typedef tbb::concurrent_unordered_map<std::string, dns_info> c_dns_table;
	c_dns_table m_cache;
#endif

	// tbb concurrent unordered map is not thread-safe for deletions,
	// so we still need a mutex, but the chances of waiting are really
	// low, since we will almost never do an erase.
	std::mutex m_erase_mutex;

	// used to let m_resolver know when to terminate
	std::promise<void> m_exit_signal;

	std::thread *m_resolver;

	uint64_t m_erase_timeout;
	uint64_t m_base_refresh_timeout;
	uint64_t m_max_refresh_timeout;

	friend sinsp_dns_resolver;
};
