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

#include "dns_manager.h"

void sinsp_dns_resolver::refresh(uint64_t erase_timeout, uint64_t base_refresh_timeout, uint64_t max_refresh_timeout, std::future<void> f_exit)
{
#if defined(HAS_CAPTURE) && !defined(CYGWING_AGENT)
	sinsp_dns_manager &manager = sinsp_dns_manager::get();
	while(true)
	{
		if(!manager.m_cache.empty())
		{
			std::list<std::string> to_delete;

			uint64_t ts = sinsp_utils::get_current_time_ns();

			for(auto &it: manager.m_cache)
			{
				const std::string &name = it.first;
				sinsp_dns_manager::dns_info &info = it.second;

				if((ts > info.m_last_used_ts) &&
				   (ts - info.m_last_used_ts) > erase_timeout)
				{
					// remove the entry if it's hasn't been used for a whole hour
					to_delete.push_back(name);
				}
				else if(ts > (info.m_last_resolve_ts + info.m_timeout))
				{
					sinsp_dns_manager::dns_info refreshed_info = manager.resolve(name, ts);
					refreshed_info.m_timeout = base_refresh_timeout;
					refreshed_info.m_last_resolve_ts = info.m_last_resolve_ts = ts;

					// dns_info::operator!= will check if some
					// v4 or v6 addresses are changed from the
					// last resolution
					if(refreshed_info != info)
					{
						info = refreshed_info;
					}
					else if(info.m_timeout < max_refresh_timeout)
					{
						// double the timeout until 320 secs
						info.m_timeout <<= 1;
					}
				}
			}
			if(!to_delete.empty())
			{
				manager.m_erase_mutex.lock();
				for(const auto &name : to_delete)
				{
					manager.m_cache.unsafe_erase(name);
				}
				manager.m_erase_mutex.unlock();
			}
		}

		if(f_exit.wait_for(std::chrono::nanoseconds(base_refresh_timeout)) == std::future_status::ready)
		{
			break;
		}
	}
#endif
}

#if defined(HAS_CAPTURE) && !defined(CYGWING_AGENT)
inline sinsp_dns_manager::dns_info sinsp_dns_manager::resolve(const std::string &name, uint64_t ts)
{
	dns_info dinfo;

	struct addrinfo hints, *result, *rp;
	memset(&hints, 0, sizeof(struct addrinfo));

	// Allow IPv4 or IPv6, all socket types, all protocols
	hints.ai_family = AF_UNSPEC;

	int s = getaddrinfo(name.c_str(), NULL, &hints, &result);
	if (!s && result)
	{
		for (rp = result; rp != NULL; rp = rp->ai_next)
		{
			if(rp->ai_family == AF_INET)
			{
				dinfo.m_v4_addrs.insert(((struct sockaddr_in*)rp->ai_addr)->sin_addr.s_addr);
			}
			else // AF_INET6
			{
				ipv6addr v6;
				memcpy(v6.m_b, ((struct sockaddr_in6*)rp->ai_addr)->sin6_addr.s6_addr, sizeof(ipv6addr));
				dinfo.m_v6_addrs.insert(v6);
			}
		}
		freeaddrinfo(result);
	}
	return dinfo;
}
#endif

bool sinsp_dns_manager::match(const char *name, int af, void *addr, uint64_t ts)
{
#if defined(HAS_CAPTURE) && !defined(CYGWING_AGENT)
	if(!m_resolver)
	{
		m_resolver = new thread(sinsp_dns_resolver::refresh, m_erase_timeout, m_base_refresh_timeout, m_max_refresh_timeout, m_exit_signal.get_future());
	}

	string sname = string(name);

	m_erase_mutex.lock();

	if(m_cache.find(sname) == m_cache.end())
	{
		dns_info dinfo = resolve(sname, ts);
		dinfo.m_timeout = m_base_refresh_timeout;
		dinfo.m_last_resolve_ts = ts;
		m_cache[sname] = dinfo;
	}

	m_cache[sname].m_last_used_ts = ts;
	dns_info &dinfo = m_cache[sname];

	m_erase_mutex.unlock();

	if(af == AF_INET6)
	{
		ipv6addr v6;
		memcpy(v6.m_b, addr, sizeof(ipv6addr));
		return dinfo.m_v6_addrs.find(v6) != dinfo.m_v6_addrs.end();
	}
	else if(af == AF_INET)
	{
		return dinfo.m_v4_addrs.find(*(uint32_t *)addr) != dinfo.m_v4_addrs.end();
	}
#endif
	return false;
}

string sinsp_dns_manager::name_of(int af, void *addr, uint64_t ts)
{
	string ret;

#if defined(HAS_CAPTURE) && !defined(CYGWING_AGENT)
	if(!m_cache.empty())
	{
		m_erase_mutex.lock();
		for(auto &it: m_cache)
		{
			const std::string &name = it.first;
			sinsp_dns_manager::dns_info &info = it.second;

			if(af == AF_INET6)
			{
				ipv6addr v6;
				memcpy(v6.m_b, addr, sizeof(ipv6addr));
				if (info.m_v6_addrs.find(v6) != info.m_v6_addrs.end())
				{
					info.m_last_used_ts = ts;
					ret = name;
					break;
				}
			}
			else if(af == AF_INET && info.m_v4_addrs.find(*(uint32_t *)addr) != info.m_v4_addrs.end())
			{
				info.m_last_used_ts = ts;
				ret = name;
				break;
			}
		}
		m_erase_mutex.unlock();
	}
#endif
	return ret;
}

void sinsp_dns_manager::cleanup()
{
	if(m_resolver)
	{
		m_exit_signal.set_value();
		m_resolver->join();
		m_resolver = NULL;
		m_exit_signal = std::promise<void>();
	}
}
