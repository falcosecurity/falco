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

#include "sinsp.h"
#include "sinsp_int.h"

sinsp_network_interfaces::sinsp_network_interfaces(sinsp* inspector)
	: m_inspector(inspector)
{
	if(inet_pton(AF_INET6, "::1", m_ipv6_loopback_addr.m_b) != 1)
	{
		throw sinsp_exception("Could not convert ipv6 loopback address ::1 to ipv6addr struct");
	}
}

sinsp_ipv4_ifinfo::sinsp_ipv4_ifinfo(uint32_t addr, uint32_t netmask, uint32_t bcast, const char* name)
{
	m_addr = addr;
	m_netmask = netmask;
	m_bcast = bcast;
	m_name = name;
}

void sinsp_ipv4_ifinfo::convert_to_string(char * dest, const uint32_t addr)
{
	sprintf(
		dest,
		"%d.%d.%d.%d",
		(addr & 0xFF),
		((addr & 0xFF00) >> 8),
		((addr & 0xFF0000) >> 16),
		((addr & 0xFF000000) >> 24));
}

string sinsp_ipv4_ifinfo::address() const
{
	char str_addr[16];
	convert_to_string(str_addr, m_addr);
	return string(str_addr);
}

string sinsp_ipv4_ifinfo::to_string() const
{
	char s[100];
	char str_addr[16];
	char s_netmask[16];
	char s_bcast[16];

	convert_to_string(str_addr, m_addr);
	convert_to_string(s_netmask, m_netmask);
	convert_to_string(s_bcast, m_bcast);
	snprintf(s, sizeof(s), "%s inet %s netmask %s broadcast %s", m_name.c_str(), str_addr, s_netmask, s_bcast);
	return string(s);
}

uint32_t sinsp_network_interfaces::infer_ipv4_address(uint32_t destination_address)
{
	vector<sinsp_ipv4_ifinfo>::iterator it;

	// first try to find exact match
	for(it = m_ipv4_interfaces.begin(); it != m_ipv4_interfaces.end(); it++)
	{
		if(it->m_addr == destination_address)
		{
			return it->m_addr;
		}
	}

	// try to find an interface for the same subnet
	for(it = m_ipv4_interfaces.begin(); it != m_ipv4_interfaces.end(); it++)
	{
		if((it->m_addr & it->m_netmask) == (destination_address & it->m_netmask))
		{
			return it->m_addr;
		}
	}

	// otherwise take the first non loopback interface
	for(it = m_ipv4_interfaces.begin(); it != m_ipv4_interfaces.end(); it++)
	{
		if(it->m_addr != LOOPBACK_ADDR)
		{
			return it->m_addr;
		}
	}
	return 0;
}

void sinsp_network_interfaces::update_fd(sinsp_fdinfo_t *fd)
{
	ipv4tuple *pipv4info = &(fd->m_sockinfo.m_ipv4info);
	ipv6tuple *pipv6info = &(fd->m_sockinfo.m_ipv6info);

	//
	// only handle ipv4/ipv6 udp sockets
	//
	if(fd->m_type != SCAP_FD_IPV4_SOCK &&
	   fd->m_type != SCAP_FD_IPV6_SOCK)
	{
		return;
	}

	if(fd->m_type == SCAP_FD_IPV4_SOCK)
	{

		if(0 != pipv4info->m_fields.m_sip && 0 != pipv4info->m_fields.m_dip)
		{
			return;
		}
		if(0 == pipv4info->m_fields.m_sip)
		{
			uint32_t newaddr;
			newaddr = infer_ipv4_address(pipv4info->m_fields.m_dip);

			if(newaddr == pipv4info->m_fields.m_dip)
			{
				if(pipv4info->m_fields.m_sport == pipv4info->m_fields.m_dport)
				{
					return;
				}
			}

			pipv4info->m_fields.m_sip = newaddr;
		}
		else
		{
			uint32_t newaddr;
			newaddr = infer_ipv4_address(pipv4info->m_fields.m_sip);

			if(newaddr == pipv4info->m_fields.m_sip)
			{
				if(pipv4info->m_fields.m_sport == pipv4info->m_fields.m_dport)
				{
					return;
				}
			}

			pipv4info->m_fields.m_dip = newaddr;
		}
	}
	else if(fd->m_type == SCAP_FD_IPV6_SOCK)
	{

		if(ipv6addr::empty_address != pipv6info->m_fields.m_sip &&
		   ipv6addr::empty_address != pipv6info->m_fields.m_dip)
		{
			return;
		}
		if(ipv6addr::empty_address == pipv6info->m_fields.m_sip)
		{
			ipv6addr newaddr;
			newaddr = infer_ipv6_address(pipv6info->m_fields.m_dip);

			if(newaddr == pipv6info->m_fields.m_dip)
			{
				if(pipv6info->m_fields.m_sport == pipv6info->m_fields.m_dport)
				{
					return;
				}
			}

			pipv6info->m_fields.m_sip = newaddr;
		}
		else
		{
			ipv6addr newaddr;
			newaddr = infer_ipv6_address(pipv6info->m_fields.m_sip);

			if(newaddr == pipv6info->m_fields.m_sip)
			{
				if(pipv6info->m_fields.m_sport == pipv6info->m_fields.m_dport)
				{
					return;
				}
			}

			pipv6info->m_fields.m_dip = newaddr;
		}
	}
}

bool sinsp_network_interfaces::is_ipv4addr_in_subnet(uint32_t addr)
{
	vector<sinsp_ipv4_ifinfo>::iterator it;

	//
	// Accept everything that comes from 192.168.0.0/16 or 10.0.0.0/8
	//
	if((addr & 0x000000ff) == 0x0000000a ||
		(addr & 0x0000ffff) == 0x0000a8c0 ||
		(addr & 0x00003fff) == 0x000010ac)
	{
		return true;
	}

	// try to find an interface for the same subnet
	for(it = m_ipv4_interfaces.begin(); it != m_ipv4_interfaces.end(); it++)
	{
		if((it->m_addr & it->m_netmask) == (addr & it->m_netmask))
		{
			return true;
		}
	}

	return false;
}

bool sinsp_network_interfaces::is_ipv4addr_in_local_machine(uint32_t addr, sinsp_threadinfo* tinfo)
{
	if(!tinfo->m_container_id.empty())
	{
		const sinsp_container_info::ptr_t container_info =
			m_inspector->m_container_manager.get_container(tinfo->m_container_id);

		//
		// Note: if we don't have container info, any pick we make is arbitrary.
		// To at least achieve consistency across client and server, we just match the host interface addresses.
		//
		if(container_info)
		{
			if(container_info->m_container_ip != 0)
			{
				//
				// We have a container info with a valid container IP. Let's use it.
				//
				if(addr == htonl(container_info->m_container_ip))
				{
					return true;
				}
			}
			else
			{
				//
				// Container info is valid, but the IP address is zero.
				// Scan the list of the containers looking for matches.
				// If no match is found, we just jump to checking the
				// host interfaces.
				//

				if(!container_info->is_successful())
				{
					g_logger.format(sinsp_logger::SEV_DEBUG,
						"Checking IP address of container %s with incomplete metadata (state=%d)",
						tinfo->m_container_id.c_str(), container_info->m_lookup_state);
				}

				const sinsp_container_manager::map_ptr_t clist = m_inspector->m_container_manager.get_containers();

				for(const auto& it : *clist)
				{
					if(!it.second->is_successful())
					{
						g_logger.format(sinsp_logger::SEV_DEBUG,
							"Checking IP address of container %s with incomplete metadata (in context of %s; state=%d)",
							it.second->m_id.c_str(), tinfo->m_container_id.c_str(),
							it.second->m_lookup_state);
					}

					if(htonl(it.second->m_container_ip) == addr)
					{
						return true;
					}
				}
			}
		}
	}

	vector<sinsp_ipv4_ifinfo>::iterator it;

	// try to find an interface that has the given IP as address
	for(it = m_ipv4_interfaces.begin(); it != m_ipv4_interfaces.end(); it++)
	{
		if(it->m_addr == addr)
		{
			return true;
		}
	}

	return false;
}

void sinsp_network_interfaces::import_ipv4_ifaddr_list(uint32_t count, scap_ifinfo_ipv4* plist)
{
	if (count == 0)
	{
		return;
	}
	for(uint32_t j = 0; j < count; j++)
	{
		sinsp_ipv4_ifinfo info;
		info.m_addr = plist->addr;
		info.m_netmask = plist->netmask;
		info.m_bcast = plist->bcast;
		info.m_name = plist->ifname;
		m_ipv4_interfaces.push_back(info);
		plist++;
	}
}

ipv6addr sinsp_network_interfaces::infer_ipv6_address(ipv6addr &destination_address)
{
	vector<sinsp_ipv6_ifinfo>::iterator it;

	// first try to find exact match
	for(it = m_ipv6_interfaces.begin(); it != m_ipv6_interfaces.end(); it++)
	{
		if(destination_address == it->m_net)
		{
			return it->m_net;
		}
	}

	// try to find an interface for the same subnet
	for(it = m_ipv6_interfaces.begin(); it != m_ipv6_interfaces.end(); it++)
	{
		if(it->m_net.in_subnet(destination_address))
		{
			return it->m_net;
		}
	}

	// otherwise take the first non loopback interface
	for(it = m_ipv6_interfaces.begin(); it != m_ipv6_interfaces.end(); it++)
	{
		if(it->m_net != m_ipv6_loopback_addr)
		{
			return it->m_net;
		}
	}

	return ipv6addr::empty_address;
}

bool sinsp_network_interfaces::is_ipv6addr_in_local_machine(ipv6addr &addr, sinsp_threadinfo* tinfo)
{
	if(!tinfo->m_container_id.empty())
	{
		// For now, not supporting ipv6 networking for containers. So always return false;
		return false;
	}

	vector<sinsp_ipv6_ifinfo>::iterator it;

	// try to find an interface that has the given IP as address
	for(it = m_ipv6_interfaces.begin(); it != m_ipv6_interfaces.end(); it++)
	{
		if(addr.in_subnet(it->m_net))
		{
			return true;
		}
	}

	return false;
}

void sinsp_network_interfaces::import_ipv6_ifaddr_list(uint32_t count, scap_ifinfo_ipv6* plist)
{
	if (count == 0)
	{
		return;
	}
	for(uint32_t j = 0; j < count; j++)
	{
		sinsp_ipv6_ifinfo info;

		// Only saving the address portion. (Assumes
		// convention of first 48 bits for network, next 16
		// bits for subnet).
		memcpy(info.m_net.m_b, plist->addr, SCAP_IPV6_ADDR_LEN);

		info.m_name = plist->ifname;
		m_ipv6_interfaces.push_back(info);
		plist++;
	}
}

void sinsp_network_interfaces::import_interfaces(scap_addrlist* paddrlist)
{
	if(NULL != paddrlist)
	{
		clear();
		import_ipv4_ifaddr_list(paddrlist->n_v4_addrs, paddrlist->v4list);
		import_ipv6_ifaddr_list(paddrlist->n_v6_addrs, paddrlist->v6list);
	}
}

void sinsp_network_interfaces::import_ipv4_interface(const sinsp_ipv4_ifinfo& ifinfo)
{
	m_ipv4_interfaces.push_back(ifinfo);
}

void sinsp_network_interfaces::import_ipv6_interface(const sinsp_ipv6_ifinfo& ifinfo)
{
	m_ipv6_interfaces.push_back(ifinfo);
}

vector<sinsp_ipv4_ifinfo>* sinsp_network_interfaces::get_ipv4_list()
{
	return &m_ipv4_interfaces;
}

vector<sinsp_ipv6_ifinfo>* sinsp_network_interfaces::get_ipv6_list()
{
	return &m_ipv6_interfaces;
}
