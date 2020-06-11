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

#include "tuples.h"

#define LOOPBACK_ADDR 0x0100007f

#ifndef VISIBILITY_PRIVATE
#define VISIBILITY_PRIVATE private:
#endif

//
// network interface info ipv4
//
class SINSP_PUBLIC sinsp_ipv4_ifinfo
{
public:
	sinsp_ipv4_ifinfo() {};

	sinsp_ipv4_ifinfo(uint32_t addr, uint32_t netmask, uint32_t bcast, const char* name);

	string to_string() const;
	string address() const;

	uint32_t m_addr;
	uint32_t m_netmask;
	uint32_t m_bcast;
	string m_name;
private:
	static void convert_to_string(char * dest, const uint32_t addr);
};

//
// network interface info ipv6
//
class SINSP_PUBLIC sinsp_ipv6_ifinfo
{
public:
	sinsp_ipv6_ifinfo() {};

	ipv6addr m_net;

	string m_name;
};

class SINSP_PUBLIC sinsp_network_interfaces
{
public:
	sinsp_network_interfaces(sinsp* inspector);

	void import_interfaces(scap_addrlist* paddrlist);
	void import_ipv4_interface(const sinsp_ipv4_ifinfo& ifinfo);
	void update_fd(sinsp_fdinfo_t *fd);
	bool is_ipv4addr_in_subnet(uint32_t addr);
	bool is_ipv4addr_in_local_machine(uint32_t addr, sinsp_threadinfo* tinfo);
	void import_ipv6_interface(const sinsp_ipv6_ifinfo& ifinfo);
	bool is_ipv6addr_in_local_machine(ipv6addr &addr, sinsp_threadinfo* tinfo);
	vector<sinsp_ipv4_ifinfo>* get_ipv4_list();
	vector<sinsp_ipv6_ifinfo>* get_ipv6_list();
	inline void clear();

	ipv6addr m_ipv6_loopback_addr;

VISIBILITY_PRIVATE
	uint32_t infer_ipv4_address(uint32_t destination_address);
	void import_ipv4_ifaddr_list(uint32_t count, scap_ifinfo_ipv4* plist);
	ipv6addr infer_ipv6_address(ipv6addr &destination_address);
	void import_ipv6_ifaddr_list(uint32_t count, scap_ifinfo_ipv6* plist);
	vector<sinsp_ipv4_ifinfo> m_ipv4_interfaces;
	vector<sinsp_ipv6_ifinfo> m_ipv6_interfaces;
	sinsp* m_inspector;
};

void sinsp_network_interfaces::clear()
{
	m_ipv4_interfaces.clear();
	m_ipv6_interfaces.clear();
}