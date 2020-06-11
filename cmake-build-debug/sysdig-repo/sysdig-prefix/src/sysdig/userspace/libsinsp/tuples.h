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

#include <stdint.h>

/** @defgroup state State management
 *  @{
 */

/*!
	\brief An IPv4 tuple. 
*/
typedef union _ipv4tuple
{
	struct 
	{
		uint32_t m_sip; ///< Source (i.e. client) address. 
		uint32_t m_dip; ///< Destination (i.e. server) address.
		uint16_t m_sport; ///< Source (i.e. client) port.
		uint16_t m_dport; ///< Destination (i.e. server) port.
		uint8_t m_l4proto; ///< Layer 4 protocol (e.g. TCP, UDP...).
	}m_fields;
	uint8_t m_all[13]; ///< The fields as a raw array ob bytes. Used for hasing.
}ipv4tuple;

/*!
	\brief An IPv4 network.
*/
typedef struct ipv4net
{
	uint32_t m_ip; ///< IP addr
	uint32_t m_netmask; ///< Subnet mask
}ipv4net;

typedef struct _ipv6addr
{
	uint32_t m_b[4];

	bool operator==(const _ipv6addr &other) const;
	bool operator!=(const _ipv6addr &other) const;
	bool operator<(const _ipv6addr &other) const;
	bool in_subnet(const _ipv6addr &other) const;

	static struct _ipv6addr empty_address;
}ipv6addr;


/*!
	\brief An IPv6 tuple. 
*/
typedef union _ipv6tuple
{
	struct {

		ipv6addr m_sip; ///< source (i.e. client) address.
		ipv6addr m_dip; ///< destination (i.e. server) address.
		uint16_t m_sport; ///< source (i.e. client) port.
		uint16_t m_dport; ///< destination (i.e. server) port.
		uint8_t m_l4proto; ///< Layer 4 protocol (e.g. TCP, UDP...)
	} m_fields;
	uint8_t m_all[37]; ///< The fields as a raw array ob bytes. Used for hasing.
} ipv6tuple;

/*!
	\brief An IPv4 server address. 
*/
typedef struct ipv4serverinfo
{
	uint32_t m_ip; ///< address
	uint16_t m_port; ///< port
	uint8_t m_l4proto; ///< IP protocol
} ipv4serverinfo;

/*!
	\brief An IPv6 server address. 
*/
typedef struct ipv6serverinfo
{
	ipv6addr m_ip;  ///< address
	uint16_t m_port;  ///< port
	uint8_t m_l4proto;  ///< IP protocol
} ipv6serverinfo;

/*!
	\brief A unix socket tuple. 
*/
typedef union _unix_tuple
{
	struct
	{
		uint64_t m_source;  ///< source OS pointer.
		uint64_t m_dest;  ///< destination OS pointer.
	} m_fields;
	uint8_t m_all[16]; ///< The fields as a raw array ob bytes. Used for hasing.
} unix_tuple;

/*@}*/
