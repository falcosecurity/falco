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

#ifndef _WIN32
#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#include <algorithm>
#endif
#include "sinsp.h"
#include "sinsp_int.h"

///////////////////////////////////////////////////////////////////////////////
// sinsp_fdinfo inomlementation
///////////////////////////////////////////////////////////////////////////////
template<> sinsp_fdinfo_t::sinsp_fdinfo()
{
	m_type = SCAP_FD_UNINITIALIZED;
	m_flags = FLAGS_NONE;
	m_callbaks = NULL;
	m_usrstate = NULL;
}

template<> void sinsp_fdinfo_t::reset()
{
	m_type = SCAP_FD_UNINITIALIZED;
	m_flags = FLAGS_NONE;
	delete(m_callbaks);
	m_callbaks = NULL;
	m_usrstate = NULL;
}

template<> string* sinsp_fdinfo_t::tostring()
{
	return &m_name;
}

template<> char sinsp_fdinfo_t::get_typechar()
{
	switch(m_type)
	{
	case SCAP_FD_FILE_V2:
	case SCAP_FD_FILE:
		return CHAR_FD_FILE;
	case SCAP_FD_IPV4_SOCK:
		return CHAR_FD_IPV4_SOCK;
	case SCAP_FD_IPV6_SOCK:
		return CHAR_FD_IPV6_SOCK;
	case SCAP_FD_DIRECTORY:
		return CHAR_FD_DIRECTORY;
	case SCAP_FD_IPV4_SERVSOCK:
		return CHAR_FD_IPV4_SERVSOCK;
	case SCAP_FD_IPV6_SERVSOCK:
		return CHAR_FD_IPV6_SERVSOCK;
	case SCAP_FD_FIFO:
		return CHAR_FD_FIFO;
	case SCAP_FD_UNIX_SOCK:
		return CHAR_FD_UNIX_SOCK;
	case SCAP_FD_EVENT:
		return CHAR_FD_EVENT;
	case SCAP_FD_UNKNOWN:
		return CHAR_FD_UNKNOWN;
	case SCAP_FD_UNSUPPORTED:
		return CHAR_FD_UNSUPPORTED;
	case SCAP_FD_SIGNALFD:
		return CHAR_FD_SIGNAL;
	case SCAP_FD_EVENTPOLL:
		return CHAR_FD_EVENTPOLL;
	case SCAP_FD_INOTIFY:
		return CHAR_FD_INOTIFY;
	case SCAP_FD_TIMERFD:
		return CHAR_FD_TIMERFD;
	case SCAP_FD_NETLINK:
		return CHAR_FD_NETLINK;
	default:
//		ASSERT(false);
		return '?';
	}
}

template<> char* sinsp_fdinfo_t::get_typestring()
{
	switch(m_type)
	{
	case SCAP_FD_FILE_V2:
	case SCAP_FD_FILE:
		return (char*)"file";
	case SCAP_FD_DIRECTORY:
		return (char*)"directory";
	case SCAP_FD_IPV4_SOCK:
	case SCAP_FD_IPV4_SERVSOCK:
		return (char*)"ipv4";
	case SCAP_FD_IPV6_SOCK:
	case SCAP_FD_IPV6_SERVSOCK:
		return (char*)"ipv6";
	case SCAP_FD_UNIX_SOCK:
		return (char*)"unix";
	case SCAP_FD_FIFO:
		return (char*)"pipe";
	case SCAP_FD_EVENT:
		return (char*)"event";
	case SCAP_FD_SIGNALFD:
		return (char*)"signalfd";
	case SCAP_FD_EVENTPOLL:
		return (char*)"eventpoll";
	case SCAP_FD_INOTIFY:
		return (char*)"inotify";
	case SCAP_FD_TIMERFD:
		return (char*)"timerfd";
	case SCAP_FD_NETLINK:
		return (char*)"netlink";
	default:
		return (char*)"<NA>";
	}
}

template<> string sinsp_fdinfo_t::tostring_clean()
{
	string m_tstr = m_name;
	sanitize_string(m_tstr);

	return m_tstr;
}

template<> void sinsp_fdinfo_t::add_filename(const char* fullpath)
{
	m_name = fullpath;
}

template<> bool sinsp_fdinfo_t::set_net_role_by_guessing(sinsp* inspector,
										  sinsp_threadinfo* ptinfo,
										  sinsp_fdinfo_t* pfdinfo,
										  bool incoming)
{
	//
	// If this process owns the port, mark it as server, otherwise mark it as client
	//
	if(ptinfo->is_bound_to_port(pfdinfo->m_sockinfo.m_ipv4info.m_fields.m_dport))
	{
		if(ptinfo->uses_client_port(pfdinfo->m_sockinfo.m_ipv4info.m_fields.m_sport))
		{
			goto wildass_guess;
		}

		pfdinfo->set_role_server();
		return true;
	}
	else
	{
		pfdinfo->set_role_client();
		return true;
	}

wildass_guess:
	if(!(pfdinfo->m_flags & (sinsp_fdinfo_t::FLAGS_ROLE_CLIENT | sinsp_fdinfo_t::FLAGS_ROLE_SERVER)))
	{
		//
		// We just assume that a server usually starts with a read and a client with a write
		//
		if(incoming)
		{
			pfdinfo->set_role_server();
		}
		else
		{
			pfdinfo->set_role_client();
		}
	}

	return true;
}

template<> scap_l4_proto sinsp_fdinfo_t::get_l4proto()
{
	scap_fd_type evt_type = m_type;

	if(evt_type == SCAP_FD_IPV4_SOCK)
	{
		if((scap_l4_proto)m_sockinfo.m_ipv4info.m_fields.m_l4proto == SCAP_L4_RAW)
		{
			return SCAP_L4_RAW;
		}

		if(is_role_none())
		{
			return SCAP_L4_NA;
		}

		return (scap_l4_proto)(m_sockinfo.m_ipv4info.m_fields.m_l4proto);
	}
	else if(evt_type == SCAP_FD_IPV4_SERVSOCK)
	{
		return (scap_l4_proto)(m_sockinfo.m_ipv4serverinfo.m_l4proto);
	}
	else if(evt_type == SCAP_FD_IPV6_SOCK)
	{
		if((scap_l4_proto)m_sockinfo.m_ipv6info.m_fields.m_l4proto == SCAP_L4_RAW)
		{
			return SCAP_L4_RAW;
		}

		if(is_role_none())
		{
			return SCAP_L4_NA;
		}

		return (scap_l4_proto)(m_sockinfo.m_ipv6info.m_fields.m_l4proto);
	}
	else if(evt_type == SCAP_FD_IPV6_SERVSOCK)
	{
		return (scap_l4_proto)(m_sockinfo.m_ipv6serverinfo.m_l4proto);
	}
	else
	{
		return SCAP_L4_NA;
	}
}

template<> void sinsp_fdinfo_t::register_event_callback(sinsp_pd_callback_type etype, sinsp_protodecoder* dec)
{
	if(this->m_callbaks == NULL)
	{
		m_callbaks = new fd_callbacks_info();
	}

	switch(etype)
	{
	case CT_READ:
		m_callbaks->m_read_callbacks.push_back(dec);
		break;
	case CT_WRITE:
		m_callbaks->m_write_callbacks.push_back(dec);
		break;
	default:
		ASSERT(false);
		break;
	}

	return;
}

template<> void sinsp_fdinfo_t::unregister_event_callback(sinsp_pd_callback_type etype, sinsp_protodecoder* dec)
{
	vector<sinsp_protodecoder*>::iterator it;

	if(m_callbaks == NULL)
	{
		ASSERT(false);
		return;
	}

	switch(etype)
	{
	case CT_READ:
		for(it = m_callbaks->m_read_callbacks.begin(); it != m_callbaks->m_read_callbacks.end(); ++it)
		{
			if(*it == dec)
			{
				m_callbaks->m_read_callbacks.erase(it);
				return;
			}
		}

		break;
	case CT_WRITE:
		for(it = m_callbaks->m_write_callbacks.begin(); it != m_callbaks->m_write_callbacks.end(); ++it)
		{
			if(*it == dec)
			{
				m_callbaks->m_write_callbacks.erase(it);
				return;
			}
		}

		break;
	default:
		ASSERT(false);
		break;
	}

	return;
}

///////////////////////////////////////////////////////////////////////////////
// sinsp_fdtable implementation
///////////////////////////////////////////////////////////////////////////////
sinsp_fdtable::sinsp_fdtable(sinsp* inspector)
{
	m_inspector = inspector;
	reset_cache();
}

sinsp_fdinfo_t* sinsp_fdtable::add(int64_t fd, sinsp_fdinfo_t* fdinfo)
{
	//
	// Look for the FD in the table
	//
	auto it = m_table.find(fd);

	// Three possible exits here:
	// 1. fd is not on the table
	//   a. the table size is under the limit so create a new entry
	//   b. table size is over the limit, discard the fd
	// 2. fd is already in the table, replace it
	if(it == m_table.end())
	{
		if(m_table.size() < m_inspector->m_max_fdtable_size)
		{
			//
			// No entry in the table, this is the normal case
			//
			m_last_accessed_fd = -1;
#ifdef GATHER_INTERNAL_STATS
			m_inspector->m_stats.m_n_added_fds++;
#endif
			pair<unordered_map<int64_t, sinsp_fdinfo_t>::iterator, bool> insert_res = m_table.emplace(fd, *fdinfo);
			return &(insert_res.first->second);
		}
		else
		{
			return nullptr;
		}
	}
	else
	{
		//
		// the fd is already in the table.
		//
		if(it->second.m_flags & sinsp_fdinfo_t::FLAGS_CLOSE_IN_PROGRESS)
		{
			//
			// Sometimes an FD-creating syscall can be called on an FD that is being closed (i.e
			// the close enter has arrived but the close exit has not arrived yet).
			// If this is the case, mark the new entry so that the successive close exit won't
			// destroy it.
			//
			fdinfo->m_flags &= ~sinsp_fdinfo_t::FLAGS_CLOSE_IN_PROGRESS;
			fdinfo->m_flags |= sinsp_fdinfo_t::FLAGS_CLOSE_CANCELED;

			m_table[CANCELED_FD_NUMBER] = it->second;
		}
		else
		{
			//
			// This can happen if:
			//  - the event is a dup2 or dup3 that overwrites an existing FD (perfectly legal)
			//  - a close() has been dropped when capturing
			//  - an fd has been closed by clone() or execve() (it happens when the fd is opened with the FD_CLOEXEC flag,
			//    which we don't currently parse.
			// In either case, removing the old fd, replacing it with the new one and keeping going is a reasonable
			// choice. We include an assertion to catch the situation.
			//
			// XXX Can't have this enabled until the FD_CLOEXEC flag is supported
			//ASSERT(false);
		}

		//
		// Replace the fd as a struct copy
		//
		it->second.copy(*fdinfo, true);
		return &(it->second);
	}
}

void sinsp_fdtable::erase(int64_t fd)
{
	unordered_map<int64_t, sinsp_fdinfo_t>::iterator fdit = m_table.find(fd);

	if(fd == m_last_accessed_fd)
	{
		m_last_accessed_fd = -1;
	}

	if(fdit == m_table.end())
	{
		//
		// Looks like there's no fd to remove.
		// Either the fd creation event was dropped or (more likely) our logic doesn't support the
		// call that created this fd. The assertion will detect it, while in release mode we just
		// keep going.
		//
		ASSERT(false);
#ifdef GATHER_INTERNAL_STATS
		m_inspector->m_stats.m_n_failed_fd_lookups++;
#endif
	}
	else
	{
		m_table.erase(fdit);
#ifdef GATHER_INTERNAL_STATS
		m_inspector->m_stats.m_n_noncached_fd_lookups++;
		m_inspector->m_stats.m_n_removed_fds++;
#endif
	}
}

void sinsp_fdtable::clear()
{
	m_table.clear();
}

size_t sinsp_fdtable::size()
{
	return m_table.size();
}

void sinsp_fdtable::reset_cache()
{
	m_last_accessed_fd = -1;
}
