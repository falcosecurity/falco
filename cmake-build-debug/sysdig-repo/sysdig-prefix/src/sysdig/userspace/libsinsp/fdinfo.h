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
#include "sinsp_pd_callback_type.h"
#include <unordered_map>
#include <vector>

#ifdef _WIN32
#define CANCELED_FD_NUMBER INT64_MAX
#else
#define CANCELED_FD_NUMBER std::numeric_limits<int64_t>::max()
#endif

class sinsp_protodecoder;

// fd type characters
#define CHAR_FD_FILE			'f'
#define CHAR_FD_IPV4_SOCK		'4'
#define CHAR_FD_IPV6_SOCK		'6'
#define CHAR_FD_DIRECTORY		'd'
#define CHAR_FD_IPV4_SERVSOCK	'4'
#define CHAR_FD_IPV6_SERVSOCK	'6'
#define CHAR_FD_FIFO			'p'
#define CHAR_FD_UNIX_SOCK		'u'
#define CHAR_FD_EVENT			'e'
#define CHAR_FD_UNKNOWN			'o'
#define CHAR_FD_UNSUPPORTED		'X'
#define CHAR_FD_SIGNAL			's'
#define CHAR_FD_EVENTPOLL		'l'
#define CHAR_FD_INOTIFY			'i'
#define CHAR_FD_TIMERFD			't'
#define CHAR_FD_NETLINK			'n'

/** @defgroup state State management 
 * A collection of classes to query process and FD state.
 *  @{
 */

typedef union _sinsp_sockinfo
{
	ipv4tuple m_ipv4info; ///< The tuple if this an IPv4 socket.
	ipv6tuple m_ipv6info; ///< The tuple if this an IPv6 socket.
	ipv4serverinfo m_ipv4serverinfo;  ///< Information about an IPv4 server socket.
	ipv6serverinfo m_ipv6serverinfo; ///< Information about an IPv6 server socket.
	unix_tuple m_unixinfo; ///< The tuple if this a unix socket.
}sinsp_sockinfo;

class fd_callbacks_info
{
public:
	std::vector<sinsp_protodecoder*> m_write_callbacks;
	std::vector<sinsp_protodecoder*> m_read_callbacks;
};

/*!
  \brief File Descriptor information class.
  This class contains the full state for a FD, and a bunch of functions to
  manipulate FDs and retrieve FD information.

  \note As a library user, you won't need to construct thread objects. Rather,
   you get them by calling \ref sinsp_evt::get_fd_info or 
   \ref sinsp_threadinfo::get_fd.
*/template<class T>
class SINSP_PUBLIC sinsp_fdinfo
{
public:
	sinsp_fdinfo();
	sinsp_fdinfo (const sinsp_fdinfo &other) 
	{
		copy(other, false);
	}

	~sinsp_fdinfo()
	{
		if(m_callbaks != NULL)
		{
			delete m_callbaks;
		}

		if(m_usrstate != NULL)
		{
			delete m_usrstate;
		}
	}

	sinsp_fdinfo& operator=(const sinsp_fdinfo& other)
	{
		copy(other, true);
		return *this;
	}

	void reset();
	std::string* tostring();

	inline void copy(const sinsp_fdinfo &other, bool free_state)
	{
		m_type = other.m_type;
		m_openflags = other.m_openflags;	
		m_sockinfo = other.m_sockinfo;
		m_name = other.m_name;
		m_oldname = other.m_oldname;
		m_flags = other.m_flags;
		m_dev = other.m_dev;
		m_ino = other.m_ino;
		
		if(free_state)
		{
			if(m_callbaks != NULL)
			{
				delete m_callbaks;
			}

			if(m_usrstate != NULL)
			{
				delete m_usrstate;
			}
		}

		if(other.m_callbaks != NULL)
		{
			m_callbaks = new fd_callbacks_info();
			*m_callbaks = *other.m_callbaks;
		}
		else
		{
			m_callbaks = NULL;
		}

		if(other.m_usrstate != NULL)
		{
			m_usrstate = new T(*other.m_usrstate);
		}
		else
		{
			m_usrstate = NULL;
		}
	}

	/*!
	  \brief Return a single ASCII character that identifies the FD type.

	  Refer to the CHAR_FD_* defines in this fdinfo.h.
	*/
	char get_typechar();

	/*!
	  \brief Return an ASCII string that identifies the FD type.

	  Can be on of 'file', 'directory', ipv4', 'ipv6', 'unix', 'pipe', 'event', 'signalfd', 'eventpoll', 'inotify', 'signalfd'.
	*/
	char* get_typestring();

	/*!
	  \brief Return the fd name, after removing unprintable or invalid characters from it.
	*/
	std::string tostring_clean();

	/*!
	  \brief Returns true if this is a unix socket.
	*/
	bool is_unix_socket()
	{
		return m_type == SCAP_FD_UNIX_SOCK;
	}

	/*!
	  \brief Returns true if this is an IPv4 socket.
	*/
	bool is_ipv4_socket()
	{
		return m_type == SCAP_FD_IPV4_SOCK;
	}

	/*!
	  \brief Returns true if this is an IPv4 socket.
	*/
	bool is_ipv6_socket()
	{
		return m_type == SCAP_FD_IPV6_SOCK;
	}

	/*!
	  \brief Returns true if this is a UDP socket.
	*/
	bool is_udp_socket()
	{
		return m_type == SCAP_FD_IPV4_SOCK && m_sockinfo.m_ipv4info.m_fields.m_l4proto == SCAP_L4_UDP;
	}

	/*!
	  \brief Returns true if this is a unix TCP.
	*/
	bool is_tcp_socket()
	{
		return m_type == SCAP_FD_IPV4_SOCK && m_sockinfo.m_ipv4info.m_fields.m_l4proto == SCAP_L4_TCP;
	}

	/*!
	  \brief Returns true if this is a pipe.
	*/
	bool is_pipe()
	{
		return m_type == SCAP_FD_FIFO;
	}

	/*!
	  \brief Returns true if this is a file.
	*/
	bool is_file()
	{
		return m_type == SCAP_FD_FILE || m_type == SCAP_FD_FILE_V2;
	}

	/*!
	  \brief Returns true if this is a directory.
	*/
	bool is_directory()
	{
		return m_type == SCAP_FD_DIRECTORY;
	}

	uint16_t get_serverport()
	{
		if(m_type == SCAP_FD_IPV4_SOCK)
		{
			return m_sockinfo.m_ipv4info.m_fields.m_dport;
		}
		else if(m_type == SCAP_FD_IPV6_SOCK)
		{
			return m_sockinfo.m_ipv6info.m_fields.m_dport;
		}
		else
		{
			return 0;
		}
	}

	uint32_t get_device() const
	{
		return m_dev;
	}

	// see new_encode_dev in include/linux/kdev_t.h
	uint32_t get_device_major() const
	{
		return (m_dev & 0xfff00) >> 8;
	}

	// see new_encode_dev in include/linux/kdev_t.h
	uint32_t get_device_minor() const
	{
		return (m_dev & 0xff) | ((m_dev >> 12) & 0xfff00);
	}

	/*!
	  \brief If this is a socket, returns the IP protocol. Otherwise, return SCAP_FD_UNKNOWN.
	*/
	scap_l4_proto get_l4proto();

	/*!
	  \brief Used by protocol decoders to register callbacks related to this FD.
	*/
	void register_event_callback(sinsp_pd_callback_type etype, sinsp_protodecoder* dec);

	/*!
	  \brief Used by protocol decoders to unregister callbacks related to this FD.
	*/
	void unregister_event_callback(sinsp_pd_callback_type etype, sinsp_protodecoder* dec);

	/*!
	  \brief Return true if this FD is a socket server
	*/
	inline bool is_role_server()
	{
		return (m_flags & FLAGS_ROLE_SERVER) == FLAGS_ROLE_SERVER;
	}

	/*!
	  \brief Return true if this FD is a socket client
	*/
	inline bool is_role_client()
	{
		return (m_flags & FLAGS_ROLE_CLIENT) == FLAGS_ROLE_CLIENT;
	}

	/*!
	  \brief Return true if this FD is neither a client nor a server
	*/
	inline bool is_role_none()
	{
		return (m_flags & (FLAGS_ROLE_CLIENT | FLAGS_ROLE_SERVER)) == 0;
	}

	inline bool is_socket_connected()
	{
		return (m_flags & FLAGS_SOCKET_CONNECTED) == FLAGS_SOCKET_CONNECTED;
	}

	inline bool is_socket_pending()
	{
		return (m_flags & FLAGS_CONNECTION_PENDING) == FLAGS_CONNECTION_PENDING;
	}

	inline bool is_socket_failed()
	{
		return (m_flags & FLAGS_CONNECTION_FAILED) == FLAGS_CONNECTION_FAILED;
	}

	inline bool is_cloned()
	{
		return (m_flags & FLAGS_IS_CLONED) == FLAGS_IS_CLONED;
	}

	scap_fd_type m_type; ///< The fd type, e.g. file, directory, IPv4 socket...
	uint32_t m_openflags; ///< If this FD is a file, the flags that were used when opening it. See the PPM_O_* definitions in driver/ppm_events_public.h.
	
	/*!
	  \brief Socket-specific state.
	  This is uninitialized for non-socket FDs.
	*/
	sinsp_sockinfo m_sockinfo;

	std::string m_name; ///< Human readable rendering of this FD. For files, this is the full file name. For sockets, this is the tuple. And so on.
	std::string m_oldname; // The name of this fd at the beginning of event parsing. Used to detect name changes that result from parsing an event.

	inline bool has_decoder_callbacks()
	{
		return (m_callbaks != NULL);
	}

VISIBILITY_PRIVATE

// Doxygen doesn't understand VISIBILITY_PRIVATE
#ifdef _DOXYGEN
private:
#endif

	/*!
	  \brief FD flags.
	*/
	enum flags
	{
		FLAGS_NONE = 0,
		FLAGS_FROM_PROC = (1 << 0),
		//FLAGS_TRANSACTION = (1 << 1),
		FLAGS_ROLE_CLIENT = (1 << 2),
		FLAGS_ROLE_SERVER = (1 << 3),
		FLAGS_CLOSE_IN_PROGRESS = (1 << 4),
		FLAGS_CLOSE_CANCELED = (1 << 5),
		FLAGS_IS_SOCKET_PIPE = (1 << 6),
		FLAGS_IS_TRACER_FILE = (1 << 7),
		FLAGS_IS_TRACER_FD = (1 << 8),
		FLAGS_IS_NOT_TRACER_FD = (1 << 9),
		FLAGS_IN_BASELINE_R = (1 << 10),
		FLAGS_IN_BASELINE_RW = (1 << 11),
		FLAGS_IN_BASELINE_OTHER = (1 << 12),
		FLAGS_SOCKET_CONNECTED = (1 << 13),
		FLAGS_IS_CLONED = (1 << 14),
		FLAGS_CONNECTION_PENDING = (1 << 15),
		FLAGS_CONNECTION_FAILED = (1 << 16),
	};

	void add_filename(const char* fullpath);

public:
	inline bool is_transaction() const
	{
		return (m_usrstate != NULL); 
	}

	T* get_usrstate()
	{
		return m_usrstate;
	}


	

private:
	inline void set_role_server()
	{
		m_flags |= FLAGS_ROLE_SERVER;
	}

	inline void set_role_client()
	{
		m_flags |= FLAGS_ROLE_CLIENT;
	}

	bool set_net_role_by_guessing(sinsp* inspector, 
		sinsp_threadinfo* ptinfo, 
		sinsp_fdinfo_t* pfdinfo,
		bool incoming);

	inline void reset_flags()
	{
		m_flags = FLAGS_NONE;
	}

	inline void set_socketpipe()
	{
		m_flags |= FLAGS_IS_SOCKET_PIPE;
	}

	inline bool is_socketpipe()
	{
		return (m_flags & FLAGS_IS_SOCKET_PIPE) == FLAGS_IS_SOCKET_PIPE; 
	}

	inline bool has_no_role()
	{
		return !is_role_client() && !is_role_server();
	}

	inline void set_inpipeline_r()
	{
		m_flags |= FLAGS_IN_BASELINE_R;
	}

	inline void set_inpipeline_rw()
	{
		m_flags |= FLAGS_IN_BASELINE_RW;
	}

	inline void set_inpipeline_other()
	{
		m_flags |= FLAGS_IN_BASELINE_OTHER;
	}

	inline void reset_inpipeline()
	{
		m_flags &= ~FLAGS_IN_BASELINE_R;
		m_flags &= ~FLAGS_IN_BASELINE_RW;
		m_flags &= ~FLAGS_IN_BASELINE_OTHER;
	}

	inline bool is_inpipeline_r()
	{
		return (m_flags & FLAGS_IN_BASELINE_R) == FLAGS_IN_BASELINE_R; 
	}

	inline bool is_inpipeline_rw()
	{
		return (m_flags & FLAGS_IN_BASELINE_RW) == FLAGS_IN_BASELINE_RW; 
	}

	inline bool is_inpipeline_other()
	{
		return (m_flags & FLAGS_IN_BASELINE_OTHER) == FLAGS_IN_BASELINE_OTHER; 
	}

	inline void set_socket_connected()
	{
		m_flags &= ~(FLAGS_CONNECTION_PENDING | FLAGS_CONNECTION_FAILED);
		m_flags |= FLAGS_SOCKET_CONNECTED;
	}

	inline void set_socket_pending()
	{
		m_flags &= ~(FLAGS_SOCKET_CONNECTED | FLAGS_CONNECTION_FAILED);
		m_flags |= FLAGS_CONNECTION_PENDING;
	}

	inline void set_socket_failed()
	{
		m_flags &= ~(FLAGS_SOCKET_CONNECTED | FLAGS_CONNECTION_PENDING);
		m_flags |= FLAGS_CONNECTION_FAILED;
	}

	inline void set_is_cloned()
	{
		m_flags |= FLAGS_IS_CLONED;
	}

	T* m_usrstate;
	uint32_t m_flags;
	uint32_t m_dev;
	uint64_t m_ino;

	fd_callbacks_info* m_callbaks;

	friend class sinsp;
	friend class sinsp_parser;
	friend class sinsp_threadinfo;
	friend class sinsp_analyzer;
	friend class sinsp_analyzer_fd_listener;
	friend class sinsp_fdtable;
	friend class sinsp_filter_check_fd;
	friend class sinsp_filter_check_event;
	friend class lua_cbacks;
	friend class sinsp_proto_detector;
	friend class sinsp_baseliner;
};

/*@}*/

///////////////////////////////////////////////////////////////////////////////
// fd info table
///////////////////////////////////////////////////////////////////////////////
class sinsp_fdtable
{
public:
	sinsp_fdtable(sinsp* inspector);

	inline sinsp_fdinfo_t* find(int64_t fd)
	{
		std::unordered_map<int64_t, sinsp_fdinfo_t>::iterator fdit;

		//
		// Try looking up in our simple cache
		//
		if(m_last_accessed_fd != -1 && fd == m_last_accessed_fd)
		{
	#ifdef GATHER_INTERNAL_STATS
			m_inspector->m_stats.m_n_cached_fd_lookups++;
	#endif
			return m_last_accessed_fdinfo;
		}

		//
		// Caching failed, do a real lookup
		//
		fdit = m_table.find(fd);

		if(fdit == m_table.end())
		{
	#ifdef GATHER_INTERNAL_STATS
			m_inspector->m_stats.m_n_failed_fd_lookups++;
	#endif
			return NULL;
		}
		else
		{
	#ifdef GATHER_INTERNAL_STATS
			m_inspector->m_stats.m_n_noncached_fd_lookups++;
	#endif
			m_last_accessed_fd = fd;
			m_last_accessed_fdinfo = &(fdit->second);
			return &(fdit->second);
		}
	}
	
	// If the key is already present, overwrite the existing value and return false.
	sinsp_fdinfo_t* add(int64_t fd, sinsp_fdinfo_t* fdinfo);
	// If the key is present, returns true, otherwise returns false.
	void erase(int64_t fd);
	void clear();
	size_t size();
	void reset_cache();

	sinsp* m_inspector;
	std::unordered_map<int64_t, sinsp_fdinfo_t> m_table;

	//
	// Simple fd cache
	//
	int64_t m_last_accessed_fd;
	sinsp_fdinfo_t *m_last_accessed_fdinfo;
};
