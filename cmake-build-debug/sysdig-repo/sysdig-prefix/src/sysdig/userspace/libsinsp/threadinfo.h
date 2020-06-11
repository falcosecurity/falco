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

#ifndef VISIBILITY_PRIVATE
#define VISIBILITY_PRIVATE private:
#endif

#ifdef _WIN32
struct iovec {
	void  *iov_base;    /* Starting address */
	size_t iov_len;     /* Number of bytes to transfer */
};
#else
#include <sys/uio.h>
#endif

#include <functional>
#include <memory>
#include <set>
#include "fdinfo.h"
#include "internal_metrics.h"

class sinsp_delays_info;
class sinsp_threadtable_listener;
class sinsp_tracerparser;
class blprogram;

typedef struct erase_fd_params
{
	bool m_remove_from_table;
	int64_t m_fd;
	sinsp_threadinfo* m_tinfo;
	sinsp_fdinfo_t* m_fdinfo;
	uint64_t m_ts;
}erase_fd_params;

/** @defgroup state State management
 *  @{
 */

/*!
  \brief Thread/process information class.
  This class contains the full state for a thread, and a bunch of functions to
  manipulate threads and retrieve thread information.

  \note As a library user, you won't need to construct thread objects. Rather,
   you get them by calling \ref sinsp_evt::get_thread_info or
   \ref sinsp::get_thread.
  \note sinsp_threadinfo is also used to keep process state. For the sinsp
   library, a process is just a thread with TID=PID.
*/
class SINSP_PUBLIC sinsp_threadinfo
{
public:
	sinsp_threadinfo(sinsp *inspector = nullptr);
	virtual ~sinsp_threadinfo();

	/*!
	  \brief Return the name of the process containing this thread, e.g. "top".
	*/
	std::string get_comm();

	/*!
	  \brief Return the name of the process containing this thread from argv[0], e.g. "/bin/top".
	*/
	std::string get_exe();

	/*!
	  \brief Return the full executable path of the process containing this thread, e.g. "/bin/top".
	*/
	std::string get_exepath();

	/*!
	  \brief Return the working directory of the process containing this thread.
	*/
	std::string get_cwd();

	/*!
	  \brief Return the values of all environment variables for the process
	  containing this thread.
	*/
	const std::vector<std::string>& get_env();

	/*!
	  \brief Return the value of the specified environment variable for the process
	  containing this thread. Returns empty string if variable is not found.
	*/
	std::string get_env(const std::string& name);

	/*!
	  \brief Return true if this is a process' main thread.
	*/
	inline bool is_main_thread() const
	{
		return m_tid == m_pid;
	}

	/*!
	  \brief Get the main thread of the process containing this thread.
	*/
	inline sinsp_threadinfo* get_main_thread() const
	{
		auto main_thread = m_main_thread.lock();
		if(!main_thread)
		{
			//
			// Is this a child thread?
			//
			if(m_pid == m_tid)
			{
				//
				// No, this is either a single thread process or the root thread of a
				// multithread process.
				// Note: we don't set m_main_thread because there are cases in which this is
				//       invoked for a threadinfo that is in the stack. Caching the this pointer
				//       would cause future mess.
				//
				return const_cast<sinsp_threadinfo*>(this);
			}
			else
			{
				//
				// Yes, this is a child thread. Find the process root thread.
				//
				auto ptinfo = lookup_thread();
				if (!ptinfo)
				{
					return NULL;
				}
				m_main_thread = ptinfo;
				return &*ptinfo;
			}
		}

		return &*main_thread;
	}

	/*!
	  \brief Get the process that launched this thread's process.
	*/
	sinsp_threadinfo* get_parent_thread();

	/*!
	  \brief Retrieve information about one of this thread/process FDs.

	  \param fd The file descriptor number, e.g. 0 for stdin.

	  \return Pointer to the FD information, or NULL if the given FD doesn't
	   exist
	*/
	inline sinsp_fdinfo_t* get_fd(int64_t fd)
	{
		if(fd < 0)
		{
			return NULL;
		}

		sinsp_fdtable* fdt = get_fd_table();

		if(fdt)
		{
			sinsp_fdinfo_t *fdinfo = fdt->find(fd);
			if(fdinfo)
			{
				// Its current name is now its old
				// name. The name might change as a
				// result of parsing.
				fdinfo->m_oldname = fdinfo->m_name;
				return fdinfo;
			}
		}

		return NULL;
	}

	/*!
	  \brief Return true if this thread is bound to the given server port.
	*/
	bool is_bound_to_port(uint16_t number);

	/*!
	  \brief Return true if this thread has a client socket open on the given port.
	*/
	bool uses_client_port(uint16_t number);

	void* get_private_state(uint32_t id);

	/*!
	  \brief Return the ratio between open FDs and maximum available FDs for this thread.
	*/
	uint64_t get_fd_usage_pct();
	double get_fd_usage_pct_d();

	/*!
	  \brief Return the number of open FDs for this thread.
	*/
	uint64_t get_fd_opencount() const;

	/*!
	  \brief Return the maximum number of FDs this thread can open.
	*/
	uint64_t get_fd_limit();

	/*!
	  \brief Return the cgroup name for a specific subsystem
	 */
	 const std::string& get_cgroup(const std::string& subsys) const;

	//
	// Walk up the parent process hierarchy, calling the provided
	// function for each node. If the function returns false, the
	// traversal stops.
	//
	typedef std::function<bool (sinsp_threadinfo *)> visitor_func_t;
	void traverse_parent_state(visitor_func_t &visitor);

	static void populate_cmdline(std::string &cmdline, sinsp_threadinfo *tinfo);

	// Return true if this thread is a part of a healthcheck,
	// readiness probe, or liveness probe.
	bool is_health_probe();

	//
	// Core state
	//
	int64_t m_tid;  ///< The id of this thread
	int64_t m_pid; ///< The id of the process containing this thread. In single thread threads, this is equal to tid.
	int64_t m_ptid; ///< The id of the process that started this thread.
	int64_t m_sid; ///< The session id of the process containing this thread.
	std::string m_comm; ///< Command name (e.g. "top")
	std::string m_exe; ///< argv[0] (e.g. "sshd: user@pts/4")
	std::string m_exepath; ///< full executable path
	std::vector<std::string> m_args; ///< Command line arguments (e.g. "-d1")
	std::vector<std::string> m_env; ///< Environment variables
	std::vector<std::pair<std::string, std::string>> m_cgroups; ///< subsystem-cgroup pairs
	std::string m_container_id; ///< heuristic-based container id
	uint32_t m_flags; ///< The thread flags. See the PPM_CL_* declarations in ppm_events_public.h.
	int64_t m_fdlimit;  ///< The maximum number of FDs this thread can open
	uint32_t m_uid; ///< user id
	uint32_t m_gid; ///< group id
	uint64_t m_nchilds; ///< When this is 0 the process can be deleted
	uint32_t m_vmsize_kb; ///< total virtual memory (as kb).
	uint32_t m_vmrss_kb; ///< resident non-swapped memory (as kb).
	uint32_t m_vmswap_kb; ///< swapped memory (as kb).
	uint64_t m_pfmajor; ///< number of major page faults since start.
	uint64_t m_pfminor; ///< number of minor page faults since start.
	int64_t m_vtid;  ///< The virtual id of this thread.
	int64_t m_vpid; ///< The virtual id of the process containing this thread. In single thread threads, this is equal to vtid.
	int64_t m_vpgid; // The virtual process group id, as seen from its pid namespace
	std::string m_root;
	size_t m_program_hash; ///< Unique hash of the current program
	size_t m_program_hash_scripts;  ///< Unique hash of the current program, including arguments for scripting programs (like python or ruby)
	int32_t m_tty;
	int32_t m_loginuid; ///< loginuid (auid)

	// In some cases, a threadinfo has a category that identfies
	// why it was run. Descriptions:
	// CAT_NONE: no specific category
	// CAT_CONTAINER: a process run in a container and *not* any
	//                of the following more specific categories.
	// CAT_HEALTHCHECK: part of a container healthcheck
	// CAT_LIVENESS_PROBE: part of a k8s liveness probe
	// CAT_READINESS_PROBE: part of a k8s readiness probe
	enum command_category {
		CAT_NONE = 0,
		CAT_CONTAINER,
		CAT_HEALTHCHECK,
		CAT_LIVENESS_PROBE,
		CAT_READINESS_PROBE
	};

	command_category m_category;

	//
	// State for multi-event processing
	//
	int64_t m_lastevent_fd; ///< The FD os the last event used by this thread.
	uint64_t m_lastevent_ts; ///< timestamp of the last event for this thread.
	uint64_t m_prevevent_ts; ///< timestamp of the event before the last for this thread.
	uint64_t m_lastaccess_ts; ///< The last time this thread was looked up. Used when cleaning up the table.
	uint64_t m_clone_ts; ///< When the clone that started this process happened.

	//
	// Parser for the user events. Public so that filter fields can access it
	//
	sinsp_tracerparser* m_tracer_parser;

	size_t args_len() const;
	size_t env_len() const;
	size_t cgroups_len() const;

	void args_to_iovec(struct iovec **iov, int *iovcnt,
			   std::string &rem) const;

	void env_to_iovec(struct iovec **iov, int *iovcnt,
			  std::string &rem) const;

	void cgroups_to_iovec(struct iovec **iov, int *iovcnt,
			      std::string &rem) const;

#ifdef HAS_FILTERING
	//
	// State for filtering
	//
	uint64_t m_last_latency_entertime;
	uint64_t m_latency;
#endif

	//
	// Global state
	//
	sinsp *m_inspector;

public: // types required for use in sets
	struct hasher {
		size_t operator()(sinsp_threadinfo* tinfo) const
		{
			return tinfo->get_main_thread()->m_program_hash;
		}
	};

	struct comparer {
		size_t operator()(sinsp_threadinfo* lhs, sinsp_threadinfo* rhs) const
		{
			return lhs->get_main_thread()->m_program_hash == rhs->get_main_thread()->m_program_hash;
		}
	};

protected:
	inline sinsp_fdtable* get_fd_table()
	{
		if(!(m_flags & PPM_CL_CLONE_FILES))
		{
			return &m_fdtable;;
		}
		else
		{
			sinsp_threadinfo* root = get_main_thread();
			return (root == nullptr) ? nullptr : &(root->m_fdtable);
		}
	}

#ifndef _WIN32
	inline const sinsp_fdtable* get_fd_table() const
	{
		if(!(m_flags & PPM_CL_CLONE_FILES))
		{
			return &m_fdtable;;
		}
		else
		{
			sinsp_threadinfo* root = get_main_thread();
			return (root == nullptr) ? nullptr : &(root->m_fdtable);
		}
	}
#endif

public:
VISIBILITY_PRIVATE
	void init();
	// return true if, based on the current inspector filter, this thread should be kept
	void init(scap_threadinfo* pi);
	void fix_sockets_coming_from_proc();
	sinsp_fdinfo_t* add_fd(int64_t fd, sinsp_fdinfo_t *fdinfo);
	void add_fd_from_scap(scap_fdinfo *fdinfo, OUT sinsp_fdinfo_t *res);
	void remove_fd(int64_t fd);
	void set_cwd(const char *cwd, uint32_t cwdlen);
	sinsp_threadinfo* get_cwd_root();
	void set_args(const char* args, size_t len);
	void set_env(const char* env, size_t len);
	bool set_env_from_proc();
	void set_cgroups(const char* cgroups, size_t len);
	bool is_lastevent_data_valid();
	inline void set_lastevent_data_validity(bool isvalid)
	{
		if(isvalid)
		{
			m_lastevent_cpuid = (uint16_t)1;
		}
		else
		{
			m_lastevent_cpuid = (uint16_t) - 1;
		}
	}
	void allocate_private_state();
	void compute_program_hash();
	std::shared_ptr<sinsp_threadinfo> lookup_thread() const;

	size_t strvec_len(const std::vector<std::string> &strs) const;
	void strvec_to_iovec(const std::vector<std::string> &strs,
			     struct iovec **iov, int *iovcnt,
			     std::string &rem) const;

	void add_to_iovec(const std::string &str,
			  const bool include_trailing_null,
			  struct iovec &iov,
			  uint32_t &alen,
			  std::string &rem) const;

	void fd_to_scap(scap_fdinfo *dst, sinsp_fdinfo_t* src);

	//  void push_fdop(sinsp_fdop* op);
	// the queue of recent fd operations
	//  std::deque<sinsp_fdop> m_last_fdop;

	//
	// Parameters that can't be accessed directly because they could be in the
	// parent thread info
	//
	sinsp_fdtable m_fdtable; // The fd table of this thread
	std::string m_cwd; // current working directory
	mutable std::weak_ptr<sinsp_threadinfo> m_main_thread;
	uint8_t* m_lastevent_data; // Used by some event parsers to store the last enter event
	std::vector<void*> m_private_state;

	uint16_t m_lastevent_type;
	uint16_t m_lastevent_cpuid;
	sinsp_evt::category m_lastevent_category;
	bool m_parent_loop_detected;
	blprogram* m_blprogram;

	friend class sinsp;
	friend class sinsp_parser;
	friend class sinsp_analyzer;
	friend class sinsp_analyzer_parsers;
	friend class sinsp_evt;
	friend class sinsp_thread_manager;
	friend class sinsp_transaction_table;
	friend class sinsp_tracerparser;
	friend class lua_cbacks;
	friend class sinsp_baseliner;
};

/*@}*/

class threadinfo_map_t
{
public:
	typedef std::function<bool(sinsp_threadinfo&)> visitor_t;
	typedef std::shared_ptr<sinsp_threadinfo> ptr_t;

	inline void put(sinsp_threadinfo* tinfo)
	{
		m_threads[tinfo->m_tid] = ptr_t(tinfo);
	}

	inline sinsp_threadinfo* get(uint64_t tid)
	{
		auto it = m_threads.find(tid);
		if (it == m_threads.end())
		{
			return  nullptr;
		}
		return it->second.get();
	}

	inline ptr_t get_ref(uint64_t tid)
	{
		auto it = m_threads.find(tid);
		if (it == m_threads.end())
		{
			return  nullptr;
		}
		return it->second;
	}

	inline void erase(uint64_t tid)
	{
		m_threads.erase(tid);
	}

	inline void clear()
	{
		m_threads.clear();
	}

	bool loop(visitor_t callback)
	{
		for (auto& it : m_threads)
		{
			if (!callback(*it.second.get()))
			{
				return false;
			}
		}
		return true;
	}

	inline size_t size() const
	{
		return m_threads.size();
	}

protected:
	std::unordered_map<int64_t, ptr_t> m_threads;
};


///////////////////////////////////////////////////////////////////////////////
// Little class that manages the allocation of private state in the thread info class
///////////////////////////////////////////////////////////////////////////////
class sinsp_thread_privatestate_manager
{
public:
	//
	// The return value is the ID of the newly reserved memory area
	//
	uint32_t reserve(uint32_t size)
	{
		m_memory_sizes.push_back(size);
		return (uint32_t)m_memory_sizes.size() - 1;
	}

	uint32_t get_size()
	{
		return (uint32_t)m_memory_sizes.size();
	}

private:
	std::vector<uint32_t> m_memory_sizes;

	friend class sinsp_threadinfo;
};

///////////////////////////////////////////////////////////////////////////////
// This class manages the thread table
///////////////////////////////////////////////////////////////////////////////
class SINSP_PUBLIC sinsp_thread_manager
{
public:
	sinsp_thread_manager(sinsp* inspector);
	void clear();

	void set_listener(sinsp_threadtable_listener* listener);
	bool add_thread(sinsp_threadinfo *threadinfo, bool from_scap_proctable);
	void remove_thread(int64_t tid, bool force);
	// Returns true if the table is actually scanned
	// NOTE: this is implemented in sinsp.cpp so we can inline it from there
	inline bool remove_inactive_threads();
	void fix_sockets_coming_from_proc();
	void reset_child_dependencies();
	void create_child_dependencies();
	void recreate_child_dependencies();

	void dump_threads_to_file(scap_dumper_t* dumper);

	uint32_t get_thread_count()
	{
		return (uint32_t)m_threadtable.size();
	}

	void update_statistics();

	threadinfo_map_t* get_threads()
	{
		return &m_threadtable;
	}

	std::set<uint16_t> m_server_ports;

private:
	void increment_mainthread_childcount(sinsp_threadinfo* threadinfo);
	inline void clear_thread_pointers(sinsp_threadinfo& threadinfo);
	void free_dump_fdinfos(std::vector<scap_fdinfo*>* fdinfos_to_free);
	void thread_to_scap(sinsp_threadinfo& tinfo, scap_threadinfo* sctinfo);

	sinsp* m_inspector;
	threadinfo_map_t m_threadtable;
	int64_t m_last_tid;
	std::weak_ptr<sinsp_threadinfo> m_last_tinfo;
	uint64_t m_last_flush_time_ns;
	uint32_t m_n_drops;

	sinsp_threadtable_listener* m_listener;

	INTERNAL_COUNTER(m_failed_lookups);
	INTERNAL_COUNTER(m_cached_lookups);
	INTERNAL_COUNTER(m_non_cached_lookups);
	INTERNAL_COUNTER(m_added_threads);
	INTERNAL_COUNTER(m_removed_threads);

	friend class sinsp_parser;
	friend class sinsp_analyzer;
	friend class sinsp;
	friend class sinsp_threadinfo;
	friend class sinsp_baseliner;
};
