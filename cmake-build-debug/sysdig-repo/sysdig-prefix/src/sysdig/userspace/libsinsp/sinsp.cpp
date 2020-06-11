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

#include <stdio.h>
#include <stdlib.h>
#ifndef _WIN32
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/time.h>
#endif // _WIN32

#include "scap_open_exception.h"
#include "sinsp.h"
#include "sinsp_int.h"
#include "sinsp_auth.h"
#include "filter.h"
#include "filterchecks.h"
#include "chisel.h"
#include "cyclewriter.h"
#include "protodecoder.h"
#include "dns_manager.h"

#ifndef CYGWING_AGENT
#include "k8s_api_handler.h"
#ifdef HAS_CAPTURE
#include <curl/curl.h>
#include <mntent.h>
#endif
#endif

#ifdef HAS_ANALYZER
#include "analyzer_int.h"
#include "analyzer.h"
#include "tracer_emitter.h"
#endif

#ifdef HAS_CHISELS
extern vector<chiseldir_info>* g_chisel_dirs;
#endif

void on_new_entry_from_proc(void* context, scap_t* handle, int64_t tid, scap_threadinfo* tinfo,
							scap_fdinfo* fdinfo);

///////////////////////////////////////////////////////////////////////////////
// sinsp implementation
///////////////////////////////////////////////////////////////////////////////
sinsp::sinsp() :
	m_external_event_processor(),
	m_evt(this),
	m_lastevent_ts(0),
	m_container_manager(this),
	m_suppressed_comms()
{
#if !defined(CYGWING_AGENT) && defined(HAS_CAPTURE)
	// used by mesos and container_manager
	curl_global_init(CURL_GLOBAL_DEFAULT);
#endif
	m_h = NULL;
	m_parser = NULL;
	m_dumper = NULL;
	m_is_dumping = false;
	m_metaevt = NULL;
	m_meinfo.m_piscapevt = NULL;
	m_network_interfaces = NULL;
	m_parser = new sinsp_parser(this);
	m_thread_manager = new sinsp_thread_manager(this);
	m_max_thread_table_size = DEFAULT_THREAD_TABLE_SIZE;
	m_max_fdtable_size = MAX_FD_TABLE_SIZE;
	m_thread_timeout_ns = DEFAULT_THREAD_TIMEOUT_S * ONE_SECOND_IN_NS;
	m_inactive_thread_scan_time_ns = DEFAULT_INACTIVE_THREAD_SCAN_TIME_S * ONE_SECOND_IN_NS;
	m_inactive_container_scan_time_ns = DEFAULT_INACTIVE_CONTAINER_SCAN_TIME_S * ONE_SECOND_IN_NS;
	m_cycle_writer = NULL;
	m_write_cycling = false;

#ifdef HAS_FILTERING
	m_filter = NULL;
	m_evttype_filter = NULL;
#endif

	m_fds_to_remove = new vector<int64_t>;
	m_machine_info = NULL;
#ifdef SIMULATE_DROP_MODE
	m_isdropping = false;
#endif
	m_n_proc_lookups = 0;
	m_n_proc_lookups_duration_ns = 0;
	m_n_main_thread_lookups = 0;
	m_snaplen = DEFAULT_SNAPLEN;
	m_buffer_format = sinsp_evt::PF_NORMAL;
	m_input_fd = 0;
	m_bpf = false;
	m_isdebug_enabled = false;
	m_isfatfile_enabled = false;
	m_isinternal_events_enabled = false;
	m_hostname_and_port_resolution_enabled = false;
	m_output_time_flag = 'h';
	m_max_evt_output_len = 0;
	m_filesize = -1;
	m_track_tracers_state = false;
	m_import_users = true;
	m_next_flush_time_ns = 0;
	m_last_procrequest_tod = 0;
	m_get_procs_cpu_from_driver = false;
	m_is_tracers_capture_enabled = false;
	m_file_start_offset = 0;
	m_flush_memory_dump = false;
	m_next_stats_print_time_ns = 0;
	m_large_envs_enabled = false;
	m_increased_snaplen_port_range = DEFAULT_INCREASE_SNAPLEN_PORT_RANGE;
	m_statsd_port = -1;

	// Unless the cmd line arg "-pc" or "-pcontainer" is supplied this is false
	m_print_container_data = false;

#if defined(HAS_CAPTURE)
	m_sysdig_pid = getpid();
#endif

	uint32_t evlen = sizeof(scap_evt) + 2 * sizeof(uint16_t) + 2 * sizeof(uint64_t);
	m_meinfo.m_piscapevt = (scap_evt*)new char[evlen];
	m_meinfo.m_piscapevt->type = PPME_PROCINFO_E;
	m_meinfo.m_piscapevt->len = evlen;
	m_meinfo.m_piscapevt->nparams = 2;
	uint16_t* lens = (uint16_t*)((char *)m_meinfo.m_piscapevt + sizeof(struct ppm_evt_hdr));
	lens[0] = 8;
	lens[1] = 8;
	m_meinfo.m_piscapevt_vals = (uint64_t*)(lens + 2);

	m_meinfo.m_pievt.m_inspector = this;
	m_meinfo.m_pievt.m_info = &(g_infotables.m_event_info[PPME_SYSDIGEVENT_X]);
	m_meinfo.m_pievt.m_pevt = NULL;
	m_meinfo.m_pievt.m_cpuid = 0;
	m_meinfo.m_pievt.m_evtnum = 0;
	m_meinfo.m_pievt.m_pevt = m_meinfo.m_piscapevt;
	m_meinfo.m_pievt.m_fdinfo = NULL;
	m_meinfo.m_n_procinfo_evts = 0;
	m_meta_event_callback = NULL;
	m_meta_event_callback_data = NULL;
#ifndef CYGWING_AGENT
	m_k8s_client = NULL;
	m_k8s_last_watch_time_ns = 0;

	m_k8s_client = NULL;
	m_k8s_api_server = NULL;
	m_k8s_api_cert = NULL;

	m_mesos_client = NULL;
	m_mesos_last_watch_time_ns = 0;
#endif

	m_filter_proc_table_when_saving = false;
}

sinsp::~sinsp()
{
	close();

	if(m_fds_to_remove)
	{
		delete m_fds_to_remove;
	}

	if(m_parser)
	{
		delete m_parser;
		m_parser = NULL;
	}

	if(m_thread_manager)
	{
		delete m_thread_manager;
		m_thread_manager = NULL;
	}

	if(m_cycle_writer)
	{
		delete m_cycle_writer;
		m_cycle_writer = NULL;
	}

	if(m_meinfo.m_piscapevt)
	{
		delete[] m_meinfo.m_piscapevt;
	}

	m_container_manager.cleanup();

#ifndef CYGWING_AGENT
	delete m_k8s_client;
	delete m_k8s_api_server;
	delete m_k8s_api_cert;

	delete m_mesos_client;
#ifdef HAS_CAPTURE
	curl_global_cleanup();
	sinsp_dns_manager::get().cleanup();
#endif
#endif
}

void sinsp::add_protodecoders()
{
	m_parser->add_protodecoder("syslog");
}

void sinsp::filter_proc_table_when_saving(bool filter)
{
	m_filter_proc_table_when_saving = filter;

	if(m_h != NULL)
	{
		scap_set_refresh_proc_table_when_saving(m_h, !filter);
	}
}

void sinsp::enable_tracers_capture()
{
#if defined(HAS_CAPTURE) && ! defined(CYGWING_AGENT)
	if(!m_is_tracers_capture_enabled)
	{
		if(is_live() && m_h != NULL)
		{
			if(scap_enable_tracers_capture(m_h) != SCAP_SUCCESS)
			{
				throw sinsp_exception("error enabling tracers capture");
			}
		}

		m_is_tracers_capture_enabled = true;
	}
#endif
}

void sinsp::enable_page_faults()
{
#if defined(HAS_CAPTURE) && ! defined(CYGWING_AGENT)
	if(is_live() && m_h != NULL)
	{
		if(scap_enable_page_faults(m_h) != SCAP_SUCCESS)
		{
			throw sinsp_exception("error enabling page_faults");
		}
	}
#endif
}

void sinsp::init()
{
	//
	// Retrieve machine information
	//
	m_machine_info = scap_get_machine_info(m_h);
	if(m_machine_info != NULL)
	{
		m_num_cpus = m_machine_info->num_cpus;
	}
	else
	{
		ASSERT(false);
		m_num_cpus = 0;
	}

	//
	// Attach the protocol decoders
	//
#ifndef HAS_ANALYZER
	add_protodecoders();
#endif
	//
	// Allocate the cycle writer
	//
	if(m_cycle_writer)
	{
		delete m_cycle_writer;
		m_cycle_writer = NULL;
	}

	m_cycle_writer = new cycle_writer(is_live());

	//
	// Basic inits
	//
#ifdef GATHER_INTERNAL_STATS
	m_stats.clear();
#endif

	m_nevts = 0;
	m_tid_to_remove = -1;
	m_lastevent_ts = 0;
#ifdef HAS_FILTERING
	m_firstevent_ts = 0;
#endif
	m_fds_to_remove->clear();
	m_n_proc_lookups = 0;
	m_n_proc_lookups_duration_ns = 0;
	m_n_main_thread_lookups = 0;

	//
	// Return the tracers to the pool and clear the tracers list
	//
	for(auto it = m_partial_tracers_list.begin(); it != m_partial_tracers_list.end(); ++it)
	{
		m_partial_tracers_pool->push(*it);
	}
	m_partial_tracers_list.clear();

	//
	// If we're reading from file, we try to pre-parse the container events before
	// importing the thread table, so that thread table filtering will work with
	// container filters
	//
	if(is_capture())
	{
		uint64_t off = scap_ftell(m_h);
		scap_evt* pevent;
		uint16_t pcpuid;
		uint32_t ncnt = 0;

		//
		// Count how many container events we have
		//
		while(true)
		{
			int32_t res = scap_next(m_h, &pevent, &pcpuid);

			if(res == SCAP_SUCCESS)
			{
				if((pevent->type != PPME_CONTAINER_E) && (pevent->type != PPME_CONTAINER_JSON_E))
				{
					break;
				}
				else
				{
					ncnt++;
					continue;
				}
			}
			else
			{
				break;
			}
		}

		if (m_external_event_processor)
		{
			m_external_event_processor->on_capture_start();
		}

		//
		// Rewind, reset the event count, and consume the exact number of events
		//
		scap_fseek(m_h, off);
		scap_event_reset_count(m_h);
		for(uint32_t j = 0; j < ncnt; j++)
		{
			sinsp_evt* tevt;
			next(&tevt);
		}
	}

	if(is_capture() || m_filter_proc_table_when_saving == true)
	{
		import_thread_table();
	}

	import_ifaddr_list();

	import_user_list();

	//
	// Scan the list to create the proper parent/child dependencies
	//
	m_thread_manager->create_child_dependencies();

	//
	// Scan the list to fix the direction of the sockets
	//
	m_thread_manager->fix_sockets_coming_from_proc();

	if (m_external_event_processor)
	{
		m_external_event_processor->on_capture_start();
	}
	//
	// If m_snaplen was modified, we set snaplen now
	//
	if(m_snaplen != DEFAULT_SNAPLEN)
	{
		set_snaplen(m_snaplen);
	}

	//
	// If the port range for increased snaplen was modified, set it now
	//
	if(increased_snaplen_port_range_set())
	{
		set_fullcapture_port_range(m_increased_snaplen_port_range.range_start,
		                           m_increased_snaplen_port_range.range_end);
	}

	//
	// If the statsd port was modified, push it to the kernel now.
	//
	if(m_statsd_port != -1)
	{
		set_statsd_port(m_statsd_port);
	}

#if defined(HAS_CAPTURE)
	if(m_mode == SCAP_MODE_LIVE)
	{
		if(scap_getpid_global(m_h, &m_sysdig_pid) != SCAP_SUCCESS)
		{
			ASSERT(false);
		}
	}
#endif
}

void sinsp::set_import_users(bool import_users)
{
	m_import_users = import_users;
}

void sinsp::open(uint32_t timeout_ms)
{
	char error[SCAP_LASTERR_SIZE];

	g_logger.log("starting live capture");

	//
	// Reset the thread manager
	//
	m_thread_manager->clear();

	//
	// Start the capture
	//
	m_mode = SCAP_MODE_LIVE;
	scap_open_args oargs;
	oargs.mode = SCAP_MODE_LIVE;
	oargs.fname = NULL;
	oargs.proc_callback = NULL;
	oargs.proc_callback_context = NULL;

	if(!m_filter_proc_table_when_saving)
	{
		oargs.proc_callback = ::on_new_entry_from_proc;
		oargs.proc_callback_context = this;
	}
	oargs.import_users = m_import_users;

	add_suppressed_comms(oargs);

	if(m_bpf)
	{
		oargs.bpf_probe = m_bpf_probe.c_str();
	}
	else
	{
		oargs.bpf_probe = NULL;
	}

	add_suppressed_comms(oargs);

	int32_t scap_rc;
	m_h = scap_open(oargs, error, &scap_rc);

	if(m_h == NULL)
	{
		throw scap_open_exception(error, scap_rc);
	}

	scap_set_refresh_proc_table_when_saving(m_h, !m_filter_proc_table_when_saving);

	init();
}

void sinsp::open_nodriver()
{
	char error[SCAP_LASTERR_SIZE];

	g_logger.log("starting optimized sinsp");

	//
	// Reset the thread manager
	//
	m_thread_manager->clear();

	//
	// Start the capture
	//
	m_mode = SCAP_MODE_NODRIVER;
	scap_open_args oargs;
	oargs.mode = SCAP_MODE_NODRIVER;
	oargs.fname = NULL;
	oargs.proc_callback = NULL;
	oargs.proc_callback_context = NULL;
	if(!m_filter_proc_table_when_saving)
	{
		oargs.proc_callback = ::on_new_entry_from_proc;
		oargs.proc_callback_context = this;
	}
	oargs.import_users = m_import_users;

	int32_t scap_rc;
	m_h = scap_open(oargs, error, &scap_rc);

	if(m_h == NULL)
	{
		throw scap_open_exception(error, scap_rc);
	}

	scap_set_refresh_proc_table_when_saving(m_h, !m_filter_proc_table_when_saving);

	init();
}

int64_t sinsp::get_file_size(const std::string& fname, char *error)
{
	static string err_str = "Could not determine capture file size: ";
	std::string errdesc;
#ifdef _WIN32
	LARGE_INTEGER li = { 0 };
	HANDLE fh = CreateFile(fname.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL,
		OPEN_EXISTING, FILE_ATTRIBUTE_READONLY, NULL);
	if (fh != INVALID_HANDLE_VALUE)
	{
		if (0 != GetFileSizeEx(fh, &li))
		{
			CloseHandle(fh);
			return li.QuadPart;
		}
		errdesc = get_error_desc(err_str);
		CloseHandle(fh);
	}
#else
	struct stat st;
	if (0 == stat(fname.c_str(), &st))
	{
		return st.st_size;
	}
#endif
	if(errdesc.empty()) errdesc = get_error_desc(err_str);
	strncpy(error, errdesc.c_str(), errdesc.size() > SCAP_LASTERR_SIZE ? SCAP_LASTERR_SIZE : errdesc.size());
	return -1;
}

void sinsp::set_simpledriver_mode()
{
	if(scap_enable_simpledriver_mode(m_h) != SCAP_SUCCESS)
	{
		throw sinsp_exception(scap_getlasterr(m_h));
	}
}

unsigned sinsp::m_num_possible_cpus = 0;

unsigned sinsp::num_possible_cpus()
{
	if(m_num_possible_cpus == 0)
	{
		m_num_possible_cpus = read_num_possible_cpus();
		if(m_num_possible_cpus == 0)
		{
			g_logger.log("Unable to read num_possible_cpus, falling back to 128", sinsp_logger::SEV_WARNING);
			m_num_possible_cpus = 128;
		}
	}
	return m_num_possible_cpus;
}

vector<long> sinsp::get_n_tracepoint_hit()
{
	vector<long> ret(num_possible_cpus(), 0);
	if(scap_get_n_tracepoint_hit(m_h, ret.data()) != SCAP_SUCCESS)
	{
		throw sinsp_exception(scap_getlasterr(m_h));
	}
	return ret;
}

std::string sinsp::get_error_desc(const std::string& msg)
{
#ifdef _WIN32
	DWORD err_no = GetLastError(); // first, so error is not wiped out by intermediate calls
	std::string errstr = msg;
	DWORD flg = FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS;
	LPTSTR msg_buf = 0;
	if(FormatMessageA(flg, 0, err_no, 0, (LPTSTR)&msg_buf, 0, NULL))
	if(msg_buf)
	{
		errstr.append(msg_buf, strlen(msg_buf));
		LocalFree(msg_buf);
	}
#else
	char* msg_buf = strerror(errno); // first, so error is not wiped out by intermediate calls
	std::string errstr = msg;
	if(msg_buf)
	{
		errstr.append(msg_buf, strlen(msg_buf));
	}
#endif
	return errstr;
}

void sinsp::open_int()
{
	char error[SCAP_LASTERR_SIZE] = {0};

	//
	// Reset the thread manager
	//
	m_thread_manager->clear();

	//
	// Start the capture
	//
	m_mode = SCAP_MODE_CAPTURE;
	scap_open_args oargs;
	oargs.mode = SCAP_MODE_CAPTURE;
	if(m_input_fd != 0)
	{
		oargs.fd = m_input_fd;
	}
	else
	{
		oargs.fd = 0;
		oargs.fname = m_input_filename.c_str();
	}
	oargs.proc_callback = NULL;
	oargs.proc_callback_context = NULL;
	oargs.import_users = m_import_users;
	if(m_file_start_offset != 0)
	{
		oargs.start_offset = m_file_start_offset;
	}
	else
	{
		oargs.start_offset = 0;
	}

	add_suppressed_comms(oargs);

	int32_t scap_rc;
	m_h = scap_open(oargs, error, &scap_rc);

	if(m_h == NULL)
	{
		throw scap_open_exception(error, scap_rc);
	}

	if(m_input_fd != 0)
	{
		// We can't get a reliable filesize
		m_filesize = 0;
	}
	else
	{
		m_filesize = get_file_size(m_input_filename, error);

		if(m_filesize < 0)
		{
			throw sinsp_exception(error);
		}
	}

	init();
}

void sinsp::open(const std::string &filename)
{
	if(filename.empty())
	{
		open();
		return;
	}

	m_input_filename = filename;

	g_logger.log("starting offline capture");

	open_int();
}

void sinsp::fdopen(int fd)
{
	m_input_fd = fd;

	g_logger.log("starting offline capture");

	open_int();
}

void sinsp::close()
{
	if(m_h)
	{
		scap_close(m_h);
		m_h = NULL;
	}

	if(NULL != m_dumper)
	{
		scap_dump_close(m_dumper);
		m_dumper = NULL;
	}

	m_is_dumping = false;

	if(NULL != m_network_interfaces)
	{
		delete m_network_interfaces;
		m_network_interfaces = NULL;
	}

#ifdef HAS_FILTERING
	if(m_filter != NULL)
	{
		delete m_filter;
		m_filter = NULL;
	}

	if(m_evttype_filter != NULL)
	{
		delete m_evttype_filter;
		m_evttype_filter = NULL;
	}
#endif
}

void sinsp::autodump_start(const string& dump_filename, bool compress)
{
	if(NULL == m_h)
	{
		throw sinsp_exception("inspector not opened yet");
	}

	if(compress)
	{
		m_dumper = scap_dump_open(m_h, dump_filename.c_str(), SCAP_COMPRESSION_GZIP, false);
	}
	else
	{
		m_dumper = scap_dump_open(m_h, dump_filename.c_str(), SCAP_COMPRESSION_NONE, false);
	}

	m_is_dumping = true;

	if(NULL == m_dumper)
	{
		throw sinsp_exception(scap_getlasterr(m_h));
	}

	m_container_manager.dump_containers(m_dumper);
}

void sinsp::autodump_next_file()
{
	autodump_stop();
	autodump_start(m_cycle_writer->get_current_file_name(), m_compress);
}

void sinsp::autodump_stop()
{
	if(NULL == m_h)
	{
		throw sinsp_exception("inspector not opened yet");
	}

	if(m_dumper != NULL)
	{
		scap_dump_close(m_dumper);
		m_dumper = NULL;
	}

	m_is_dumping = false;
}

void sinsp::on_new_entry_from_proc(void* context,
								   scap_t* handle,
								   int64_t tid,
								   scap_threadinfo* tinfo,
								   scap_fdinfo* fdinfo)
{
	ASSERT(tinfo != NULL);

	m_h = handle;

	//
	// Retrieve machine information if we don't have it yet
	//
	{
		m_machine_info = scap_get_machine_info(handle);
		if(m_machine_info != NULL)
		{
			m_num_cpus = m_machine_info->num_cpus;
		}
		else
		{
			ASSERT(false);
			m_num_cpus = 0;
		}
	}

	//
	// Add the thread or FD
	//
	if(fdinfo == NULL)
	{
		bool thread_added = false;
		sinsp_threadinfo* newti = build_threadinfo();
		newti->init(tinfo);
		if(is_nodriver())
		{
			auto sinsp_tinfo = find_thread(tid, true);
			if(sinsp_tinfo == nullptr || newti->m_clone_ts > sinsp_tinfo->m_clone_ts)
			{
				thread_added = m_thread_manager->add_thread(newti, true);
			}
		}
		else
		{
			thread_added = m_thread_manager->add_thread(newti, true);
		}
		if (!thread_added) {
			delete newti;
		}
	}
	else
	{
		auto sinsp_tinfo = find_thread(tid, true);

		if(!sinsp_tinfo)
		{
			sinsp_threadinfo* newti = build_threadinfo();
			newti->init(tinfo);

			if (!m_thread_manager->add_thread(newti, true)) {
				ASSERT(false);
				delete newti;
				return;
			}

			sinsp_tinfo = find_thread(tid, true);
			if (!sinsp_tinfo) {
				ASSERT(false);
				return;
			}
		}

		sinsp_fdinfo_t sinsp_fdinfo;
		sinsp_tinfo->add_fd_from_scap(fdinfo, &sinsp_fdinfo);
	}
}

void on_new_entry_from_proc(void* context,
							scap_t* handle,
							int64_t tid,
							scap_threadinfo* tinfo,
							scap_fdinfo* fdinfo)
{
	sinsp* _this = (sinsp*)context;
	_this->on_new_entry_from_proc(context, handle, tid, tinfo, fdinfo);
}

void sinsp::import_thread_table()
{
	scap_threadinfo *pi;
	scap_threadinfo *tpi;

	scap_threadinfo *table = scap_get_proc_table(m_h);

	//
	// Scan the scap table and add the threads to our list
	//
	HASH_ITER(hh, table, pi, tpi)
	{
		sinsp_threadinfo* newti = build_threadinfo();
		newti->init(pi);
		m_thread_manager->add_thread(newti, true);
	}
}

void sinsp::import_ifaddr_list()
{
	m_network_interfaces = new sinsp_network_interfaces(this);
	m_network_interfaces->import_interfaces(scap_get_ifaddr_list(m_h));
}

sinsp_network_interfaces* sinsp::get_ifaddr_list()
{
	return m_network_interfaces;
}

void sinsp::import_user_list()
{
	uint32_t j;
	scap_userlist* ul = scap_get_user_list(m_h);

	if(ul)
	{
		for(j = 0; j < ul->nusers; j++)
		{
			m_userlist[ul->users[j].uid] = &(ul->users[j]);
		}

		for(j = 0; j < ul->ngroups; j++)
		{
			m_grouplist[ul->groups[j].gid] = &(ul->groups[j]);
		}
	}
}

void sinsp::import_ipv4_interface(const sinsp_ipv4_ifinfo& ifinfo)
{
	ASSERT(m_network_interfaces);
	m_network_interfaces->import_ipv4_interface(ifinfo);
}

void sinsp::refresh_ifaddr_list()
{
#ifdef HAS_CAPTURE
	if(!is_capture())
	{
		ASSERT(m_network_interfaces);
		scap_refresh_iflist(m_h);
		m_network_interfaces->clear();
		m_network_interfaces->import_interfaces(scap_get_ifaddr_list(m_h));
	}
#endif
}

bool should_drop(sinsp_evt *evt, bool* stopped, bool* switched);

void sinsp::add_meta_event(sinsp_evt *metaevt)
{
	m_metaevt = metaevt;
}

void sinsp::add_meta_event_callback(meta_event_callback cback, void* data)
{
	m_meta_event_callback = cback;
	m_meta_event_callback_data = data;
}

void sinsp::remove_meta_event_callback()
{
	m_meta_event_callback = NULL;
}

void schedule_next_threadinfo_evt(sinsp* _this, void* data)
{
	sinsp_proc_metainfo* mei = (sinsp_proc_metainfo*)data;
	ASSERT(mei->m_pli != NULL);

	while(true)
	{
		ASSERT(mei->m_cur_procinfo_evt <= (int32_t)mei->m_n_procinfo_evts);
		ppm_proc_info* pi = &(mei->m_pli->entries[mei->m_cur_procinfo_evt]);

		if(mei->m_cur_procinfo_evt >= 0)
		{
			mei->m_piscapevt->tid = pi->pid;
			mei->m_piscapevt_vals[0] = pi->utime;
			mei->m_piscapevt_vals[1] = pi->stime;
		}

		mei->m_cur_procinfo_evt++;

		if(mei->m_cur_procinfo_evt < (int32_t)mei->m_n_procinfo_evts)
		{
			if(pi->utime == 0 && pi->stime == 0)
			{
				continue;
			}

			_this->add_meta_event(&mei->m_pievt);
		}

		break;
	}
}

void sinsp::restart_capture_at_filepos(uint64_t filepos)
{
	//
	// Backup a couple of settings
	//
	uint64_t evtnum = m_nevts;
	string filterstring = m_filterstring;

	//
	// Close and reopen the capture
	//
	m_file_start_offset = filepos;
	close();
	open_int();

	//
	// Set again the backuped settings
	//
	m_evt.m_evtnum = evtnum;
	m_nevts = evtnum;
	if(filterstring != "")
	{
		set_filter(filterstring);
	}
}

uint64_t sinsp::max_buf_used()
{
	if(m_h)
	{
		return scap_max_buf_used(m_h);
	}
	else
	{
		return 0;
	}
}

int32_t sinsp::next(OUT sinsp_evt **puevt)
{
	sinsp_evt* evt;
	int32_t res;

	//
	// Check if there are fake cpu events to  events
	//
	if(m_metaevt != NULL)
	{
		res = SCAP_SUCCESS;
		evt = m_metaevt;
		m_metaevt = NULL;

		if(m_meta_event_callback != NULL)
		{
			m_meta_event_callback(this, m_meta_event_callback_data);
		}
	}
#ifndef _WIN32
	else if (m_pending_container_evts.try_pop(m_container_evt))
	{
		res = SCAP_SUCCESS;
		evt = m_container_evt.get();
	}
#endif
	else
	{
		evt = &m_evt;

		//
		// Reset previous event's decoders if required
		//
		if(m_decoders_reset_list.size() != 0)
		{
			vector<sinsp_protodecoder*>::iterator it;
			for(it = m_decoders_reset_list.begin(); it != m_decoders_reset_list.end(); ++it)
			{
				(*it)->on_reset(evt);
			}

			m_decoders_reset_list.clear();
		}

		//
		// Get the event from libscap
		//
		res = scap_next(m_h, &(evt->m_pevt), &(evt->m_cpuid));



		if(res != SCAP_SUCCESS)
		{
			if(res == SCAP_TIMEOUT)
			{
				if (m_external_event_processor)
				{
					m_external_event_processor->process_event(NULL, libsinsp::EVENT_RETURN_TIMEOUT);
				}
				*puevt = NULL;
				return res;
			}
			else if(res == SCAP_EOF)
			{
				if (m_external_event_processor)
				{
					m_external_event_processor->process_event(NULL, libsinsp::EVENT_RETURN_EOF);
				}
			}
			else if(res == SCAP_UNEXPECTED_BLOCK)
			{
				uint64_t filepos = scap_ftell(m_h) - scap_get_unexpected_block_readsize(m_h);
				restart_capture_at_filepos(filepos);
				return SCAP_TIMEOUT;

			}
			else
			{
				m_lasterr = scap_getlasterr(m_h);
			}

			return res;
		}
	}

	uint64_t ts = evt->get_ts();

	if(m_firstevent_ts == 0 && evt->m_pevt->type != PPME_CONTAINER_JSON_E)
	{
		m_firstevent_ts = ts;
	}

	//
	// If required, retrieve the processes cpu from the kernel
	//
	if(m_get_procs_cpu_from_driver && is_live())
	{
		if(ts > m_next_flush_time_ns)
		{
			if(m_next_flush_time_ns != 0)
			{
				struct timeval tod;
				gettimeofday(&tod, NULL);

				uint64_t procrequest_tod = (uint64_t)tod.tv_sec * 1000000000 + tod.tv_usec * 1000;

				if(procrequest_tod - m_last_procrequest_tod > ONE_SECOND_IN_NS / 2)
				{
					m_last_procrequest_tod = procrequest_tod;
					m_next_flush_time_ns = ts - (ts % ONE_SECOND_IN_NS) + ONE_SECOND_IN_NS;

					m_meinfo.m_pli = scap_get_threadlist(m_h);
					if(m_meinfo.m_pli == NULL)
					{
						throw sinsp_exception(string("scap error: ") + scap_getlasterr(m_h));
					}

					m_meinfo.m_n_procinfo_evts = m_meinfo.m_pli->n_entries;

					if(m_meinfo.m_n_procinfo_evts > 0)
					{
						m_meinfo.m_cur_procinfo_evt = -1;

						m_meinfo.m_piscapevt->ts = m_next_flush_time_ns - (ONE_SECOND_IN_NS + 1);
						add_meta_event_callback(&schedule_next_threadinfo_evt, &m_meinfo);
						schedule_next_threadinfo_evt(this, &m_meinfo);
					}

					return SCAP_TIMEOUT;
				}
			}

			m_next_flush_time_ns = ts - (ts % ONE_SECOND_IN_NS) + ONE_SECOND_IN_NS;
		}
	}

	//
	// Store a couple of values that we'll need later inside the event.
	//
	m_nevts++;
	evt->m_evtnum = m_nevts;
	m_lastevent_ts = ts;

#ifndef HAS_ANALYZER
	//
	// Deleayed removal of threads from the thread table, so that
	// things like exit() or close() can be parsed.
	// We only do this if the analyzer is not enabled, because the analyzer
	// needs the process at the end of the sample and will take care of deleting
	// it.
	//
	if(m_tid_to_remove != -1)
	{
		remove_thread(m_tid_to_remove, false);
		m_tid_to_remove = -1;
	}

	if(is_debug_enabled() && is_live())
	{
		if(ts > m_next_stats_print_time_ns)
		{
			if(m_next_stats_print_time_ns)
			{
				scap_stats stats;
				get_capture_stats(&stats);

				g_logger.format(sinsp_logger::SEV_DEBUG,
					"n_evts:%" PRIu64
					" n_drops:%" PRIu64
					" n_drops_buffer:%" PRIu64
					" n_drops_pf:%" PRIu64
					" n_drops_bug:%" PRIu64,
					stats.n_evts,
					stats.n_drops,
					stats.n_drops_buffer,
					stats.n_drops_pf,
					stats.n_drops_bug);
			}

			m_next_stats_print_time_ns = ts - (ts % ONE_SECOND_IN_NS) + ONE_SECOND_IN_NS;
		}
	}

	//
	// Run the periodic connection and thread table cleanup
	//
	if(!is_capture())
	{
		m_thread_manager->remove_inactive_threads();
		m_container_manager.remove_inactive_containers();

		update_k8s_state();

		if(m_mesos_client)
		{
			update_mesos_state();
		}
	}
#endif // HAS_ANALYZER

	//
	// Deleayed removal of the fd, so that
	// things like exit() or close() can be parsed.
	//
	uint32_t nfdr = (uint32_t)m_fds_to_remove->size();

	if(nfdr != 0)
	{
		sinsp_threadinfo* ptinfo = get_thread(m_tid_of_fd_to_remove, true, true);
		if(!ptinfo)
		{
			ASSERT(false);
			return res;
		}

		for(uint32_t j = 0; j < nfdr; j++)
		{
			ptinfo->remove_fd(m_fds_to_remove->at(j));
		}

		m_fds_to_remove->clear();
	}

#ifdef SIMULATE_DROP_MODE
	bool sd = false;
	bool sw = false;

	if(m_analyzer)
	{
		m_analyzer->m_configuration->set_analyzer_sample_len_ns(500000000);
	}

	sd = should_drop(evt, &m_isdropping, &sw);
#endif

	//
	// Run the state engine
	//
#ifdef SIMULATE_DROP_MODE
	if(!sd || m_isdropping)
	{
		m_parser->process_event(evt);
	}

	if(sd && !m_isdropping)
	{
		*evt = NULL;
		return SCAP_TIMEOUT;
	}
#else
	m_parser->process_event(evt);
#endif

	//
	// If needed, dump the event to file
	//
	if(NULL != m_dumper)
	{

#if defined(HAS_FILTERING) && defined(HAS_CAPTURE_FILTERING)
		scap_dump_flags dflags;

		bool do_drop;
		dflags = evt->get_dump_flags(&do_drop);
		if(do_drop)
		{
			*puevt = evt;
			return SCAP_TIMEOUT;
		}
#endif

		if(m_write_cycling)
		{
			switch(m_cycle_writer->consider(evt))
			{
				case cycle_writer::NEWFILE:
					autodump_next_file();
					break;

				case cycle_writer::DOQUIT:
					stop_capture();
					return SCAP_EOF;
					break;

				case cycle_writer::SAMEFILE:
					// do nothing.
					break;
			}
		}

		scap_evt* pdevt = (evt->m_poriginal_evt)? evt->m_poriginal_evt : evt->m_pevt;

		res = scap_dump(m_h, m_dumper, pdevt, evt->m_cpuid, dflags);

		if(SCAP_SUCCESS != res)
		{
			throw sinsp_exception(scap_getlasterr(m_h));
		}
	}

#if defined(HAS_FILTERING) && defined(HAS_CAPTURE_FILTERING)
	if(evt->m_filtered_out)
	{
		ppm_event_category cat = evt->get_info_category();

		// Skip the event, unless we're in internal events
		// mode and the category of this event is internal.
		if(!(m_isinternal_events_enabled && (cat & EC_INTERNAL)))
		{
			*puevt = evt;
			return SCAP_TIMEOUT;
		}
	}
#endif

	//
	// Run the analysis engine
	//
	if (m_external_event_processor)
	{
		m_external_event_processor->process_event(evt, libsinsp::EVENT_RETURN_NONE);
	}

	// Clean parse related event data after analyzer did its parsing too
	m_parser->event_cleanup(evt);

	//
	// Update the last event time for this thread
	//
	if(evt->m_tinfo &&
		evt->get_type() != PPME_SCHEDSWITCH_1_E &&
		evt->get_type() != PPME_SCHEDSWITCH_6_E)
	{
		evt->m_tinfo->m_prevevent_ts = evt->m_tinfo->m_lastevent_ts;
		evt->m_tinfo->m_lastevent_ts = m_lastevent_ts;
	}

	//
	// Done
	//
	*puevt = evt;
	return res;
}

uint64_t sinsp::get_num_events()
{
	if(m_h)
	{
		return scap_event_get_num(m_h);
	}
	else
	{
		return 0;
	}
}

sinsp_threadinfo* sinsp::find_thread_test(int64_t tid, bool lookup_only)
{
	// TODO: we pay the refcount manipulation price here
	return &*find_thread(tid, lookup_only);
}

sinsp_threadinfo* sinsp::get_thread(int64_t tid, bool query_os_if_not_found, bool lookup_only)
{
	// TODO: we pay the refcount manipulation price here
	return &*get_thread_ref(tid, query_os_if_not_found, lookup_only);
}

threadinfo_map_t::ptr_t sinsp::get_thread_ref(int64_t tid, bool query_os_if_not_found, bool lookup_only, bool main_thread)
{
	auto sinsp_proc = find_thread(tid, lookup_only);

	if(!sinsp_proc && query_os_if_not_found &&
	   (m_thread_manager->m_threadtable.size() < m_max_thread_table_size
#if defined(HAS_CAPTURE)
		   || tid == m_sysdig_pid
#endif
		))
	{
		// Certain code paths can lead to this point from scap_open() (incomplete example:
		// scap_proc_scan_proc_dir() -> resolve_container() -> get_env()). Adding a
		// defensive check here to protect both, callers of get_env and get_thread.
		if (!m_h)
		{
			g_logger.format(sinsp_logger::SEV_INFO, "%s: Unable to complete for tid=%"
							PRIu64 ": sinsp::scap_t* is uninitialized", __func__, tid);
			return NULL;
		}

		scap_threadinfo* scap_proc = NULL;
		sinsp_threadinfo* newti = build_threadinfo();

		m_n_proc_lookups++;

		if(main_thread)
		{
			m_n_main_thread_lookups++;
		}

		if(m_n_proc_lookups == m_max_n_proc_lookups)
		{
			g_logger.format(sinsp_logger::SEV_INFO, "Reached max process lookup number, duration=%" PRIu64 "ms",
				m_n_proc_lookups_duration_ns / 1000000);
		}

		if(m_max_n_proc_lookups < 0 ||
		   m_n_proc_lookups <= m_max_n_proc_lookups)
		{
#ifdef HAS_ANALYZER
			tracer_emitter("sinsp_proc_lookup");
#endif

			bool scan_sockets = false;

			if(m_max_n_proc_socket_lookups < 0 ||
			   m_n_proc_lookups <= m_max_n_proc_socket_lookups)
			{
				scan_sockets = true;
				if(m_n_proc_lookups == m_max_n_proc_socket_lookups)
				{
					g_logger.format(sinsp_logger::SEV_INFO, "Reached max socket lookup number, tid=%" PRIu64 ", duration=%" PRIu64 "ms",
						tid, m_n_proc_lookups_duration_ns / 1000000);
				}
			}

#ifdef HAS_ANALYZER
			uint64_t ts = sinsp_utils::get_current_time_ns();
#endif
			scap_proc = scap_proc_get(m_h, tid, scan_sockets);
#ifdef HAS_ANALYZER
			m_n_proc_lookups_duration_ns += sinsp_utils::get_current_time_ns() - ts;
#endif
		}

		if(scap_proc)
		{
			newti->init(scap_proc);
			scap_proc_free(m_h, scap_proc);
		}
		else
		{
			//
			// Add a fake entry to avoid a continuous lookup
			//
			newti->m_tid = tid;
			newti->m_pid = tid;
			newti->m_ptid = -1;
			newti->m_comm = "<NA>";
			newti->m_exe = "<NA>";
			newti->m_uid = 0xffffffff;
			newti->m_gid = 0xffffffff;
			newti->m_nchilds = 0;
			newti->m_loginuid = 0xffffffff;
		}

		//
		// Since this thread is created out of thin air, we need to
		// properly set its reference count, by scanning the table
		//
		m_thread_manager->m_threadtable.loop([&] (sinsp_threadinfo& tinfo) {
			if(tinfo.m_pid == tid)
			{
				newti->m_nchilds++;
			}
			return true;
		});

		//
		// Done. Add the new thread to the list.
		//
		m_thread_manager->add_thread(newti, false);
		sinsp_proc = find_thread(tid, lookup_only);
	}

	return sinsp_proc;
}

sinsp_threadinfo* sinsp::get_thread(int64_t tid)
{
	return get_thread(tid, false, true);
}

bool sinsp::add_thread(const sinsp_threadinfo *ptinfo)
{
	return m_thread_manager->add_thread((sinsp_threadinfo*)ptinfo, false);
}

void sinsp::remove_thread(int64_t tid, bool force)
{
	m_thread_manager->remove_thread(tid, force);
}

bool sinsp::suppress_events_comm(const std::string &comm)
{
	if(m_suppressed_comms.size() >= SCAP_MAX_SUPPRESSED_COMMS)
	{
		return false;
	}

	m_suppressed_comms.insert(comm);

	if(m_h)
	{
		if (scap_suppress_events_comm(m_h, comm.c_str()) != SCAP_SUCCESS)
		{
			return false;
		}
	}

	return true;
}

bool sinsp::check_suppressed(int64_t tid)
{
	return scap_check_suppressed_tid(m_h, tid);
}

void sinsp::add_suppressed_comms(scap_open_args &oargs)
{
	uint32_t i = 0;

	// Note--using direct pointers to values in
	// m_suppressed_comms. This is ok given that a scap_open()
	// will immediately follow after which the args won't be used.
	for(auto &comm : m_suppressed_comms)
	{
		oargs.suppressed_comms[i++] = comm.c_str();
	}

	oargs.suppressed_comms[i++] = NULL;
}

void sinsp::set_docker_socket_path(std::string socket_path)
{
	m_container_manager.set_docker_socket_path(std::move(socket_path));
}

void sinsp::set_query_docker_image_info(bool query_image_info)
{
	m_container_manager.set_query_docker_image_info(query_image_info);
}

void sinsp::set_cri_extra_queries(bool extra_queries)
{
	m_container_manager.set_cri_extra_queries(extra_queries);
}

void sinsp::set_cri_socket_path(const std::string& path)
{
	m_container_manager.set_cri_socket_path(path);
}

void sinsp::set_cri_timeout(int64_t timeout_ms)
{
	m_container_manager.set_cri_timeout(timeout_ms);
}

void sinsp::set_cri_async(bool async)
{
	m_container_manager.set_cri_async(async);
}

void sinsp::set_cri_delay(uint64_t delay_ms)
{
	m_container_manager.set_cri_delay(delay_ms);
}

void sinsp::set_snaplen(uint32_t snaplen)
{
	//
	// If set_snaplen is called before opening of the inspector,
	// we register the value to be set after its initialization.
	//
	if(m_h == NULL)
	{
		m_snaplen = snaplen;
		return;
	}

	if(is_live() && scap_set_snaplen(m_h, snaplen) != SCAP_SUCCESS)
	{
		throw sinsp_exception(scap_getlasterr(m_h));
	}
}

void sinsp::set_fullcapture_port_range(uint16_t range_start, uint16_t range_end)
{
	//
	// If set_fullcapture_port_range is called before opening of the inspector,
	// we register the value to be set after its initialization.
	//
	if(m_h == NULL)
	{
		m_increased_snaplen_port_range = {range_start, range_end};
		return;
	}

	if(!is_live())
	{
		throw sinsp_exception("set_fullcapture_port_range called on a trace file");
	}

	if(scap_set_fullcapture_port_range(m_h, range_start, range_end) != SCAP_SUCCESS)
	{
		throw sinsp_exception(scap_getlasterr(m_h));
	}
}

void sinsp::set_statsd_port(const uint16_t port)
{
	//
	// If this method is called before opening of the inspector,
	// we register the value to be set after its initialization.
	//
	if(m_h == NULL)
	{
		m_statsd_port = port;
		return;
	}

	if(!is_live())
	{
		throw sinsp_exception("set_statsd_port called on a trace file");
	}

	if(scap_set_statsd_port(m_h, port) != SCAP_SUCCESS)
	{
		throw sinsp_exception(scap_getlasterr(m_h));
	}
}

void sinsp::stop_capture()
{
	if(scap_stop_capture(m_h) != SCAP_SUCCESS)
	{
		throw sinsp_exception(scap_getlasterr(m_h));
	}
}

void sinsp::start_capture()
{
	if(scap_start_capture(m_h) != SCAP_SUCCESS)
	{
		throw sinsp_exception(scap_getlasterr(m_h));
	}
}

void sinsp::stop_dropping_mode()
{
	if(m_mode == SCAP_MODE_LIVE)
	{
		g_logger.format(sinsp_logger::SEV_INFO, "stopping drop mode");

		if(scap_stop_dropping_mode(m_h) != SCAP_SUCCESS)
		{
			throw sinsp_exception(scap_getlasterr(m_h));
		}
	}
}

void sinsp::start_dropping_mode(uint32_t sampling_ratio)
{
	if(m_mode == SCAP_MODE_LIVE)
	{
		g_logger.format(sinsp_logger::SEV_INFO, "setting drop mode to %" PRIu32, sampling_ratio);

		if(scap_start_dropping_mode(m_h, sampling_ratio) != SCAP_SUCCESS)
		{
			throw sinsp_exception(scap_getlasterr(m_h));
		}
	}
}

#ifdef HAS_FILTERING
void sinsp::set_filter(sinsp_filter* filter)
{
	if(m_filter != NULL)
	{
		ASSERT(false);
		throw sinsp_exception("filter can only be set once");
	}

	m_filter = filter;
}

void sinsp::set_filter(const string& filter)
{
	if(m_filter != NULL)
	{
		ASSERT(false);
		throw sinsp_exception("filter can only be set once");
	}

	sinsp_filter_compiler compiler(this, filter);
	m_filter = compiler.compile();
	m_filterstring = filter;
}

const string sinsp::get_filter()
{
	return m_filterstring;
}

void sinsp::add_evttype_filter(string &name,
			       set<uint32_t> &evttypes,
			       set<uint32_t> &syscalls,
			       set<string> &tags,
			       sinsp_filter *filter)
{
	// Create the evttype filter if it doesn't exist.
	if(m_evttype_filter == NULL)
	{
		m_evttype_filter = new sinsp_evttype_filter();
	}

	m_evttype_filter->add(name, evttypes, syscalls, tags, filter);
}

bool sinsp::run_filters_on_evt(sinsp_evt *evt)
{
	//
	// First run the global filter, if there is one.
	//
	if(m_filter && m_filter->run(evt) == true)
	{
		return true;
	}

	//
	// Then run the evttype filter, if there is one.
	if(m_evttype_filter && m_evttype_filter->run(evt) == true)
	{
		return true;
	}

	return false;
}
#endif

const scap_machine_info* sinsp::get_machine_info()
{
	return m_machine_info;
}

const unordered_map<uint32_t, scap_userinfo*>* sinsp::get_userlist()
{
	return &m_userlist;
}

scap_userinfo* sinsp::get_user(uint32_t uid)
{
	unordered_map<uint32_t, scap_userinfo*>::const_iterator it;
	if(uid == 0xffffffff)
	{
		return NULL;
	}

	it = m_userlist.find(uid);
	if(it == m_userlist.end())
	{
		return NULL;
	}

	return it->second;
}

const unordered_map<uint32_t, scap_groupinfo*>* sinsp::get_grouplist()
{
	return &m_grouplist;
}

#ifdef HAS_FILTERING
void sinsp::get_filtercheck_fields_info(OUT vector<const filter_check_info*>* list)
{
	sinsp_utils::get_filtercheck_fields_info(list);
}
#else
void sinsp::get_filtercheck_fields_info(OUT vector<const filter_check_info*>* list)
{
}
#endif

uint32_t sinsp::reserve_thread_memory(uint32_t size)
{
	if(m_h != NULL)
	{
		throw sinsp_exception("reserve_thread_memory can't be called after capture starts");
	}

	return m_thread_privatestate_manager.reserve(size);
}

void sinsp::get_capture_stats(scap_stats* stats) const
{
	if(scap_get_stats(m_h, stats) != SCAP_SUCCESS)
	{
		throw sinsp_exception(scap_getlasterr(m_h));
	}
}

void sinsp::set_max_thread_table_size(uint32_t value)
{
	uint32_t max_size = uint32_t(MAX_THREAD_TABLE_SIZE);
	m_max_thread_table_size = (value < max_size ? value : max_size);
}

#ifdef GATHER_INTERNAL_STATS
sinsp_stats sinsp::get_stats()
{
	scap_stats stats;

	//
	// Get capture stats from scap
	//
	if(m_h)
	{
		scap_get_stats(m_h, &stats);

		m_stats.m_n_seen_evts = stats.n_evts;
		m_stats.m_n_drops = stats.n_drops;
		m_stats.m_n_preemptions = stats.n_preemptions;
	}
	else
	{
		m_stats.m_n_seen_evts = 0;
		m_stats.m_n_drops = 0;
		m_stats.m_n_preemptions = 0;
	}

	//
	// Count the number of threads and fds by scanning the tables,
	// and update the thread-related stats.
	//
	if(m_thread_manager)
	{
		m_thread_manager->update_statistics();
	}

	//
	// Return the result
	//

	return m_stats;
}
#endif // GATHER_INTERNAL_STATS

void sinsp::set_log_callback(sinsp_logger_callback cb)
{
	if(cb)
	{
		g_logger.add_callback_log(cb);
	}
	else
	{
		g_logger.remove_callback_log();
	}
}

void sinsp::set_log_file(string filename)
{
	g_logger.add_file_log(filename);
}

void sinsp::set_log_stderr()
{
	g_logger.add_stderr_log();
}

void sinsp::set_min_log_severity(sinsp_logger::severity sev)
{
	g_logger.set_severity(sev);
}

sinsp_evttables* sinsp::get_event_info_tables()
{
	return &g_infotables;
}

void sinsp::add_chisel_dir(string dirname, bool front_add)
{
#ifdef HAS_CHISELS
	trim(dirname);

	if(dirname[dirname.size() -1] != '/')
	{
		dirname += "/";
	}

	chiseldir_info ncdi;

	ncdi.m_dir = std::move(dirname);
	ncdi.m_need_to_resolve = false;

	if(front_add)
	{
		g_chisel_dirs->insert(g_chisel_dirs->begin(), ncdi);
	}
	else
	{
		g_chisel_dirs->push_back(ncdi);
	}
#endif
}

void sinsp::set_buffer_format(sinsp_evt::param_fmt format)
{
	m_buffer_format = format;
}

void sinsp::set_drop_event_flags(ppm_event_flags flags)
{
	m_parser->m_drop_event_flags = flags;
}

sinsp_evt::param_fmt sinsp::get_buffer_format()
{
	return m_buffer_format;
}

void sinsp::set_large_envs(bool enable)
{
	m_large_envs_enabled = enable;
}

void sinsp::set_debug_mode(bool enable_debug)
{
	m_isdebug_enabled = enable_debug;
}

void sinsp::set_print_container_data(bool print_container_data)
{
	m_print_container_data = print_container_data;
}

void sinsp::set_fatfile_dump_mode(bool enable_fatfile)
{
	m_isfatfile_enabled = enable_fatfile;
}

void sinsp::set_internal_events_mode(bool enable_internal_events)
{
	m_isinternal_events_enabled = enable_internal_events;
}

void sinsp::set_hostname_and_port_resolution_mode(bool enable)
{
	m_hostname_and_port_resolution_enabled = enable;
}

void sinsp::set_max_evt_output_len(uint32_t len)
{
	m_max_evt_output_len = len;
}

sinsp_protodecoder* sinsp::require_protodecoder(string decoder_name)
{
	return m_parser->add_protodecoder(decoder_name);
}

void sinsp::set_eventmask(uint32_t event_types)
{
	if (scap_set_eventmask(m_h, event_types) != SCAP_SUCCESS)
	{
		throw sinsp_exception(scap_getlasterr(m_h));
	}
}

void sinsp::unset_eventmask(uint32_t event_id)
{
	if (scap_unset_eventmask(m_h, event_id) != SCAP_SUCCESS)
	{
		throw sinsp_exception(scap_getlasterr(m_h));
	}
}

void sinsp::protodecoder_register_reset(sinsp_protodecoder* dec)
{
	m_decoders_reset_list.push_back(dec);
}

sinsp_parser* sinsp::get_parser()
{
	return m_parser;
}

bool sinsp::setup_cycle_writer(string base_file_name, int rollover_mb, int duration_seconds, int file_limit, unsigned long event_limit, bool compress)
{
	m_compress = compress;

	if(rollover_mb != 0 || duration_seconds != 0 || file_limit != 0 || event_limit != 0)
	{
		m_write_cycling = true;
	}

	return m_cycle_writer->setup(base_file_name, rollover_mb, duration_seconds, file_limit, event_limit, &m_dumper);
}

double sinsp::get_read_progress()
{
	if(m_input_fd != 0)
	{
		// We can't get a reliable file size, so we can't get
		// any reliable progress
		return 0;
	}

	if(m_filesize == -1)
	{
		throw sinsp_exception(scap_getlasterr(m_h));
	}

	ASSERT(m_filesize != 0);

	int64_t fpos = scap_get_readfile_offset(m_h);

	if(fpos == -1)
	{
		throw sinsp_exception(scap_getlasterr(m_h));
	}

	return (double)fpos * 100 / m_filesize;
}

bool sinsp::remove_inactive_threads()
{
	return m_thread_manager->remove_inactive_threads();
}

#ifndef CYGWING_AGENT
void sinsp::init_mesos_client(string* api_server, bool verbose)
{
	m_verbose_json = verbose;
	if(m_mesos_client == NULL)
	{
		if(api_server)
		{
			// -m <url[,marathon_url]>
			std::string::size_type pos = api_server->find(',');
			if(pos != std::string::npos)
			{
				m_marathon_api_server.clear();
				m_marathon_api_server.push_back(api_server->substr(pos + 1));
			}
			m_mesos_api_server = api_server->substr(0, pos);
		}

		bool is_live = !m_mesos_api_server.empty();
		m_mesos_client = new mesos(m_mesos_api_server,
									m_marathon_api_server,
									true, // mesos leader auto-follow
									m_marathon_api_server.empty(), // marathon leader auto-follow if no uri
									mesos::credentials_t(), // mesos creds, the only way to provide creds in sysdig is embedded in URI
									mesos::credentials_t(), // marathon creds
									mesos::default_timeout_ms,
									is_live,
									m_verbose_json);
	}
}

void sinsp::init_k8s_ssl(const string *ssl_cert)
{
#ifdef HAS_CAPTURE
	if(ssl_cert != nullptr && !ssl_cert->empty()
	   && (!m_k8s_ssl || ! m_k8s_bt))
	{
		std::string cert;
		std::string key;
		std::string key_pwd;
		std::string ca_cert;

		// -K <bt_file> | <cert_file>:<key_file[#password]>[:<ca_cert_file>]
		std::string::size_type pos = ssl_cert->find(':');
		if(pos == std::string::npos) // ca_cert-only is obsoleted, single entry is now bearer token
		{
			m_k8s_bt = std::make_shared<sinsp_bearer_token>(*ssl_cert);
		}
		else
		{
			cert = ssl_cert->substr(0, pos);
			if(cert.empty())
			{
				throw sinsp_exception(string("Invalid K8S SSL entry: ") + *ssl_cert);
			}

			// pos < ssl_cert->length() so it's safe to take
			// substr() from head, but it may be empty
			std::string::size_type head = pos + 1;
			pos = ssl_cert->find(':', head);
			if (pos == std::string::npos)
			{
				key = ssl_cert->substr(head);
			}
			else
			{
				key = ssl_cert->substr(head, pos - head);
				ca_cert = ssl_cert->substr(pos + 1);
			}
			if(key.empty())
			{
				throw sinsp_exception(string("Invalid K8S SSL entry: ") + *ssl_cert);
			}

			// Parse the password if it exists
			pos = key.find('#');
			if(pos != std::string::npos)
			{
				key_pwd = key.substr(pos + 1);
				key = key.substr(0, pos);
			}
		}
		g_logger.format(sinsp_logger::SEV_TRACE,
				"Creating sinsp_ssl with cert %s, key %s, key_pwd %s, ca_cert %s",
				cert.c_str(), key.c_str(), key_pwd.c_str(), ca_cert.c_str());
		m_k8s_ssl = std::make_shared<sinsp_ssl>(cert, key, key_pwd,
					ca_cert, ca_cert.empty() ? false : true, "PEM");
	}
#endif // HAS_CAPTURE
}

void sinsp::make_k8s_client()
{
	bool is_live = m_k8s_api_server && !m_k8s_api_server->empty();
	m_k8s_client = new k8s(m_k8s_api_server ? *m_k8s_api_server : std::string()
		,is_live // capture
#ifdef HAS_CAPTURE
		,m_k8s_ssl
		,m_k8s_bt
		,true // blocking
#endif // HAS_CAPTURE
		,nullptr
#ifdef HAS_CAPTURE
		,m_ext_list_ptr
#else
		,nullptr
#endif // HAS_CAPTURE
	);
}

void sinsp::init_k8s_client(string* api_server, string* ssl_cert, bool verbose)
{
	ASSERT(api_server);
	m_verbose_json = verbose;
	m_k8s_api_server = api_server;
	m_k8s_api_cert = ssl_cert;


#ifdef HAS_CAPTURE
	if(m_k8s_api_detected && m_k8s_ext_detect_done)
#endif // HAS_CAPTURE
	{
		if(m_k8s_client)
		{
			delete m_k8s_client;
			m_k8s_client = nullptr;
		}
		init_k8s_ssl(ssl_cert);
		make_k8s_client();
	}
}

void sinsp::collect_k8s()
{
	if(m_parser)
	{
		if(m_k8s_api_server)
		{
			if(!m_k8s_client)
			{
				init_k8s_client(m_k8s_api_server, m_k8s_api_cert, m_verbose_json);
				if(m_k8s_client)
				{
					g_logger.log("K8s client created.", sinsp_logger::SEV_DEBUG);
				}
				else
				{
					g_logger.log("K8s client NOT created.", sinsp_logger::SEV_DEBUG);
				}
			}
			if(m_k8s_client)
			{
				if(m_lastevent_ts > m_k8s_last_watch_time_ns + ONE_SECOND_IN_NS)
				{
					m_k8s_last_watch_time_ns = m_lastevent_ts;
					g_logger.log("K8s updating state ...", sinsp_logger::SEV_DEBUG);
					uint64_t delta = sinsp_utils::get_current_time_ns();
					m_k8s_client->watch();
					m_parser->schedule_k8s_events();
					delta = sinsp_utils::get_current_time_ns() - delta;
					g_logger.format(sinsp_logger::SEV_DEBUG, "Updating Kubernetes state took %" PRIu64 " ms", delta / 1000000LL);
				}
			}
		}
	}
}

void sinsp::k8s_discover_ext()
{
#ifdef HAS_CAPTURE
	try
	{
		if(m_k8s_api_server && !m_k8s_api_server->empty() && !m_k8s_ext_detect_done)
		{
			g_logger.log("K8s API extensions handler: detecting extensions.", sinsp_logger::SEV_TRACE);
			if(!m_k8s_ext_handler)
			{
				if(!m_k8s_collector)
				{
					m_k8s_collector = std::make_shared<k8s_handler::collector_t>();
				}
				if(uri(*m_k8s_api_server).is_secure()) { init_k8s_ssl(m_k8s_api_cert); }
				m_k8s_ext_handler.reset(new k8s_api_handler(m_k8s_collector, *m_k8s_api_server,
									    "/apis/extensions/v1beta1", "[.resources[].name]",
									    "1.1", m_k8s_ssl, m_k8s_bt, true));
				g_logger.log("K8s API extensions handler: collector created.", sinsp_logger::SEV_TRACE);
			}
			else
			{
				g_logger.log("K8s API extensions handler: collecting data.", sinsp_logger::SEV_TRACE);
				m_k8s_ext_handler->collect_data();
				if(m_k8s_ext_handler->ready())
				{
					g_logger.log("K8s API extensions handler: data received.", sinsp_logger::SEV_TRACE);
					if(m_k8s_ext_handler->error())
					{
						g_logger.log("K8s API extensions handler: data error occurred while detecting API extensions.",
									 sinsp_logger::SEV_WARNING);
						m_ext_list_ptr.reset();
					}
					else
					{
						const k8s_api_handler::api_list_t& exts = m_k8s_ext_handler->extensions();
						std::ostringstream ostr;
						k8s_ext_list_t ext_list;
						for(const auto& ext : exts)
						{
							ext_list.insert(ext);
							ostr << std::endl << ext;
						}
						g_logger.log("K8s API extensions handler extensions found: " + ostr.str(),
									 sinsp_logger::SEV_DEBUG);
						m_ext_list_ptr.reset(new k8s_ext_list_t(ext_list));
					}
					m_k8s_ext_detect_done = true;
					m_k8s_collector.reset();
					m_k8s_ext_handler.reset();
				}
				else
				{
					g_logger.log("K8s API extensions handler: not ready.", sinsp_logger::SEV_TRACE);
				}
			}
		}
	}
	catch(const std::exception& ex)
	{
		g_logger.log(std::string("K8s API extensions handler error: ").append(ex.what()),
					 sinsp_logger::SEV_ERROR);
		m_k8s_ext_detect_done = false;
		m_k8s_collector.reset();
		m_k8s_ext_handler.reset();
	}
	g_logger.log("K8s API extensions handler: detection done.", sinsp_logger::SEV_TRACE);
#endif // HAS_CAPTURE
}

void sinsp::update_k8s_state()
{
#ifdef HAS_CAPTURE
	try
	{
		if(m_k8s_api_server && !m_k8s_api_server->empty())
		{
			if(!m_k8s_api_detected)
			{
				if(!m_k8s_api_handler)
				{
					if(!m_k8s_collector)
					{
						m_k8s_collector = std::make_shared<k8s_handler::collector_t>();
					}
					if(uri(*m_k8s_api_server).is_secure() && (!m_k8s_ssl || ! m_k8s_bt))
					{
						init_k8s_ssl(m_k8s_api_cert);
					}
					m_k8s_api_handler.reset(new k8s_api_handler(m_k8s_collector, *m_k8s_api_server,
										    "/api", ".versions", "1.1",
										    m_k8s_ssl, m_k8s_bt, true));
				}
				else
				{
					m_k8s_api_handler->collect_data();
					if(m_k8s_api_handler->ready())
					{
						g_logger.log("K8s API handler data received.", sinsp_logger::SEV_DEBUG);
						if(m_k8s_api_handler->error())
						{
							g_logger.log("K8s API handler data error occurred while detecting API versions.",
										 sinsp_logger::SEV_ERROR);
						}
						else
						{
							m_k8s_api_detected = m_k8s_api_handler->has("v1");
							if(m_k8s_api_detected)
							{
								g_logger.log("K8s API server v1 detected.", sinsp_logger::SEV_DEBUG);
							}
						}
						m_k8s_collector.reset();
						m_k8s_api_handler.reset();
					}
					else
					{
						g_logger.log("K8s API handler not ready yet.", sinsp_logger::SEV_DEBUG);
					}
				}
			}
			if(m_k8s_api_detected && !m_k8s_ext_detect_done)
			{
				k8s_discover_ext();
			}
			if(m_k8s_api_detected && m_k8s_ext_detect_done)
			{
				collect_k8s();
			}
		}
	}
	catch(const std::exception& e)
	{
		g_logger.log(std::string("Error fetching K8s data: ").append(e.what()), sinsp_logger::SEV_ERROR);
		throw;
	}
#endif // HAS_CAPTURE
}

bool sinsp::get_mesos_data()
{
	bool ret = false;
#ifdef HAS_CAPTURE
	try
	{
		static time_t last_mesos_refresh = 0;
		ASSERT(m_mesos_client);
		ASSERT(m_mesos_client->is_alive());

		time_t now; time(&now);
		if(last_mesos_refresh)
		{
			g_logger.log("Collecting Mesos data ...", sinsp_logger::SEV_DEBUG);
			ret = m_mesos_client->collect_data();
		}
		if(difftime(now, last_mesos_refresh) > 10)
		{
			g_logger.log("Requesting Mesos data ...", sinsp_logger::SEV_DEBUG);
			m_mesos_client->send_data_request(false);
			last_mesos_refresh = now;
		}
	}
	catch(const std::exception& ex)
	{
		g_logger.log(std::string("Mesos exception: ") + ex.what(), sinsp_logger::SEV_ERROR);
		delete m_mesos_client;
		m_mesos_client = NULL;
		init_mesos_client(0, m_verbose_json);
	}
#endif // HAS_CAPTURE
	return ret;
}

void sinsp::update_mesos_state()
{
	ASSERT(m_mesos_client);
	if(m_lastevent_ts > m_mesos_last_watch_time_ns + ONE_SECOND_IN_NS)
	{
		m_mesos_last_watch_time_ns = m_lastevent_ts;
		if(m_mesos_client->is_alive())
		{
			uint64_t delta = sinsp_utils::get_current_time_ns();
			if(m_parser && get_mesos_data())
			{
				m_parser->schedule_mesos_events();
				delta = sinsp_utils::get_current_time_ns() - delta;
				g_logger.format(sinsp_logger::SEV_DEBUG, "Updating Mesos state took %" PRIu64 " ms", delta / 1000000LL);
			}
		}
		else
		{
			g_logger.format(sinsp_logger::SEV_ERROR, "Mesos connection not active anymore, retrying ...");
			delete m_mesos_client;
			m_mesos_client = NULL;
			init_mesos_client(0, m_verbose_json);
		}
	}
}
#endif // CYGWING_AGENT

void sinsp::set_bpf_probe(const string& bpf_probe)
{
	m_bpf = true;
	m_bpf_probe = bpf_probe;
}

bool sinsp::is_bpf_enabled()
{
	// At the inspector level, bpf can be explicitly enabled via
	// sinsp::set_bpf_probe, but what's most important is whether
	// it's enabled at the libscap level, which can also be done
	// via the environment.
	if(m_h)
	{
		return scap_get_bpf_enabled(m_h);
	}

	return false;
}

///////////////////////////////////////////////////////////////////////////////
// Note: this is defined here so we can inline it in sinso::next
///////////////////////////////////////////////////////////////////////////////
bool sinsp_thread_manager::remove_inactive_threads()
{
	bool res = false;

	if(m_last_flush_time_ns == 0)
	{
		//
		// Set the first table scan for 30 seconds in, so that we can spot bugs in the logic without having
		// to wait for tens of minutes
		//
		if(m_inspector->m_inactive_thread_scan_time_ns > 30 * ONE_SECOND_IN_NS)
		{
			m_last_flush_time_ns =
				(m_inspector->m_lastevent_ts - m_inspector->m_inactive_thread_scan_time_ns + 30 * ONE_SECOND_IN_NS);
		}
		else
		{
			m_last_flush_time_ns =
				(m_inspector->m_lastevent_ts - m_inspector->m_inactive_thread_scan_time_ns);
		}
	}

	if(m_inspector->m_lastevent_ts >
		m_last_flush_time_ns + m_inspector->m_inactive_thread_scan_time_ns)
	{
		std::unordered_map<uint64_t, bool> to_delete;

		res = true;

		m_last_flush_time_ns = m_inspector->m_lastevent_ts;

		g_logger.format(sinsp_logger::SEV_INFO, "Flushing thread table");

		//
		// Go through the table and remove dead entries.
		//
		m_threadtable.loop([&] (sinsp_threadinfo& tinfo) {
			bool closed = (tinfo.m_flags & PPM_CL_CLOSED) != 0;

			if(closed ||
				((m_inspector->m_lastevent_ts > tinfo.m_lastaccess_ts + m_inspector->m_thread_timeout_ns) &&
					!scap_is_thread_alive(m_inspector->m_h, tinfo.m_pid, tinfo.m_tid, tinfo.m_comm.c_str()))
					)
			{
				//
				// Reset the cache
				//
				m_last_tid = 0;
				m_last_tinfo.reset();

#ifdef GATHER_INTERNAL_STATS
				m_removed_threads->increment();
#endif
				to_delete[tinfo.m_tid] = closed;
			}
			return true;
		});

		for (auto& it : to_delete)
		{
			remove_thread(it.first, it.second);
		}

		//
		// Rebalance the thread table dependency tree, so we free up threads that
		// exited but that are stuck because of reference counting.
		//
		recreate_child_dependencies();
	}

	return res;
}

#ifdef HAS_CAPTURE
std::shared_ptr<std::string> sinsp::lookup_cgroup_dir(const string& subsys)
{
	shared_ptr<string> cgroup_dir;
	static std::unordered_map<std::string, std::shared_ptr<std::string>> cgroup_dir_cache;

	const auto& it = cgroup_dir_cache.find(subsys);
	if(it != cgroup_dir_cache.end())
	{
		return it->second;
	}

	// Look for mount point of cgroup filesystem
	// It should be already mounted on the host or by
	// our docker-entrypoint.sh script
	if(strcmp(scap_get_host_root(), "") != 0)
	{
		// We are inside our container, so we should use the directory
		// mounted by it
		auto cgroup = std::string(scap_get_host_root()) + "/cgroup/" + subsys;
		cgroup_dir = std::make_shared<std::string>(cgroup);
	}
	else
	{
		struct mntent mntent_buf = {};
		char mntent_string_buf[4096];
		FILE* fp = setmntent("/proc/mounts", "r");
		struct mntent* entry = getmntent_r(fp, &mntent_buf,
			mntent_string_buf, sizeof(mntent_string_buf));
		while(entry != nullptr)
		{
			if(strcmp(entry->mnt_type, "cgroup") == 0 &&
			   hasmntopt(entry, subsys.c_str()) != NULL)
			{
				cgroup_dir = std::make_shared<std::string>(entry->mnt_dir);
				break;
			}
			entry = getmntent(fp);
		}
		endmntent(fp);
	}
	if(!cgroup_dir)
	{
		return std::make_shared<std::string>();
	}
	else
	{
		cgroup_dir_cache[subsys] = cgroup_dir;
		return cgroup_dir;
	}
}
#endif

sinsp_threadinfo*
libsinsp::event_processor::build_threadinfo(sinsp* inspector)
{
	return new sinsp_threadinfo(inspector);
}
