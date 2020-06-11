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
#include <unordered_set>
#include <json/json.h>
#include "filter_value.h"
#include "prefix_search.h"
#ifndef CYGWING_AGENT
#include "k8s.h"
#include "mesos.h"
#endif

#ifdef HAS_FILTERING
#include "gen_filter.h"

class sinsp_filter_check_reference;

bool flt_compare(cmpop op, ppm_param_type type, void* operand1, void* operand2, uint32_t op1_len = 0, uint32_t op2_len = 0);
bool flt_compare_avg(cmpop op, ppm_param_type type, void* operand1, void* operand2, uint32_t op1_len, uint32_t op2_len, uint32_t cnt1, uint32_t cnt2);
bool flt_compare_ipv4net(cmpop op, uint64_t operand1, ipv4net* operand2);
bool flt_compare_ipv6net(cmpop op, ipv6addr *operand1, ipv6addr* operand2);

char* flt_to_string(uint8_t* rawval, filtercheck_field_info* finfo);
int32_t gmt2local(time_t t);

class operand_info
{
public:
	uint32_t m_id;
	ppm_param_type m_type;
	string m_name;
	string m_description;
};

///////////////////////////////////////////////////////////////////////////////
// The filter check interface
// NOTE: in order to add a new type of filter check, you need to add a class for
//       it and then add it to new_filter_check_from_name.
///////////////////////////////////////////////////////////////////////////////

class sinsp_filter_check : public gen_event_filter_check
{
public:
	sinsp_filter_check();

	virtual ~sinsp_filter_check()
	{
	}

	//
	// Allocate a new check of the same type.
	// Every filtercheck plugin must implement this.
	//
	virtual sinsp_filter_check* allocate_new() = 0;

	//
	// Get the list of fields that this check exports
	//
	virtual filter_check_info* get_fields()
	{
		return &m_info;
	}

	//
	// Parse the name of the field.
	// Returns the length of the parsed field if successful, an exception in
	// case of error.
	//
	virtual int32_t parse_field_name(const char* str, bool alloc_state, bool needed_for_filtering);

	//
	// If this check is used by a filter, extract the constant to compare it to
	// Doesn't return the field length because the filtering engine can calculate it.
	//
	void add_filter_value(const char* str, uint32_t len, uint32_t i = 0 );
	virtual size_t parse_filter_value(const char* str, uint32_t len, uint8_t *storage, uint32_t storage_len);

	//
	// Called after parsing for optional validation of the filter value
	//
	void validate_filter_value(const char* str, uint32_t len) {}

	//
	// Return the info about the field that this instance contains
	//
	virtual const filtercheck_field_info* get_field_info();

	//
	// Extract the field from the event. In sanitize_strings is true, any
	// string values are sanitized to remove nonprintable characters.
	//
	uint8_t* extract(gen_event *evt, OUT uint32_t* len, bool sanitize_strings = true);
	virtual uint8_t* extract(sinsp_evt *evt, OUT uint32_t* len, bool sanitize_strings = true) = 0;

	//
	// Extract the field as json from the event (by default, fall
	// back to the regular extract functionality)
	//
	virtual Json::Value extract_as_js(sinsp_evt *evt, OUT uint32_t* len)
	{
		return Json::nullValue;
	}

	//
	// Compare the field with the constant value obtained from parse_filter_value()
	//
	bool compare(gen_event *evt);
	virtual bool compare(sinsp_evt *evt);

	//
	// Extract the value from the event and convert it into a string
	//
	virtual char* tostring(sinsp_evt* evt);

	//
	// Extract the value from the event and convert it into a Json value
	// or object
	//
	virtual Json::Value tojson(sinsp_evt* evt);

	sinsp* m_inspector;
	bool m_needs_state_tracking = false;
	sinsp_field_aggregation m_aggregation;
	sinsp_field_aggregation m_merge_aggregation;

protected:
	bool flt_compare(cmpop op, ppm_param_type type, void* operand1, uint32_t op1_len = 0, uint32_t op2_len = 0);

	char* rawval_to_string(uint8_t* rawval,
			       ppm_param_type ptype,
			       ppm_print_format print_format,
			       uint32_t len);
	Json::Value rawval_to_json(uint8_t* rawval, ppm_param_type ptype, ppm_print_format print_format, uint32_t len);
	void string_to_rawval(const char* str, uint32_t len, ppm_param_type ptype);

	char m_getpropertystr_storage[1024];
	vector<vector<uint8_t>> m_val_storages;
	inline uint8_t* filter_value_p(uint16_t i = 0) { return &m_val_storages[i][0]; }
	inline vector<uint8_t> filter_value(uint16_t i = 0) { return m_val_storages[i]; }

	unordered_set<filter_value_t,
		g_hash_membuf,
		g_equal_to_membuf> m_val_storages_members;

	path_prefix_search m_val_storages_paths;

	uint32_t m_val_storages_min_size;
	uint32_t m_val_storages_max_size;

	const filtercheck_field_info* m_field;
	filter_check_info m_info;
	uint32_t m_field_id;
	uint32_t m_th_state_id;
	uint32_t m_val_storage_len;

private:
	void set_inspector(sinsp* inspector);

friend class sinsp_filter_check_list;
};

//
// Global class that stores the list of filtercheck plugins and offers
// functions to work with it.
//
class sinsp_filter_check_list
{
public:
	sinsp_filter_check_list();
	~sinsp_filter_check_list();
	void add_filter_check(sinsp_filter_check* filter_check);
	void get_all_fields(vector<const filter_check_info*>* list);
	sinsp_filter_check* new_filter_check_from_another(sinsp_filter_check *chk);
	sinsp_filter_check* new_filter_check_from_fldname(const string& name, sinsp* inspector, bool do_exact_check);

private:
	vector<sinsp_filter_check*> m_check_list;
};

///////////////////////////////////////////////////////////////////////////////
// Filter check classes
///////////////////////////////////////////////////////////////////////////////

//
// fd checks
//
class sinsp_filter_check_fd : public sinsp_filter_check
{
public:
	enum check_type
	{
		TYPE_FDNUM = 0,
		TYPE_FDTYPE = 1,
		TYPE_FDTYPECHAR = 2,
		TYPE_FDNAME = 3,
		TYPE_DIRECTORY = 4,
		TYPE_FILENAME = 5,
		TYPE_IP = 6,
		TYPE_CLIENTIP = 7,
		TYPE_SERVERIP = 8,
		TYPE_LIP = 9,
		TYPE_RIP = 10,
		TYPE_PORT = 11,
		TYPE_CLIENTPORT = 12,
		TYPE_SERVERPORT = 13,
		TYPE_LPORT = 14,
		TYPE_RPORT = 15,
		TYPE_L4PROTO = 16,
		TYPE_SOCKFAMILY = 17,
		TYPE_IS_SERVER = 18,
		TYPE_UID = 19,
		TYPE_CONTAINERNAME = 20,
		TYPE_CONTAINERDIRECTORY = 21,
		TYPE_PROTO = 22,
		TYPE_CLIENTPROTO = 23,
		TYPE_SERVERPROTO = 24,
		TYPE_LPROTO = 25,
		TYPE_RPROTO = 26,
		TYPE_NET = 27,
		TYPE_CNET = 28,
		TYPE_SNET = 29,
		TYPE_LNET = 30,
		TYPE_RNET = 31,
		TYPE_IS_CONNECTED = 32,
		TYPE_NAME_CHANGED = 33,
		TYPE_CLIENTIP_NAME = 34,
		TYPE_SERVERIP_NAME = 35,
		TYPE_LIP_NAME = 36,
		TYPE_RIP_NAME = 37,
		TYPE_DEV = 38,
		TYPE_DEV_MAJOR = 39,
		TYPE_DEV_MINOR = 40,
	};

	enum fd_type
	{
		FDT_NONE,
		FDT_FILE,
		FDT_SOCK,
		FDT_IPV4_SOCK,
		FDT_IPV6_SOCK,
		FDT_UNIX_SOCK,
		FDT_PIPE,
		FDT_EVENT,
		FDT_SIGNALFD,
		FDT_EVENTPOLL,
		FDT_INOTIFY,
		FDT_TIMERFD
	};

	sinsp_filter_check_fd();
	sinsp_filter_check* allocate_new();
	uint8_t* extract(sinsp_evt *evt, OUT uint32_t* len, bool sanitize_strings = true);
	bool compare_ip(sinsp_evt *evt);
	bool compare_net(sinsp_evt *evt);
	bool compare_port(sinsp_evt *evt);
	bool compare_domain(sinsp_evt *evt);
	bool compare(sinsp_evt *evt);

	sinsp_threadinfo* m_tinfo;
	sinsp_fdinfo_t* m_fdinfo;
	fd_type m_fd_type;
	string m_tstr;
	uint8_t m_tcstr[2];
	uint32_t m_tbool;

private:
	uint8_t* extract_from_null_fd(sinsp_evt *evt, OUT uint32_t* len, bool sanitize_strings);
	bool extract_fdname_from_creator(sinsp_evt *evt, OUT uint32_t* len, bool sanitize_strings);
	bool extract_fd(sinsp_evt *evt);
};

//
// thread sinsp_filter_check_thread
//
class sinsp_filter_check_thread : public sinsp_filter_check
{
public:
	enum check_type
	{
		TYPE_PID = 0,
		TYPE_EXE = 1,
		TYPE_NAME = 2,
		TYPE_ARGS = 3,
		TYPE_ENV = 4,
		TYPE_CMDLINE = 5,
		TYPE_EXELINE = 6,
		TYPE_CWD = 7,
		TYPE_NTHREADS = 8,
		TYPE_NCHILDS = 9,
		TYPE_PPID = 10,
		TYPE_PNAME = 11,
		TYPE_PCMDLINE = 12,
		TYPE_APID = 13,
		TYPE_ANAME = 14,
		TYPE_LOGINSHELLID = 15,
		TYPE_DURATION = 16,
		TYPE_FDOPENCOUNT = 17,
		TYPE_FDLIMIT = 18,
		TYPE_FDUSAGE = 19,
		TYPE_VMSIZE = 20,
		TYPE_VMRSS = 21,
		TYPE_VMSWAP = 22,
		TYPE_PFMAJOR = 23,
		TYPE_PFMINOR = 24,
		TYPE_TID = 25,
		TYPE_ISMAINTHREAD = 26,
		TYPE_EXECTIME = 27,
		TYPE_TOTEXECTIME = 28,
		TYPE_CGROUPS = 29,
		TYPE_CGROUP = 30,
		TYPE_VTID = 31,
		TYPE_VPID = 32,
		TYPE_THREAD_CPU = 33,
		TYPE_THREAD_CPU_USER = 34,
		TYPE_THREAD_CPU_SYSTEM = 35,
		TYPE_THREAD_VMSIZE = 36,
		TYPE_THREAD_VMRSS = 37,
		TYPE_THREAD_VMSIZE_B = 38,
		TYPE_THREAD_VMRSS_B = 39,
		TYPE_SID = 40,
		TYPE_SNAME = 41,
		TYPE_TTY = 42,
		TYPE_EXEPATH = 43,
		TYPE_NAMETID = 44,
		TYPE_VPGID = 45,
		TYPE_IS_CONTAINER_HEALTHCHECK = 46,
		TYPE_IS_CONTAINER_LIVENESS_PROBE = 47,
		TYPE_IS_CONTAINER_READINESS_PROBE = 48,
	};

	sinsp_filter_check_thread();
	sinsp_filter_check* allocate_new();
	int32_t parse_field_name(const char* str, bool alloc_state, bool needed_for_filtering);
	uint8_t* extract(sinsp_evt *evt, OUT uint32_t* len, bool sanitize_strings = true);
	bool compare(sinsp_evt *evt);

private:
	uint64_t extract_exectime(sinsp_evt *evt);
	int32_t extract_arg(string fldname, string val, OUT const struct ppm_param_info** parinfo);
	uint8_t* extract_thread_cpu(sinsp_evt *evt, OUT uint32_t* len, sinsp_threadinfo* tinfo, bool extract_user, bool extract_system);
	inline bool compare_full_apid(sinsp_evt *evt);
	bool compare_full_aname(sinsp_evt *evt);

	int32_t m_argid;
	string m_argname;
	uint32_t m_tbool;
	string m_tstr;
	uint64_t m_u64val;
	int64_t m_s64val;
	double m_dval;
	vector<uint64_t> m_last_proc_switch_times;
	uint32_t m_th_state_id;
	uint64_t m_cursec_ts;
};

//
// event checks
//
class sinsp_filter_check_event : public sinsp_filter_check
{
public:
	enum check_type
	{
		TYPE_NUMBER = 0,
		TYPE_TIME = 1,
		TYPE_TIME_S = 2,
		TYPE_TIME_ISO8601 = 3,
		TYPE_DATETIME = 4,
		TYPE_RAWTS = 5,
		TYPE_RAWTS_S = 6,
		TYPE_RAWTS_NS = 7,
		TYPE_RELTS = 8,
		TYPE_RELTS_S = 9,
		TYPE_RELTS_NS = 10,
		TYPE_LATENCY = 11,
		TYPE_LATENCY_S = 12,
		TYPE_LATENCY_NS = 13,
		TYPE_LATENCY_QUANTIZED = 14,
		TYPE_LATENCY_HUMAN = 15,
		TYPE_DELTA = 16,
		TYPE_DELTA_S = 17,
		TYPE_DELTA_NS = 18,
		TYPE_RUNTIME_TIME_OUTPUT_FORMAT = 19,
		TYPE_DIR = 20,
		TYPE_TYPE = 21,
		TYPE_TYPE_IS = 22,
		TYPE_SYSCALL_TYPE = 23,
		TYPE_CATEGORY = 24,
		TYPE_CPU = 25,
		TYPE_ARGS = 26,
		TYPE_ARGSTR = 27,
		TYPE_ARGRAW = 28,
		TYPE_INFO = 29,
		TYPE_BUFFER = 30,
		TYPE_BUFLEN = 31,
		TYPE_RESSTR = 32,
		TYPE_RESRAW = 33,
		TYPE_FAILED = 34,
		TYPE_ISIO = 35,
		TYPE_ISIO_READ = 36,
		TYPE_ISIO_WRITE = 37,
		TYPE_IODIR = 38,
		TYPE_ISWAIT = 39,
		TYPE_WAIT_LATENCY = 40,
		TYPE_ISSYSLOG = 41,
		TYPE_COUNT = 42,
		TYPE_COUNT_ERROR = 43,
		TYPE_COUNT_ERROR_FILE = 44,
		TYPE_COUNT_ERROR_NET = 45,
		TYPE_COUNT_ERROR_MEMORY = 46,
		TYPE_COUNT_ERROR_OTHER = 47,
		TYPE_COUNT_EXIT = 48,
		TYPE_COUNT_PROCINFO = 49,
		TYPE_COUNT_THREADINFO = 50,
		TYPE_AROUND = 51,
		TYPE_ABSPATH = 52,
		TYPE_BUFLEN_IN = 53,
		TYPE_BUFLEN_OUT = 54,
		TYPE_BUFLEN_FILE = 55,
		TYPE_BUFLEN_FILE_IN = 56,
		TYPE_BUFLEN_FILE_OUT = 57,
		TYPE_BUFLEN_NET = 58,
		TYPE_BUFLEN_NET_IN = 59,
		TYPE_BUFLEN_NET_OUT = 60,
		TYPE_ISOPEN_READ = 61,
		TYPE_ISOPEN_WRITE = 62,
		TYPE_INFRA_DOCKER_NAME = 63,
		TYPE_INFRA_DOCKER_CONTAINER_ID = 64,
		TYPE_INFRA_DOCKER_CONTAINER_NAME = 65,
		TYPE_INFRA_DOCKER_CONTAINER_IMAGE = 66,
	};

	sinsp_filter_check_event();
	~sinsp_filter_check_event();
	sinsp_filter_check* allocate_new();
	int32_t parse_field_name(const char* str, bool alloc_state, bool needed_for_filtering);
	size_t parse_filter_value(const char* str, uint32_t len, uint8_t *storage, uint32_t storage_len);
	void validate_filter_value(const char* str, uint32_t len);
	const filtercheck_field_info* get_field_info();
	uint8_t* extract(sinsp_evt *evt, OUT uint32_t* len, bool sanitize_strings = true);
	Json::Value extract_as_js(sinsp_evt *evt, OUT uint32_t* len);
	bool compare(sinsp_evt *evt);

	uint64_t m_u64val;
	uint64_t m_tsdelta;
	uint32_t m_u32val;
	string m_strstorage;
	string m_argname;
	int32_t m_argid;
	uint32_t m_evtid;
	uint32_t m_evtid1;
	const ppm_param_info* m_arginfo;

	//
	// Note: this copy of the field is used by some fields, like TYPE_ARGS and
	// TYPE_RESARG, that need to do on the fly type customization
	//
	filtercheck_field_info m_customfield;

private:
	int32_t extract_arg(string fldname, string val, OUT const struct ppm_param_info** parinfo);
	int32_t extract_type(string fldname, string val, OUT const struct ppm_param_info** parinfo);
	uint8_t* extract_error_count(sinsp_evt *evt, OUT uint32_t* len);
	uint8_t *extract_abspath(sinsp_evt *evt, OUT uint32_t *len);
	inline uint8_t* extract_buflen(sinsp_evt *evt, OUT uint32_t* len);

	bool m_is_compare;
	char* m_storage;
	uint32_t m_storage_size;
	const char* m_cargname;
	sinsp_filter_check_reference* m_converter;
};

//
// user checks
//
class sinsp_filter_check_user : public sinsp_filter_check
{
public:
	enum check_type
	{
		TYPE_UID = 0,
		TYPE_NAME = 1,
		TYPE_HOMEDIR = 2,
		TYPE_SHELL = 3,
		TYPE_LOGINUID = 4,
		TYPE_LOGINNAME = 5,
	};

	sinsp_filter_check_user();
	sinsp_filter_check* allocate_new();
	uint8_t* extract(sinsp_evt *evt, OUT uint32_t* len, bool sanitize_strings = true);

	uint32_t m_uid;
	string m_strval;
};

//
// group checks
//
class sinsp_filter_check_group : public sinsp_filter_check
{
public:
	enum check_type
	{
		TYPE_GID,
		TYPE_NAME,
	};

	sinsp_filter_check_group();
	sinsp_filter_check* allocate_new();
	uint8_t* extract(sinsp_evt *evt, OUT uint32_t* len, bool sanitize_strings = true);

	uint32_t m_gid;
	string m_name;
};

//
// Tracers
//
#define TEXT_ARG_ID -1000000

class sinsp_filter_check_tracer : public sinsp_filter_check
{
public:
	enum check_type
	{
		TYPE_ID = 0,
		TYPE_TIME,
		TYPE_NTAGS,
		TYPE_NARGS,
		TYPE_TAGS,
		TYPE_TAG,
		TYPE_ARGS,
		TYPE_ARG,
		TYPE_ENTERARGS,
		TYPE_ENTERARG,
		TYPE_DURATION,
		TYPE_DURATION_QUANTIZED,
		TYPE_DURATION_HUMAN,
		TYPE_TAGDURATION,
		TYPE_COUNT,
		TYPE_TAGCOUNT,
		TYPE_TAGCHILDSCOUNT,
		TYPE_IDTAG,
		TYPE_RAWTIME,
		TYPE_RAWPARENTTIME,
	};

	sinsp_filter_check_tracer();
	~sinsp_filter_check_tracer();
	sinsp_filter_check* allocate_new();
	int32_t parse_field_name(const char* str, bool alloc_state, bool needed_for_filtering);
	uint8_t* extract(sinsp_evt *evt, OUT uint32_t* len, bool sanitize_strings = true);

private:
	int32_t extract_arg(string fldname, string val, OUT const struct ppm_param_info** parinfo);
	inline uint8_t* extract_duration(uint16_t etype, sinsp_tracerparser* eparser, OUT uint32_t* len);
	uint8_t* extract_args(sinsp_partial_tracer* pae, OUT uint32_t *len);
	uint8_t* extract_arg(sinsp_partial_tracer* pae, OUT uint32_t *len);

	int32_t m_argid;
	string m_argname;
	const char* m_cargname;
	char* m_storage;
	uint32_t m_storage_size;
	int64_t m_s64val;
	int32_t m_u32val;
	sinsp_filter_check_reference* m_converter;
	string m_strstorage;
};

//
// Events in tracers checks
//
class sinsp_filter_check_evtin : public sinsp_filter_check
{
public:
	enum check_type
	{
		TYPE_ID = 0,
		TYPE_NTAGS,
		TYPE_NARGS,
		TYPE_TAGS,
		TYPE_TAG,
		TYPE_ARGS,
		TYPE_ARG,
		TYPE_P_ID,
		TYPE_P_NTAGS,
		TYPE_P_NARGS,
		TYPE_P_TAGS,
		TYPE_P_TAG,
		TYPE_P_ARGS,
		TYPE_P_ARG,
		TYPE_S_ID,
		TYPE_S_NTAGS,
		TYPE_S_NARGS,
		TYPE_S_TAGS,
		TYPE_S_TAG,
		TYPE_S_ARGS,
		TYPE_S_ARG,
		TYPE_M_ID,
		TYPE_M_NTAGS,
		TYPE_M_NARGS,
		TYPE_M_TAGS,
		TYPE_M_TAG,
		TYPE_M_ARGS,
		TYPE_M_ARG,
	};

	sinsp_filter_check_evtin();
	~sinsp_filter_check_evtin();
	int32_t parse_field_name(const char* str, bool alloc_state, bool needed_for_filtering);
	sinsp_filter_check* allocate_new();
	uint8_t* extract(sinsp_evt *evt, OUT uint32_t* len, bool sanitize_strings = true);
	bool compare(sinsp_evt *evt);

	uint64_t m_u64val;
	uint64_t m_tsdelta;
	uint32_t m_u32val;
	string m_strstorage;
	string m_argname;
	int32_t m_argid;
	uint32_t m_evtid;
	uint32_t m_evtid1;
	const ppm_param_info* m_arginfo;

	//
	// Note: this copy of the field is used by some fields, like TYPE_ARGS and
	// TYPE_RESARG, that need to do on the fly type customization
	//
	filtercheck_field_info m_customfield;

private:
	int32_t extract_arg(string fldname, string val);
	inline uint8_t* extract_tracer(sinsp_evt *evt, sinsp_partial_tracer* pae, OUT uint32_t* len);
	inline bool compare_tracer(sinsp_evt *evt, sinsp_partial_tracer* pae);

	bool m_is_compare;
	char* m_storage;
	uint32_t m_storage_size;
	const char* m_cargname;
	sinsp_filter_check_reference* m_converter;
};

//
// Fake filter check used by the event formatter to render format text
//
class rawstring_check : public sinsp_filter_check
{
public:
	rawstring_check(string text);
	sinsp_filter_check* allocate_new();
	void set_text(string text);
	int32_t parse_field_name(const char* str, bool alloc_state, bool needed_for_filtering);
	uint8_t* extract(sinsp_evt *evt, OUT uint32_t* len, bool sanitize_strings = true);

	// XXX this is overkill and wasted for most of the fields.
	// It could be optimized by dynamically allocating the right amount
	// of memory, but we don't care for the moment since we expect filters
	// to be pretty small.
	string m_text;
	uint32_t m_text_len;
};

//
// syslog checks
//
class sinsp_decoder_syslog;

class sinsp_filter_check_syslog : public sinsp_filter_check
{
public:
	enum check_type
	{
		TYPE_FACILITY_STR = 0,
		TYPE_FACILITY,
		TYPE_SEVERITY_STR,
		TYPE_SEVERITY,
		TYPE_MESSAGE,
	};

	sinsp_filter_check_syslog();
	sinsp_filter_check* allocate_new();
	int32_t parse_field_name(const char* str, bool alloc_state, bool needed_for_filtering);
	uint8_t* extract(sinsp_evt *evt, OUT uint32_t* len, bool sanitize_strings = true);

	sinsp_decoder_syslog* m_decoder;
	uint32_t m_gid;
	string m_name;
};

class sinsp_filter_check_container : public sinsp_filter_check
{
public:
	enum check_type
	{
		TYPE_CONTAINER_ID = 0,
		TYPE_CONTAINER_NAME,
		TYPE_CONTAINER_IMAGE,
		TYPE_CONTAINER_IMAGE_ID,
		TYPE_CONTAINER_TYPE,
		TYPE_CONTAINER_PRIVILEGED,
		TYPE_CONTAINER_MOUNTS,
		TYPE_CONTAINER_MOUNT,
		TYPE_CONTAINER_MOUNT_SOURCE,
		TYPE_CONTAINER_MOUNT_DEST,
		TYPE_CONTAINER_MOUNT_MODE,
		TYPE_CONTAINER_MOUNT_RDWR,
		TYPE_CONTAINER_MOUNT_PROPAGATION,
		TYPE_CONTAINER_IMAGE_REPOSITORY,
		TYPE_CONTAINER_IMAGE_TAG,
		TYPE_CONTAINER_IMAGE_DIGEST,
		TYPE_CONTAINER_HEALTHCHECK,
		TYPE_CONTAINER_LIVENESS_PROBE,
		TYPE_CONTAINER_READINESS_PROBE,
	};

	sinsp_filter_check_container();
	sinsp_filter_check* allocate_new();
	uint8_t* extract(sinsp_evt *evt, OUT uint32_t* len, bool sanitize_strings = true);

private:
	int32_t parse_field_name(const char* str, bool alloc_state, bool needed_for_filtering);
	int32_t extract_arg(const string& val, size_t basename);

	string m_tstr;
	uint32_t m_u32val;
	int32_t m_argid;
	string m_argstr;
};

//
// For internal use
//
class sinsp_filter_check_reference : public sinsp_filter_check
{
public:
	enum alignment
	{
		ALIGN_LEFT,
		ALIGN_RIGHT,
	};

	sinsp_filter_check_reference();
	sinsp_filter_check* allocate_new();
	inline void set_val(ppm_param_type type, uint8_t* val,
		int32_t len, uint32_t cnt,
		ppm_print_format print_format)
	{
		m_finfo.m_type = type;
		m_val = val;
		m_len = len;
		m_cnt = cnt;
		m_print_format = print_format;
	}
	int32_t parse_field_name(const char* str, bool alloc_state, bool needed_for_filtering);
	uint8_t* extract(sinsp_evt *evt, OUT uint32_t* len, bool sanitize_strings = true);
	char* tostring_nice(sinsp_evt* evt, uint32_t str_len, uint64_t time_delta);
	Json::Value tojson(sinsp_evt* evt, uint32_t str_len, uint64_t time_delta);

private:
	inline char* format_bytes(double val, uint32_t str_len, bool is_int);
	inline char* format_time(uint64_t val, uint32_t str_len);
	char* print_double(uint8_t* rawval, uint32_t str_len);
	char* print_int(uint8_t* rawval, uint32_t str_len);

	filtercheck_field_info m_finfo;
	uint8_t* m_val;
	uint32_t m_len;
	double m_cnt;		// For averages, this stores the entry count
	ppm_print_format m_print_format;
};

//
// For internal use
//
class sinsp_filter_check_utils : public sinsp_filter_check
{
public:
	enum check_type
	{
		TYPE_CNT,
	};

	sinsp_filter_check_utils();
	sinsp_filter_check* allocate_new();
	uint8_t* extract(sinsp_evt *evt, OUT uint32_t* len, bool sanitize_strings = true);

private:
	uint64_t m_cnt;
};

//
// fdlist checks
//
class sinsp_filter_check_fdlist : public sinsp_filter_check
{
public:
	enum check_type
	{
		TYPE_FDNUMS = 0,
		TYPE_FDNAMES = 1,
		TYPE_CLIENTIPS = 2,
		TYPE_SERVERIPS = 3,
		TYPE_CLIENTPORTS = 4,
		TYPE_SERVERPORTS = 5,
	};

	sinsp_filter_check_fdlist();
	sinsp_filter_check* allocate_new();
	uint8_t* extract(sinsp_evt *evt, OUT uint32_t* len, bool sanitize_strings = true);

private:
	string m_strval;
	char m_addrbuff[100];
};

#ifndef CYGWING_AGENT

class sinsp_filter_check_k8s : public sinsp_filter_check
{
public:
	enum check_type
	{
		TYPE_K8S_POD_NAME = 0,
		TYPE_K8S_POD_ID,
		TYPE_K8S_POD_LABEL,
		TYPE_K8S_POD_LABELS,
		TYPE_K8S_RC_NAME,
		TYPE_K8S_RC_ID,
		TYPE_K8S_RC_LABEL,
		TYPE_K8S_RC_LABELS,
		TYPE_K8S_SVC_NAME,
		TYPE_K8S_SVC_ID,
		TYPE_K8S_SVC_LABEL,
		TYPE_K8S_SVC_LABELS,
		TYPE_K8S_NS_NAME,
		TYPE_K8S_NS_ID,
		TYPE_K8S_NS_LABEL,
		TYPE_K8S_NS_LABELS,
		TYPE_K8S_RS_NAME,
		TYPE_K8S_RS_ID,
		TYPE_K8S_RS_LABEL,
		TYPE_K8S_RS_LABELS,
		TYPE_K8S_DEPLOYMENT_NAME,
		TYPE_K8S_DEPLOYMENT_ID,
		TYPE_K8S_DEPLOYMENT_LABEL,
		TYPE_K8S_DEPLOYMENT_LABELS,
	};

	sinsp_filter_check_k8s();
	sinsp_filter_check* allocate_new();
	int32_t parse_field_name(const char* str, bool alloc_state, bool needed_for_filtering);
	uint8_t* extract(sinsp_evt *evt, OUT uint32_t* len, bool sanitize_strings = true);

private:
	int32_t extract_arg(const string& fldname, const string& val);
	const k8s_pod_t* find_pod_for_thread(const sinsp_threadinfo* tinfo);
	const k8s_ns_t* find_ns_by_name(const string& ns_name);
	const k8s_rc_t* find_rc_by_pod(const k8s_pod_t* pod);
	const k8s_rs_t* find_rs_by_pod(const k8s_pod_t* pod);
	vector<const k8s_service_t*> find_svc_by_pod(const k8s_pod_t* pod);
	const k8s_deployment_t* find_deployment_by_pod(const k8s_pod_t* pod);
	void concatenate_labels(const k8s_pair_list& labels, string* s);
	bool find_label(const k8s_pair_list& labels, const string& key, string* value);

	string m_argname;
	string m_tstr;
};

#endif // CYGWING_AGENT

#ifndef CYGWING_AGENT
class sinsp_filter_check_mesos : public sinsp_filter_check
{
public:
	enum check_type
	{
		TYPE_MESOS_TASK_NAME = 0,
		TYPE_MESOS_TASK_ID,
		TYPE_MESOS_TASK_LABEL,
		TYPE_MESOS_TASK_LABELS,
		TYPE_MESOS_FRAMEWORK_NAME,
		TYPE_MESOS_FRAMEWORK_ID,
		TYPE_MARATHON_APP_NAME,
		TYPE_MARATHON_APP_ID,
		TYPE_MARATHON_APP_LABEL,
		TYPE_MARATHON_APP_LABELS,
		TYPE_MARATHON_GROUP_NAME,
		TYPE_MARATHON_GROUP_ID,
	};

	sinsp_filter_check_mesos();
	sinsp_filter_check* allocate_new();
	int32_t parse_field_name(const char* str, bool alloc_state, bool needed_for_filtering);
	uint8_t* extract(sinsp_evt *evt, OUT uint32_t* len, bool sanitize_strings = true);

private:

	int32_t extract_arg(const string& fldname, const string& val);
	mesos_task::ptr_t find_task_for_thread(const sinsp_threadinfo* tinfo);
	const mesos_framework* find_framework_by_task(mesos_task::ptr_t task);
	marathon_app::ptr_t find_app_by_task(mesos_task::ptr_t task);
	marathon_group::ptr_t find_group_by_task(mesos_task::ptr_t task);
	void concatenate_labels(const mesos_pair_list& labels, string* s);
	bool find_label(const mesos_pair_list& labels, const string& key, string* value);

	string m_argname;
	string m_tstr;
};
#endif // CYGWING_AGENT

#endif // HAS_FILTERING
