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

#ifdef HAS_CHISELS

class sinsp_filter_check;
class sinsp_evt_formatter;
class sinsp_view_info;

typedef struct lua_State lua_State;

/** @defgroup filter Filtering events
 * Filtering infrastructure.
 *  @{
 */

/*!
  \brief This is the class that compiles and runs sysdig-type filters.
*/
typedef struct chiseldir_info
{
	bool m_need_to_resolve;
	std::string m_dir;
}chiseldir_info;

class chiselarg_desc
{
public:
	chiselarg_desc(string name, string type, string description, bool optional)
	{
		m_name = name;
		m_type = type;
		m_description = description;
		m_optional = optional;
	}

	string m_name;
	string m_type;
	string m_description;
	bool m_optional;
};

class chisel_desc
{
public:
	void reset()
	{
		m_name = "";
		m_description = "";
		m_category = "";
		m_shortdesc = "";
		m_args.clear();
	}

	string m_name;
	string m_description;
	string m_category;
	string m_shortdesc;
	vector<chiselarg_desc> m_args;
	sinsp_view_info m_viewinfo;
};

class chiselinfo
{
public:
	chiselinfo(sinsp* inspector);
	void init(string filterstr, string formatterstr); 
	void set_filter(string filterstr);
	void set_formatter(string formatterstr);
	void set_callback_interval(uint64_t interval);
	void set_callback_precise_interval(uint64_t interval);
	~chiselinfo();
	sinsp_filter* m_filter;
	sinsp_evt_formatter* m_formatter;
	sinsp_dumper* m_dumper;
	uint64_t m_callback_interval;
	uint64_t m_callback_precise_interval;
	bool m_has_nextrun_args;
	string m_nextrun_args;
	bool m_end_capture;

private:
	sinsp* m_inspector;
};

class SINSP_PUBLIC sinsp_chisel
{
public:
	sinsp_chisel(sinsp* inspector, string filename);
	~sinsp_chisel();
	static void add_lua_package_path(lua_State* ls, const char* path);
	static void get_chisel_list(vector<chisel_desc>* chisel_descs);
	void load(string cmdstr);
	string get_name()
	{
		return m_filename;
	}
	uint32_t get_n_args();
	uint32_t get_n_optional_args();
	uint32_t get_n_required_args();
	void set_args(string args);
	void set_args(vector<pair<string, string>> args);
	bool run(sinsp_evt* evt);
	void do_timeout(sinsp_evt* evt);
	void do_end_of_sample();
	void on_init();
	void on_capture_start();
	void on_capture_end();
	bool get_nextrun_args(OUT string* args);
	chisel_desc* get_lua_script_info()
	{
		return &m_lua_script_info;
	}

private:
	bool openfile(string filename, OUT ifstream* is);
	void free_lua_chisel();
	static sinsp_field_aggregation string_to_aggregation(string ag);
	static void parse_view_column(lua_State *ls, OUT chisel_desc* cd, OUT void* columns);
	static void parse_view_columns(lua_State *ls, OUT chisel_desc* cd, OUT void* columns);
	static void parse_view_action(lua_State *ls, OUT chisel_desc* cd, OUT void* actions);
	static void parse_view_actions(lua_State *ls, OUT chisel_desc* cd, OUT void* actions);
	static bool parse_view_info(lua_State *ls, OUT chisel_desc* cd);
	static bool init_lua_chisel(chisel_desc &cd, string const &path);
	void first_event_inits(sinsp_evt* evt);

	sinsp* m_inspector;
	string m_description;
	vector<string> m_argvals;
	string m_filename;
	lua_State* m_ls;
	chisel_desc m_lua_script_info;
	bool m_lua_has_handle_evt;
	bool m_lua_is_first_evt;
	uint64_t m_lua_last_interval_sample_time;
	uint64_t m_lua_last_interval_ts;
	vector<sinsp_filter_check*> m_allocated_fltchecks;
	char m_lua_fld_storage[PPM_MAX_ARG_SIZE];
	chiselinfo* m_lua_cinfo;
	string m_new_chisel_to_exec;
	int m_udp_socket;
	struct sockaddr_in m_serveraddr;

	friend class lua_cbacks;
};

/*@}*/

#endif // HAS_CHISELS

