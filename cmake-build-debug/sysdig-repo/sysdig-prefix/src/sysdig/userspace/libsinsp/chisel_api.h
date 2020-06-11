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

class lua_cbacks
{
public:
	static uint32_t rawval_to_lua_stack(lua_State *ls, uint8_t* rawval, ppm_param_type ptype, uint32_t len);

	static int get_num(lua_State *ls); 
	static int get_ts(lua_State *ls);
	static int get_type(lua_State *ls);
	static int get_cpuid(lua_State *ls);
	static int request_field(lua_State *ls);
	static int field(lua_State *ls);
	static int set_global_filter(lua_State *ls);
	static int set_filter(lua_State *ls);
	static int set_snaplen(lua_State *ls);
	static int set_output_format(lua_State *ls);
	static int set_fatfile_dump_mode(lua_State *ls);
	static int make_ts(lua_State *ls);
	static int add_ts(lua_State *ls);
	static int subtract_ts(lua_State *ls);
	static int run_sysdig(lua_State *ls);
	static int end_capture(lua_State *ls);
	static int is_live(lua_State *ls);
	static int is_tty(lua_State *ls);
	static int get_terminal_info(lua_State *ls);
	static int get_filter(lua_State *ls);
	static int get_machine_info(lua_State *ls);
	static int get_thread_table(lua_State *ls);
	static int get_thread_table_nofds(lua_State *ls);
	static int get_thread_table_barebone(lua_State *ls);
	static int get_thread_table_barebone_nofds(lua_State *ls);
	static int get_container_table(lua_State *ls);
	static int is_print_container_data(lua_State *ls);
	static int get_output_format(lua_State *ls);
	static int get_evtsource_name(lua_State *ls);
	static int get_firstevent_ts(lua_State *ls);
	static int get_lastevent_ts(lua_State *ls);
	static int set_event_formatter(lua_State *ls);
	static int set_interval_ns(lua_State *ls);
	static int set_interval_s(lua_State *ls);
	static int set_precise_interval_ns(lua_State *ls);
	static int exec(lua_State *ls);
	static int log(lua_State *ls);
	static int udp_setpeername(lua_State *ls);
	static int udp_send(lua_State *ls);
	static int get_read_progress(lua_State *ls);
#ifdef HAS_ANALYZER
	static int push_metric(lua_State *ls);
#endif
private:
	static int get_thread_table_int(lua_State *ls, bool include_fds, bool barebone);
};

#endif // HAS_CHISELS

