/*
Copyright (C) 2016 Draios inc.

This file is part of falco.

falco is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License version 2 as
published by the Free Software Foundation.

falco is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with falco.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <cstdlib>
#include <unistd.h>
#include <string>
#include <fstream>

#include "falco_engine.h"
#include "config_falco_engine.h"

extern "C" {
#include "lpeg.h"
#include "lyaml.h"
}

#include "utils.h"


string lua_on_event = "on_event";
string lua_print_stats = "print_stats";

using namespace std;

falco_engine::falco_engine(bool seed_rng)
	: m_rules(NULL), m_sampling_ratio(1), m_sampling_multiplier(0),
	  m_replace_container_info(false)
{
	luaopen_lpeg(m_ls);
	luaopen_yaml(m_ls);

	falco_common::init(m_lua_main_filename.c_str(), FALCO_ENGINE_SOURCE_LUA_DIR);
	falco_rules::init(m_ls);

	if(seed_rng)
	{
		srandom((unsigned) getpid());
	}
}

falco_engine::~falco_engine()
{
	if (m_rules)
	{
		delete m_rules;
	}
}

void falco_engine::load_rules(const string &rules_content, bool verbose, bool all_events)
{
	// The engine must have been given an inspector by now.
	if(! m_inspector)
	{
		throw falco_exception("No inspector provided");
	}

	if(!m_rules)
	{
		m_rules = new falco_rules(m_inspector, this, m_ls);
	}
	m_rules->load_rules(rules_content, verbose, all_events, m_extra, m_replace_container_info);
}

void falco_engine::load_rules_file(const string &rules_filename, bool verbose, bool all_events)
{
	ifstream is;

	is.open(rules_filename);
	if (!is.is_open())
	{
		throw falco_exception("Could not open rules filename " +
				      rules_filename + " " +
				      "for reading");
	}

	string rules_content((istreambuf_iterator<char>(is)),
			     istreambuf_iterator<char>());

	load_rules(rules_content, verbose, all_events);
}

void falco_engine::enable_rule(string &pattern, bool enabled)
{
	m_evttype_filter.enable(pattern, enabled);
}

falco_engine::rule_result *falco_engine::process_event(sinsp_evt *ev)
{

	if(should_drop_evt())
	{
		return NULL;
	}

	if(!m_evttype_filter.run(ev))
	{
		return NULL;
	}

	struct rule_result *res = new rule_result();

	lua_getglobal(m_ls, lua_on_event.c_str());

	if(lua_isfunction(m_ls, -1))
	{
		lua_pushlightuserdata(m_ls, ev);
		lua_pushnumber(m_ls, ev->get_check_id());

		if(lua_pcall(m_ls, 2, 3, 0) != 0)
		{
			const char* lerr = lua_tostring(m_ls, -1);
			string err = "Error invoking function output: " + string(lerr);
			throw falco_exception(err);
		}
		res->evt = ev;
		const char *p =  lua_tostring(m_ls, -3);
		res->rule = p;
		res->priority = lua_tostring(m_ls, -2);
		res->format = lua_tostring(m_ls, -1);
		lua_pop(m_ls, 3);
	}
	else
	{
		throw falco_exception("No function " + lua_on_event + " found in lua compiler module");
	}

	return res;
}

void falco_engine::describe_rule(string *rule)
{
	return m_rules->describe_rule(rule);
}

// Print statistics on the the rules that triggered
void falco_engine::print_stats()
{
	lua_getglobal(m_ls, lua_print_stats.c_str());

	if(lua_isfunction(m_ls, -1))
	{
		if(lua_pcall(m_ls, 0, 0, 0) != 0)
		{
			const char* lerr = lua_tostring(m_ls, -1);
			string err = "Error invoking function print_stats: " + string(lerr);
			throw falco_exception(err);
		}
	}
	else
	{
		throw falco_exception("No function " + lua_print_stats + " found in lua rule loader module");
	}

}

void falco_engine::add_evttype_filter(string &rule,
				      list<uint32_t> &evttypes,
				      sinsp_filter* filter)
{
	m_evttype_filter.add(rule, evttypes, filter);
}

void falco_engine::set_sampling_ratio(uint32_t sampling_ratio)
{
	m_sampling_ratio = sampling_ratio;
}

void falco_engine::set_sampling_multiplier(double sampling_multiplier)
{
	m_sampling_multiplier = sampling_multiplier;
}

void falco_engine::set_extra(string &extra, bool replace_container_info)
{
	m_extra = extra;
	m_replace_container_info = replace_container_info;
}

inline bool falco_engine::should_drop_evt()
{
	if(m_sampling_multiplier == 0)
	{
		return false;
	}

	if(m_sampling_ratio == 1)
	{
		return false;
	}

	double coin = (random() * (1.0/RAND_MAX));
	return (coin >= (1.0/(m_sampling_multiplier * m_sampling_ratio)));
}
