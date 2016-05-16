#include "rules.h"

extern "C" {
#include "lua.h"
#include "lualib.h"
#include "lauxlib.h"
}


falco_rules::falco_rules(sinsp* inspector, lua_State *ls, string lua_main_filename)
{
        m_inspector = inspector;
	m_ls = ls;

	m_lua_parser = new lua_parser(inspector, m_ls);

	load_compiler(lua_main_filename);
}


void falco_rules::load_compiler(string lua_main_filename)
{
	ifstream is;
	is.open(lua_main_filename);
	if(!is.is_open())
	{
		throw sinsp_exception("can't open file " + lua_main_filename);
	}

	string scriptstr((istreambuf_iterator<char>(is)),
			 istreambuf_iterator<char>());

	//
	// Load the compiler script
	//
	if(luaL_loadstring(m_ls, scriptstr.c_str()) || lua_pcall(m_ls, 0, 0, 0))
	{
		throw sinsp_exception("Failed to load script " +
			lua_main_filename + ": " + lua_tostring(m_ls, -1));
	}
}

void falco_rules::load_rules(string rules_filename)
{
	lua_getglobal(m_ls, m_lua_load_rules.c_str());
	if(lua_isfunction(m_ls, -1))
	{
		// Create a table containing the syscalls/events that
		// are ignored by the kernel module. load_rules will
		// return an error if any rule references one of these
		// syscalls/events.
		sinsp_evttables* einfo = m_inspector->get_event_info_tables();
		const struct ppm_event_info* etable = einfo->m_event_info;
		const struct ppm_syscall_desc* stable = einfo->m_syscall_info_table;

		lua_newtable(m_ls);

		for(uint32_t j = 0; j < PPM_EVENT_MAX; j++)
		{
			if(etable[j].flags & EF_DROP_FALCO)
			{
				lua_pushstring(m_ls, etable[j].name);
				lua_pushnumber(m_ls, 1);
				lua_settable(m_ls, -3);
			}
		}

		lua_setglobal(m_ls, m_lua_ignored_events.c_str());

		lua_newtable(m_ls);

		for(uint32_t j = 0; j < PPM_SC_MAX; j++)
		{
			if(stable[j].flags & EF_DROP_FALCO)
			{
				lua_pushstring(m_ls, stable[j].name);
				lua_pushnumber(m_ls, 1);
				lua_settable(m_ls, -3);
			}
		}

		lua_setglobal(m_ls, m_lua_ignored_syscalls.c_str());

		lua_pushstring(m_ls, rules_filename.c_str());
		if(lua_pcall(m_ls, 1, 0, 0) != 0)
		{
			const char* lerr = lua_tostring(m_ls, -1);
			string err = "Error loading rules:" + string(lerr);
			throw sinsp_exception(err);
		}
	} else {
		throw sinsp_exception("No function " + m_lua_load_rules + " found in lua rule module");
	}
}

void falco_rules::describe_rule(std::string *rule)
{
	lua_getglobal(m_ls, m_lua_describe_rule.c_str());
	if(lua_isfunction(m_ls, -1))
	{
		if (rule == NULL)
		{
			lua_pushnil(m_ls);
		} else {
			lua_pushstring(m_ls, rule->c_str());
		}

		if(lua_pcall(m_ls, 1, 0, 0) != 0)
		{
			const char* lerr = lua_tostring(m_ls, -1);
			string err = "Could not describe " + (rule == NULL ? "all rules" : "rule " + *rule) + ": " + string(lerr);
			throw sinsp_exception(err);
		}
	} else {
		throw sinsp_exception("No function " + m_lua_describe_rule + " found in lua rule module");
	}
}


sinsp_filter* falco_rules::get_filter()
{
	return m_lua_parser->get_filter();
}

falco_rules::~falco_rules()
{
	delete m_lua_parser;
}

