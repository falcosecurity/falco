#include "rules.h"

extern "C" {
#include "lua.h"
#include "lualib.h"
#include "lauxlib.h"
}


digwatch_rules::digwatch_rules(sinsp* inspector, lua_State *ls, string lua_main_filename, string lua_dir)
{
	m_ls = ls;

	m_lua_parser = new lua_parser(inspector, m_ls);

	add_lua_path(lua_dir);
	load_compiler(lua_main_filename);
}

void digwatch_rules::add_lua_path(string path)
{
	path += "?.lua";

	lua_getglobal(m_ls, "package");
	lua_getfield(m_ls, -1, "path");

	string cur_path = lua_tostring(m_ls, -1 );
	cur_path += ';';

	cur_path.append(path.c_str());
	lua_pop(m_ls, 1);

	lua_pushstring(m_ls, cur_path.c_str());
	lua_setfield(m_ls, -2, "path");
	lua_pop(m_ls, 1);
}

void digwatch_rules::load_compiler(string lua_main_filename)
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

void digwatch_rules::load_rules(string rules_filename)
{
	ifstream is;
	is.open(rules_filename);
	if(!is.is_open())
	{
		throw sinsp_exception("can't open file " + rules_filename);
	}

	lua_getglobal(m_ls, m_lua_load_rule.c_str());
	if(lua_isfunction(m_ls, -1))
	{
		lua_pop(m_ls, 1);
	} else {
		throw sinsp_exception("No function " + m_lua_load_rule + " found in lua compiler module");
	}

	std::string line;
	while (std::getline(is, line))
	{
		lua_getglobal(m_ls, m_lua_load_rule.c_str());
		lua_pushstring(m_ls, line.c_str());

		if(lua_pcall(m_ls, 1, 0, 0) != 0)
		{
			const char* lerr = lua_tostring(m_ls, -1);
			string err = "Error loading rule '" + line + "':" + string(lerr);
			throw sinsp_exception(err);
		}
	}

	lua_getglobal(m_ls, m_lua_on_done.c_str());
	if(lua_isfunction(m_ls, -1))
	{
		if(lua_pcall(m_ls, 0, 0, 0) != 0)
		{
			const char* lerr = lua_tostring(m_ls, -1);
			string err = "Error installing rules: " + string(lerr);
			throw sinsp_exception(err);
		}
	} else {
		throw sinsp_exception("No function " + m_lua_on_done + " found in lua compiler module");
	}

}

sinsp_filter* digwatch_rules::get_filter()
{
	return m_lua_parser->get_filter();
}

digwatch_rules::~digwatch_rules()
{
	delete m_lua_parser;
}

