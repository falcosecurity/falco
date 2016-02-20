#include "rules.h"

extern "C" {
#include "lua.h"
#include "lualib.h"
#include "lauxlib.h"
}

digwatch_rules::digwatch_rules(sinsp* inspector, string compiler_filename)
{
	m_lua_parser = new lua_parser(inspector);
	m_ls = m_lua_parser->m_ls;

	trim(compiler_filename);

	ifstream is;
	is.open(compiler_filename);
	if(!is.is_open())
	{
		throw sinsp_exception("can't open file " + compiler_filename);
	}

	string scriptstr((istreambuf_iterator<char>(is)),
			 istreambuf_iterator<char>());

	//
	// Load the compiler script
	//
	if(luaL_loadstring(m_ls, scriptstr.c_str()) || lua_pcall(m_ls, 0, 0, 0))
	{
		throw sinsp_exception("Failed to load script " +
			compiler_filename + ": " + lua_tostring(m_ls, -1));
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

