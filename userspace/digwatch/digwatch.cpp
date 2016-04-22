#define __STDC_FORMAT_MACROS

#include <stdio.h>
#include <iostream>
#include <signal.h>
#include <time.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <algorithm>
#include <unistd.h>
#include <getopt.h>

extern "C" {
#include "lua.h"
#include "lualib.h"
#include "lauxlib.h"
#include "lpeg.h"
}

#include <sinsp.h>
#include "config_digwatch.h"
#include "configuration.h"
#include "rules.h"
#include "formats.h"
#include "fields.h"
#include "syslog.h"
#include "utils.h"
#include <yaml-cpp/yaml.h>


std::vector<string> valid_output_names {"stdout", "syslog"};

//
// Program help
//
static void usage()
{
    printf(
	   "Usage: digwatch [options] rules_filename\n\n"
	   "Options:\n"
	   " -h, --help         Print this page\n"
	   " -c                 Configuration file (default " DIGWATCH_SOURCE_CONF_FILE ", " DIGWATCH_INSTALL_CONF_FILE ")\n"
	   " -o                 Output type (options are 'stdout', 'syslog', default is 'stdout')\n"
           " -e <events_file>   Read the events from <events_file> (in .scap format) instead of tapping into live.\n"
           " -r <rules_file>    Rules file (defaults to value set in configuration file, or /etc/digwatch_rules.conf).\n"
	   "\n"
    );
}

string lua_on_event = "on_event";
string lua_add_output = "add_output";

//
// Event processing loop
//
void do_inspect(sinsp* inspector,
		digwatch_rules* rules,
		lua_State* ls)
{
	int32_t res;
	sinsp_evt* ev;
	string line;

	//
	// Loop through the events
	//
	while(1)
	{

		res = inspector->next(&ev);

		if(res == SCAP_TIMEOUT)
		{
			continue;
		}
		else if(res == SCAP_EOF)
		{
			break;
		}
		else if(res != SCAP_SUCCESS)
		{
			//
			// Event read error.
			// Notify the chisels that we're exiting, and then die with an error.
			//
			cerr << "res = " << res << endl;
			throw sinsp_exception(inspector->getlasterr().c_str());
		}

		if(!inspector->is_debug_enabled() &&
			ev->get_category() & EC_INTERNAL)
		{
			continue;
		}

		lua_getglobal(ls, lua_on_event.c_str());

		if(lua_isfunction(ls, -1))
		{
			lua_pushlightuserdata(ls, ev);
			lua_pushnumber(ls, ev->get_check_id());

			if(lua_pcall(ls, 2, 0, 0) != 0)
			{
				const char* lerr = lua_tostring(ls, -1);
				string err = "Error invoking function output: " + string(lerr);
				throw sinsp_exception(err);
			}
		}
		else
		{
			throw sinsp_exception("No function " + lua_on_event + " found in lua compiler module");
		}
	}
}

void add_lua_path(lua_State *ls, string path)
{
	string cpath = string(path);
	path += "?.lua";
	cpath += "?.so";

	lua_getglobal(ls, "package");

	lua_getfield(ls, -1, "path");
	string cur_path = lua_tostring(ls, -1 );
	cur_path += ';';
	lua_pop(ls, 1);

	cur_path.append(path.c_str());

	lua_pushstring(ls, cur_path.c_str());
	lua_setfield(ls, -2, "path");

	lua_getfield(ls, -1, "cpath");
	string cur_cpath = lua_tostring(ls, -1 );
	cur_cpath += ';';
	lua_pop(ls, 1);

	cur_cpath.append(cpath.c_str());

	lua_pushstring(ls, cur_cpath.c_str());
	lua_setfield(ls, -2, "cpath");

	lua_pop(ls, 1);
}

void add_output(lua_State *ls, output_config oc)
{

	uint8_t nargs = 1;
	lua_getglobal(ls, lua_add_output.c_str());

	if(!lua_isfunction(ls, -1))
	{
		throw sinsp_exception("No function " + lua_add_output + " found. ");
	}
	lua_pushstring(ls, oc.name.c_str());

	// If we have options, build up a lua table containing them
	if (oc.options.size())
	{
		nargs = 2;
		lua_createtable(ls, 0, oc.options.size());

		for (auto it = oc.options.cbegin(); it != oc.options.cend(); ++it)
		{
			lua_pushstring(ls, (*it).second.c_str());
			lua_setfield(ls, -2, (*it).first.c_str());
		}
	}

	if(lua_pcall(ls, nargs, 0, 0) != 0)
	{
		const char* lerr = lua_tostring(ls, -1);
		throw sinsp_exception(string(lerr));
	}

}


//
// ARGUMENT PARSING AND PROGRAM SETUP
//
int digwatch_init(int argc, char **argv)
{
	int result = EXIT_SUCCESS;
	sinsp* inspector = NULL;
	digwatch_rules* rules = NULL;
	int op;
	sinsp_evt::param_fmt event_buffer_format;
	int long_index = 0;
	string lua_main_filename;
	string output_name = "stdout";
	string scap_filename;
	string conf_filename;
	string rules_filename;
	string lua_dir = DIGWATCH_LUA_DIR;
	lua_State* ls = NULL;

	static struct option long_options[] =
	{
		{"help", no_argument, 0, 'h' },
		{0, 0, 0, 0}
	};

	try
	{
		inspector = new sinsp();
		bool valid;

		//
		// Parse the args
		//
		while((op = getopt_long(argc, argv,
                                        "c:ho:e:r:",
                                        long_options, &long_index)) != -1)
		{
			switch(op)
			{
			case 'h':
				usage();
				goto exit;
			case 'c':
				conf_filename = optarg;
				break;
			case 'o':
				valid = std::find(valid_output_names.begin(), valid_output_names.end(), optarg) != valid_output_names.end();
				if (!valid)
				{
					throw sinsp_exception(string("Invalid output name ") + optarg);
				}
				output_name = optarg;
				break;
			case 'e':
				scap_filename = optarg;
				break;
			case 'r':
				rules_filename = optarg;
				break;
			case '?':
				result = EXIT_FAILURE;
				goto exit;
			default:
				break;
			}

		}


		ifstream* conf_stream;
		if (conf_filename.size())
		{
			conf_stream = new ifstream(conf_filename);
			if (!conf_stream->good())
			{
				fprintf(stderr, "Could not find configuration file at %s \n", conf_filename.c_str());
				result = EXIT_FAILURE;
				goto exit;
			}
		}
		else
		{
			conf_stream = new ifstream(DIGWATCH_SOURCE_CONF_FILE);
			if (conf_stream->good())
			{
				conf_filename = DIGWATCH_SOURCE_CONF_FILE;
			}
			else
			{
				conf_stream = new ifstream(DIGWATCH_INSTALL_CONF_FILE);
				if (conf_stream->good())
				{
					conf_filename = DIGWATCH_INSTALL_CONF_FILE;
				}
				else
				{
					conf_filename = "";
				}
			}
		}

		digwatch_configuration config;
		if (conf_filename.size())
		{
			cout << "Using configuration file " + conf_filename + "\n";
			config.init(conf_filename);
		}
		else
		{
			cout << "No configuration file found, proceeding with defaults\n";
			config.init();
		}

		if (rules_filename.size())
		{
			config.m_rules_filename = rules_filename;
		}
		cout << "Using rules file " + config.m_rules_filename + "\n";

		lua_main_filename = lua_dir + DIGWATCH_LUA_MAIN;
		if (!std::ifstream(lua_main_filename))
		{
			lua_dir = DIGWATCH_SOURCE_LUA_DIR;
			lua_main_filename = lua_dir + DIGWATCH_LUA_MAIN;
			if (!std::ifstream(lua_main_filename))
			{
				fprintf(stderr, "Could not find Digwatch Lua libraries (tried %s, %s). \n",
					DIGWATCH_LUA_DIR DIGWATCH_LUA_MAIN,
					lua_main_filename.c_str());
				result = EXIT_FAILURE;
				goto exit;
			}
		}

		// Initialize Lua interpreter
		ls = lua_open();
		luaL_openlibs(ls);
		luaopen_lpeg(ls);
		add_lua_path(ls, lua_dir);

		rules = new digwatch_rules(inspector, ls, lua_main_filename);

		digwatch_formats::init(inspector, ls);
		digwatch_fields::init(inspector, ls);

		digwatch_syslog::init(ls);

		rules->load_rules(config.m_rules_filename);
		inspector->set_filter(rules->get_filter());

		inspector->set_hostname_and_port_resolution_mode(false);

		if (config.m_json_output)
		{
			event_buffer_format = sinsp_evt::PF_JSON;
		}
		else
		{
			event_buffer_format = sinsp_evt::PF_NORMAL;
		}
		inspector->set_buffer_format(event_buffer_format);

		for(std::vector<output_config>::iterator it = config.m_outputs.begin(); it != config.m_outputs.end(); ++it)
		{
			add_output(ls, *it);
		}

		if (scap_filename.size())
		{
			inspector->open(scap_filename);
		}
		else
		{
			try
			{
				inspector->open();
			}
			catch(sinsp_exception e)
			{
				if(system("modprobe " PROBE_NAME " > /dev/null 2> /dev/null"))
				{
					fprintf(stderr, "Unable to load the driver\n");
				}
				inspector->open();
			}
		}
		do_inspect(inspector,
			   rules,
			   ls);

		inspector->close();
	}
	catch(sinsp_exception& e)
	{
		cerr << e.what() << endl;
		result = EXIT_FAILURE;
	}
	catch(...)
	{
		printf("Error, exiting.\n");
		result = EXIT_FAILURE;
	}

exit:

	if(inspector)
	{
		delete inspector;
	}

	if(ls)
	{
		lua_close(ls);
	}
	return result;
}

//
// MAIN
//
int main(int argc, char **argv)
{
	return digwatch_init(argc, argv);
}
