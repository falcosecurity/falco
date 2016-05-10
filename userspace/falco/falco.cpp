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
#include "lyaml.h"
}

#include <sinsp.h>
#include "config_falco.h"
#include "configuration.h"
#include "rules.h"
#include "formats.h"
#include "fields.h"
#include "logger.h"
#include "utils.h"
#include <yaml-cpp/yaml.h>


//
// Program help
//
static void usage()
{
    printf(
	   "Usage: falco [options]\n\n"
	   "Options:\n"
	   " -h, --help                    Print this page\n"
	   " -c                            Configuration file (default " FALCO_SOURCE_CONF_FILE ", " FALCO_INSTALL_CONF_FILE ")\n"
	   " -o, --option <key>=<val>      Set the value of option <key> to <val>. Overrides values in configuration file.\n"
	   "                               <key> can be a two-part <key>.<subkey>\n"
	   " -d, --daemon                  Run as a daemon\n"
	   " -p, --pidfile <pid_file>      When run as a daemon, write pid to specified file\n"
           " -e <events_file>              Read the events from <events_file> (in .scap format) instead of tapping into live.\n"
           " -r <rules_file>               Rules file (defaults to value set in configuration file, or /etc/falco_rules.conf).\n"
	   "\n"
    );
}

static void display_fatal_err(const string &msg, bool daemon)
{
	falco_logger::log(LOG_ERR, msg);

	/**
	 * If stderr logging is not enabled, also log to stderr. When
	 * daemonized this will simply write to /dev/null.
	 */
	if (! falco_logger::log_stderr)
	{
		std::cerr << msg;
	}
}

string lua_on_event = "on_event";
string lua_add_output = "add_output";

// Splitting into key=value or key.subkey=value will be handled by configuration class.
std::list<string> cmdline_options;

//
// Event processing loop
//
void do_inspect(sinsp* inspector,
		falco_rules* rules,
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
int falco_init(int argc, char **argv)
{
	int result = EXIT_SUCCESS;
	sinsp* inspector = NULL;
	falco_rules* rules = NULL;
	int op;
	sinsp_evt::param_fmt event_buffer_format;
	int long_index = 0;
	string lua_main_filename;
	string scap_filename;
	string conf_filename;
	string rules_filename;
	string lua_dir = FALCO_LUA_DIR;
	lua_State* ls = NULL;
	bool daemon = false;
	string pidfilename = "/var/run/falco.pid";

	static struct option long_options[] =
	{
		{"help", no_argument, 0, 'h' },
		{"daemon", no_argument, 0, 'd' },
		{"option", required_argument, 0, 'o'},
		{"pidfile", required_argument, 0, 'p' },

		{0, 0, 0, 0}
	};

	try
	{
		inspector = new sinsp();

		//
		// Parse the args
		//
		while((op = getopt_long(argc, argv,
                                        "c:ho:e:r:dp:",
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
				cmdline_options.push_back(optarg);
				break;
			case 'e':
				scap_filename = optarg;
				break;
			case 'r':
				rules_filename = optarg;
				break;
			case 'd':
				daemon = true;
				break;
			case 'p':
				pidfilename = optarg;
				break;
			case '?':
				result = EXIT_FAILURE;
				goto exit;
			default:
				break;
			}

		}

		// Some combinations of arguments are not allowed.
		if (daemon && pidfilename == "") {
			throw sinsp_exception("If -d is provided, a pid file must also be provided");
		}

		ifstream* conf_stream;
		if (conf_filename.size())
		{
			conf_stream = new ifstream(conf_filename);
			if (!conf_stream->good())
			{
				throw sinsp_exception("Could not find configuration file at " + conf_filename);
			}
		}
		else
		{
			conf_stream = new ifstream(FALCO_SOURCE_CONF_FILE);
			if (conf_stream->good())
			{
				conf_filename = FALCO_SOURCE_CONF_FILE;
			}
			else
			{
				conf_stream = new ifstream(FALCO_INSTALL_CONF_FILE);
				if (conf_stream->good())
				{
					conf_filename = FALCO_INSTALL_CONF_FILE;
				}
				else
				{
					conf_filename = "";
				}
			}
		}

		falco_configuration config;
		if (conf_filename.size())
		{
			config.init(conf_filename, cmdline_options);
			// log after config init because config determines where logs go
			falco_logger::log(LOG_INFO, "Falco initialized with configuration file " + conf_filename + "\n");
		}
		else
		{
			config.init(cmdline_options);
			falco_logger::log(LOG_INFO, "Falco initialized. No configuration file found, proceeding with defaults\n");
		}

		if (rules_filename.size())
		{
			config.m_rules_filename = rules_filename;
		}

		lua_main_filename = lua_dir + FALCO_LUA_MAIN;
		if (!std::ifstream(lua_main_filename))
		{
			lua_dir = FALCO_SOURCE_LUA_DIR;
			lua_main_filename = lua_dir + FALCO_LUA_MAIN;
			if (!std::ifstream(lua_main_filename))
			{
				falco_logger::log(LOG_ERR, "Could not find Falco Lua libraries (tried " +
						     string(FALCO_LUA_DIR FALCO_LUA_MAIN) + ", " +
						     lua_main_filename + "). Exiting.\n");
				result = EXIT_FAILURE;
				goto exit;
			}
		}

		// Initialize Lua interpreter
		ls = lua_open();
		luaL_openlibs(ls);
		luaopen_lpeg(ls);
		luaopen_yaml(ls);
		add_lua_path(ls, lua_dir);

		rules = new falco_rules(inspector, ls, lua_main_filename);

		falco_formats::init(inspector, ls);
		falco_fields::init(inspector, ls);

		falco_logger::init(ls);


		inspector->set_drop_event_flags(EF_DROP_FALCO);
		rules->load_rules(config.m_rules_filename);
		inspector->set_filter(rules->get_filter());
		falco_logger::log(LOG_INFO, "Parsed rules from file " + config.m_rules_filename + "\n");

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
					falco_logger::log(LOG_ERR, "Unable to load the driver. Exiting.\n");
				}
				inspector->open();
			}
		}

		// If daemonizing, do it here so any init errors will
		// be returned in the foreground process.
		if (daemon) {
			pid_t pid, sid;

			pid = fork();
			if (pid < 0) {
				// error
				falco_logger::log(LOG_ERR, "Could not fork. Exiting.\n");
				result = EXIT_FAILURE;
				goto exit;
			} else if (pid > 0) {
				// parent. Write child pid to pidfile and exit
				std::ofstream pidfile;
				pidfile.open(pidfilename);

				if (!pidfile.good())
				{
					falco_logger::log(LOG_ERR, "Could not write pid to pid file " + pidfilename + ". Exiting.\n");
					result = EXIT_FAILURE;
					goto exit;
				}
				pidfile << pid;
				pidfile.close();
				goto exit;
			}
			// if here, child.

			// Become own process group.
			sid = setsid();
			if (sid < 0) {
				falco_logger::log(LOG_ERR, "Could not set session id. Exiting.\n");
				result = EXIT_FAILURE;
				goto exit;
			}

			// Set umask so no files are world anything or group writable.
			umask(027);

			// Change working directory to '/'
			if ((chdir("/")) < 0) {
				falco_logger::log(LOG_ERR, "Could not change working directory to '/'. Exiting.\n");
				result = EXIT_FAILURE;
				goto exit;
			}

			// Close stdin, stdout, stderr and reopen to /dev/null
			close(0);
			close(1);
			close(2);
			open("/dev/null", O_RDONLY);
			open("/dev/null", O_RDWR);
			open("/dev/null", O_RDWR);
		}

		do_inspect(inspector,
			   rules,
			   ls);

		inspector->close();
	}
	catch(sinsp_exception& e)
	{
		display_fatal_err("Runtime error: " + string(e.what()) + ". Exiting.\n", daemon);

		result = EXIT_FAILURE;
	}
	catch(...)
	{
		display_fatal_err("Unexpected error, Exiting\n", daemon);

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
	return falco_init(argc, argv);
}
