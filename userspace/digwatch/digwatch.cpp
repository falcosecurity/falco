#define __STDC_FORMAT_MACROS

#include <stdio.h>
#include <iostream>
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
}

#include <sinsp.h>
#include <config_digwatch.h>
#include "rules.h"
#include "formats.h"
#include "digwatch.h"
#include "utils.h"


//
// Program help
//
static void usage()
{
    printf(
	   "Usage: digwatch [options] rules_filename\n\n"
	   "Options:\n"
	   " -h, --help         Print this page\n"
	   " -m <filename>, --main-lua <filename>\n"
	   "                    Name of lua compiler main file\n"
	   "                    (default: rules_loader.lua)\n"
	   " -M <num_seconds>   Stop collecting after <num_seconds> reached.\n"
	   " -N                 Don't convert port numbers to names.\n"
	   " -n <num>, --numevents=<num>\n"
	   "                    Stop capturing after <num> events\n"
	   " -r <readfile>, --read=<readfile>\n"
	   "                    Read the events from <readfile>.\n"
	   " --unbuffered       Turn off output buffering. This causes every single line\n"
	   "                    emitted by digwatch to be flushed, which generates higher CPU\n"
	   "                    usage but is useful when piping digwatch's output into another\n"
	   "                    process or into a script.\n"
	   "\n"
    );
}


//
// Event processing loop
//
captureinfo do_inspect(sinsp* inspector,
		       uint64_t cnt,
		       int duration_to_tot,
		       digwatch_rules* rules,
		       digwatch_formats* formats)
{
	captureinfo retval;
	int32_t res;
	sinsp_evt* ev;
	string line;
        int duration_start = 0;
	sinsp_evt_formatter* formatter;

	//
	// Loop through the events
	//
	duration_start = ((double)clock()) / CLOCKS_PER_SEC;
	while(1)
	{
		if(duration_to_tot > 0)
		{
			int duration_tot = ((double)clock()) / CLOCKS_PER_SEC - duration_start;
			if(duration_tot >= duration_to_tot)
			{
				break;
			}
		}
		if(retval.m_nevts == cnt)
		{
			//
			// End of capture, either because the user stopped it, or because
			// we reached the event count specified with -n.
			//
			break;
		}

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

		retval.m_nevts++;

		if(!inspector->is_debug_enabled() &&
			ev->get_category() & EC_INTERNAL)
		{
			continue;
		}

		formatter = formats->lookup_formatter(ev->get_check_id());
		if(!formatter)
		{
			throw sinsp_exception("Error: No formatter for event with id %d " + to_string(ev->get_check_id()));
		}

		bool has_all = formatter->tostring(ev, &line);
		if(!has_all) {
			cout << "(missing fields) ";
		}
		cout << line;
		cout << endl;


	}

	return retval;
}

//
// ARGUMENT PARSING AND PROGRAM SETUP
//
int digwatch_init(int argc, char **argv)
{
	int result;
	sinsp* inspector = NULL;
	digwatch_rules* rules = NULL;
	digwatch_formats* formats = NULL;
	int op;
	uint64_t cnt = -1;
	sinsp_evt::param_fmt event_buffer_format = sinsp_evt::PF_NORMAL;
	int duration_to_tot = 0;
	captureinfo cinfo;
	int long_index = 0;
	string lua_main_filename;
	string lua_dir = DIGWATCH_INSTALLATION_DIR;
	lua_State* ls;

	static struct option long_options[] =
	{
		{"help", no_argument, 0, 'h' },
		{"numevents", required_argument, 0, 'n' },
		{"main-lua", required_argument, 0, 'u' },
		{"readfile", required_argument, 0, 'r' },
		{"unbuffered", no_argument, 0, 0 },
		{0, 0, 0, 0}
	};

	try
	{
		inspector = new sinsp();


		//
		// Parse the args
		//
		while((op = getopt_long(argc, argv,
                                        "hm:M:Nn:r:",
                                        long_options, &long_index)) != -1)
		{
			switch(op)
			{
			case 'h':
				usage();
				result = EXIT_SUCCESS;
				goto exit;
			case 'm':
				lua_main_filename = optarg;
				break;
			case 'M':
				duration_to_tot = atoi(optarg);
				if(duration_to_tot <= 0)
				{
					throw sinsp_exception(string("invalid duration") + optarg);
				}
				break;
			case 'N':
				inspector->set_hostname_and_port_resolution_mode(false);
				break;
			case 'n':
				try
				{
					cnt = sinsp_numparser::parseu64(optarg);
				}
				catch(...)
				{
					throw sinsp_exception("can't parse the -n argument, make sure it's a number");
				}

				if(cnt <= 0)
				{
					throw sinsp_exception(string("invalid event count ") + optarg);
				}
				break;
			case '?':
				result = EXIT_FAILURE;
				goto exit;
			default:
				break;
			}

		}

		inspector->set_buffer_format(event_buffer_format);

		string rules_file;

		if(optind < argc)
		{
#ifdef HAS_FILTERING
			for(int32_t j = optind ; j < argc; j++)
			{
				rules_file += argv[j];
				if(j < argc - 1)
				{
					rules_file += " ";
				}
			}

#else
			fprintf(stderr, "filtering not compiled.\n");
			result = EXIT_FAILURE;
			goto exit;
#endif
		}

		if(rules_file.size() == 0) {
			usage();
			result = EXIT_FAILURE;
			goto exit;

		}

		//
		char* env_lua_dir = getenv("DIGWATCH_LUA_DIR");
		if(env_lua_dir)
		{
			lua_dir = string(env_lua_dir);
		}

		trim(lua_main_filename);
		if(lua_main_filename.size() == 0)
		{
			lua_main_filename = lua_dir + DIGWATCH_LUA_MAIN;
		}

		// Initialize Lua interpreter
		ls = lua_open();
		luaL_openlibs(ls);

		rules = new digwatch_rules(inspector, ls, lua_main_filename, lua_dir);
		formats = new digwatch_formats(inspector, ls);

		rules->load_rules(rules_file);
		inspector->set_filter(rules->get_filter());
		inspector->open("");

		cinfo = do_inspect(inspector,
				   cnt,
				   duration_to_tot,
				   rules,
				   formats);

		inspector->close();
	}
	catch(sinsp_exception& e)
	{
		cerr << e.what() << endl;
		result = EXIT_FAILURE;
	}
	catch(...)
	{
		printf("Exception\n");
		result = EXIT_FAILURE;
	}

exit:

	if(inspector)
	{
		delete inspector;
	}

	lua_close(ls);
	return result;
}

//
// MAIN
//
int main(int argc, char **argv)
{
	return digwatch_init(argc, argv);
}
