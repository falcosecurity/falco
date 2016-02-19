#define __STDC_FORMAT_MACROS

#include <stdio.h>
#include <iostream>
#include <time.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <algorithm>

#include <sinsp.h>
#include "lua_parser.h"
#include "digwatch.h"
#include "utils.h"

#include <unistd.h>
#include <getopt.h>

lua_parser* g_lua_parser;

static void usage();

//
// Program help
//
static void usage()
{
    printf(
	   "Usage: digwatch [options] [-p <output_format>] [filter]\n\n"
	   "Options:\n"
	   " -h, --help         Print this page\n"
	   " -M <num_seconds>   Stop collecting after <num_seconds> reached.\n"
	   " -N                 Don't convert port numbers to names.\n"
	   " -n <num>, --numevents=<num>\n"
	   "                    Stop capturing after <num> events\n"
	   " -u <filename>, --user-parser <filename>\n"
	   "                    Name of lua file containing parser\n"
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
		       sinsp_evt_formatter* formatter)
{
	captureinfo retval;
	int32_t res;
	sinsp_evt* ev;
	string line;
        int duration_start = 0;

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
		if(formatter->tostring(ev, &line))
		{
			cout << line;
			cout << endl;
		}

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
	int op;
	uint64_t cnt = -1;
	sinsp_evt::param_fmt event_buffer_format = sinsp_evt::PF_NORMAL;
	int duration_to_tot = 0;
	captureinfo cinfo;
	string output_format;
	int long_index = 0;
	string user_parser;

	static struct option long_options[] =
	{
		{"help", no_argument, 0, 'h' },
		{"numevents", required_argument, 0, 'n' },
		{"user-parser", required_argument, 0, 'u' },
		{"readfile", required_argument, 0, 'r' },
		{"unbuffered", no_argument, 0, 0 },
		{0, 0, 0, 0}
	};

	output_format = "*%evt.num %evt.outputtime %evt.cpu %proc.name (%thread.tid) %evt.dir %evt.type %evt.info";

	try
	{
		inspector = new sinsp();


		//
		// Parse the args
		//
		while((op = getopt_long(argc, argv,
                                        "hM:Nn:r:u:",
                                        long_options, &long_index)) != -1)
		{
			switch(op)
			{
			case 'h':
				usage();
				result = EXIT_SUCCESS;
				goto exit;
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
			case 'u':
				user_parser = optarg;
				break;
			case '?':
				result = EXIT_FAILURE;
				goto exit;
			default:
				break;
			}

		}

		inspector->set_buffer_format(event_buffer_format);

		string filter;

		//
		// the filter is at the end of the command line
		//
		if(optind < argc)
		{
#ifdef HAS_FILTERING
			for(int32_t j = optind ; j < argc; j++)
			{
				filter += argv[j];
				if(j < argc - 1)
				{
					filter += " ";
				}
			}

#else
			fprintf(stderr, "filtering not compiled.\n");
			result = EXIT_FAILURE;
			goto exit;
#endif
		}

		//
		// Create the event formatter
		//
		sinsp_evt_formatter formatter(inspector, output_format);

		g_lua_parser = new lua_parser(inspector, user_parser);

		inspector->set_filter(g_lua_parser->m_filter);
		inspector->open("");

		cinfo = do_inspect(inspector,
				   cnt,
				   duration_to_tot,
				   &formatter);

		inspector->close();
	}
	catch(sinsp_exception& e)
	{
		cerr << e.what() << endl;
		result = EXIT_FAILURE;
	}
	catch(...)
	{
		printf("Exeception\n");
		result = EXIT_FAILURE;
	}

exit:

	if(inspector)
	{
		delete inspector;
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
