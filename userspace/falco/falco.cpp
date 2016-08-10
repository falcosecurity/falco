#define __STDC_FORMAT_MACROS

#include <stdio.h>
#include <fstream>
#include <set>
#include <list>
#include <string>
#include <signal.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <getopt.h>

#include <sinsp.h>

#include "logger.h"

#include "configuration.h"
#include "falco_engine.h"
#include "config_falco.h"

bool g_terminate = false;
//
// Helper functions
//
static void signal_callback(int signal)
{
	g_terminate = true;
}

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
           " -r <rules_file>               Rules file (defaults to value set in configuration file, or /etc/falco_rules.yaml).\n"
	   "                               Can be specified multiple times to read from multiple files.\n"
	   " -D <pattern>                  Disable any rules matching the regex <pattern>. Can be specified multiple times.\n"
	   " -L                            Show the name and description of all rules and exit.\n"
	   " -l <rule>                     Show the name and description of the rule with name <rule> and exit.\n"
	   " -v                            Verbose output.\n"
	   " -A                            Monitor all events, including those with EF_DROP_FALCO flag.\n"
	   "\n"
    );
}

static void display_fatal_err(const string &msg)
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

// Splitting into key=value or key.subkey=value will be handled by configuration class.
std::list<string> cmdline_options;

//
// Event processing loop
//
void do_inspect(falco_engine *engine,
		falco_outputs *outputs,
		sinsp* inspector)
{
	int32_t res;
	sinsp_evt* ev;

	//
	// Loop through the events
	//
	while(1)
	{

		res = inspector->next(&ev);

		if (g_terminate)
		{
			break;
		}
		else if(res == SCAP_TIMEOUT)
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

		// As the inspector has no filter at its level, all
		// events are returned here. Pass them to the falco
		// engine, which will match the event against the set
		// of rules. If a match is found, pass the event to
		// the outputs.
		falco_engine::rule_result *res = engine->process_event(ev);
		if(res)
		{
			outputs->handle_event(res->evt, res->rule, res->priority, res->format);
			delete(res);
		}
	}
}

//
// ARGUMENT PARSING AND PROGRAM SETUP
//
int falco_init(int argc, char **argv)
{
	int result = EXIT_SUCCESS;
	sinsp* inspector = NULL;
	falco_engine *engine = NULL;
	falco_outputs *outputs = NULL;
	int op;
	int long_index = 0;
	string scap_filename;
	string conf_filename;
	list<string> rules_filenames;
	bool daemon = false;
	string pidfilename = "/var/run/falco.pid";
	bool describe_all_rules = false;
	string describe_rule = "";
	bool verbose = false;
	bool all_events = false;

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
		engine = new falco_engine();
		engine->set_inspector(inspector);

		outputs = new falco_outputs();
		outputs->set_inspector(inspector);

		set<string> disabled_rule_patterns;
		string pattern;

		//
		// Parse the args
		//
		while((op = getopt_long(argc, argv,
                                        "c:ho:e:r:D:dp:Ll:vA",
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
				rules_filenames.push_back(optarg);
				break;
			case 'D':
				pattern = optarg;
				disabled_rule_patterns.insert(pattern);
				break;
			case 'd':
				daemon = true;
				break;
			case 'p':
				pidfilename = optarg;
				break;
			case 'L':
				describe_all_rules = true;
				break;
			case 'v':
				verbose = true;
				break;
			case 'A':
				all_events = true;
				break;
			case 'l':
				describe_rule = optarg;
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
			throw std::invalid_argument("If -d is provided, a pid file must also be provided");
		}

		ifstream conf_stream;
		if (conf_filename.size())
		{
			conf_stream.open(conf_filename);
			if (!conf_stream.is_open())
			{
				throw std::runtime_error("Could not find configuration file at " + conf_filename);
			}
		}
		else
		{
			conf_stream.open(FALCO_SOURCE_CONF_FILE);
			if (!conf_stream.is_open())
			{
				conf_filename = FALCO_SOURCE_CONF_FILE;
			}
			else
			{
				conf_stream.open(FALCO_INSTALL_CONF_FILE);
				if (!conf_stream.is_open())
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

		if (rules_filenames.size())
		{
			config.m_rules_filenames = rules_filenames;
		}

		for (auto filename : config.m_rules_filenames)
		{
			engine->load_rules_file(filename, verbose, all_events);
			falco_logger::log(LOG_INFO, "Parsed rules from file " + filename + "\n");
		}

		for (auto pattern : disabled_rule_patterns)
		{
			falco_logger::log(LOG_INFO, "Disabling rules matching pattern: " + pattern + "\n");
			engine->enable_rule(pattern, false);
		}

		outputs->init(config.m_json_output);

		if(!all_events)
		{
			inspector->set_drop_event_flags(EF_DROP_FALCO);
		}

		if (describe_all_rules)
		{
			engine->describe_rule(NULL);
			goto exit;
		}

		if (describe_rule != "")
		{
			engine->describe_rule(&describe_rule);
			goto exit;
		}

		inspector->set_hostname_and_port_resolution_mode(false);

		for(auto output : config.m_outputs)
		{
			outputs->add_output(output);
		}

		if(signal(SIGINT, signal_callback) == SIG_ERR)
		{
			fprintf(stderr, "An error occurred while setting SIGINT signal handler.\n");
			result = EXIT_FAILURE;
			goto exit;
		}

		if(signal(SIGTERM, signal_callback) == SIG_ERR)
		{
			fprintf(stderr, "An error occurred while setting SIGTERM signal handler.\n");
			result = EXIT_FAILURE;
			goto exit;
		}

		if (scap_filename.size())
		{
			inspector->open(scap_filename);
		}
		else
		{
			try
			{
				inspector->open(200);
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

		do_inspect(engine,
			   outputs,
			   inspector);

		inspector->close();

		engine->print_stats();
	}
	catch(exception &e)
	{
		display_fatal_err("Runtime error: " + string(e.what()) + ". Exiting.\n");

		result = EXIT_FAILURE;
	}

exit:

	delete inspector;
	delete engine;
	delete outputs;

	return result;
}

//
// MAIN
//
int main(int argc, char **argv)
{
	return falco_init(argc, argv);
}
