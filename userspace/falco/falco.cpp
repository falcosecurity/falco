/*
Copyright (C) 2020 The Falco Authors.

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

#define __STDC_FORMAT_MACROS

#include <stdio.h>
#include <fstream>
#include <set>
#include <list>
#include <vector>
#include <algorithm>
#include <string>
#include <chrono>
#include <functional>
#include <signal.h>
#include <fcntl.h>
#include <sys/utsname.h>
#include <sys/stat.h>
#include <unistd.h>
#include <getopt.h>

#include <sinsp.h>

#include "logger.h"
#include "utils.h"
#include "fields_info.h"
#include "falco_utils.h"

#include "event_drops.h"
#include "configuration.h"
#include "falco_engine.h"
#include "falco_engine_version.h"
#include "config_falco.h"
#include "statsfilewriter.h"
#ifndef MINIMAL_BUILD
#include "webserver.h"
#include "grpc_server.h"
#endif
#include "banned.h" // This raises a compilation error when certain functions are used

typedef function<void(sinsp* inspector)> open_t;

bool g_terminate = false;
bool g_reopen_outputs = false;
bool g_restart = false;
bool g_daemonized = false;

//
// Helper functions
//
static void signal_callback(int signal)
{
	g_terminate = true;
}

static void reopen_outputs(int signal)
{
	g_reopen_outputs = true;
}

static void restart_falco(int signal)
{
	g_restart = true;
}

//
// Program help
//
static void usage()
{
    printf(
	   "Falco version: " FALCO_VERSION "\n"
	   "Usage: falco [options]\n\n"
	   "Options:\n"
	   " -h, --help                    Print this page\n"
	   " -c                            Configuration file (default " FALCO_SOURCE_CONF_FILE ", " FALCO_INSTALL_CONF_FILE ")\n"
	   " -A                            Monitor all events, including those with EF_DROP_SIMPLE_CONS flag.\n"
	   " --alternate-lua-dir <path>    Specify an alternate path for loading Falco lua files\n"
	   " -b, --print-base64            Print data buffers in base64.\n"
	   "                               This is useful for encoding binary data that needs to be used over media designed to.\n"
	   " --cri <path>                  Path to CRI socket for container metadata.\n"
	   "                               Use the specified socket to fetch data from a CRI-compatible runtime.\n"
	   " -d, --daemon                  Run as a daemon.\n"
	   " --disable-cri-async           Disable asynchronous CRI metadata fetching.\n"
	   "                               This is useful to let the input event wait for the container metadata fetch\n"
	   "                               to finish before moving forward. Async fetching, in some environments leads\n"
	   "                               to empty fields for container metadata when the fetch is not fast enough to be\n"
	   "                               completed asynchronously. This can have a performance penalty on your environment\n"
	   "                               depending on the number of containers and the frequency at which they are created/started/stopped\n"
	   " --disable-source <event_source>\n"
	   "                               Disable a specific event source.\n"
	   "                               Available event sources are: syscall, k8s_audit.\n"
	   "                               It can be passed multiple times.\n"
	   "                               Can not disable both the event sources.\n"
	   " -D <substring>                Disable any rules with names having the substring <substring>. Can be specified multiple times.\n"
	   "                               Can not be specified with -t.\n"
	   " -e <events_file>              Read the events from <events_file> (in .scap format for sinsp events, or jsonl for\n"
	   "                               k8s audit events) instead of tapping into live.\n"
#ifndef MINIMAL_BUILD
	   " -k <url>, --k8s-api <url>\n"
	   "                               Enable Kubernetes support by connecting to the API server specified as argument.\n"
       "                               E.g. \"http://admin:password@127.0.0.1:8080\".\n"
	   "                               The API server can also be specified via the environment variable FALCO_K8S_API.\n"
	   " -K <bt_file> | <cert_file>:<key_file[#password]>[:<ca_cert_file>], --k8s-api-cert <bt_file> | <cert_file>:<key_file[#password]>[:<ca_cert_file>]\n"
	   "                               Use the provided files names to authenticate user and (optionally) verify the K8S API server identity.\n"
	   "                               Each entry must specify full (absolute, or relative to the current directory) path to the respective file.\n"
	   "                               Private key password is optional (needed only if key is password protected).\n"
	   "                               CA certificate is optional. For all files, only PEM file format is supported. \n"
	   "                               Specifying CA certificate only is obsoleted - when single entry is provided \n"
	   "                               for this option, it will be interpreted as the name of a file containing bearer token.\n"
	   "                               Note that the format of this command-line option prohibits use of files whose names contain\n"
	   "                               ':' or '#' characters in the file name.\n"
	   " --k8s-node <node_name>        The node name will be used as a filter when requesting metadata of pods to the API server.\n"
	   "                               Usually, it should be set to the current node on which Falco is running.\n"
	   "                               If empty, no filter is set, which may have a performance penalty on large clusters.\n"
#endif
	   " -L                            Show the name and description of all rules and exit.\n"
	   " -l <rule>                     Show the name and description of the rule with name <rule> and exit.\n"
	   " --list [<source>]             List all defined fields. If <source> is provided, only list those fields for\n"
	   "                               the source <source>. Current values for <source> are \"syscall\", \"k8s_audit\"\n"
#ifndef MINIMAL_BUILD
	   " -m <url[,marathon_url]>, --mesos-api <url[,marathon_url]>\n"
	   "                               Enable Mesos support by connecting to the API server\n"
	   "                               specified as argument. E.g. \"http://admin:password@127.0.0.1:5050\".\n"
	   "                               Marathon url is optional and defaults to Mesos address, port 8080.\n"
	   "                               The API servers can also be specified via the environment variable FALCO_MESOS_API.\n"
#endif
	   " -M <num_seconds>              Stop collecting after <num_seconds> reached.\n"
	   " -N                            When used with --list, only print field names.\n"
	   " -o, --option <key>=<val>      Set the value of option <key> to <val>. Overrides values in configuration file.\n"
	   "                               <key> can be a two-part <key>.<subkey>\n"
	   " -p <output_format>, --print <output_format>\n"
	   "                               Add additional information to each falco notification's output.\n"
	   "                               With -pc or -pcontainer will use a container-friendly format.\n"
	   "                               With -pk or -pkubernetes will use a kubernetes-friendly format.\n"
	   "                               With -pm or -pmesos will use a mesos-friendly format.\n"
	   "                               Additionally, specifying -pc/-pk/-pm will change the interpretation\n"
	   "                               of %%container.info in rule output fields.\n"
	   " -P, --pidfile <pid_file>      When run as a daemon, write pid to specified file\n"
       " -r <rules_file>               Rules file/directory (defaults to value set in configuration file, or /etc/falco_rules.yaml).\n"
       "                               Can be specified multiple times to read from multiple files/directories.\n"
	   " -s <stats_file>               If specified, append statistics related to Falco's reading/processing of events\n"
	   "                               to this file (only useful in live mode).\n"
	   " --stats-interval <msec>       When using -s <stats_file>, write statistics every <msec> ms.\n"
	   "                               This uses signals, so don't recommend intervals below 200 ms.\n"
	   "                               Defaults to 5000 (5 seconds).\n"
	   " -S <len>, --snaplen <len>\n"
	   "                               Capture the first <len> bytes of each I/O buffer.\n"
	   "                               By default, the first 80 bytes are captured. Use this\n"
	   "                               option with caution, it can generate huge trace files.\n"
	   " --support                     Print support information including version, rules files used, etc. and exit.\n"
	   " -T <tag>                      Disable any rules with a tag=<tag>. Can be specified multiple times.\n"
	   "                               Can not be specified with -t.\n"
	   " -t <tag>                      Only run those rules with a tag=<tag>. Can be specified multiple times.\n"
	   "                               Can not be specified with -T/-D.\n"
	   " -U,--unbuffered               Turn off output buffering to configured outputs.\n"
	   "                               This causes every single line emitted by falco to be flushed,\n"
	   "                               which generates higher CPU usage but is useful when piping those outputs\n"
	   "                               into another process or into a script.\n"
	   " -u, --userspace               Parse events from userspace.\n"
	   "                               To be used in conjunction with the ptrace(2) based driver (pdig).\n"
	   " -V, --validate <rules_file>   Read the contents of the specified rules(s) file and exit.\n"
	   "                               Can be specified multiple times to validate multiple files.\n"
	   " -v                            Verbose output.\n"
       " --version                     Print version number.\n"
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

#ifndef MINIMAL_BUILD
// Read a jsonl file containing k8s audit events and pass each to the engine.
void read_k8s_audit_trace_file(falco_engine *engine,
			       falco_outputs *outputs,
			       string &trace_filename)
{
	ifstream ifs(trace_filename);

	uint64_t line_num = 0;

	while(ifs)
	{
		string line, errstr;

		getline(ifs, line);
		line_num++;

		if(line == "")
		{
			continue;
		}

		if(!k8s_audit_handler::accept_data(engine, outputs, line, errstr))
		{
			falco_logger::log(LOG_ERR, "Could not read k8s audit event line #" + to_string(line_num) + ", \"" + line + "\": " + errstr + ", stopping");
			return;
		}
	}
}
#endif

static std::string read_file(std::string filename)
{
	std::ifstream t(filename);
	std::string str((std::istreambuf_iterator<char>(t)),
			std::istreambuf_iterator<char>());

	return str;
}

//
// Event processing loop
//
uint64_t do_inspect(falco_engine *engine,
			falco_outputs *outputs,
			sinsp* inspector,
			falco_configuration &config,
			syscall_evt_drop_mgr &sdropmgr,
			uint64_t duration_to_tot_ns,
			string &stats_filename,
			uint64_t stats_interval,
			bool all_events,
			int &result)
{
	uint64_t num_evts = 0;
	int32_t rc;
	sinsp_evt* ev;
	StatsFileWriter writer;
	uint64_t duration_start = 0;
	uint32_t timeouts_since_last_success_or_msg = 0;

	sdropmgr.init(inspector,
		      outputs,
		      config.m_syscall_evt_drop_actions,
		      config.m_syscall_evt_drop_threshold,
		      config.m_syscall_evt_drop_rate,
		      config.m_syscall_evt_drop_max_burst,
		      config.m_syscall_evt_simulate_drops);

	if (stats_filename != "")
	{
		string errstr;

		if (!writer.init(inspector, stats_filename, stats_interval, errstr))
		{
			throw falco_exception(errstr);
		}
	}

	//
	// Loop through the events
	//
	while(1)
	{

		rc = inspector->next(&ev);

		writer.handle();

		if(g_reopen_outputs)
		{
			outputs->reopen_outputs();
			g_reopen_outputs = false;
		}

		if(g_terminate)
		{
			falco_logger::log(LOG_INFO, "SIGINT received, exiting...\n");
			break;
		}
		else if (g_restart)
		{
			falco_logger::log(LOG_INFO, "SIGHUP received, restarting...\n");
			break;
		}
		else if(rc == SCAP_TIMEOUT)
		{
			if(unlikely(ev == nullptr))
			{
				timeouts_since_last_success_or_msg++;
				if(timeouts_since_last_success_or_msg > config.m_syscall_evt_timeout_max_consecutives)
				{
					std::string rule = "Falco internal: timeouts notification";
					std::string msg = rule + ". " + std::to_string(config.m_syscall_evt_timeout_max_consecutives) + " consecutive timeouts without event.";
					std::string last_event_time_str = "none";
					if(duration_start > 0)
					{
						sinsp_utils::ts_to_string(duration_start, &last_event_time_str, false, true);
					}
					std::map<std::string, std::string> o = {
						{"last_event_time", last_event_time_str},
					};
					auto now = std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
					outputs->handle_msg(now, falco_common::PRIORITY_DEBUG, msg, rule, o);
					// Reset the timeouts counter, Falco alerted
					timeouts_since_last_success_or_msg = 0;
				}
			}

			continue;
		}
		else if(rc == SCAP_EOF)
		{
			break;
		}
		else if(rc != SCAP_SUCCESS)
		{
			//
			// Event read error.
			//
			cerr << "rc = " << rc << endl;
			throw sinsp_exception(inspector->getlasterr().c_str());
		}

		// Reset the timeouts counter, Falco succesfully got an event to process
		timeouts_since_last_success_or_msg = 0;
		if(duration_start == 0)
		{
			duration_start = ev->get_ts();
		}
		else if(duration_to_tot_ns > 0)
		{
			if(ev->get_ts() - duration_start >= duration_to_tot_ns)
			{
				break;
			}
		}

		if(!sdropmgr.process_event(inspector, ev))
		{
			result = EXIT_FAILURE;
			break;
		}

		if(!ev->simple_consumer_consider() && !all_events)
		{
			continue;
		}

		// As the inspector has no filter at its level, all
		// events are returned here. Pass them to the falco
		// engine, which will match the event against the set
		// of rules. If a match is found, pass the event to
		// the outputs.
		unique_ptr<falco_engine::rule_result> res = engine->process_sinsp_event(ev);
		if(res)
		{
			outputs->handle_event(res->evt, res->rule, res->source, res->priority_num, res->format);
		}

		num_evts++;
	}

	return num_evts;
}

static void print_all_ignored_events(sinsp *inspector)
{
	sinsp_evttables* einfo = inspector->get_event_info_tables();
	const struct ppm_event_info* etable = einfo->m_event_info;
	const struct ppm_syscall_desc* stable = einfo->m_syscall_info_table;

	std::set<string> ignored_event_names;
	for(uint32_t j = 0; j < PPM_EVENT_MAX; j++)
	{
		if(!sinsp::simple_consumer_consider_evtnum(j))
		{
			std::string name = etable[j].name;
			// Ignore event names NA*
			if(name.find("NA") != 0)
			{
				ignored_event_names.insert(name);
			}
		}
	}

	for(uint32_t j = 0; j < PPM_SC_MAX; j++)
	{
		if(!sinsp::simple_consumer_consider_syscallid(j))
		{
			std::string name = stable[j].name;
			// Ignore event names NA*
			if(name.find("NA") != 0)
			{
				ignored_event_names.insert(name);
			}
		}
	}

	printf("Ignored Event(s):");
	for(auto it : ignored_event_names)
	{
		printf(" %s", it.c_str());
	}
	printf("\n");
}

static void list_source_fields(falco_engine *engine, bool verbose, bool names_only, std::string &source)
{
	if(source.size() > 0 &&
	   !(source == "syscall" || source == "k8s_audit"))
	{
		throw std::invalid_argument("Value for --list must be \"syscall\" or \"k8s_audit\"");
	}
	if(source == "" || source == "syscall")
	{
		list_fields(verbose, false, names_only);
	}
	if(source == "" || source == "k8s_audit")
	{
		engine->list_fields(names_only);
	}
}

//
// ARGUMENT PARSING AND PROGRAM SETUP
//
int falco_init(int argc, char **argv)
{
	int result = EXIT_SUCCESS;
	sinsp* inspector = NULL;
	sinsp_evt::param_fmt event_buffer_format = sinsp_evt::PF_NORMAL;
	falco_engine *engine = NULL;
	falco_outputs *outputs = NULL;
	syscall_evt_drop_mgr sdropmgr;
	int op;
	int long_index = 0;
	string trace_filename;
	bool trace_is_scap = true;
	string conf_filename;
	string outfile;
	list<string> rules_filenames;
	bool daemon = false;
	string pidfilename = "/var/run/falco.pid";
	bool describe_all_rules = false;
	string describe_rule = "";
	list<string> validate_rules_filenames;
	string stats_filename = "";
	uint64_t stats_interval = 5000;
	bool verbose = false;
	bool names_only = false;
	bool all_events = false;
#ifndef MINIMAL_BUILD
	string* k8s_api = 0;
	string* k8s_api_cert = 0;
	string *k8s_node_name = 0;
	string* mesos_api = 0;
#endif
	string output_format = "";
	uint32_t snaplen = 0;
	bool replace_container_info = false;
	int duration_to_tot = 0;
	bool print_ignored_events = false;
	bool list_flds = false;
	string list_flds_source = "";
	bool print_support = false;
	string cri_socket_path;
	bool cri_async = true;
	set<string> disable_sources;
	bool disable_syscall = false;
	bool disable_k8s_audit = false;
	bool userspace = false;

	// Used for writing trace files
	int duration_seconds = 0;
	int rollover_mb = 0;
	int file_limit = 0;
	unsigned long event_limit = 0L;
	bool compress = false;
	bool buffered_outputs = true;
	bool buffered_cmdline = false;
	std::map<string,uint64_t> required_engine_versions;

	// Used for stats
	double duration;
	scap_stats cstats;

#ifndef MINIMAL_BUILD
	falco_webserver webserver;
	falco::grpc::server grpc_server;
	std::thread grpc_server_thread;
#endif

	static struct option long_options[] =
		{
			{"alternate-lua-dir", required_argument, 0},
			{"cri", required_argument, 0},
			{"daemon", no_argument, 0, 'd'},
			{"disable-cri-async", no_argument, 0, 0},
			{"disable-source", required_argument, 0},
			{"help", no_argument, 0, 'h'},
			{"ignored-events", no_argument, 0, 'i'},
			{"k8s-api-cert", required_argument, 0, 'K'},
			{"k8s-api", required_argument, 0, 'k'},
			{"k8s-node", required_argument, 0},
			{"list", optional_argument, 0},
			{"mesos-api", required_argument, 0, 'm'},
			{"option", required_argument, 0, 'o'},
			{"pidfile", required_argument, 0, 'P'},
			{"print-base64", no_argument, 0, 'b'},
			{"print", required_argument, 0, 'p'},
			{"snaplen", required_argument, 0, 'S'},
			{"stats-interval", required_argument, 0},
			{"support", no_argument, 0},
			{"unbuffered", no_argument, 0, 'U'},
			{"userspace", no_argument, 0, 'u'},
			{"validate", required_argument, 0, 'V'},
			{"version", no_argument, 0, 0},
			{"writefile", required_argument, 0, 'w'},
			{0, 0, 0, 0}};

	try
	{
		set<string> disabled_rule_substrings;
		string substring;
		string all_rules = "";
		string alternate_lua_dir = FALCO_ENGINE_SOURCE_LUA_DIR;
		set<string> disabled_rule_tags;
		set<string> enabled_rule_tags;

		//
		// Parse the args
		//
		while((op = getopt_long(argc, argv,
                                        "hc:AbdD:e:F:ik:K:Ll:m:M:No:P:p:r:S:s:T:t:UuvV:w:",
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
			case 'A':
				all_events = true;
				break;
			case 'b':
				event_buffer_format = sinsp_evt::PF_BASE64;
				break;
			case 'd':
				daemon = true;
				break;
			case 'D':
				substring = optarg;
				disabled_rule_substrings.insert(substring);
				break;
			case 'e':
				trace_filename = optarg;
#ifndef MINIMAL_BUILD
				k8s_api = new string();
				mesos_api = new string();
#endif
				break;
			case 'F':
				list_flds = optarg;
				break;
			case 'i':
				print_ignored_events = true;
				break;
#ifndef MINIMAL_BUILD
			case 'k':
				k8s_api = new string(optarg);
				break;
			case 'K':
				k8s_api_cert = new string(optarg);
				break;
#endif
			case 'L':
				describe_all_rules = true;
				break;
			case 'l':
				describe_rule = optarg;
				break;
#ifndef MINIMAL_BUILD
			case 'm':
				mesos_api = new string(optarg);
				break;
#endif
			case 'M':
				duration_to_tot = atoi(optarg);
				if(duration_to_tot <= 0)
				{
					throw sinsp_exception(string("invalid duration") + optarg);
				}
				break;
			case 'N':
				names_only = true;
				break;
			case 'o':
				cmdline_options.push_back(optarg);
				break;
			case 'P':
				pidfilename = optarg;
				break;
			case 'p':
				if(string(optarg) == "c" || string(optarg) == "container")
				{
					output_format = "container=%container.name (id=%container.id)";
					replace_container_info = true;
				}
				else if(string(optarg) == "k" || string(optarg) == "kubernetes")
				{
					output_format = "k8s.ns=%k8s.ns.name k8s.pod=%k8s.pod.name container=%container.id";
					replace_container_info = true;
				}
				else if(string(optarg) == "m" || string(optarg) == "mesos")
				{
					output_format = "task=%mesos.task.name container=%container.id";
					replace_container_info = true;
				}
				else
				{
					output_format = optarg;
					replace_container_info = false;
				}
				break;
			case 'r':
				falco_configuration::read_rules_file_directory(string(optarg), rules_filenames);
				break;
			case 'S':
				snaplen = atoi(optarg);
				break;
			case 's':
				stats_filename = optarg;
				break;
			case 'T':
				disabled_rule_tags.insert(optarg);
				break;
			case 't':
				enabled_rule_tags.insert(optarg);
				break;
			case 'U':
				buffered_outputs = false;
				buffered_cmdline = true;
				break;
			case 'u':
				userspace = true;
				break;
			case 'v':
				verbose = true;
				break;
			case 'V':
				validate_rules_filenames.push_back(optarg);
				break;
			case 'w':
				outfile = optarg;
				break;
			case '?':
				result = EXIT_FAILURE;
				goto exit;

			case 0:
				if(string(long_options[long_index].name) == "version")
				{
					printf("Falco version: %s\n", FALCO_VERSION);
					printf("Driver version: %s\n", DRIVER_VERSION);
					return EXIT_SUCCESS;
				}
				else if (string(long_options[long_index].name) == "cri")
				{
					if(optarg != NULL)
					{
						cri_socket_path = optarg;
					}
				}
				else if (string(long_options[long_index].name) == "disable-cri-async")
				{
				  cri_async = false;
				}
#ifndef MINIMAL_BUILD
				else if(string(long_options[long_index].name) == "k8s-node")
				{
					k8s_node_name = new string(optarg);
					if (k8s_node_name->size() == 0) {
						throw std::invalid_argument("If --k8s-node is provided, it cannot be an empty string");
					}
				}
#endif
				else if (string(long_options[long_index].name) == "list")
				{
					list_flds = true;
					if(optarg != NULL)
					{
						list_flds_source = optarg;
					}
				}
				else if (string(long_options[long_index].name) == "stats-interval")
				{
					stats_interval = atoi(optarg);
				}
				else if (string(long_options[long_index].name) == "support")
				{
					print_support = true;
				}
				else if (string(long_options[long_index].name) == "disable-source")
				{
					if(optarg != NULL)
					{
						disable_sources.insert(optarg);
					}
				}
				else if (string(long_options[long_index].name)== "alternate-lua-dir")
				{
					if(optarg != NULL)
					{
						alternate_lua_dir = optarg;
						if (alternate_lua_dir.back() != '/') {
							alternate_lua_dir += '/';
						}
					}
				}
				break;

			default:
				break;
			}

		}

		inspector = new sinsp();
		inspector->set_buffer_format(event_buffer_format);

		// If required, set the CRI path
		if(!cri_socket_path.empty())
		{
			inspector->set_cri_socket_path(cri_socket_path);
		}

		// Decide wether to do sync or async for CRI metadata fetch
		inspector->set_cri_async(cri_async);

		//
		// If required, set the snaplen
		//
		if(snaplen != 0)
		{
			inspector->set_snaplen(snaplen);
		}

		if(print_ignored_events)
		{
			print_all_ignored_events(inspector);
			delete(inspector);
			return EXIT_SUCCESS;
		}

		engine = new falco_engine(true, alternate_lua_dir);
		engine->set_inspector(inspector);
		engine->set_extra(output_format, replace_container_info);

		if(list_flds)
		{
			list_source_fields(engine, verbose, names_only, list_flds_source);
			return EXIT_SUCCESS;
		}

		if(disable_sources.size() > 0)
		{
			auto it = disable_sources.begin();
			while(it != disable_sources.end())
			{
				if(*it != "syscall" && *it != "k8s_audit")
				{
					it = disable_sources.erase(it);
					continue;
				}
				++it;
			}
			disable_syscall = disable_sources.count("syscall") > 0;
			disable_k8s_audit = disable_sources.count("k8s_audit") > 0;
			if (disable_syscall && disable_k8s_audit) {
				throw std::invalid_argument("The event source \"syscall\" and \"k8s_audit\" can not be disabled together");
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
			if (conf_stream.is_open())
			{
				conf_filename = FALCO_SOURCE_CONF_FILE;
			}
			else
			{
				conf_stream.open(FALCO_INSTALL_CONF_FILE);
				if (conf_stream.is_open())
				{
					conf_filename = FALCO_INSTALL_CONF_FILE;
				}
				else
				{
					throw std::invalid_argument("You must create a config file at " FALCO_SOURCE_CONF_FILE ", " FALCO_INSTALL_CONF_FILE " or by passing -c\n");
				}
			}
		}

		if(validate_rules_filenames.size() > 0)
		{
			falco_logger::log(LOG_INFO, "Validating rules file(s):\n");
			for(auto file : validate_rules_filenames)
			{
				falco_logger::log(LOG_INFO, "   " + file + "\n");
			}
			for(auto file : validate_rules_filenames)
			{
				// Only include the prefix if there is more than one file
				std::string prefix = (validate_rules_filenames.size() > 1 ? file + ": " : "");
				try {
					engine->load_rules_file(file, verbose, all_events);
				}
				catch(falco_exception &e)
				{
					printf("%s%s", prefix.c_str(), e.what());
					throw;
				}
				printf("%sOk\n", prefix.c_str());
			}
			falco_logger::log(LOG_INFO, "Ok\n");
			goto exit;
		}

		falco_configuration config;
		if (conf_filename.size())
		{
			config.init(conf_filename, cmdline_options);
			falco_logger::set_time_format_iso_8601(config.m_time_format_iso_8601);

			// log after config init because config determines where logs go
			falco_logger::log(LOG_INFO, "Falco version " + std::string(FALCO_VERSION) + " (driver version " + std::string(DRIVER_VERSION) + ")\n");
			falco_logger::log(LOG_INFO, "Falco initialized with configuration file " + conf_filename + "\n");
		}
		else
		{
			throw std::runtime_error("Could not find configuration file at " + conf_filename);
		}

		if (rules_filenames.size())
		{
			config.m_rules_filenames = rules_filenames;
		}

		engine->set_min_priority(config.m_min_priority);

		if(buffered_cmdline)
		{
			config.m_buffered_outputs = buffered_outputs;
		}

		if(config.m_rules_filenames.size() == 0)
		{
			throw std::invalid_argument("You must specify at least one rules file/directory via -r or a rules_file entry in falco.yaml");
		}

		falco_logger::log(LOG_DEBUG, "Configured rules filenames:\n");
		for (auto filename : config.m_rules_filenames)
		{
			falco_logger::log(LOG_DEBUG, string("   ") + filename + "\n");
		}

		for (auto filename : config.m_rules_filenames)
		{
			falco_logger::log(LOG_INFO, "Loading rules from file " + filename + ":\n");
			uint64_t required_engine_version;

			try {
				engine->load_rules_file(filename, verbose, all_events, required_engine_version);
			}
			catch(falco_exception &e)
			{
				std::string prefix = "Could not load rules file " + filename + ": ";

				throw falco_exception(prefix + e.what());
			}
			required_engine_versions[filename] = required_engine_version;
		}

		// You can't both disable and enable rules
		if((disabled_rule_substrings.size() + disabled_rule_tags.size() > 0) &&
		    enabled_rule_tags.size() > 0) {
			throw std::invalid_argument("You can not specify both disabled (-D/-T) and enabled (-t) rules");
		}

		for (auto substring : disabled_rule_substrings)
		{
			falco_logger::log(LOG_INFO, "Disabling rules matching substring: " + substring + "\n");
			engine->enable_rule(substring, false);
		}

		if(disabled_rule_tags.size() > 0)
		{
			for(auto tag : disabled_rule_tags)
			{
				falco_logger::log(LOG_INFO, "Disabling rules with tag: " + tag + "\n");
			}
			engine->enable_rule_by_tag(disabled_rule_tags, false);
		}

		if(enabled_rule_tags.size() > 0)
		{

			// Since we only want to enable specific
			// rules, first disable all rules.
			engine->enable_rule(all_rules, false);
			for(auto tag : enabled_rule_tags)
			{
				falco_logger::log(LOG_INFO, "Enabling rules with tag: " + tag + "\n");
			}
			engine->enable_rule_by_tag(enabled_rule_tags, true);
		}

		if(print_support)
		{
			nlohmann::json support;
			struct utsname sysinfo;
			std::string cmdline;

			if(uname(&sysinfo) != 0)
			{
				throw std::runtime_error(string("Could not uname() to find system info: %s\n") + strerror(errno));
			}

			for(char **arg = argv; *arg; arg++)
			{
				if(cmdline.size() > 0)
				{
					cmdline += " ";
				}
				cmdline += *arg;
			}

			support["version"] = FALCO_VERSION;
			support["system_info"]["sysname"] = sysinfo.sysname;
			support["system_info"]["nodename"] = sysinfo.nodename;
			support["system_info"]["release"] = sysinfo.release;
			support["system_info"]["version"] = sysinfo.version;
			support["system_info"]["machine"] = sysinfo.machine;
			support["cmdline"] = cmdline;
			support["engine_info"]["engine_version"] = FALCO_ENGINE_VERSION;
			support["config"] = read_file(conf_filename);
			support["rules_files"] = nlohmann::json::array();
			for(auto filename : config.m_rules_filenames)
			{
				nlohmann::json finfo;
				finfo["name"] = filename;
				nlohmann::json variant;
				variant["required_engine_version"] = required_engine_versions[filename];
				variant["content"] = read_file(filename);
				finfo["variants"].push_back(variant);
				support["rules_files"].push_back(finfo);
			}
			printf("%s\n", support.dump().c_str());
			goto exit;
		}

		// read hostname
		string hostname;
		if(char* env_hostname = getenv("FALCO_GRPC_HOSTNAME"))
		{
			hostname = env_hostname;
		}
		else
		{
			char c_hostname[256];
			int err = gethostname(c_hostname, 256);
			if(err != 0)
			{
				throw falco_exception("Failed to get hostname");
			}
			hostname = c_hostname;
		}

		if(!all_events)
		{
			inspector->set_drop_event_flags(EF_DROP_SIMPLE_CONS);
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

		if(signal(SIGUSR1, reopen_outputs) == SIG_ERR)
		{
			fprintf(stderr, "An error occurred while setting SIGUSR1 signal handler.\n");
			result = EXIT_FAILURE;
			goto exit;
		}

		if(signal(SIGHUP, restart_falco) == SIG_ERR)
		{
			fprintf(stderr, "An error occurred while setting SIGHUP signal handler.\n");
			result = EXIT_FAILURE;
			goto exit;
		}

		// If daemonizing, do it here so any init errors will
		// be returned in the foreground process.
		if (daemon && !g_daemonized) {
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

			g_daemonized = true;
		}

		outputs = new falco_outputs();

		outputs->init(config.m_json_output,
			config.m_json_include_output_property,
			config.m_output_timeout,
			config.m_notifications_rate, config.m_notifications_max_burst,
			config.m_buffered_outputs,
			config.m_time_format_iso_8601,
			hostname);

		for(auto output : config.m_outputs)
		{
			outputs->add_output(output);
		}

		if(trace_filename.size())
		{
			// Try to open the trace file as a sysdig
			// capture file first.
			try {
				inspector->open(trace_filename);
				falco_logger::log(LOG_INFO, "Reading system call events from file: " + trace_filename + "\n");
			}
			catch(sinsp_exception &e)
			{
				falco_logger::log(LOG_DEBUG, "Could not read trace file \"" + trace_filename + "\": " + string(e.what()));
				trace_is_scap=false;
			}

			if(!trace_is_scap)
			{
#ifdef MINIMAL_BUILD
				// Note that the webserver is not available when MINIMAL_BUILD is defined.
				fprintf(stderr, "Cannot use k8s audit events trace file with a minimal Falco build");
				result = EXIT_FAILURE;
				goto exit;
#else
				try {
					string line;
					nlohmann::json j;

					// Note we only temporarily open the file here.
					// The read file read loop will be later.
					ifstream ifs(trace_filename);
					getline(ifs, line);
					j = nlohmann::json::parse(line);

					falco_logger::log(LOG_INFO, "Reading k8s audit events from file: " + trace_filename + "\n");
				}
				catch (nlohmann::json::parse_error& e)
				{
					fprintf(stderr, "Trace filename %s not recognized as system call events or k8s audit events\n", trace_filename.c_str());
					result = EXIT_FAILURE;
					goto exit;
				}
				catch (exception &e)
				{
					fprintf(stderr, "Could not open trace filename %s for reading: %s\n", trace_filename.c_str(), e.what());
					result = EXIT_FAILURE;
					goto exit;
				}
#endif
			}
		}
		else
		{
			open_t open_cb = [&userspace](sinsp* inspector)
			{
				if(userspace)
				{
					// open_udig() is the underlying method used in the capture code to parse userspace events from the kernel.
					//
					// Falco uses a ptrace(2) based userspace implementation.
					// Regardless of the implementation, the underlying method remains the same.
					inspector->open_udig();
					return;
				}
				inspector->open();
			};
			open_t open_nodriver_cb = [](sinsp* inspector) {
				inspector->open_nodriver();
			};
			open_t open_f;

			// Default mode: both event sources enabled
			if (!disable_syscall && !disable_k8s_audit) {
				open_f = open_cb;
			}
			if (disable_syscall) {
				open_f = open_nodriver_cb;
			}
			if (disable_k8s_audit) {
				open_f = open_cb;
			}

			try
			{
				open_f(inspector);
			}
			catch(sinsp_exception &e)
			{
				// If syscall input source is enabled and not through userspace instrumentation
				if (!disable_syscall && !userspace)
				{
					// Try to insert the Falco kernel module
					if(system("modprobe " PROBE_NAME " > /dev/null 2> /dev/null"))
					{
						falco_logger::log(LOG_ERR, "Unable to load the driver.\n");
					}
					open_f(inspector);
				}
				else
				{
					rethrow_exception(current_exception());
				}
			}
		}

		// This must be done after the open
		if(!all_events)
		{
			inspector->start_dropping_mode(1);
		}

		if(outfile != "")
		{
			inspector->setup_cycle_writer(outfile, rollover_mb, duration_seconds, file_limit, event_limit, compress);
			inspector->autodump_next_file();
		}

		duration = ((double)clock()) / CLOCKS_PER_SEC;

#ifndef MINIMAL_BUILD
		//
		// Run k8s, if required
		//
		if(k8s_api)
		{
			if(!k8s_api_cert)
			{
				if(char* k8s_cert_env = getenv("FALCO_K8S_API_CERT"))
				{
					k8s_api_cert = new string(k8s_cert_env);
				}
			}
			inspector->init_k8s_client(k8s_api, k8s_api_cert, k8s_node_name, verbose);
			k8s_api = 0;
			k8s_api_cert = 0;
		}
		else if(char* k8s_api_env = getenv("FALCO_K8S_API"))
		{
			if(k8s_api_env != NULL)
			{
				if(!k8s_api_cert)
				{
					if(char* k8s_cert_env = getenv("FALCO_K8S_API_CERT"))
					{
						k8s_api_cert = new string(k8s_cert_env);
					}
				}
				k8s_api = new string(k8s_api_env);
				inspector->init_k8s_client(k8s_api, k8s_api_cert, k8s_node_name, verbose);
			}
			else
			{
				delete k8s_api;
				delete k8s_api_cert;
			}
			k8s_api = 0;
			k8s_api_cert = 0;
		}

		//
		// Run mesos, if required
		//
		if(mesos_api)
		{
			inspector->init_mesos_client(mesos_api, verbose);
		}
		else if(char* mesos_api_env = getenv("FALCO_MESOS_API"))
		{
			if(mesos_api_env != NULL)
			{
				mesos_api = new string(mesos_api_env);
				inspector->init_mesos_client(mesos_api, verbose);
			}
		}
		delete mesos_api;
		mesos_api = 0;

		if(trace_filename.empty() && config.m_webserver_enabled && !disable_k8s_audit)
		{
			std::string ssl_option = (config.m_webserver_ssl_enabled ? " (SSL)" : "");
			falco_logger::log(LOG_INFO, "Starting internal webserver, listening on port " + to_string(config.m_webserver_listen_port) + ssl_option + "\n");
			webserver.init(&config, engine, outputs);
			webserver.start();
		}

		// gRPC server
		if(config.m_grpc_enabled)
		{
			falco_logger::log(LOG_INFO, "gRPC server threadiness equals to " + to_string(config.m_grpc_threadiness) + "\n");
			// TODO(fntlnz,leodido): when we want to spawn multiple threads we need to have a queue per thread, or implement
			// different queuing mechanisms, round robin, fanout? What we want to achieve?
			grpc_server.init(
				config.m_grpc_bind_address,
				config.m_grpc_threadiness,
				config.m_grpc_private_key,
				config.m_grpc_cert_chain,
				config.m_grpc_root_certs,
				config.m_log_level
			);
			grpc_server_thread = std::thread([&grpc_server] {
				grpc_server.run();
			});
		}
#endif

		if(!trace_filename.empty() && !trace_is_scap)
		{
#ifndef MINIMAL_BUILD
			read_k8s_audit_trace_file(engine,
						  outputs,
						  trace_filename);
#endif
		}
		else
		{
			uint64_t num_evts;

			num_evts = do_inspect(engine,
					      outputs,
					      inspector,
					      config,
					      sdropmgr,
					      uint64_t(duration_to_tot*ONE_SECOND_IN_NS),
					      stats_filename,
					      stats_interval,
					      all_events,
					      result);

			duration = ((double)clock()) / CLOCKS_PER_SEC - duration;

			inspector->get_capture_stats(&cstats);

			if(verbose)
			{
				fprintf(stderr, "Driver Events:%" PRIu64 "\nDriver Drops:%" PRIu64 "\n",
					cstats.n_evts,
					cstats.n_drops);

				fprintf(stderr, "Elapsed time: %.3lf, Captured Events: %" PRIu64 ", %.2lf eps\n",
					duration,
					num_evts,
					num_evts / duration);
			}

		}

		// Honor -M also when using a trace file.
		// Since inspection stops as soon as all events have been consumed
		// just await the given duration is reached, if needed.
		if(!trace_filename.empty() && duration_to_tot>0)
		{
			std::this_thread::sleep_for(std::chrono::seconds(duration_to_tot));
		}

		inspector->close();
		engine->print_stats();
		sdropmgr.print_stats();
#ifndef MINIMAL_BUILD
		webserver.stop();
		if(grpc_server_thread.joinable())
		{
			grpc_server.shutdown();
			grpc_server_thread.join();
		}
#endif
	}
	catch(exception &e)
	{
		display_fatal_err("Runtime error: " + string(e.what()) + ". Exiting.\n");

		result = EXIT_FAILURE;

#ifndef MINIMAL_BUILD
		webserver.stop();
		if(grpc_server_thread.joinable())
		{
			grpc_server.shutdown();
			grpc_server_thread.join();
		}
#endif
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
	int rc;

	// g_restart will cause the falco loop to exit, but we
	// should reload everything and start over.
	while((rc = falco_init(argc, argv)) == EXIT_SUCCESS && g_restart)
	{
		g_restart = false;
		optind = 1;
	}

	return rc;
}
