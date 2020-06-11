/*
Copyright (C) 2013-2018 Draios Inc dba Sysdig.

This file is part of sysdig.

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
#include <iostream>
#include <time.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <assert.h>
#include <algorithm>

#include <sinsp.h>
#include "chisel.h"
#include "sysdig.h"
#include "table.h"
#include "utils.h"

#ifdef _WIN32
#include "win32/getopt.h"
#include <io.h>
#else
#include <unistd.h>
#include <getopt.h>
#include <term.h>
#endif

#include "cursescomponents.h"
#include "cursestable.h"
#include "cursesui.h"
#include "scap_open_exception.h"
#include "sinsp_capture_interrupt_exception.h"

#define MOUSE_CAPABLE_TERM "xterm-1003"
#define MOUSE_CAPABLE_TERM_COMPAT "xterm-1002"

static bool g_terminate = false;
static void usage();

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
"csysdig version " SYSDIG_VERSION "\n"
"Usage: csysdig [options] [filter]\n\n"
"Options:\n"
" -A, --print-ascii  When emitting JSON, only print the text portion of data buffers, and echo\n"
"                    end-of-lines. This is useful to only display human-readable\n"
"                    data.\n"
" -B<bpf_probe>, --bpf=<bpf_probe>\n"
"                    Enable live capture using the specified BPF probe instead of the kernel module.\n"
"                    The BPF probe can also be specified via the environment variable\n"
"                    SYSDIG_BPF_PROBE. If <bpf_probe> is left empty, sysdig will\n"
"                    try to load one from the sysdig-probe-loader script.\n"
#ifdef HAS_CAPTURE
" --cri <path>       Path to CRI socket for container metadata\n"
"                    Use the specified socket to fetch data from a CRI-compatible runtime\n"
"\n"
" --cri-timeout <timeout_ms>\n"
"                    Wait at most <timeout_ms> milliseconds for response from CRI\n"
#endif
" -d <period>, --delay=<period>\n"
"                    Set the delay between updates, in milliseconds. This works\n"
"                    similarly to the -d option in top.\n"
" -E, --exclude-users\n"
"                    Don't create the user/group tables by querying the OS when\n"
"                    sysdig starts. This also means that no user or group info\n"
"                    will be written to the tracefile by the -w flag.\n"
"                    The user/group tables are necessary to use filter fields\n"
"                    like user.name or group.name. However, creating them can\n"
"                    increase sysdig's startup time. Moreover, they contain\n"
"                    information that could be privacy sensitive.\n"
" --force-term-compat\n"
"                    Try to configure simple terminal settings (xterm-1002) that work\n"
"                    better with terminals like putty. Try to use this flag if you experience\n"
"                    terminal issues like the mouse not working.\n"
" -h, --help         Print this page\n"
" -k <url>, --k8s-api=<url>\n"
"                    Enable Kubernetes support by connecting to the API server\n"
"                    specified as argument. E.g. \"http://admin:password@127.0.0.1:8080\".\n"
"                    The API server can also be specified via the environment variable\n"
"                    SYSDIG_K8S_API.\n"
" -K <bt_file> | <cert_file>:<key_file[#password]>[:<ca_cert_file>], --k8s-api-cert=<bt_file> | <cert_file>:<key_file[#password]>[:<ca_cert_file>]\n"
"                    Use the provided files names to authenticate user and (optionally) verify the K8S API\n"
"                    server identity.\n"
"                    Each entry must specify full (absolute, or relative to the current directory) path\n"
"                    to the respective file.\n"
"                    Private key password is optional (needed only if key is password protected).\n"
"                    CA certificate is optional. For all files, only PEM file format is supported. \n"
"                    Specifying CA certificate only is obsoleted - when single entry is provided \n"
"                    for this option, it will be interpreted as the name of a file containing bearer token.\n"
"                    Note that the format of this command-line option prohibits use of files whose names contain\n"
"                    ':' or '#' characters in the file name.\n"
"                    Option can also be provided via the environment variable SYSDIG_K8S_API_CERT.\n"
" -l, --list         List all the fields that can be used in views.\n"
" --large-environment\n"
"                    Support environments larger than 4KiB\n"
"                    When the environment is larger than 4KiB, load the whole\n"
"                    environment from /proc instead of truncating to the first 4KiB\n"
"                    This may fail for short-lived processes and in that case\n"
"                    the truncated environment is used instead.\n"
" --logfile=<file>\n"
"                    Print program logs into the given file.\n"
" -n <num>, --numevents=<num>\n"
"                    Stop capturing after <num> events\n"
" --page-faults      Capture user/kernel major/minor page faults\n"
" -pc, -pcontainer\n"
"                    Instruct csysdig to use a container-friendly format in its\n"
"                    views.\n"
"                    This will cause several of the views to contain additional\n"
"                    container-related columns.\n"
" -R                 Resolve port numbers to names.\n"
" -r <readfile>, --read=<readfile>\n"
"                    Read the events from <readfile>.\n"
" --raw              Print raw output on a regular terminal instead of enabling\n"
"                    ncurses-based ANSI output.\n"
" -s <len>, --snaplen=<len>\n"
"                    Capture the first <len> bytes of each I/O buffer.\n"
"                    By default, the first 80 bytes are captured. Use this\n"
"                    option with caution, it can generate huge trace files.\n"
" -T, --force-tracers-capture\n"
"                    Tell the driver to make sure full buffers are captured from\n"
"                    /dev/null, to make sure that tracers are completely\n"
"                    captured. Note that sysdig will enable extended /dev/null\n"
"                    capture by itself after detecting that tracers are written\n"
"                    there, but that could result in the truncation of some\n"
"                    tracers at the beginning of the capture. This option allows\n"
"                    preventing that.\n"
" -v <view_id>, --view=<view_id>\n"
"                    Run the view with the given ID when csysdig starts.\n"
"                    View IDs can be found in the view documentation pages in\n"
"                    csysdig. Combine  this option with a command line filter for\n"
"                    complete output customization.\n"
" --version          Print version number.\n"
" -X, --print-hex-ascii\n"
"                    When emitting JSON, print data buffers in hex and ASCII.\n"
"\n"
"How to use csysdig:\n"
"1. you can either see real time data, or analyze a trace file by using the -r\n"
"   command line flag.\n"
"2. you can switch to a different view by using the F2 key.\n"
"3. You can drill down into a selection by typing enter.\n"
"   You can navigate back by typing backspace.\n"
"4. you can observe reads and writes (F5) or see sysdig events (F6) for any\n"
"   selection.\n"
"\nAdditional help can be obtained by clicking F1 while the program is running,\n"
"and in the man page.\n\n"
    );
}

#ifdef HAS_CHISELS
static void add_chisel_dirs(sinsp* inspector)
{
	//
	// Add the default chisel directory statically configured by the build system
	//
	inspector->add_chisel_dir(SYSDIG_INSTALLATION_DIR CHISELS_INSTALLATION_DIR, false);

	//
	// Add the directories configured in the SYSDIG_CHISEL_DIR environment variable
	//
	char* s_user_cdirs = getenv("SYSDIG_CHISEL_DIR");

	if(s_user_cdirs != NULL)
	{
		vector<string> user_cdirs = sinsp_split(s_user_cdirs, ';');

		for(uint32_t j = 0; j < user_cdirs.size(); j++)
		{
			inspector->add_chisel_dir(user_cdirs[j], true);
		}
	}
}

static void print_views(sinsp_view_manager* view_manager)
{
	Json::FastWriter writer;
	Json::Value root;

	vector<sinsp_view_info>* vlist = view_manager->get_views();

	for(auto it = vlist->begin(); it != vlist->end(); ++it)
	{
		Json::Value jv;
		sinsp_view_info& vinfo = *it;

		jv["id"] = vinfo.m_id;
		jv["name"] = vinfo.m_name;
		jv["description"] = vinfo.m_description;
		jv["isRoot"] = vinfo.m_is_root;
		jv["drilldownTarget"] = vinfo.m_drilldown_target;
		jv["filter"] = vinfo.m_filter;
		jv["canDrillDown"] = (vinfo.m_type == sinsp_view_info::T_TABLE);

		for(auto it = vinfo.m_applies_to.begin(); it != vinfo.m_applies_to.end(); ++it)
		{
			jv["appliesTo"].append(*it);
		}
		for(auto it = vinfo.m_tags.begin(); it != vinfo.m_tags.end(); ++it)
		{
			jv["tags"].append(*it);
		}
		for(auto it = vinfo.m_tips.begin(); it != vinfo.m_tips.end(); ++it)
		{
			jv["tips"].append(*it);
		}

		root.append(jv);
	}

	string ouput = writer.write(root);
	printf("%s", ouput.substr(0, ouput.size() - 1).c_str());
}
#endif

captureinfo do_inspect(sinsp* inspector,
					   uint64_t cnt,
					   sinsp_cursesui* ui)
{
	captureinfo retval;
	int32_t res;
	sinsp_evt* ev;

	//
	// Loop through the events
	//
	while(1)
	{
		if(retval.m_nevts == cnt || g_terminate)
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
		else if(res != SCAP_EOF && res != SCAP_SUCCESS)
		{
			//
			// Event read error.
			// Notify the chisels that we're exiting, and then die with an error.
			//
			if(inspector->is_live())
			{
				throw sinsp_exception(inspector->getlasterr());
			}
			else
			{
				ui->set_truncated_input(true);
				res = SCAP_EOF;
			}
		}

		if(ui->process_event(ev, res) == true)
		{
			return retval;
		}

		retval.m_nevts++;
	}

	return retval;
}

string g_version_string = SYSDIG_VERSION;

sysdig_init_res csysdig_init(int argc, char **argv)
{
	sysdig_init_res res;
	sinsp* inspector = NULL;
	vector<string> infiles;
	int op;
	uint64_t cnt = -1;
	uint32_t snaplen = 0;
	int long_index = 0;
	int32_t n_filterargs = 0;
	captureinfo cinfo;
	string errorstr;
	string display_view;
	bool print_containers = false;
	uint64_t refresh_interval_ns = 2000000000;
	bool list_flds = false;
	bool is_interactive = false;
	int32_t json_first_row = 0;
	int32_t json_last_row = 0;
	int32_t sorting_col = -1;
	bool list_views = false;
	bool bpf = false;
	string bpf_probe;
#ifdef HAS_CAPTURE
	string cri_socket_path;
#endif

#ifndef _WIN32
	sinsp_table::output_type output_type = sinsp_table::OT_CURSES;
#else
	sinsp_table::output_type output_type = sinsp_table::OT_JSON;
#endif
	string* k8s_api = 0;
	string* k8s_api_cert = 0;
	string* mesos_api = 0;
	bool terminal_with_mouse = false;
	bool force_tracers_capture = false;
	bool force_term_compat = false;
	sinsp_evt::param_fmt event_buffer_format = sinsp_evt::PF_NORMAL;
	bool page_faults = false;

	static struct option long_options[] =
	{
		{"print-ascii", no_argument, 0, 'A' },
		{"bpf", optional_argument, 0, 'B' },
#ifdef HAS_CAPTURE
		{"cri", required_argument, 0, 0 },
		{"cri-timeout", required_argument, 0, 0 },
#endif
		{"delay", required_argument, 0, 'd' },
		{"exclude-users", no_argument, 0, 'E' },
		{"from", required_argument, 0, 0 },
		{"help", no_argument, 0, 'h' },
		{"k8s-api", required_argument, 0, 'k'},
		{"k8s-api-cert", required_argument, 0, 'K' },
		{"json", no_argument, 0, 'j' },
		{"interactive", optional_argument, 0, 0 },
		{"large-environment", no_argument, 0, 0 },
		{"list", optional_argument, 0, 'l' },
		{"list-views", no_argument, 0, 0},
		{"mesos-api", required_argument, 0, 'm'},
		{"numevents", required_argument, 0, 'n' },
		{"page-faults", no_argument, 0, 0 },
		{"print", required_argument, 0, 'p' },
		{"resolve-ports", no_argument, 0, 'R'},
		{"readfile", required_argument, 0, 'r' },
		{"raw", no_argument, 0, 0 },
		{"snaplen", required_argument, 0, 's' },
		{"logfile", required_argument, 0, 0 },
		{"force-tracers-capture", required_argument, 0, 'T'},
		{"force-term-compat", no_argument, 0, 0},
		{"sortingcol", required_argument, 0, 0 },
		{"to", required_argument, 0, 0 },
		{"view", required_argument, 0, 'v' },
		{"version", no_argument, 0, 0 },
		{"print-hex-ascii", no_argument, 0, 'X'},
		{0, 0, 0, 0}
	};

	//
	// Parse the arguments
	//
	try
	{
		inspector = new sinsp();

#ifdef HAS_CHISELS
		add_chisel_dirs(inspector);
#endif

		//
		// Parse the args
		//
		while((op = getopt_long(argc, argv,
			"AB::d:Ehk:K:jlm:n:p:Rr:s:Tv:X", long_options, &long_index)) != -1)
		{
			switch(op)
			{
			case '?':
				//
				// Command line error
				//
				throw sinsp_exception("command line error");
				break;
			case 'A':
				if(event_buffer_format != sinsp_evt::PF_NORMAL)
				{
					fprintf(stderr, "you cannot specify more than one output format\n");
					delete inspector;
					return sysdig_init_res(EXIT_SUCCESS);
				}

				event_buffer_format = sinsp_evt::PF_EOLS_COMPACT;
				break;
			case 'B':
			{
				bpf = true;
				if(optarg)
				{
					bpf_probe = optarg;
				}
				break;
			}
			case 'd':
				try
				{
					refresh_interval_ns = sinsp_numparser::parseu64(optarg) * 1000000;
				}
				catch(...)
				{
					throw sinsp_exception("can't parse the -d argument, make sure it's a number");
				}

				if(refresh_interval_ns < 100000000)
				{
					throw sinsp_exception("Period must be bigger then 100ms");
				}

				break;
			case 'E':
				inspector->set_import_users(false);
				break;
			case 'h':
				usage();
				delete inspector;
				return sysdig_init_res(EXIT_SUCCESS);
			case 'k':
				k8s_api = new string(optarg);
				break;
			case 'K':
				k8s_api_cert = new string(optarg);
				break;
			case 'j':
				output_type = sinsp_table::OT_JSON;
				break;
			case 'l':
				list_flds = true;
				break;
			case 'm':
				mesos_api = new string(optarg);
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
					res.m_res = EXIT_FAILURE;
					goto exit;
				}
				break;
			case 'p':
				if(string(optarg) == "c" || string(optarg) == "container")
				{
					inspector->set_print_container_data(true);
					print_containers = true;
				}

				break;
			case 'R':
				inspector->set_hostname_and_port_resolution_mode(true);
				break;
			case 'r':
				infiles.push_back(optarg);
				k8s_api = new string();
				mesos_api = new string();
				break;
			case 's':
				snaplen = atoi(optarg);
				break;
			case 'T':
				force_tracers_capture = true;
				break;
			case 'v':
				display_view = optarg;
				break;
			case 'X':
				if(event_buffer_format != sinsp_evt::PF_NORMAL)
				{
					fprintf(stderr, "you cannot specify more than one output format\n");
					delete inspector;
					return sysdig_init_res(EXIT_FAILURE);
				}

				event_buffer_format = sinsp_evt::PF_HEXASCII;
				break;
			case 0:
				{
					if(long_options[long_index].flag != 0)
					{
						break;
					}

					string optname = string(long_options[long_index].name);
					if(optname == "version")
					{
						printf("sysdig version %s\n", SYSDIG_VERSION);
						delete inspector;
						return sysdig_init_res(EXIT_SUCCESS);
					}
					else if(optname == "interactive")
					{
						is_interactive = true;
						output_type = sinsp_table::OT_JSON;
					}
					else if(optname == "large-environment")
					{
						inspector->set_large_envs(true);
					}
#ifdef HAS_CAPTURE
					else if(optname == "cri")
					{
						cri_socket_path = optarg;
					}
					else if(optname == "cri-timeout")
					{
						inspector->set_cri_timeout(sinsp_numparser::parsed64(optarg));
					}
#endif
					else if(optname == "logfile")
					{
						inspector->set_log_file(optarg);
					}
					else if(optname == "raw")
					{
						output_type = sinsp_table::OT_RAW;
					}
					else if(optname == "force-term-compat")
					{
						force_term_compat = true;
					}
					else if(optname == "from")
					{
						json_first_row = sinsp_numparser::parsed32(optarg);
					}
					else if(optname == "to")
					{
						json_last_row = sinsp_numparser::parsed32(optarg);
					}
					else if(optname == "sortingcol")
					{
						sorting_col = sinsp_numparser::parsed32(optarg);
					}
					else if(optname == "list-views")
					{
						list_views = true;
					}
					else if(optname == "page-faults")
					{
						page_faults = true;
					}
				}
				break;
			default:
				break;
			}
		}

#ifdef HAS_CAPTURE
		if(!cri_socket_path.empty())
		{
			inspector->set_cri_socket_path(cri_socket_path);
		}
#endif

		string filter;

		//
		// If -l was specified, print the fields and exit
		//
		if(list_flds)
		{
			list_fields(false, false);

			res.m_res = EXIT_SUCCESS;
			goto exit;
		}

		//
		// the filter is at the end of the command line
		//
		if(optind + n_filterargs < argc)
		{
#ifdef HAS_FILTERING
			for(int32_t j = optind + n_filterargs; j < argc; j++)
			{
				filter += argv[j];
				if(j < argc)
				{
					filter += " ";
				}
			}
#else
			fprintf(stderr, "filtering not compiled.\n");
			res.m_res = EXIT_FAILURE;
			goto exit;
#endif
		}

		if(!bpf)
		{
			const char *probe = scap_get_bpf_probe_from_env();
			if(probe)
			{
				bpf = true;
				bpf_probe = probe;
			}
		}

		if(bpf)
		{
			inspector->set_bpf_probe(bpf_probe);
		}

		if(signal(SIGINT, signal_callback) == SIG_ERR)
		{
			fprintf(stderr, "An error occurred while setting SIGINT signal handler.\n");
			res.m_res = EXIT_FAILURE;
			goto exit;
		}

		if(signal(SIGTERM, signal_callback) == SIG_ERR)
		{
			fprintf(stderr, "An error occurred while setting SIGTERM signal handler.\n");
			res.m_res = EXIT_FAILURE;
			goto exit;
		}

		if(json_last_row < json_first_row)
		{
			fprintf(stderr, "'to' argument cannot be smaller than the 'from' one.\n");
			res.m_res = EXIT_FAILURE;
			goto exit;
		}

		//
		// Initialize ncurses
		//
#ifndef NOCURSESUI
		if(output_type == sinsp_table::OT_CURSES)
		{
			//
			// Check if terminal has mouse support
			//
			const char* mct = force_term_compat? MOUSE_CAPABLE_TERM_COMPAT : MOUSE_CAPABLE_TERM;
			terminal_with_mouse = (tgetent(NULL, mct) != 0);

			if(terminal_with_mouse)
			{
				//
				// Enable fine-grained mouse activity capture by setting xterm-1002
				//
				setenv("TERM", mct, 1);
			}

			(void) initscr();      // initialize the curses library
			(void) nonl();         // tell curses not to do NL->CR/NL on output
			intrflush(stdscr, false);
			keypad(stdscr, true);
			curs_set(0);
			if(has_colors())
			{
			  start_color();
			}
			use_default_colors();
			mousemask(ALL_MOUSE_EVENTS | REPORT_MOUSE_POSITION, NULL);
			noecho();

			timeout(0);

			// If this is uncommented, it's possible to natively handle stuff like CTRL+c
			//raw();
		}
#endif

		//
		// Create the list of views
		//
		sinsp_view_manager view_manager;

		//
		// Scan the chisel list to load the Lua views, and add them to the list
		//
		vector<chisel_desc> chlist;
		sinsp_chisel::get_chisel_list(&chlist);

		for(auto it : chlist)
		{
			if(it.m_viewinfo.m_valid)
			{
				if(print_containers)
				{
					it.m_viewinfo.apply_tag("containers");
				}
				else
				{
					it.m_viewinfo.apply_tag("default");
				}

				if(it.m_viewinfo.m_tags.size() != 0)
				{
					if(it.m_viewinfo.m_tags[0] == "Containers")
					{
						continue;
					}
				}

				if(output_type != sinsp_table::OT_JSON)
				{
					if(std::find(it.m_viewinfo.m_tags.begin(),
						it.m_viewinfo.m_tags.end(),
						"nocsysdig") != it.m_viewinfo.m_tags.end())
					{
						continue;
					}
				}

				view_manager.add(&it.m_viewinfo);
			}
		}

		//
		// Set the initial display view
		//
		view_manager.set_selected_view(display_view);

		if(list_views)
		{
			print_views(&view_manager);
			goto exit;
		}

		//
		// Go through the input sources and apply the processing to all of them
		//
		for(uint32_t j = 0; j < infiles.size() || infiles.size() == 0; j++)
		{
			//
			// Initialize the UI
			//
			sinsp_cursesui ui(inspector,
				(infiles.size() != 0)? infiles[0] : "",
				(filter.size() != 0)? filter : "",
				refresh_interval_ns,
				print_containers,
				output_type,
				terminal_with_mouse,
				json_first_row,
				json_last_row,
				sorting_col,
				event_buffer_format);

			ui.configure(&view_manager);

			if(display_view == "dig" || display_view == "echo")
			{
				ui.start(false, true);
			}
			else
			{
				ui.start(false, false);
			}

			if(is_interactive)
			{
				printf("ready\n");

				//
				// In interactive mode, make sure stderr is flushed at every printf
				//
				setbuf(stderr, NULL);

				//
				// Set the UI in interactive mode and start listening to user
				// input.
				//
				ui.set_interactive(true);
			}

			//
			// Launch the capture
			//
			if(infiles.size() != 0)
			{
				//
				// We have a file to open
				//
				inspector->open(infiles[j]);
			}
			else
			{
				if(j > 0)
				{
					break;
				}

				//
				// No file to open, this is a live capture
				//
#if defined(HAS_CAPTURE)
				bool open_success = true;

				try
				{
					inspector->open("");
				}
				catch(const sinsp_exception& e)
				{
					open_success = false;
				}

				//
				// Starting the live capture failed, try to load the driver with
				// modprobe.
				//
				if(!open_success)
				{
					open_success = true;

					if(bpf)
					{
						if(bpf_probe.empty())
						{
							if(system("sysdig-probe-loader bpf"))
							{
								fprintf(stderr, "Unable to load the BPF probe\n");
							}
						}
					}
					else
					{
						if(system("modprobe " PROBE_NAME " > /dev/null 2> /dev/null"))
						{
							fprintf(stderr, "Unable to load the driver\n");
						}
					}

					inspector->open("");
				}
#else
				//
				// Starting live capture
				// If this fails on Windows and OSX, don't try with any driver
				//
				inspector->open("");
#endif

				//
				// Enable gathering the CPU from the kernel module
				//
				inspector->set_get_procs_cpu_from_driver(true);
			}

			//
			// If required, set the snaplen
			//
			if(snaplen != 0)
			{
				inspector->set_snaplen(snaplen);
			}

			//
			// If required, tell the driver to enable tracers capture
			//
			if(force_tracers_capture)
			{
				inspector->enable_tracers_capture();
			}

			if(page_faults)
			{
				inspector->enable_page_faults();
			}

			//
			// run k8s, if required
			//
			if(k8s_api)
			{
				if(!k8s_api_cert)
				{
					if(char* k8s_cert_env = getenv("SYSDIG_K8S_API_CERT"))
					{
						k8s_api_cert = new string(k8s_cert_env);
					}
				}
				inspector->init_k8s_client(k8s_api, k8s_api_cert);
				k8s_api = 0;
				k8s_api_cert = 0;
			}
			else if(char* k8s_api_env = getenv("SYSDIG_K8S_API"))
			{
				if(k8s_api_env != NULL)
				{
					if(!k8s_api_cert)
					{
						if(char* k8s_cert_env = getenv("SYSDIG_K8S_API_CERT"))
						{
							k8s_api_cert = new string(k8s_cert_env);
						}
					}
					k8s_api = new string(k8s_api_env);
					inspector->init_k8s_client(k8s_api, k8s_api_cert);
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
			// run mesos, if required
			//
			if(mesos_api)
			{
				inspector->init_mesos_client(mesos_api);
			}
			else if(char* mesos_api_env = getenv("SYSDIG_MESOS_API"))
			{
				if(mesos_api_env != NULL)
				{
					mesos_api = new string(mesos_api_env);
					inspector->init_mesos_client(mesos_api);
				}
			}
			delete mesos_api;
			mesos_api = 0;

			if(output_type == sinsp_table::OT_JSON)
			{
				printf("{\"slices\": [\n");
				if(display_view != "dig" && display_view != "echo")
				{
					printf("{\"progress\": 0},\n");
				}
			}

			//
			// Start the capture loop
			//
			cinfo = do_inspect(inspector,
				cnt,
				&ui);

			if(output_type == sinsp_table::OT_JSON)
			{
				printf("]}\n");
				//printf("%c", EOF);
			}

			//
			// Done. Close the capture.
			//
			inspector->close();
		}
	}
	catch(const sinsp_capture_interrupt_exception&)
	{
	}
	catch(const scap_open_exception& e)
	{
		errorstr = e.what();
		res.m_res = e.scap_rc();
	}
	catch(const std::exception& e)
	{
		errorstr = e.what();
		res.m_res = EXIT_FAILURE;
	}
	catch(...)
	{
		errorstr = "uncaught exception";
		res.m_res = EXIT_FAILURE;
	}

exit:
	if(inspector)
	{
		delete inspector;
	}

	//
	// Restore the original screen
	//
#ifndef NOCURSESUI
	if(output_type == sinsp_table::OT_CURSES)
	{
		endwin();
	}
#endif

	if(errorstr != "")
	{
		cerr << errorstr << endl;
	}

	return res;
}

//
// MAIN
//
int main(int argc, char **argv)
{
	sysdig_init_res res;

	//
	// Run csysdig
	//
	res = csysdig_init(argc, argv);

#ifdef _WIN32
	_CrtDumpMemoryLeaks();
#endif

	return res.m_res;
}
