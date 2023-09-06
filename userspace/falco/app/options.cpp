/*
Copyright (C) 2023 The Falco Authors.

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

#include "options.h"
#include "../configuration.h"
#include "config_falco.h"

#include <cxxopts.hpp>

#include <fstream>

namespace falco {
namespace app {

// Most bool member variables do not need to be set explicitly, as
// they are bound to command line options that have default
// values. However, a few options can be ifdef'd out so explicitly
// initialize their linked variables.
options::options()
	: event_buffer_format(sinsp_evt::PF_NORMAL),
	  gvisor_config(""),	
	  list_fields(false),
	  list_plugins(false),
	  list_syscall_events(false),
	  markdown(false),
	  userspace(false),
	  modern_bpf(false),
	  dry_run(false),
	  nodriver(false)
{
}

options::~options()
{
}

bool options::parse(int argc, char **argv, std::string &errstr)
{
	cxxopts::Options opts("falco", "Falco - Cloud Native Runtime Security");
	define(opts);
	m_usage_str = opts.help();

	cxxopts::ParseResult m_cmdline_parsed;
	try {
		m_cmdline_parsed = opts.parse(argc, argv);
	}
	catch (std::exception &e)
	{
		errstr = e.what();
		return false;
	}

	// Some options require additional processing/validation
	std::ifstream conf_stream;
	if (!conf_filename.empty())
	{
		conf_stream.open(conf_filename);
		if (!conf_stream.is_open())
		{
			errstr = std::string("Could not find configuration file at ") + conf_filename;
			return false;
		}
	}
	else
	{
#ifndef BUILD_TYPE_RELEASE
		conf_stream.open(FALCO_SOURCE_CONF_FILE);
		if (conf_stream.is_open())
		{
			conf_filename = FALCO_SOURCE_CONF_FILE;
		}
		else
#endif
		{
			conf_stream.open(FALCO_INSTALL_CONF_FILE);
			if (conf_stream.is_open())
			{
				conf_filename = FALCO_INSTALL_CONF_FILE;
			}
			else
			{
				// Note we do not return false here. Although there is
				// no valid config file, some ways of running falco
				// (e.g. --help, --list) do not need a config file.
				//
				// Later, when it comes time to read a config file, if
				// the filename is empty we exit with an error.
				conf_filename = "";
			}
		}
	}

	if(m_cmdline_parsed.count("b") > 0)
	{
		event_buffer_format = sinsp_evt::PF_BASE64;
	}

	if(m_cmdline_parsed.count("r") > 0)
	{
		for(auto &path : m_cmdline_parsed["r"].as<std::vector<std::string>>())
		{
			rules_filenames.push_back(path);
		}
	}

	// Convert the vectors of enabled/disabled tags into sets to match falco engine API
	if(m_cmdline_parsed.count("T") > 0)
	{
		for(auto &tag : m_cmdline_parsed["T"].as<std::vector<std::string>>())
		{
			disabled_rule_tags.insert(tag);
		}
	}

	if(m_cmdline_parsed.count("t") > 0)
	{
		for(auto &tag : m_cmdline_parsed["t"].as<std::vector<std::string>>())
		{
			enabled_rule_tags.insert(tag);
		}
	}

	// Some combinations of arguments are not allowed.

	// You can't both disable and enable rules
	if((disabled_rule_substrings.size() + disabled_rule_tags.size() > 0) &&
	   enabled_rule_tags.size() > 0)
	{
		errstr = std::string("You can not specify both disabled (-D/-T) and enabled (-t) rules");
		return false;
	}

	list_fields = m_cmdline_parsed.count("list") > 0 ? true : false;

	int open_modes = 0;
	open_modes += !trace_filename.empty();
	open_modes += userspace;
	open_modes += !gvisor_config.empty();
	open_modes += modern_bpf;
	open_modes += getenv("FALCO_BPF_PROBE") != NULL;
	open_modes += nodriver;
	if (open_modes > 1)
	{
		errstr = std::string("You can not specify more than one of -e, -u (--userspace), -g (--gvisor-config), --modern-bpf, --nodriver, and the FALCO_BPF_PROBE env var");
		return false;
	}

	return true;
}

const std::string& options::usage()
{
	return m_usage_str;
}

void options::define(cxxopts::Options& opts)
{
	opts.add_options()
		("h,help",                        "Print this help list and exit.", cxxopts::value(help)->default_value("false"))
#ifdef BUILD_TYPE_RELEASE
		("c",                             "Configuration file. If not specified uses " FALCO_INSTALL_CONF_FILE ".", cxxopts::value(conf_filename), "<path>")
#else
		("c",                             "Configuration file. If not specified tries " FALCO_SOURCE_CONF_FILE ", " FALCO_INSTALL_CONF_FILE ".", cxxopts::value(conf_filename), "<path>")
#endif
		("A",                             "Monitor all events supported by Falco and defined in rules and configs. Some events are ignored by default when -A is not specified (the -i option lists these events ignored). Using -A can impact performance. This option has no effect when reproducing events from a capture file.", cxxopts::value(all_events)->default_value("false"))
		("b,print-base64",                "Print data buffers in base64. This is useful for encoding binary data that needs to be used over media designed to consume this format.")
#if !defined(_WIN32) && !defined(__EMSCRIPTEN__) && !defined(MINIMAL_BUILD)
		("cri",                           "Path to CRI socket for container metadata. Use the specified <path> to fetch data from a CRI-compatible runtime. If not specified, built-in defaults for commonly known paths are used. This option can be passed multiple times to specify a list of sockets to be tried until a successful one is found.", cxxopts::value(cri_socket_paths), "<path>")
		("disable-cri-async",             "Turn off asynchronous CRI metadata fetching. This is useful to let the input event wait for the container metadata fetch to finish before moving forward. Async fetching, in some environments leads to empty fields for container metadata when the fetch is not fast enough to be completed asynchronously. This can have a performance penalty on your environment depending on the number of containers and the frequency at which they are created/started/stopped.", cxxopts::value(disable_cri_async)->default_value("false"))
#endif
		("disable-source",                "Turn off a specific <event_source>. By default, all loaded sources get enabled. Available sources are 'syscall' plus all sources defined by loaded plugins supporting the event sourcing capability. This option can be passed multiple times, but turning off all event sources simultaneously is not permitted. This option can not be mixed with --enable-source. This option has no effect when reproducing events from a capture file.", cxxopts::value(disable_sources), "<event_source>")
		("dry-run",                       "Run Falco without processing events. It can help check that the configuration and rules do not have any errors.", cxxopts::value(dry_run)->default_value("false"))
		("D",                             "Turn off any rules with names having the substring <substring>. This option can be passed multiple times. It cannot be mixed with -t.", cxxopts::value(disabled_rule_substrings), "<substring>")
		("e",                             "Reproduce the events by reading from the given <capture_file> instead of opening a live session. Only capture files in .scap format are supported.", cxxopts::value(trace_filename), "<events_file>")
		("enable-source",                 "Enable a specific <event_source>. By default, all loaded sources get enabled. Available sources are 'syscall' plus all sources defined by loaded plugins supporting the event sourcing capability. This option can be passed multiple times. When using this option, only the event sources specified by it will be enabled. This option can not be mixed with --disable-source. This option has no effect when reproducing events from a capture file.", cxxopts::value(enable_sources), "<event_source>")
#ifdef HAS_GVISOR
		("g,gvisor-config",				  "Collect 'syscall' events from gVisor using the specified <gvisor_config> file. A Falco-compatible configuration file can be generated with --gvisor-generate-config and utilized for both runsc and Falco.", cxxopts::value(gvisor_config), "<gvisor_config>")
		("gvisor-generate-config",		  "Generate a configuration file that can be used for gVisor and exit. See --gvisor-config for more details.", cxxopts::value<std::string>(gvisor_generate_config_with_socket)->implicit_value("/run/falco/gvisor.sock"), "<socket_path>")
		("gvisor-root",					  "Set gVisor root directory for storage of container state when used in conjunction with --gvisor-config. The <gvisor_root> to be passed is the one usually passed to runsc --root flag.", cxxopts::value(gvisor_root), "<gvisor_root>")
#endif
#ifdef HAS_MODERN_BPF
		("modern-bpf",				  "Use the BPF modern probe driver to instrument the kernel and observe 'syscall' events.", cxxopts::value(modern_bpf)->default_value("false"))
#endif
		("i",                             "Print those events that are ignored by default for performance reasons and exit. See -A for more details.", cxxopts::value(print_ignored_events)->default_value("false"))
#if !defined(_WIN32) && !defined(__EMSCRIPTEN__) && !defined(MINIMAL_BUILD)
		("k,k8s-api",                     "Enable Kubernetes metadata support by connecting to the given API server <URL>\n(e.g. \"http://admin:password@127.0.0.1:8080\". The API server can also be specified via the environment variable FALCO_K8S_API.", cxxopts::value(k8s_api), "<URL>")
		("K,k8s-api-cert",                "Use the provided file names to authenticate the user and (optionally) verify the K8S API server identity. Each entry must specify the full (absolute or relative to the current directory) path to the respective file. Passing a private key password is optional (unless the key is password-protected). CA certificate is optional. For all files, only the PEM file format is supported. Specifying the CA certificate only is obsoleted - when a single entry is provided for this option, it will be interpreted as the name of a file containing the bearer token. Note that the format of this command-line option prohibits the use of files whose names contain ':' or '#' characters in the file name. This option has effect only when used in conjunction with -k.", cxxopts::value(k8s_api_cert), "(<bt_file> | <cert_file>:<key_file[#password]>[:<ca_cert_file>])")
		("k8s-node",                      "Filter Kubernetes metadata for a specified <node_name>. The node name will be used as a filter when requesting metadata of pods to the API server. Usually, this should be set to the current node on which Falco is running. No filter is set if empty, which may have a performance penalty on large clusters. This option has effect only when used in conjunction with -k.", cxxopts::value(k8s_node_name), "<node_name>")
#endif
		("L",                             "Show the name and description of all rules and exit. If json_output is set to true, it prints details about all rules, macros, and lists in JSON format.", cxxopts::value(describe_all_rules)->default_value("false"))
		("l",                             "Show the name and description of the rule specified <rule> and exit. If json_output is set to true, it prints details about the rule in JSON format.", cxxopts::value(describe_rule), "<rule>")
		("list",                          "List all defined fields and exit. If <source> is provided, only list those fields for the source <source>. Current values for <source> are \"syscall\" or any source from a configured plugin with event sourcing capability.", cxxopts::value(list_source_fields)->implicit_value(""), "<source>")
		("list-events",                   "List all defined syscall events, metaevents, tracepoint events and exit.", cxxopts::value<bool>(list_syscall_events))
		("list-plugins",                  "Print info on all loaded plugins and exit.", cxxopts::value(list_plugins)->default_value("false"))
		("M",                             "Stop Falco execution after <num_seconds> are passed.", cxxopts::value(duration_to_tot)->default_value("0"), "<num_seconds>")
		("markdown",                      "Print output in Markdown format when used in conjunction with --list or --list-events options. It has no effect when used with other options.", cxxopts::value<bool>(markdown))
		("N",                             "Only print field names when used in conjunction with the --list option. It has no effect when used with other options.", cxxopts::value(names_only)->default_value("false"))
		("nodriver",                      "Do not use a driver to instrument the kernel. If a loaded plugin has event-sourcing capability and can produce system events, it will be used for event collection. Otherwise, no event will be collected.", cxxopts::value(nodriver)->default_value("false"))
		("o,option",                      "Set the value of option <opt> to <val>. Overrides values in the configuration file. <opt> can be identified using its location in the configuration file using dot notation. Elements of list entries can be accessed via square brackets [].\n    E.g. base.id = val\n         base.subvalue.subvalue2 = val\n         base.list[1]=val", cxxopts::value(cmdline_config_options), "<opt>=<val>")
		("plugin-info",                   "Print info for the plugin specified by <plugin_name> and exit.\nThis includes all descriptive information like name and author, along with the\nschema format for the init configuration and a list of suggested open parameters.\n<plugin_name> can be the plugin's name or its configured 'library_path'.", cxxopts::value(print_plugin_info), "<plugin_name>")
		("p,print",                       "Print (or replace) additional information in the rule's output.\nUse -pc or -pcontainer to append container details.\nUse -pk or -pkubernetes to add both container and Kubernetes details.\nIf using gVisor, choose -pcg or -pkg variants (or -pcontainer-gvisor and -pkubernetes-gvisor, respectively).\nIf a rule's output contains %container.info, it will be replaced with the corresponding details. Otherwise, these details will be directly appended to the rule's output.\nAlternatively, use -p <output_format> for a custom format. In this case, the given <output_format> will be appended to the rule's output without any replacement.", cxxopts::value(print_additional), "<output_format>")
		("P,pidfile",                     "Write PID to specified <pid_file> path. By default, no PID file is created.", cxxopts::value(pidfilename)->default_value(""), "<pid_file>")
		("r",                             "Rules file or directory to be loaded. This option can be passed multiple times. Falco defaults to the values in the configuration file when this option is not specified.", cxxopts::value<std::vector<std::string>>(), "<rules_file>")
		("S,snaplen",                     "Collect only the first <len> bytes of each I/O buffer for 'syscall' events. By default, the first 80 bytes are collected by the driver and sent to the user space for processing. Use this option with caution since it can have a strong performance impact.", cxxopts::value(snaplen)->default_value("0"), "<len>")
		("support",                       "Print support information, including version, rules files used, loaded configuration, etc., and exit. The output is in JSON format.", cxxopts::value(print_support)->default_value("false"))
		("T",                             "Turn off any rules with a tag=<tag>. This option can be passed multiple times. This option can not be mixed with -t.", cxxopts::value<std::vector<std::string>>(), "<tag>")
		("t",                             "Only enable those rules with a tag=<tag>. This option can be passed multiple times. This option can not be mixed with -T/-D.", cxxopts::value<std::vector<std::string>>(), "<tag>")
		("U,unbuffered",                  "Turn off output buffering for configured outputs. This causes every single line emitted by Falco to be flushed, which generates higher CPU usage but is useful when piping those outputs into another process or a script.", cxxopts::value(unbuffered_outputs)->default_value("false"))
#if !defined(_WIN32) && !defined(__EMSCRIPTEN__) && !defined(MINIMAL_BUILD)
		("u,userspace",                   "[DEPRECATED: this option will be removed in Falco 0.37] Use a userspace driver to collect 'syscall' events. To be used in conjunction with the ptrace(2) based driver (pdig).", cxxopts::value(userspace)->default_value("false"))
#endif
		("V,validate",                    "Read the contents of the specified <rules_file> file(s), validate the loaded rules, and exit. This option can be passed multiple times to validate multiple files.", cxxopts::value(validate_rules_filenames), "<rules_file>")
		("v",                             "Enable verbose output.", cxxopts::value(verbose)->default_value("false"))
		("version",                       "Print version information and exit.", cxxopts::value(print_version_info)->default_value("false"))
		("page-size",                     "Print the system page size and exit. This utility may help choose the right syscall ring buffer size.", cxxopts::value(print_page_size)->default_value("false"));


	opts.set_width(140);
}

}; // namespace app
}; // namespace falco
