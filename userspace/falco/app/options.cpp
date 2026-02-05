// SPDX-License-Identifier: Apache-2.0
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

// disable cxxopts vector delimiter, meaning that
// -o test1,test2,test3 won't be treated like -o test1 -o test2 -o test3
#define CXXOPTS_VECTOR_DELIMITER '\0'
#include <cxxopts.hpp>

#include <fstream>

namespace falco {
namespace app {

bool options::parse(int argc, char **argv, std::string &errstr) {
	cxxopts::Options opts("falco", "Falco - Cloud Native Runtime Security");
	define(opts);
	m_usage_str = opts.help();

	cxxopts::ParseResult m_cmdline_parsed;
	try {
		m_cmdline_parsed = opts.parse(argc, argv);
	} catch(std::exception &e) {
		errstr = e.what();
		return false;
	}

	// Some options require additional processing/validation
	std::ifstream conf_stream;
	if(!conf_filename.empty()) {
		conf_stream.open(conf_filename);
		if(!conf_stream.is_open()) {
			errstr = std::string("Could not find configuration file at ") + conf_filename;
			return false;
		}
	} else {
#ifdef BUILD_TYPE_DEBUG
		conf_stream.open(FALCO_SOURCE_CONF_FILE);
		if(conf_stream.is_open()) {
			conf_filename = FALCO_SOURCE_CONF_FILE;
		} else
#endif
		{
			conf_stream.open(FALCO_INSTALL_CONF_FILE);
			if(conf_stream.is_open()) {
				conf_filename = FALCO_INSTALL_CONF_FILE;
			} else {
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

	if(m_cmdline_parsed.count("r") > 0) {
		for(auto &path : m_cmdline_parsed["r"].as<std::vector<std::string>>()) {
			rules_filenames.push_back(path);
		}
	}

	list_fields = m_cmdline_parsed.count("list") > 0;

	return true;
}

const std::string &options::usage() {
	return m_usage_str;
}

// clang-format off
void options::define(cxxopts::Options& opts)
{
	opts.add_options()
		("h,help",                   "Print this help list and exit.", cxxopts::value(help)->default_value("false"))
#ifndef BUILD_TYPE_DEBUG
		("c",                        "Configuration file. If not specified uses " FALCO_INSTALL_CONF_FILE ".", cxxopts::value(conf_filename), "<path>")
#else
		("c",                        "Configuration file. If not specified tries " FALCO_SOURCE_CONF_FILE ", " FALCO_INSTALL_CONF_FILE ".", cxxopts::value(conf_filename), "<path>")
#endif
		("config-schema",            "Print the config json schema and exit.", cxxopts::value(print_config_schema)->default_value("false"))
		("rule-schema",              "Print the rule json schema and exit.", cxxopts::value(print_rule_schema)->default_value("false"))
		("disable-source",           "Turn off a specific <event_source>. By default, all loaded sources get enabled. Available sources are 'syscall' plus all sources defined by loaded plugins supporting the event sourcing capability. This option can be passed multiple times, but turning off all event sources simultaneously is not permitted. This option can not be mixed with --enable-source. This option has no effect when reproducing events from a capture file.", cxxopts::value(disable_sources), "<event_source>")
		("dry-run",                  "Run Falco without processing events. It can help check that the configuration and rules do not have any errors.", cxxopts::value(dry_run)->default_value("false"))
		("enable-source",            "Enable a specific <event_source>. By default, all loaded sources get enabled. Available sources are 'syscall' plus all sources defined by loaded plugins supporting the event sourcing capability. This option can be passed multiple times. When using this option, only the event sources specified by it will be enabled. This option can not be mixed with --disable-source. This option has no effect when reproducing events from a capture file.", cxxopts::value(enable_sources), "<event_source>")
		("i",                        "Print those events that are ignored by default for performance reasons and exit.", cxxopts::value(print_ignored_events)->default_value("false"))
		("L",                        "Show the name and description of all rules and exit. If json_output is set to true, it prints details about all rules, macros, and lists in JSON format.", cxxopts::value(describe_all_rules)->default_value("false"))
		("l",                        "Show the name and description of the rule specified <rule> and exit. If json_output is set to true, it prints details about the rule in JSON format.", cxxopts::value(describe_rule), "<rule>")
		("list",                     "List all defined fields and exit. If <source> is provided, only list those fields for the source <source>. Current values for <source> are \"syscall\" or any source from a configured plugin with event sourcing capability.", cxxopts::value(list_source_fields)->implicit_value(""), "<source>")
		("list-events",              "List all defined syscall events, metaevents, tracepoint events and exit.", cxxopts::value<bool>(list_syscall_events))
		("list-plugins",             "Print info on all loaded plugins and exit.", cxxopts::value(list_plugins)->default_value("false"))
		("M",                        "Stop Falco execution after <num_seconds> are passed.", cxxopts::value(duration_to_tot)->default_value("0"), "<num_seconds>")
		("markdown",                 "Print output in Markdown format when used in conjunction with --list or --list-events options. It has no effect when used with other options.", cxxopts::value<bool>(markdown))
		("N",                        "Only print field names when used in conjunction with the --list option. It has no effect when used with other options.", cxxopts::value(names_only)->default_value("false"))
		("o,option",                 "Set the value of option <opt> to <val>. Overrides values in the configuration file. <opt> can be identified using its location in the configuration file using dot notation. Elements of list entries can be accessed via square brackets [].\n    E.g. base.id = val\n         base.subvalue.subvalue2 = val\n         base.list[1]=val", cxxopts::value(cmdline_config_options), "<opt>=<val>")
		("plugin-info",              "Print info for the plugin specified by <plugin_name> and exit.\nThis includes all descriptive information like name and author, along with the\nschema format for the init configuration and a list of suggested open parameters.\n<plugin_name> can be the plugin's name or its configured 'library_path'.", cxxopts::value(print_plugin_info), "<plugin_name>")
		("p,print",                  "DEPRECATED: use -o append_output... instead. Print additional information in the rule's output.\nUse -pc or -pcontainer to append container details to syscall events.\nUse -pk or -pkubernetes to add both container and Kubernetes details to syscall events.\nThe details will be directly appended to the rule's output.\nAlternatively, use -p <output_format> for a custom format. In this case, the given <output_format> will be appended to the rule's output without any replacement to all events, including plugin events.", cxxopts::value(print_additional), "<output_format>")
		("P,pidfile",                "Write PID to specified <pid_file> path. By default, no PID file is created.", cxxopts::value(pidfilename)->default_value(""), "<pid_file>")
		("r",                        "Rules file or directory to be loaded. This option can be passed multiple times. Falco defaults to the values in the configuration file when this option is not specified. Only files with .yml or .yaml extension are considered.", cxxopts::value<std::vector<std::string>>(), "<rules_file>")
		("support",                  "Print support information, including version, rules files used, loaded configuration, etc., and exit. The output is in JSON format.", cxxopts::value(print_support)->default_value("false"))
		("U,unbuffered",             "Turn off output buffering for configured outputs. This causes every single line emitted by Falco to be flushed, which generates higher CPU usage but is useful when piping those outputs into another process or a script.", cxxopts::value(unbuffered_outputs)->default_value("false"))
		("V,validate",               "Read the contents of the specified <rules_file> file(s), validate the loaded rules, and exit. This option can be passed multiple times to validate multiple files.", cxxopts::value(validate_rules_filenames), "<rules_file>")
		("v",                        "Enable verbose output.", cxxopts::value(verbose)->default_value("false"))
		("version",                  "Print version information and exit.", cxxopts::value(print_version_info)->default_value("false"))
		("page-size",                "Print the system page size and exit. This utility may help choose the right syscall ring buffer size.", cxxopts::value(print_page_size)->default_value("false"));

	opts.set_width(140);
}
// clang-format on

};  // namespace app
};  // namespace falco
