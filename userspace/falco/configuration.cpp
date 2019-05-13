/*
Copyright (C) 2016-2018 Draios Inc dba Sysdig.

This file is part of falco.

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

#include <algorithm>

#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "configuration.h"
#include "logger.h"

using namespace std;

falco_configuration::falco_configuration()
	: m_buffered_outputs(false),
	  m_time_format_iso_8601(false),
	  m_webserver_enabled(false),
	  m_webserver_listen_port(8765),
	  m_webserver_k8s_audit_endpoint("/k8s_audit"),
	  m_webserver_ssl_enabled(false),
	  m_config(NULL)
{
}

falco_configuration::~falco_configuration()
{
	if (m_config)
	{
		delete m_config;
	}
}

// If we don't have a configuration file, we just use stdout output and all other defaults
void falco_configuration::init(list<string> &cmdline_options)
{
	init_cmdline_options(cmdline_options);

	falco_outputs::output_config stdout_output;
	stdout_output.name = "stdout";
	m_outputs.push_back(stdout_output);
}

void falco_configuration::init(string conf_filename, list<string> &cmdline_options)
{
	string m_config_file = conf_filename;
	m_config = new yaml_configuration(m_config_file);

	init_cmdline_options(cmdline_options);

	list<string> rules_files;

	m_config->get_sequence<list<string>>(rules_files, string("rules_file"));

	for(auto &file : rules_files)
	{
		// Here, we only include files that exist
		struct stat buffer;
		if(stat(file.c_str(), &buffer) == 0)
		{
			read_rules_file_directory(file, m_rules_filenames);
		}
	}

	m_json_output = m_config->get_scalar<bool>("json_output", false);
	m_json_include_output_property = m_config->get_scalar<bool>("json_include_output_property", true);

	falco_outputs::output_config file_output;
	file_output.name = "file";
	if (m_config->get_scalar<bool>("file_output", "enabled", false))
	{
		string filename, keep_alive;
		filename = m_config->get_scalar<string>("file_output", "filename", "");
		if (filename == string(""))
		{
			throw invalid_argument("Error reading config file (" + m_config_file + "): file output enabled but no filename in configuration block");
		}
		file_output.options["filename"] = filename;

		keep_alive = m_config->get_scalar<string>("file_output", "keep_alive", "");
		file_output.options["keep_alive"] = keep_alive;

		m_outputs.push_back(file_output);
	}

	falco_outputs::output_config stdout_output;
	stdout_output.name = "stdout";
	if (m_config->get_scalar<bool>("stdout_output", "enabled", false))
	{
		m_outputs.push_back(stdout_output);
	}

	falco_outputs::output_config syslog_output;
	syslog_output.name = "syslog";
	if (m_config->get_scalar<bool>("syslog_output", "enabled", false))
	{
		m_outputs.push_back(syslog_output);
	}

	falco_outputs::output_config program_output;
	program_output.name = "program";
	if (m_config->get_scalar<bool>("program_output", "enabled", false))
	{
		string program, keep_alive;
		program = m_config->get_scalar<string>("program_output", "program", "");
		if (program == string(""))
		{
			throw sinsp_exception("Error reading config file (" + m_config_file + "): program output enabled but no program in configuration block");
		}
		program_output.options["program"] = program;

		keep_alive = m_config->get_scalar<string>("program_output", "keep_alive", "");
		program_output.options["keep_alive"] = keep_alive;

		m_outputs.push_back(program_output);
	}

	falco_outputs::output_config http_output;
	http_output.name = "http";
	if (m_config->get_scalar<bool>("http_output", "enabled", false))
	{
		string url;
		url = m_config->get_scalar<string>("http_output", "url", "");

		if (url == string(""))
		{
			throw sinsp_exception("Error reading config file (" + m_config_file + "): http output enabled but no url in configuration block");
		}
		http_output.options["url"] = url;

		m_outputs.push_back(http_output);
	}

	if (m_outputs.size() == 0)
	{
		throw invalid_argument("Error reading config file (" + m_config_file + "): No outputs configured. Please configure at least one output file output enabled but no filename in configuration block");
	}

	string log_level = m_config->get_scalar<string>("log_level", "info");

	falco_logger::set_level(log_level);

	m_notifications_rate = m_config->get_scalar<uint32_t>("outputs", "rate", 1);
	m_notifications_max_burst = m_config->get_scalar<uint32_t>("outputs", "max_burst", 1000);

	string priority = m_config->get_scalar<string>("priority", "debug");
	vector<string>::iterator it;

	auto comp = [priority] (string &s) {
		return (strcasecmp(s.c_str(), priority.c_str()) == 0);
	};

	if((it = std::find_if(falco_common::priority_names.begin(), falco_common::priority_names.end(), comp)) == falco_common::priority_names.end())
	{
		throw invalid_argument("Unknown priority \"" + priority + "\"--must be one of emergency, alert, critical, error, warning, notice, informational, debug");
	}
	m_min_priority = (falco_common::priority_type) (it - falco_common::priority_names.begin());

	m_buffered_outputs = m_config->get_scalar<bool>("buffered_outputs", false);
	m_time_format_iso_8601 = m_config->get_scalar<bool>("time_format_iso_8601", false);

	falco_logger::log_stderr = m_config->get_scalar<bool>("log_stderr", false);
	falco_logger::log_syslog = m_config->get_scalar<bool>("log_syslog", true);

	m_webserver_enabled = m_config->get_scalar<bool>("webserver", "enabled", false);
	m_webserver_listen_port = m_config->get_scalar<uint32_t>("webserver", "listen_port", 8765);
	m_webserver_k8s_audit_endpoint = m_config->get_scalar<string>("webserver", "k8s_audit_endpoint", "/k8s_audit");
	m_webserver_ssl_enabled = m_config->get_scalar<bool>("webserver", "ssl_enabled", false);
	m_webserver_ssl_certificate = m_config->get_scalar<string>("webserver", "ssl_certificate","/etc/falco/falco.pem");

	std::list<string> syscall_event_drop_acts;
	m_config->get_sequence(syscall_event_drop_acts, "syscall_event_drops", "actions");

	for(std::string &act : syscall_event_drop_acts)
	{
		if(act == "ignore")
		{
			m_syscall_evt_drop_actions.insert(syscall_evt_drop_mgr::ACT_IGNORE);
		}
		else if (act == "log")
		{
			m_syscall_evt_drop_actions.insert(syscall_evt_drop_mgr::ACT_LOG);
		}
		else if (act == "alert")
		{
			m_syscall_evt_drop_actions.insert(syscall_evt_drop_mgr::ACT_ALERT);
		}
		else if (act == "exit")
		{
			m_syscall_evt_drop_actions.insert(syscall_evt_drop_mgr::ACT_EXIT);
		}
		else
		{
			throw invalid_argument("Error reading config file (" + m_config_file + "): syscall event drop action " + act + " must be one of \"ignore\", \"log\", \"alert\", or \"exit\"");
		}
	}

	if(m_syscall_evt_drop_actions.empty())
	{
		m_syscall_evt_drop_actions.insert(syscall_evt_drop_mgr::ACT_IGNORE);
	}

	m_syscall_evt_drop_rate = m_config->get_scalar<double>("syscall_event_drops", "rate", 0.3333);
	m_syscall_evt_drop_max_burst = m_config->get_scalar<double>("syscall_event_drops", "max_burst", 10);

	m_syscall_evt_simulate_drops = m_config->get_scalar<bool>("syscall_event_drops", "simulate_drops", false);
}

void falco_configuration::read_rules_file_directory(const string &path, list<string> &rules_filenames)
{
	struct stat st;

	int rc = stat(path.c_str(), &st);

	if(rc != 0)
	{
		std::cerr << "Could not get info on rules file " << path << ": " << strerror(errno) << std::endl;
		exit(-1);
	}

	if(st.st_mode & S_IFDIR)
	{
		// It's a directory. Read the contents, sort
		// alphabetically, and add every path to
		// rules_filenames
		vector<string> dir_filenames;

		DIR *dir = opendir(path.c_str());

		if(!dir)
		{
			std::cerr << "Could not get read contents of directory " << path << ": " << strerror(errno) << std::endl;
			exit(-1);
		}

		for (struct dirent *ent = readdir(dir); ent; ent = readdir(dir))
		{
			string efile = path + "/" + ent->d_name;

			rc = stat(efile.c_str(), &st);

			if(rc != 0)
			{
				std::cerr << "Could not get info on rules file " << efile << ": " << strerror(errno) << std::endl;
				exit(-1);
			}

			if(st.st_mode & S_IFREG)
			{
				dir_filenames.push_back(efile);
			}
		}

		closedir(dir);

		std::sort(dir_filenames.begin(),
			  dir_filenames.end());

		for (string &ent : dir_filenames)
		{
			rules_filenames.push_back(ent);
		}
	}
	else
	{
		// Assume it's a file and just add to
		// rules_filenames. If it can't be opened/etc that
		// will be reported later..
		rules_filenames.push_back(path);
	}
}

static bool split(const string &str, char delim, pair<string,string> &parts)
{
	size_t pos;

	if ((pos = str.find_first_of(delim)) == string::npos) {
		return false;
	}
	parts.first = str.substr(0, pos);
	parts.second = str.substr(pos + 1);

	return true;
}

void falco_configuration::init_cmdline_options(list<string> &cmdline_options)
{
	for(const string &option : cmdline_options)
	{
		set_cmdline_option(option);
	}
}

void falco_configuration::set_cmdline_option(const string &opt)
{
	pair<string,string> keyval;
	pair<string,string> subkey;

	if (! split(opt, '=', keyval)) {
		throw invalid_argument("Error parsing config option \"" + opt + "\". Must be of the form key=val or key.subkey=val");
	}

	if (split(keyval.first, '.', subkey)) {
		m_config->set_scalar(subkey.first, subkey.second, keyval.second);
	} else {
		m_config->set_scalar(keyval.first, keyval.second);
	}
}
