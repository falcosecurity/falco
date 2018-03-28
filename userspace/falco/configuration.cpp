/*
Copyright (C) 2016 Draios inc.

This file is part of falco.

falco is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License version 2 as
published by the Free Software Foundation.

falco is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with falco.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "configuration.h"
#include "logger.h"

using namespace std;

falco_configuration::falco_configuration()
	: m_buffered_outputs(true),
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
			m_rules_filenames.push_back(file);
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

	m_buffered_outputs = m_config->get_scalar<bool>("buffered_outputs", true);

	falco_logger::log_stderr = m_config->get_scalar<bool>("log_stderr", false);
	falco_logger::log_syslog = m_config->get_scalar<bool>("log_syslog", true);
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
