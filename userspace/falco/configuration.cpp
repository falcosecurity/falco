#include "configuration.h"
#include "config_falco.h"
#include "sinsp.h"
#include "logger.h"

using namespace std;


// If we don't have a configuration file, we just use stdout output and all other defaults
void falco_configuration::init(std::list<std::string> &cmdline_options)
{
	init_cmdline_options(cmdline_options);

	output_config stdout_output;
	stdout_output.name = "stdout";
	m_outputs.push_back(stdout_output);
}

void falco_configuration::init(string conf_filename, std::list<std::string> &cmdline_options)
{
	string m_config_file = conf_filename;
	m_config = new yaml_configuration(m_config_file);

	init_cmdline_options(cmdline_options);

	m_rules_filename = m_config->get_scalar<string>("rules_file", "/etc/falco_rules.yaml");
	m_json_output = m_config->get_scalar<bool>("json_output", false);

	output_config file_output;
	file_output.name = "file";
	if (m_config->get_scalar<bool>("file_output", "enabled", false))
	{
		string filename;
		filename = m_config->get_scalar<string>("file_output", "filename", "");
		if (filename == string(""))
		{
			throw sinsp_exception("Error reading config file (" + m_config_file + "): file output enabled but no filename in configuration block");
		}
		file_output.options["filename"] = filename;
		m_outputs.push_back(file_output);
	}

	output_config stdout_output;
	stdout_output.name = "stdout";
	if (m_config->get_scalar<bool>("stdout_output", "enabled", false))
	{
		m_outputs.push_back(stdout_output);
	}

	output_config syslog_output;
	syslog_output.name = "syslog";
	if (m_config->get_scalar<bool>("syslog_output", "enabled", false))
	{
		m_outputs.push_back(syslog_output);
	}

	if (m_outputs.size() == 0)
	{
		throw sinsp_exception("Error reading config file (" + m_config_file + "): No outputs configured. Please configure at least one output file output enabled but no filename in configuration block");
	}

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

void falco_configuration::init_cmdline_options(std::list<std::string> &cmdline_options)
{
	for(const string &option : cmdline_options)
	{
		set_cmdline_option(option);
	}
}

void falco_configuration::set_cmdline_option(const std::string &opt)
{
	pair<string,string> keyval;
	pair<string,string> subkey;

	if (! split(opt, '=', keyval)) {
		throw sinsp_exception("Error parsing config option \"" + opt + "\". Must be of the form key=val or key.subkey=val");
	}

	if (split(keyval.first, '.', subkey)) {
		m_config->set_scalar(subkey.first, subkey.second, keyval.second);
	} else {
		m_config->set_scalar(keyval.first, keyval.second);
	}
}
