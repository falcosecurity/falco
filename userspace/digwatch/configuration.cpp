#include "configuration.h"
#include "config_digwatch.h"
#include "sinsp.h"

using namespace std;

void digwatch_configuration::init()
{
	string m_config_file = DIGWATCH_CONF_FILE;
	m_config = new yaml_configuration(m_config_file);

	m_rules_file = m_config->get_scalar<string>("rules_file", "/etc/digwatch.conf");
	m_priority_level = m_config->get_scalar<string>("priority_level", "warning");

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
}
