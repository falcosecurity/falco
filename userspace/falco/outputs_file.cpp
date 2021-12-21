/*
Copyright (C) 2020 The Falco Authors

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

#include "outputs_file.h"
#include <iostream>
#include <fstream>
#include "banned.h" // This raises a compilation error when certain functions are used

falco::outputs::output_file::output_file()
{
	m_lastlog = time(nullptr);
}

void falco::outputs::output_file::open_file()
{
	if(!m_buffered)
	{
		m_outfile.rdbuf()->pubsetbuf(0, 0);
	}
	if(!m_outfile.is_open())
	{
		m_outfile.open(m_oc.options["filename"], fstream::app);
		if (m_outfile.fail())
		{
			throw falco_exception("failed to open output file " + m_oc.options["filename"]);
		}
	}
}

void falco::outputs::output_file::output(const message *msg)
{
	open_file();
	m_outfile << msg->msg + "\n";

	logrotate();

	if(m_oc.options["keep_alive"] != "true")
	{
		cleanup();
	}
}

void falco::outputs::output_file::logrotate()
{
	if(m_oc.options["log_maxage"] == "0")
	{
		return;
	}

	std::time_t now = time(nullptr);
	double diff = difftime(now, m_lastlog);

	if(diff/m_secs_day < std::stoi(m_oc.options["log_maxage"]))
	{
		return;
	}

	if(m_oc.options["log_maxbackup"] == "0")
	{
		// Return value of truncate is not meaningful.
		if(!truncate(m_oc.options["filename"].c_str(), 0))
		{
			//Do nothing.
		}
	}
	else
	{
		cleanup();
		m_lastlog = now;
		struct tm *tn = localtime(&now);

		std::string log_name = m_oc.options["filename"]+"_" + to_string(tn->tm_year) + to_string(tn->tm_mon) + to_string(tn->tm_mday) + to_string(tn->tm_hour) + to_string(tn->tm_min) + to_string(tn->tm_sec) + ".txt";

		m_rotating_queue.push(log_name);
		rename(m_oc.options["filename"].c_str(), log_name.c_str());
		if(m_rotating_queue.size()> stoi(m_oc.options["log_maxbackup"]))
		{
			remove(m_rotating_queue.front().data());
			m_rotating_queue.pop();
		}
	}


}

void falco::outputs::output_file::cleanup()
{
	if(m_outfile.is_open())
	{
		m_outfile.close();
	}
}

void falco::outputs::output_file::reopen()
{
	cleanup();
	open_file();
}
