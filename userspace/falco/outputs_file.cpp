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

void falco::outputs::output_file::open_file()
{
	if(!m_buffered)
	{
		m_outfile.rdbuf()->pubsetbuf(0, 0);
	}
	if(!m_outfile.is_open())
	{
		m_outfile.open(m_oc.options["filename"], fstream::app);
	}
}

void falco::outputs::output_file::output_event(gen_event *evt, std::string &rule, std::string &source,
					       falco_common::priority_type priority, std::string &format, std::string &msg)
{
	output_msg(priority, msg);
}

void falco::outputs::output_file::output_msg(falco_common::priority_type priority, std::string &msg)
{
	open_file();
	m_outfile << msg + "\n";

	if(m_oc.options["keep_alive"] != "true")
	{
		cleanup();
	}
}

void falco::outputs::output_file::cleanup()
{
	if(m_outfile.is_open())
	{
		m_outfile.flush();
		m_outfile.close();
	}
}

void falco::outputs::output_file::reopen()
{
	cleanup();
	open_file();
}
