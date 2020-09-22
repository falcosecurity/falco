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

#include "falco_outputs_program.h"
#include <stdio.h>
#include "banned.h" // This raises a compilation error when certain functions are used

void falco::outputs::output_program::open_pfile()
{

	if(m_pfile == nullptr)
	{
		m_pfile = popen(m_oc.options["program"].c_str(), "w");
		// todo(leogr): handle errno
	}

	// if(!m_buffered)
	// {
	// 	m_pipe.rdbuf()->pubsetbuf(0, 0);
	// }
}

void falco::outputs::output_program::output_event(gen_event *evt, std::string &rule, std::string &source,
						  falco_common::priority_type priority, std::string &format, std::string &msg)
{
	output_msg(priority, msg);
}

void falco::outputs::output_program::output_msg(falco_common::priority_type priority, std::string &msg)
{
	open_pfile();
	fprintf(m_pfile, "%s\n", msg.c_str());

	if(m_oc.options["keep_alive"] != "true")
	{
		cleanup();
	}
}

void falco::outputs::output_program::cleanup()
{
	if(m_pfile != nullptr)
	{
		fflush(m_pfile);
		fclose(m_pfile);
	}
}

void falco::outputs::output_program::reopen()
{
	cleanup();
	open_pfile();
}
