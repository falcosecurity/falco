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

#include "outputs_program.h"
#include <stdio.h>
#include "banned.h" // This raises a compilation error when certain functions are used

void falco::outputs::output_program::open_pfile()
{
	if(m_pfile == nullptr)
	{
		m_pfile = popen(m_oc.options["program"].c_str(), "w");

		if(!m_buffered)
		{
			setvbuf(m_pfile, NULL, _IONBF, 0);
		}
	}
}

void falco::outputs::output_program::output(const message *msg)
{
	open_pfile();

	fprintf(m_pfile, "%s\n", msg->msg.c_str());

	if(m_oc.options["keep_alive"] != "true")
	{
		cleanup();
	}
}

void falco::outputs::output_program::cleanup()
{
	if(m_pfile != nullptr)
	{
		pclose(m_pfile);
		m_pfile = nullptr;
	}
}

void falco::outputs::output_program::reopen()
{
	cleanup();
	open_pfile();
}
