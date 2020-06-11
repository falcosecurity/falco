/*
Copyright (C) 2013-2018 Draios Inc dba Sysdig.

This file is part of sysdig.

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
#include "sinsp.h"
#include "sinsp_int.h"
#include "cyclewriter.h"

cycle_writer::cycle_writer(bool is_live) :
	m_base_file_name(""),
	m_rollover_mb(0L),
	m_duration_seconds(0),
	m_file_limit(0),
	m_event_limit(0L),
	m_last_time(0),
	m_file_count_total(0),
	m_file_index(0),
	m_first_consider(false),
	m_event_count(0L),
	m_dumper(NULL),
	m_past_names(NULL)
{
	//
	// null terminate the first
	// character of the limit format
	// to say that we want things to
	// be created when we consider() the 
	// next file.
	//
	m_limit_format[0] = 0;
	this->live = is_live;
}

bool cycle_writer::setup(string base_file_name, int rollover_mb, int duration_seconds, int file_limit, unsigned long event_limit, scap_dumper_t** dumper)
{
	if(m_first_consider) 
	{
		return false;
	}
	m_base_file_name = base_file_name;
	m_rollover_mb = rollover_mb * 1000000L;
	m_duration_seconds = duration_seconds;
	m_file_limit = file_limit;
	m_event_limit = event_limit;
	m_dumper = dumper;

	if(duration_seconds > 0 && file_limit > 0)
	{
		m_past_names = new string[file_limit];
		
		for(int32_t j = 0; j < file_limit; j++)
		{
			m_past_names[j] = "";
		}
	}

	//
	// Seed the filename with an initial
	// value.
	//
	consider(NULL);
	return true;
}

// 
// consider a certain number of bytes given the parameters
// passed in through setup.  Consider will recommend one 
// of the following:
//
//  * SAMEFILE - use the same file
//  * NEWFILE - use a new file (inquiry with get_current_file_name())
//  * DOQUIT - end the capture.
//
cycle_writer::conclusion cycle_writer::consider(sinsp_evt* evt) 
{
	if(m_first_consider == false) 
	{
		m_first_consider = true;
	}

	if(evt == NULL)	// First run
	{
		if(!live && m_duration_seconds > 0 && m_base_file_name.find("%") != string::npos)	// Here's the fuckin' bug
			m_last_file_name = "first_dump.scap";
		else
		{
			if(live) m_last_time = time(NULL);
			next_file();
		}
		return NEWFILE;
	}
	
	m_event_count++;

	if(m_duration_seconds > 0) 
	{
		//
		// If this is our first consideration, 
		// we set the timer up.
		// 
		if(m_last_time == 0) 
		{
			m_last_time = evt->get_ts() / 1000000000; // 10^(-9) because it's nanoseconds
		}

		if((int)difftime(evt->get_ts() / 1000000000, m_last_time) >= m_duration_seconds) 
		{
			m_last_time = evt->get_ts() / 1000000000;
			m_last_reason = "Maximum Time Reached";
			return next_file();
		}
	}

	if(m_rollover_mb > 0 && scap_dump_get_offset(*m_dumper) > m_rollover_mb)
	{
		m_last_reason = "Maximum File Size Reached";
		return next_file();
	}

	// Event limit
	if(m_event_limit > 0 && m_event_count >= m_event_limit)
	{
		m_event_count = 0L;
		m_last_reason = "Maximum Event Number Reached";
		return next_file();
	}

	//
	// This is for any routine which restricts 
	// execution after an initial consider()
	//
	/*if(m_first_consider == false) 
	{
		m_first_consider = true;

		// We need to generate an initial file name
		// but still continue our logic.
		next_file();
	}*/

	return SAMEFILE;
}

string cycle_writer::get_current_file_name() 
{
	return m_last_file_name;
}

//
// next_file doesn't return the file pointer
// instead it returns advice on whether a new
// file should be used or not.
//
// If it advices a new file, then the new file
// name advised can be found in the
// get_current_file_name() routine.
//
cycle_writer::conclusion cycle_writer::next_file() 
{
	if (m_file_limit > 0 && m_file_index >= m_file_limit) 
	{
		m_file_index = 0;
	}
	

	if(m_duration_seconds > 0)
	{
		// if the user has specified a format then use it
		if(m_base_file_name.find("%") != string::npos)
		{
			const size_t our_size = 4096;
			size_t their_size;
			char file_name[our_size];
			const struct tm *our_time = localtime(&m_last_time);

			their_size = strftime(file_name, our_size, m_base_file_name.c_str(), our_time);

			if(their_size == 0) {/* TODO: if fail but as string size has been increased to 4096 it's very unlikely we get here */ }

			if(m_file_limit > 0)
			{
				if(m_past_names[m_file_index] != "")
				{
					remove(m_past_names[m_file_index].c_str());
				}

				m_past_names[m_file_index] = string(file_name);
			}

			m_last_file_name = file_name;
		}
		else	// if no format is provided, then use a counter
		{
			m_last_file_name = m_base_file_name + to_string(m_file_index);
		}
	} 
	else 
	{
		m_last_file_name = m_base_file_name; 
	}

	if(m_rollover_mb > 0)
	{

		if(m_limit_format[0] == 0) // I have no idea if this part is executed and, if so, if it works correctly
		{
			int digit_count = 0;
			int our_file_limit = m_file_limit;

			while(our_file_limit > 0) 
			{
				digit_count++;
				our_file_limit /= 10;
			}

			snprintf(
				// The format we are trying to derive
				m_limit_format,
				sizeof(m_limit_format),

				//
				// Read the string below like this:
				//
				// %05d
				//
				// Which is what we want.
				//
				"%%0%dd",

				digit_count
			);
		}	

		char index[22];

		snprintf(index, sizeof(index), m_limit_format, m_file_index);

		m_last_file_name += index;
	}

	if(m_event_limit > 0)
	{
		m_last_file_name = m_base_file_name + to_string(m_file_index);
	}

	m_file_count_total++;
	m_file_index++;

	return NEWFILE;
}
