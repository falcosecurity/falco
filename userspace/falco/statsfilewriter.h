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

#pragma once

#include <fstream>
#include <string>
#include <map>

#include <sinsp.h>

// Periodically collects scap stats files and writes them to a file as
// json.

class StatsFileWriter {
public:
	StatsFileWriter();
	virtual ~StatsFileWriter();

	// Returns success as bool. On false fills in errstr.
	bool init(sinsp *inspector, std::string &filename,
		  uint32_t interval_msec,
		  string &errstr);

	// Should be called often (like for each event in a sinsp
	// loop).
	void handle();

protected:
	uint32_t m_num_stats;
	sinsp *m_inspector;
	std::ofstream m_output;
	std::string m_extra;
	scap_stats m_last_stats;
};
