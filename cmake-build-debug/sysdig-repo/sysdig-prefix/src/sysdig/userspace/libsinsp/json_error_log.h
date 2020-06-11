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
#pragma once

#include <string>
#include <map>

#include "token_bucket.h"

class json_error_log
{
public:

	json_error_log();
	virtual ~json_error_log();

	// Upon any json parsing error, write the error and json
	// document that had the error to this file. Not enabled by
	// default.
	void set_json_parse_errors_file(const std::string& filename);

	void set_events_rate(double events_rate, uint32_t max_burst);

	// Possibly log a json parsing error, depending on whether or
	// not the above filename was set.
	void log(const std::string &json, const std::string &errstr, uint64_t ts_ns, const std::string &uri);

	void set_machine_id(const std::string& machine_id);

private:

	// Return a token bucket limiting errors related to the
	// configured uri, creating it if necessary.
	token_bucket &get_bucket(const std::string &uri);

	std::string m_json_parse_errors_file;
	std::string m_machine_id;
	double m_events_rate;
	uint32_t m_events_max_burst;

	// Rate-limit json parse error events by uri.
	std::map<std::string,token_bucket> m_buckets;
};

inline void json_error_log::set_machine_id(const std::string& machine_id)
{
	m_machine_id = machine_id;
}

extern json_error_log g_json_error_log;

