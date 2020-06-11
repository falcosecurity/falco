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
//
// json_parser.h
//
// jq wrapper
//

#ifdef __linux__

#include "json_query.h"
#include "sinsp.h"

json_query::json_query(const std::string& json, const std::string& filter, bool dbg) :
	m_jq(jq_init()), m_input{0}, m_result{0}, m_processed(false)
{
	if(!m_jq) { cleanup(); }
	process(json, filter, dbg);
}

json_query::~json_query()
{
	cleanup();
}

bool json_query::process(const std::string& json, const std::string& filter, bool dbg)
{
	cleanup(m_input);
	cleanup(m_result);
	clear();

	if(!m_jq) { cleanup(); }
	if(!jq_compile(m_jq, filter.c_str()))
	{
		m_error = "Filter parsing failed.";
		return false;
	}

	m_input = jv_parse/*_sized*/(json.c_str()/*, json.length()*/);
	if (!jv_is_valid(m_input))
	{
		cleanup(m_input, "JSON parse error.");
		return false;
	}

	jq_start(m_jq, m_input, dbg ? JQ_DEBUG_TRACE : 0);
	m_input = jv_null(); // jq_start() freed it
	m_result = jq_next(m_jq);
	if (!jv_is_valid(m_result))
	{
		cleanup(m_result, "json_query filtering result invalid.");
		return false;
	}
	m_json = json;
	m_filter = filter;
	return m_processed = true;
}

const std::string& json_query::result(int flags)
{
	if(m_processed)
	{
		static const std::string ret;
		if(!m_error.empty()) { return ret; }
		char* buf;
		size_t len;
		FILE* f = open_memstream(&buf, &len);
		if(f == NULL)
		{
			m_error = "Can't open memory stream for writing.";
			return ret;
		}
		jv_dumpf(m_result, f, flags);
		m_result = jv_null();
		clear();
		fclose (f);
		m_filtered_json.assign(buf, len);
		free (buf);
		m_processed = false;
	}
	return m_filtered_json;
}

void json_query::clear()
{
	m_result = jv_null();
	m_input = jv_null();
	m_filtered_json.clear();
	m_error.clear();
	m_processed = false;
}

void json_query::cleanup()
{
	if(m_jq)
	{
		cleanup(m_input);
		cleanup(m_result);
		clear();
		jq_teardown(&m_jq);
		m_jq = 0;
	}
	else
	{
		throw std::runtime_error("json_query handle is null.");
	}
}

void json_query::cleanup(jv& j, const std::string& msg)
{
	if(j.u.ptr)
	{
		jv_free(j);
		j = jv_null();
	}
	m_error = msg;
}

#endif // __linux__
