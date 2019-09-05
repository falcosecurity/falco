/*
Copyright (C) 2018 Draios inc.

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

#include <ctype.h>

#include "uri.h"
#include "utils.h"

#include "falco_common.h"
#include "json_evt.h"

using json = nlohmann::json;
using namespace std;

json_event::json_event()
{
}

json_event::~json_event()
{
}

void json_event::set_jevt(json &evt, uint64_t ts)
{
	m_jevt = evt;
	m_event_ts = ts;
}

const json &json_event::jevt()
{
	return m_jevt;
}

uint64_t json_event::get_ts()
{
	return m_event_ts;
}

json_event_value::json_event_value()
{
}

json_event_value::~json_event_value()
{
}

json_event_value::json_event_value(const std::string &val)
{
	if(parse_as_pair_int64(m_pairval, val))
	{
		m_type = JT_INT64_PAIR;
	}
	else if (parse_as_int64(m_intval, val))
	{
		m_type = JT_INT64;
	}
	else
	{
		m_stringval = val;
		m_type = JT_STRING;
	}
}

bool json_event_value::operator==(const json_event_value &val) const
{
	// A JT_INT64 can be compared to a JT_INT64_PAIR. The value
	// must be within the range specified by the pair.
	if(m_type == JT_INT64 &&
	   val.m_type == JT_INT64_PAIR)
	{
		return (m_intval >= val.m_pairval.first &&
			m_intval <= val.m_pairval.second);
	}
	else if(m_type != val.m_type)
	{
		return false;
	}

	switch(m_type)
	{
	case JT_STRING:
		return (m_stringval == val.m_stringval);
		break;
	case JT_INT64:
		return (m_intval == val.m_intval);
		break;
	case JT_INT64_PAIR:
		return (m_pairval == val.m_pairval);
		break;
	default:
		return false;
	}
}

bool json_event_value::operator<(const json_event_value &val) const
{
	// This shouldn't be called when the types differ, but just in
	// case, use m_type for initial ordering.
	if(m_type != val.m_type)
	{
		return (m_type < val.m_type);
	}

	switch(m_type)
	{
	case JT_STRING:
		return (m_stringval < val.m_stringval);
		break;
	case JT_INT64:
		return (m_intval < val.m_intval);
		break;
	case JT_INT64_PAIR:
		if(m_pairval.first != val.m_pairval.first)
		{
			return (m_pairval.first < val.m_pairval.first);
		}
		else
		{
			return (m_pairval.second < val.m_pairval.second);
		}
		break;
	default:
		return false;
	}
}

bool json_event_value::operator>(const json_event_value &val) const
{
	// This shouldn't be called when the types differ, but just in
	// case, use m_type for initial ordering.
	if(m_type != val.m_type)
	{
		return (m_type < val.m_type);
	}

	switch(m_type)
	{
	case JT_STRING:
		return (m_stringval > val.m_stringval);
		break;
	case JT_INT64:
		return (m_intval > val.m_intval);
		break;
	case JT_INT64_PAIR:
		if(m_pairval.first != val.m_pairval.first)
		{
			return (m_pairval.first > val.m_pairval.first);
		}
		else
		{
			return (m_pairval.second > val.m_pairval.second);
		}
		break;
	default:
		return false;
	}
}

bool json_event_value::startswith(const json_event_value &val) const
{
	if(m_type == JT_STRING &&
	   val.m_type == JT_STRING)
	{
		return m_stringval.compare(0, val.m_stringval.size(), val.m_stringval);
	}

	return false;
}

bool json_event_value::parse_as_pair_int64(std::pair<int64_t,int64_t> &pairval, const std::string &val)
{
	size_t pos = val.find_first_of(':');
	if(pos != std::string::npos &&
	   json_event_value::parse_as_int64(pairval.first, val.substr(0, pos)) &&
	   json_event_value::parse_as_int64(pairval.second, val.substr(pos+1)))
	{
		return true;
	}

	return false;
}

bool json_event_value::parse_as_int64(int64_t &intval, const std::string &val)
{
	try {
		std::string::size_type ptr;

		intval = std::stoll(val, &ptr);

		if(ptr != val.length())
		{
			return false;
		}
	}
	catch (std::invalid_argument &e)
	{
		return false;
	}

	return true;
}

std::string json_event_filter_check::no_value = "<NA>";

// XXX/mstemm fix this
bool json_event_filter_check::def_extract(const nlohmann::json &root,
					  json_event_filter_check::values_t values,
					  const std::list<nlohmann::json::json_pointer> &ptrs,
					  std::list<nlohmann::json::json_pointer>::iterator &it)
{
	try {
		const json &j = root.at(*it);

		if(root.is_array())
		{
			for(auto &item : root)
			{
				values.emplace_back(json_as_string(item));
			}
		}
		else
		{
			values.emplace_back(json_as_string(root));
		}
	}
	else
	{
		try {


			if(j.is_array())
			{
				for(auto &item : root)
				{
					if(!def_extract(item, values, ptrs, ++it))
					{
						return false;
					}
				}
				else
				{

					if(!def_extract(j, values, ptrs, ++it))
				{
					return false;
					values.clear();
					values.push_back(json_event_filter_check::no_value);
					return false;
				}
			}
			catch(json::out_of_range &e)
			{
				values.clear();
				values.push_back(json_event_filter_check::no_value);
				return false;
			}
		}
	}

	return true;
}

void json_event_filter_check::def_index(json_event_filter_check::values_t &values, std::string &idx)
{
	// The default index function only knows how to index by numeric values
	uint64_t idx_num = (idx.empty() ? 0 : stoi(idx));

	values_t new_values;

	if(idx_num < values.size())
	{
		new_values.emplace_back(values.at(idx_num));
	}
	else
	{
		new_values.emplace_back(json_event_filter_check::no_value);
	}

	values = new_values;
}

std::string json_event_filter_check::json_as_string(const json &j)
{
	if(j.type() == json::value_t::string)
	{
		return j;
	}
	else
	{
		return j.dump();
	}
}

json_event_filter_check::field_info::field_info():
	m_idx_mode(IDX_NONE),
	m_idx_type(IDX_NUMERIC)
{
}

json_event_filter_check::field_info::field_info(std::string name,
						std::string desc):
	m_name(name),
	m_desc(desc),
	m_idx_mode(IDX_NONE),
	m_idx_type(IDX_NUMERIC)
{
}

json_event_filter_check::field_info::field_info(std::string name,
						std::string desc,
						index_mode mode):
	m_name(name),
	m_desc(desc),
	m_idx_mode(mode),
	m_idx_type(IDX_NUMERIC)
{
}

json_event_filter_check::field_info::field_info(std::string name,
						std::string desc,
						index_mode mode,
						index_type itype):
	m_name(name),
	m_desc(desc),
	m_idx_mode(mode),
	m_idx_type(itype)
{
}

json_event_filter_check::field_info::~field_info()
{
}

json_event_filter_check::alias::alias()
{
}

json_event_filter_check::alias::alias(std::list<nlohmann::json::json_pointer> &ptrs) :
	m_jptrs(ptrs)
{
}

json_event_filter_check::alias::alias(std::list<nlohmann::json::json_pointer> &ptrs,
				      index_t index) :
	m_jptrs(ptrs),
	m_index(index)
{
}

json_event_filter_check::alias::alias(extract_t extract) :
	m_extract(extract)
{
}

json_event_filter_check::alias::alias(extract_t extract,
				      index_t index) :

	m_extract(extract),
	m_index(index)
{
}

json_event_filter_check::alias::~alias()
{
}

json_event_filter_check::json_event_filter_check()
{
}

json_event_filter_check::~json_event_filter_check()
{
}

int32_t json_event_filter_check::parse_field_name(const char *str, bool alloc_state, bool needed_for_filtering)
{
	// Look for the longest match amongst the aliases. str is not
	// necessarily terminated on a filtercheck boundary.
	size_t match_len = 0;

	size_t idx_len = 0;

	for(auto &info : m_info.m_fields)
	{
		if(m_aliases.find(info.m_name) == m_aliases.end())
		{
			throw falco_exception("Could not find alias for field name " + info.m_name);
		}

		auto &al = m_aliases[info.m_name];

		// What follows the match must not be alphanumeric or a dot
		if(strncmp(info.m_name.c_str(), str, info.m_name.size()) == 0 &&
		   !isalnum((int)str[info.m_name.size()]) &&
		   str[info.m_name.size()] != '.' &&
		   info.m_name.size() > match_len)
		{
			m_jptrs = al.m_jptrs;
			m_field = info.m_name;
			if(al.m_index)
			{
				m_index = al.m_index;
			}
			if(al.m_extract)
			{
				m_extract = al.m_extract;
			}
			m_type = al.m_type;
			match_len = info.m_name.size();

			const char *start = str + m_field.size();

			// Check for an optional index
			if(*start == '[')
			{
				start++;
				const char *end = strchr(start, ']');

				if(end != NULL)
				{
					m_idx = string(start, end - start);
				}

				idx_len = (end - start + 2);
			}

			if(m_idx.empty() && info.m_idx_mode == IDX_REQUIRED)
			{
				throw falco_exception(string("When parsing filtercheck ") + string(str) + string(": ") + m_field + string(" requires an index but none provided"));
			}

			if(!m_idx.empty() && info.m_idx_mode == IDX_NONE)
			{
				throw falco_exception(string("When parsing filtercheck ") + string(str) + string(": ") + m_field + string(" forbids an index but one provided"));
			}

			if(!m_idx.empty() &&
			   info.m_idx_type == IDX_NUMERIC &&
			   m_idx.find_first_not_of("0123456789") != string::npos)
			{
				throw falco_exception(string("When parsing filtercheck ") + string(str) + string(": ") + m_field + string(" requires a numeric index"));
			}
		}
	}

	return match_len + idx_len;
}

void json_event_filter_check::add_filter_value(const char *str, uint32_t len, uint32_t i)
{
	m_values.push_back(string(str));
}

bool json_event_filter_check::compare(gen_event *evt)
{
	json_event *jevt = (json_event *)evt;

	const extracted_values_t *evalues = extract(jevt);
	values_list_t::iterator it;
	values_list_t itvals;

	switch(m_cmpop)
	{
	case CO_EQ:
		return evalues->second == m_values;
		break;
	case CO_NE:
		return evalues->second != m_values;
		break;
	case CO_CONTAINS:
		it = std::set_intersection(evalues->second.begin(), evalues->second.end(),
					   m_values.begin(), m_values.end());
		itvals.resize(it-itvals.begin());

		return (itvals.size() == m_values.size());
		break;
	case CO_STARTSWITH:
		return (evalues->first.size() == 1 &&
			m_values.size() == 1 &&
			evalues->first.at(0).startswith(m_values[0]));
		break;
	case CO_IN:
		it = std::set_intersection(evalues->second.begin(), evalues->second.end(),
					   m_values.begin(), m_values.end());
		itvals.resize(it-itvals.begin());

		return (itvals.size() == evalues->second.size());
		break;
	case CO_INTERSECTS:
		it = std::set_intersection(evalues->second.begin(), evalues->second.end(),
					   m_values.begin(), m_values.end());
		itvals.resize(it-itvals.begin());

		return (itvals.size() > 0);
		break;
	case CO_LT:
		return (evalues->first.size() == 1 &&
			m_values.size() == 1 &&
			evalues->first.at(0).m_type == m_values.at(0).m_type &&
			evalues->first.at(0) < m_values.at(0));
		break;
	case CO_LE:
		return (evalues->first.size() == 1 &&
			m_values.size() == 1 &&
			evalues->first.at(0).m_type == m_values.at(0).m_type &&
			(evalues->first.at(0) < m_values.at(0) ||
			 evalues->first.at(0) == m_values.at(0)));
	case CO_GT:
		return (evalues->first.size() == 1 &&
			m_values.size() == 1 &&
			evalues->first.at(0).m_type == m_values.at(0).m_type &&
			evalues->first.at(0) > m_values.at(0));
	case CO_GE:
		return (evalues->first.size() == 1 &&
			m_values.size() == 1 &&
			evalues->first.at(0).m_type == m_values.at(0).m_type &&
			(evalues->first.at(0) > m_values.at(0) ||
			 evalues->first.at(0) == m_values.at(0)));
		break;
	case CO_EXISTS:
		return (evalues->size() == 1 &&
			(evalues->first.at(0) != json_event_filter_check::no_value));
		break;
	default:
		throw falco_exception("filter error: unsupported comparison operator");
	}
}

const std::string &json_event_filter_check::field()
{
	return m_field;
}

const std::string &json_event_filter_check::idx()
{
	return m_idx;
}

size_t json_event_filter_check::parsed_size()
{
	if(m_idx.empty())
	{
		return m_field.size();
	}
	else
	{
		return m_field.size() + m_idx.size() + 2;
	}
}

json_event_filter_check::check_info &json_event_filter_check::get_fields()
{
	return m_info;
}

uint8_t *json_event_filter_check::extract(gen_event *evt, uint32_t *len, bool sanitize_strings)
{
	json_event *jevt = (json_event *)evt;

	try
	{
		if(m_extract)
		{
			m_evalues.first = m_extract(j, m_field);
		}
		else
		{
			m_evalues.first = def_extract(j, m_jptrs, m_jptrs.begin());
		}

		if(! m_idx.empty())
		{
			if(m_index)
			{
				m_evalues.first = m_index(m_evalues.first, m_field, m_idx);
			}
			else
			{
				m_evalues.first = def_index(m_evalues.first, m_idx);
			}
		}

		// Now populate the values set with the distinct
		// values from the vector
		for(auto &str : m_evalues.first)
		{
			m_evalues.second.insert(str);
		}
	}
	catch(json::out_of_range &e)
	{
		m_evalues.first.push_back(json_event_filter_check::no_value);
		m_evalues.second.insert(json_event_filter_check::no_value);
	}

	*len = sizeof(m_evalues);

	return (uint8_t *)&m_evalues;
}

std::string jevt_filter_check::s_jevt_time_field = "jevt.time";
std::string jevt_filter_check::s_jevt_time_iso_8601_field = "jevt.time.iso8601";
std::string jevt_filter_check::s_jevt_rawtime_field = "jevt.rawtime";
std::string jevt_filter_check::s_jevt_value_field = "jevt.value";
std::string jevt_filter_check::s_jevt_obj_field = "jevt.obj";

jevt_filter_check::jevt_filter_check()
{
	m_info = {"jevt",
		  "generic ways to access json events",
		  {{s_jevt_time_field, "json event timestamp as a string that includes the nanosecond part"},
		   {s_jevt_time_iso_8601_field, "json event timestamp in ISO 8601 format, including nanoseconds and time zone offset (in UTC)"},
		   {s_jevt_rawtime_field, "absolute event timestamp, i.e. nanoseconds from epoch."},
		   {s_jevt_value_field, "General way to access single property from json object. The syntax is [<json pointer expression>]. The property is returned as a string", IDX_REQUIRED, IDX_KEY},
		   {s_jevt_obj_field, "The entire json object, stringified"}}};
}

jevt_filter_check::~jevt_filter_check()
{
}

int32_t jevt_filter_check::parse_field_name(const char *str, bool alloc_state, bool needed_for_filtering)
{
	if(strncmp(s_jevt_time_iso_8601_field.c_str(), str, s_jevt_time_iso_8601_field.size()) == 0)
	{
		m_field = s_jevt_time_iso_8601_field;
		return s_jevt_time_iso_8601_field.size();
	}

	if(strncmp(s_jevt_time_field.c_str(), str, s_jevt_time_field.size()) == 0)
	{
		m_field = s_jevt_time_field;
		return s_jevt_time_field.size();
	}

	if(strncmp(s_jevt_rawtime_field.c_str(), str, s_jevt_rawtime_field.size()) == 0)
	{
		m_field = s_jevt_rawtime_field;
		return s_jevt_rawtime_field.size();
	}

	if(strncmp(s_jevt_obj_field.c_str(), str, s_jevt_obj_field.size()) == 0)
	{
		m_field = s_jevt_obj_field;
		return s_jevt_obj_field.size();
	}

	if(strncmp(s_jevt_value_field.c_str(), str, s_jevt_value_field.size()) == 0)
	{
		const char *end;

		// What follows must be [<json pointer expression>]
		if(*(str + s_jevt_value_field.size()) != '[' ||
		   ((end = strchr(str + 1, ']')) == NULL))

		{
			throw falco_exception(string("Could not parse filtercheck field \"") + str + "\". Did not have expected format with 'jevt.value[<json pointer>]'");
		}

		try
		{
			m_jptr = json::json_pointer(string(str + (s_jevt_value_field.size() + 1), (end - str - (s_jevt_value_field.size() + 1))));
		}
		catch(json::parse_error &e)
		{
			throw falco_exception(string("Could not parse filtercheck field \"") + str + "\". Invalid json selector (" + e.what() + ")");
		}

		// The +1 accounts for the closing ']'
		m_field = string(str, end - str + 1);
		return (end - str + 1);
	}

	return 0;
}

uint8_t *jevt_filter_check::extract(gen_event *evt, uint32_t *len, bool sanitize_stings)
{
	if(m_field == s_jevt_rawtime_field)
	{
		m_tstr = to_string(evt->get_ts());
		*len = m_tstr.size();
		return (uint8_t *)m_tstr.c_str();
	}
	else if(m_field == s_jevt_time_field)
	{
		sinsp_utils::ts_to_string(evt->get_ts(), &m_tstr, false, true);
		*len = m_tstr.size();
		return (uint8_t *)m_tstr.c_str();
	}
	else if(m_field == s_jevt_time_iso_8601_field)
	{
		sinsp_utils::ts_to_iso_8601(evt->get_ts(), &m_tstr);
		*len = m_tstr.size();
		return (uint8_t *)m_tstr.c_str();
	}
	else if(m_field == s_jevt_obj_field)
	{
		json_event *jevt = (json_event *)evt;
		m_tstr = jevt->jevt().dump();
		*len = m_tstr.size();
		return (uint8_t *)m_tstr.c_str();
	}

	return json_event_filter_check::extract(evt, len, sanitize_stings);
}

json_event_filter_check *jevt_filter_check::allocate_new()
{
	jevt_filter_check *chk = new jevt_filter_check();

	return (json_event_filter_check *)chk;
}

void k8s_audit_filter_check::extract_images(const json &j,
					    json_event_filter_check::values_t &values,
					    std::string &field)
{
	static json::json_pointer containers_ptr = "/requestObject/spec/containers"_json_pointer;

	try
	{
		const json containers = j.at(containers_ptr);

		for(auto &spec : containers)
		{
			std::string image = j.at("image");

			// If the filtercheck ends with .repository, we want only the
			// repo name from the image.
			std::string suffix = ".repository";
			if(suffix.size() <= field.size() &&
			   std::equal(suffix.rbegin(), suffix.rend(), field.rbegin()))
			{
				std::string hostname, port, name, tag, digest;

				sinsp_utils::split_container_image(image,
								   hostname,
								   port,
								   name,
								   tag,
								   digest,
								   false);
				values.push_back(name);
			}
			else
			{
				values.push_back(image);
			}
		}
	}
	catch(json::out_of_range &e)
	{
		values.clear();
		values.push_back(json_event_filter_check::no_value);
	}
}

void k8s_audit_filter_check::extract_query_params(const nlohmann::json &j,
						  json_event_filter_check::values_t &values,
						  std::string &field)
{
	static json::json_pointer request_uri_ptr = "/requestURI"_json_pointer;

	try {
		string uri = j.at(request_uri_ptr);

		std::vector<std::string> uri_parts, query_parts;

		uri_parts = sinsp_split(uri, '?');

		if(uri_parts.size() != 2)
		{
			values.push_back(json_event_filter_check::no_value);
			return;
		}

		query_parts = sinsp_split(uri_parts[1], '&');

		for(auto &part : query_parts)
		{
			values.push_back(part);
		}

	}
	catch(json::out_of_range &e)
	{
		values.clear();
		values.push_back(json_event_filter_check::no_value);
	}
}


void k8s_audit_filter_check::extract_rule_attrs(const json &j,
						json_event_filter_check::values_t &values,
						std::string &field)
{
	static json::json_pointer rules_ptr = "/requestObject/rules"_json_pointer;

	// Use the suffix of the field to determine which property to
	// select from each object.
	std::string prop = field.substr(field.find_last_of(".") + 1);

	try
	{
		const json rules = j.at(rules_ptr);

		values.push_back(rules.at(prop));
	}
	catch(json::out_of_range &e)
	{
		values.clear();
		values.push_back(json_event_filter_check::no_value);
	}
}

void k8s_audit_filter_check::extract_volume_types(const json &j,
						  json_event_filter_check::values_t &values,
						  std::string &field)
{
	static json::json_pointer volumes_ptr = "/requestObject/spec/volumes"_json_pointer;

	try {

		const nlohmann::json &vols = j.at(volumes_ptr);

		for(auto &vol : vols)
		{
			for (auto it = vol.begin(); it != vol.end(); ++it)
			{
				// Any key other than "name" represents a volume type
				if(it.key() != "name")
				{
					values.push_back(it.key());
				}
			}
		}
	}
	catch(json::out_of_range &e)
	{
		values.clear();
		values.push_back(json_event_filter_check::no_value);
	}
}

void k8s_audit_filter_check::extract_host_port(const json &j,
					       json_event_filter_check::values_t &values,
					       std::string &field)
{
	static json::json_pointer containers_ptr = "/requestObject/spec/containers"_json_pointer;

	try {
		const json containers = j.at(containers_ptr);

		for(auto &container : containers)
		{
			if(container.find("ports") == container.end())
			{
				continue;
			}

			nlohmann::json ports = container["ports"];

			for(auto &cport : ports)
			{
				if(cport.find("hostPort") != cport.end())
				{
					values.emplace_back(cport.at("hostPort"));
				}
				else if (cport.find("containerPort") != cport.end())
				{
					// When hostNetwork is true, this will match the host port.
					values.emplace_back(cport.at("containerPort"));
				}
			}
		}
	}
	catch(json::out_of_range &e)
	{
		values.clear();
		values.push_back(json_event_filter_check::no_value);
	}
}

void k8s_audit_filter_check::index_query_param(values_t &values,
					       std::string &field,
					       std::string &idx)
{
	values_t new_values;

	for(auto &str : values)
	{
		std::vector<std::string> param_parts = sinsp_split(str, '=');

		if(param_parts.size() == 2 && uri::decode(param_parts[0], true) == idx)
		{
			new_values.push_back(param_parts[1]);
			values = new_values;
			return;
		}
	}

	new_values.push_back(no_value);
	values = new_values;
}

k8s_audit_filter_check::k8s_audit_filter_check()
{
	m_info = {"ka",
		  "Access K8s Audit Log Events",
		  {{"ka.auditid", "The unique id of the audit event"},
		   {"ka.stage", "Stage of the request (e.g. RequestReceived, ResponseComplete, etc.)"},
		   {"ka.auth.decision", "The authorization decision"},
		   {"ka.auth.reason", "The authorization reason"},
		   {"ka.user.name", "The user name performing the request"},
		   {"ka.user.groups", "The groups to which the user belongs"},
		   {"ka.impuser.name", "The impersonated user name"},
		   {"ka.verb", "The action being performed"},
		   {"ka.uri", "The request URI as sent from client to server"},
		   {"ka.uri.param", "The value of a given query parameter in the uri (e.g. when uri=/foo?key=val, ka.uri.param[key] is val).", IDX_REQUIRED, IDX_KEY},
		   {"ka.target.name", "The target object name"},
		   {"ka.target.namespace", "The target object namespace"},
		   {"ka.target.resource", "The target object resource"},
		   {"ka.target.subresource", "The target object subresource"},
		   {"ka.req.binding.subjects", "When the request object refers to a cluster role binding, the subject (e.g. account/users) being linked by the binding"},
		   {"ka.req.binding.role", "When the request object refers to a cluster role binding, the role being linked by the binding"},
		   {"ka.req.configmap.name", "If the request object refers to a configmap, the configmap name"},
		   {"ka.req.configmap.obj", "If the request object refers to a configmap, the entire configmap object"},
		   {"ka.req.container.image", "When the request object refers to a container, the container's images. Can be indexed (e.g. ka.req.container.image[0]). Without any index, returns all images for all containers", IDX_ALLOWED, IDX_NUMERIC},
		   {"ka.req.container.image.repository", "The same as req.container.image, but only the repository part (e.g. sysdig/falco)", IDX_ALLOWED, IDX_NUMERIC},
		   {"ka.req.container.host_ipc", "When the request object refers to a container, the value of the hostIPC flag."},
		   {"ka.req.container.host_network", "When the request object refers to a container, the value of the hostNetwork flag."},
		   {"ka.req.container.host_pid", "When the request object refers to a container, the value of the hostPID flag."},
		   {"ka.req.container.host_port", "When the request object refers to a container, the container's hostPort values.  Can be indexed (e.g. ka.req.container.host_port[0]). Without any index, returns all hostPort values for all containers", IDX_ALLOWED, IDX_NUMERIC},
		   {"ka.req.container.privileged", "When the request object refers to a container, whether or not any container is run privileged. With an index, return whether or not the ith container is run privileged.", IDX_ALLOWED, IDX_NUMERIC},
		   {"ka.req.container.allow_privilege_escalation", "When the request object refers to a container, whether or not any container has allowPrivilegeEscalation=true. With an index, return whether or not the ith container has allowPrivilegeEscalation=true.", IDX_ALLOWED, IDX_NUMERIC},
		   {"ka.req.container.read_write_fs", "When the request object refers to a container, whether or not any container is missing a readOnlyRootFilesystem annotation. With an index, return whether or not the ith container is missing a readOnlyRootFilesystem annotation.", IDX_ALLOWED, IDX_NUMERIC},
		   {"ka.req.container.run_as_user", "When the request object refers to a container, the user id that will be used for the container's entrypoint. Both the security context's runAsUser and the container's runAsUser are considered, with the security context taking precedence, and defaulting to uid 0 if neither are specified. With an index, return the uid for the ith container. With no index, returns the uids for all containers", IDX_ALLOWED, IDX_NUMERIC},
		   {"ka.req.container.run_as_group", "When the request object refers to a container, the group id that will be used for the container's entrypoint. Both the security context's runAsGroup and the container's runAsGroup are considered, with the security context taking precedence, and defaulting to gid 0 if neither are specified. With an index, return the gid for the ith container. With no index, returns the gid for first container", IDX_ALLOWED, IDX_NUMERIC},
		   {"ka.req.role.rules", "When the request object refers to a role/cluster role, the rules associated with the role"},
		   {"ka.req.role.rules.apiGroups", "When the request object refers to a role/cluster role, the api groups associated with the role's rules. With an index, return only the api groups from the ith rule. Without an index, return all api groups concatenated", IDX_ALLOWED, IDX_NUMERIC},
		   {"ka.req.role.rules.nonResourceURLs", "When the request object refers to a role/cluster role, the non resource urls associated with the role's rules. With an index, return only the non resource urls from the ith rule. Without an index, return all non resource urls concatenated", IDX_ALLOWED, IDX_NUMERIC},
		   {"ka.req.role.rules.verbs", "When the request object refers to a role/cluster role, the verbs associated with the role's rules. With an index, return only the verbs from the ith rule. Without an index, return all verbs concatenated", IDX_ALLOWED, IDX_NUMERIC},
		   {"ka.req.role.rules.resources", "When the request object refers to a role/cluster role, the resources associated with the role's rules. With an index, return only the resources from the ith rule. Without an index, return all resources concatenated", IDX_ALLOWED, IDX_NUMERIC},
		   {"ka.req.sec_ctx.fs_group", "When the request object refers to a pod, the fsGroup gid specified by the security context."},
		   {"ka.req.sec_ctx.supplemental_groups", "When the request object refers to a pod, the supplementalGroup gids specified by the security context."},
		   {"ka.req.sec_ctx.added_capabilities", "When the request object refers to a pod, all capabilities to add when running the container."},
		   {"ka.req.service.type", "When the request object refers to a service, the service type"},
		   {"ka.req.service.ports", "When the request object refers to a service, the service's ports. Can be indexed (e.g. ka.req.service.ports[0]). Without any index, returns all ports", IDX_ALLOWED, IDX_NUMERIC},
		   {"ka.req.volume.hostpath", "All hostPath paths specified for all volume types", IDX_REQUIRED, IDX_KEY},
		   {"ka.req.volume.flexvolume_drivers", "When the request object refers to a pod, all flexvolume drivers used by volumes created with the pod"},
		   {"ka.req.volume.volume_types", "When the request object refers to a pod, all volume types used by volumes created with the pod"},
		   {"ka.resp.name", "The response object name"},
		   {"ka.response.code", "The response code"},
		   {"ka.response.reason", "The response reason (usually present only for failures)"},
		   {"ka.useragent", "The useragent of the client who made the request to the apiserver"}}};

	{
		m_aliases = {
			{"ka.auditid", {{"/auditID"_json_pointer}}},
			{"ka.stage", {{"/stage"_json_pointer}}},
			{"ka.auth.decision", {{"/annotations/authorization.k8s.io~1decision"_json_pointer}}},
			{"ka.auth.reason", {{"/annotations/authorization.k8s.io~1reason"_json_pointer}}},
			{"ka.user.name", {{"/user/username"_json_pointer}}},
			{"ka.user.groups", {{"/user/groups"_json_pointer}}},
			{"ka.impuser.name", {{"/impersonatedUser/username"_json_pointer}}},
			{"ka.verb", {{"/verb"_json_pointer}}},
			{"ka.uri", {{"/requestURI"_json_pointer}}},
			{"ka.uri.param", {extract_query_params, index_query_param}},
			{"ka.target.name", {{"/objectRef/name"_json_pointer}}},
			{"ka.target.namespace", {{"/objectRef/namespace"_json_pointer}}},
			{"ka.target.resource", {{"/objectRef/resource"_json_pointer}}},
			{"ka.target.subresource", {{"/objectRef/subresource"_json_pointer}}},
			{"ka.req.binding.subjects", {{"/requestObject/subjects"_json_pointer}}},
			{"ka.req.binding.role", {{"/requestObject/roleRef/name"_json_pointer}}},
			{"ka.req.configmap.name", {{"/objectRef/name"_json_pointer}}},
			{"ka.req.configmap.obj", {{"/requestObject/data"_json_pointer}}},
			{"ka.req.container.image", {extract_images}},
			{"ka.req.container.image.repository", {extract_images}},
			{"ka.req.container.host_ipc", {{"/requestObject/spec/hostIPC"_json_pointer}}},
			{"ka.req.container.host_network", {{"/requestObject/spec/hostNetwork"_json_pointer}}},
			{"ka.req.container.host_pid", {{"/requestObject/spec/hostPID"_json_pointer}}},
			{"ka.req.container.host_port", {extract_host_port}},
			{"ka.req.container.privileged", {{"/requestObject/spec/containers"_json_pointer, "/securityContext/privileged"_json_pointer}}},
			{"ka.req.container.allow_privilege_escalation", {{"/requestObject/spec/containers"_json_pointer, "/securityContext/allowPrivilegeEscalation"_json_pointer}}},
			{"ka.req.container.read_write_fs", {{"/requestObject/spec/containers"_json_pointer, "/securityContext/readOnlyRootFilesystem"_json_pointer}}},
			{"ka.req.container.run_as_user", {{"/requestObject/spec"_json_pointer, "/securityContext/runAsUser"_json_pointer}}},
			{"ka.req.container.run_as_group", {{"/requestObject/spec"_json_pointer, "/securityContext/runAsGroup"_json_pointer}}},
			{"ka.req.container.proc_mount", {{"/requestObject/spec/containers"_json_pointer, "/securityContext/procMount"_json_pointer}}},
			{"ka.req.role.rules", {{"/requestObject/rules"_json_pointer}}},
			{"ka.req.role.rules.apiGroups", {extract_rule_attrs}},
			{"ka.req.role.rules.nonResourceURLs", {extract_rule_attrs}},
			{"ka.req.role.rules.verbs", {extract_rule_attrs}},
			{"ka.req.role.rules.resources", {extract_rule_attrs}},
			{"ka.req.sec_ctx.fs_group", {{"/requestObject/spec/securityContext/fsGroup"_json_pointer}}},
			{"ka.req.sec_ctx.supplemental_groups", {{"/requestObject/spec/securityContext/supplementalGroups"_json_pointer}}},
			{"ka.req.sec_ctx.added_capabilities", {{"/requestObject/spec/containers"_json_pointer, "/securityContext/capabilities/add"_json_pointer}}},
			{"ka.req.service.type", {{"/requestObject/spec/type"_json_pointer}}},
			{"ka.req.service.ports", {{"/requestObject/spec/ports"_json_pointer}}},
                        {"ka.req.volume.hostpath", {{"/requestObject/spec"_json_pointer, "/volumes"_json_pointer, "/hostPath"_json_pointer}}},
			{"ka.req.volume.flexvolume_drivers", {{"/requestObject/spec"_json_pointer, "/volumes"_json_pointer, "/flexVolume/driver"_json_pointer}}},
			{"ka.req.volume_types", {extract_volume_types}},
			{"ka.resp.name", {{"/responseObject/metadata/name"_json_pointer}}},
			{"ka.response.code", {{"/responseStatus/code"_json_pointer}}},
			{"ka.response.reason", {{"/responseStatus/reason"_json_pointer}}},
			{"ka.useragent", {{"/userAgent"_json_pointer}}}};
	}
}

k8s_audit_filter_check::~k8s_audit_filter_check()
{
}

json_event_filter_check *k8s_audit_filter_check::allocate_new()
{
	k8s_audit_filter_check *chk = new k8s_audit_filter_check();

	return (json_event_filter_check *)chk;
}

json_event_filter::json_event_filter()
{
}

json_event_filter::~json_event_filter()
{
}

json_event_filter_factory::json_event_filter_factory()
{
	m_defined_checks.push_back(shared_ptr<json_event_filter_check>(new jevt_filter_check()));
	m_defined_checks.push_back(shared_ptr<json_event_filter_check>(new k8s_audit_filter_check()));

	for(auto &chk : m_defined_checks)
	{
		m_info.push_back(chk->get_fields());
	}
}

json_event_filter_factory::~json_event_filter_factory()
{
}

gen_event_filter *json_event_filter_factory::new_filter()
{
	return new json_event_filter();
}

gen_event_filter_check *json_event_filter_factory::new_filtercheck(const char *fldname)
{
	for(auto &chk : m_defined_checks)
	{
		json_event_filter_check *newchk = chk->allocate_new();

		int32_t parsed = newchk->parse_field_name(fldname, false, true);

		if(parsed > 0)
		{
			return newchk;
		}

		delete newchk;
	}

	return NULL;
}

std::list<json_event_filter_check::check_info> &json_event_filter_factory::get_fields()
{
	return m_info;
}

json_event_formatter::json_event_formatter(json_event_filter_factory &json_factory, std::string &format):
	m_format(format),
	m_json_factory(json_factory)
{
	parse_format();
}

json_event_formatter::~json_event_formatter()
{
}

std::string json_event_formatter::tostring(json_event *ev)
{
	std::string ret;

	std::list<std::pair<std::string, std::string>> resolved;

	resolve_tokens(ev, resolved);

	for(auto &res : resolved)
	{
		ret += res.second;
	}

	return ret;
}

std::string json_event_formatter::tojson(json_event *ev)
{
	nlohmann::json ret;

	std::list<std::pair<std::string, std::string>> resolved;

	resolve_tokens(ev, resolved);

	for(auto &res : resolved)
	{
		// Only include the fields and not the raw text blocks.
		if(!res.first.empty())
		{
			ret[res.first] = res.second;
		}
	}

	return ret.dump();
}

void json_event_formatter::parse_format()
{
	string tformat = m_format;

	// Remove any leading '*' if present
	if(tformat.front() == '*')
	{
		tformat.erase(0, 1);
	}

	while(tformat.size() > 0)
	{
		size_t size;
		struct fmt_token tok;

		if(tformat.front() == '%')
		{
			// Skip the %
			tformat.erase(0, 1);
			json_event_filter_check *chk = (json_event_filter_check *)m_json_factory.new_filtercheck(tformat.c_str());

			if(!chk)
			{
				throw falco_exception(string("Could not parse format string \"") + m_format + "\": unknown filtercheck field " + tformat);
			}

			size = chk->parsed_size();
			tok.check.reset(chk);
		}
		else
		{
			size = tformat.find_first_of("%");
			if(size == string::npos)
			{
				size = tformat.size();
			}
		}

		if(size == 0)
		{
			// Empty fields are only allowed at the beginning of the string
			if(m_tokens.size() > 0)
			{
				throw falco_exception(string("Could not parse format string \"" + m_format + "\": empty filtercheck field"));
			}
			continue;
		}

		tok.text = tformat.substr(0, size);
		m_tokens.push_back(tok);

		tformat.erase(0, size);
	}
}

void json_event_formatter::resolve_tokens(json_event *ev, std::list<std::pair<std::string, std::string>> &resolved)
{
	for(auto tok : m_tokens)
	{
		if(tok.check)
		{
			const json_event_filter_check::extracted_values_t *evals = tok.check->extract(ev);

			std::string res_str = json_event_filter_check::no_value;
			if(evals->first.size() == 1)
			{
				res_str = evals->first.at(0);
			}
			else if (evals->first.size() > 1)
			{
				res_str = "(";
				for(auto &val : evals->first)
				{
					if(res_str != "(")
					{
						res_str += ",";
					}
					res_str += val;
				}
				res_str += ")";
			}

			resolved.push_back(std::make_pair(tok.check->field(), res_str));
		}
		else
		{
			resolved.push_back(std::make_pair("", tok.text));
		}
	}
}
