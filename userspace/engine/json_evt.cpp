/*
Copyright (C) 2019 The Falco Authors.

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

json_event_value::json_event_value(int64_t val) :
	m_type(JT_INT64),
	m_intval(val)
{
}

json_event_value::param_type json_event_value::ptype() const
{
	return m_type;
}

std::string json_event_value::as_string() const
{
	switch(m_type)
	{
	case JT_STRING:
		return m_stringval;
		break;
	case JT_INT64:
		return std::to_string(m_intval);
		break;
	case JT_INT64_PAIR:
		return std::to_string(m_pairval.first) + ":" + std::to_string(m_pairval.second);
		break;
	default:
		return json_event_filter_check::no_value;
	}
}

// This operator allows for somewhat-flexible comparisons between
// numeric values and ranges. A numeric value and range are considered
// "equal" if the value falls within the range. Otherwise, the value
// types must match and be equal.

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
	else if(m_type == JT_INT64_PAIR &&
		val.m_type == JT_INT64)
	{
		return (val.m_intval >= m_pairval.first &&
			val.m_intval <= m_pairval.second);
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

bool json_event_value::operator!=(const json_event_value &val) const
{
	return !operator==(val);
}

// This operator allows for somewhat-flexible comparisons between
// numeric values and ranges, or two ranges, and allows for ordering
// values in a set. In practice, a set of values will all have the
// same type, but it will be possible to check for set membership
// between a value and a set of ranges.
//
// A numeric value is less than a range if the value is below the
// lower part of the range. A range A is less than another range B if
// the beginning of A is less than the beginning of B. If A and B
// start at the same value, then the end of the ranges are used
// instead.
//
// For other types, the values are simply compared and for mixed
// types, the event types are considered.
//
bool json_event_value::operator<(const json_event_value &val) const
{
	if(m_type == JT_INT64 &&
	   val.m_type == JT_INT64_PAIR)
	{
		return (m_intval < val.m_pairval.first);
	}
	else if(m_type == JT_INT64_PAIR &&
		val.m_type == JT_INT64)
	{
		return (m_pairval.second < val.m_intval);
	}
	else if(m_type != val.m_type)
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

// See operator< for details. The only thing that changes is the
// comparisons for numeric value and range, or two ranges.
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
	std::string str = as_string();
	std::string valstr = val.as_string();

	return (str.compare(0, valstr.size(), valstr) == 0);
}

bool json_event_value::contains(const json_event_value &val) const
{
	std::string str = as_string();
	std::string valstr = val.as_string();

	return (str.find(valstr) != string::npos);
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
std::vector<std::string> json_event_filter_check::s_index_mode_strs = {"IDX_REQUIRED", "IDX_ALLOWED", "IDX_NONE"};
std::vector<std::string> json_event_filter_check::s_index_type_strs = {"IDX_KEY", "IDX_NUMERIC"};

bool json_event_filter_check::def_extract(const nlohmann::json &root,
					  const std::list<nlohmann::json::json_pointer> &ptrs,
					  std::list<nlohmann::json::json_pointer>::iterator it)
{
	if(it == ptrs.end())
	{
		add_extracted_value(json_as_string(root));
		return true;
	}

	try {
		const json &j = root.at(*it);

		if(j.is_array())
		{
			for(auto &item : j)
			{
				if(!def_extract(item, ptrs, std::next(it, 1)))
				{
					return false;
				}
			}
		}
		else
		{
			add_extracted_value(json_as_string(j));
		}
	}
	catch(json::out_of_range &e)
	{
		return false;
	}

	return true;
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
	m_idx_type(IDX_NUMERIC),
	m_uses_paths(false)
{
}

json_event_filter_check::field_info::field_info(std::string name,
						std::string desc):
	m_name(name),
	m_desc(desc),
	m_idx_mode(IDX_NONE),
	m_idx_type(IDX_NUMERIC),
	m_uses_paths(false)
{
}

json_event_filter_check::field_info::field_info(std::string name,
						std::string desc,
						index_mode mode):
	m_name(name),
	m_desc(desc),
	m_idx_mode(mode),
	m_idx_type(IDX_NUMERIC),
	m_uses_paths(false)
{
}

json_event_filter_check::field_info::field_info(std::string name,
						std::string desc,
						index_mode mode,
						index_type itype):
	m_name(name),
	m_desc(desc),
	m_idx_mode(mode),
	m_idx_type(itype),
	m_uses_paths(false)
{
}

json_event_filter_check::field_info::field_info(std::string name,
						std::string desc,
						index_mode mode,
						index_type itype,
						bool uses_paths):
	m_name(name),
	m_desc(desc),
	m_idx_mode(mode),
	m_idx_type(itype),
	m_uses_paths(uses_paths)
{
}

json_event_filter_check::field_info::~field_info()
{
}

json_event_filter_check::alias::alias()
{
}

json_event_filter_check::alias::alias(std::list<nlohmann::json::json_pointer> ptrs) :
	m_jptrs(ptrs)
{
}

json_event_filter_check::alias::alias(extract_t extract) :
	m_extract(extract)
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

		m_uses_paths = info.m_uses_paths;

		auto &al = m_aliases[info.m_name];

		// What follows the match must not be alphanumeric or a dot
		if(strncmp(info.m_name.c_str(), str, info.m_name.size()) == 0 &&
		   !isalnum((int)str[info.m_name.size()]) &&
		   str[info.m_name.size()] != '.' &&
		   info.m_name.size() > match_len)
		{
			m_jptrs = al.m_jptrs;
			m_field = info.m_name;

			if(al.m_extract)
			{
				m_extract = al.m_extract;
			}
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
	m_values.insert(string(str));
}

const json_event_filter_check::values_t &json_event_filter_check::extracted_values()
{
	return m_evalues.first;
}

bool json_event_filter_check::compare(gen_event *evt)
{
	json_event *jevt = (json_event *)evt;

	uint32_t len;

	const extracted_values_t *evalues = (const extracted_values_t *) extract(jevt, &len);
	values_set_t setvals;

	switch(m_cmpop)
	{
	case CO_EQ:
		return evalues->second == m_values;
		break;
	case CO_NE:
		return evalues->second != m_values;
		break;
	case CO_STARTSWITH:
		return (evalues->first.size() == 1 &&
			m_values.size() == 1 &&
			evalues->first.at(0).startswith(*(m_values.begin())));
		break;
	case CO_CONTAINS:
		return (evalues->first.size() == 1 &&
			m_values.size() == 1 &&
			evalues->first.at(0).contains(*(m_values.begin())));
		break;
	case CO_IN:
		for(auto &item : evalues->second)
		{
			if(m_values.find(item) == m_values.end())
			{
				return false;
			}
		}
		return true;
		break;
	case CO_PMATCH:
		for(auto &item : evalues->second)
		{
			if(item.as_string() != no_value)
			{
				if(!m_prefix_search.match(item.as_string().c_str()))
				{
					return false;
				}
			}
		}
		return true;
		break;
	case CO_INTERSECTS:
		std::set_intersection(evalues->second.begin(), evalues->second.end(),
				      m_values.begin(), m_values.end(),
				      std::inserter(setvals, setvals.begin()));
		return (setvals.size() > 0);
		break;
	case CO_LT:
		return (evalues->first.size() == 1 &&
			m_values.size() == 1 &&
			evalues->first.at(0).ptype() == m_values.begin()->ptype() &&
			evalues->first.at(0) < *(m_values.begin()));
		break;
	case CO_LE:
		return (evalues->first.size() == 1 &&
			m_values.size() == 1 &&
			evalues->first.at(0).ptype() == m_values.begin()->ptype() &&
			(evalues->first.at(0) < *(m_values.begin()) ||
			 evalues->first.at(0) == *(m_values.begin())));
	case CO_GT:
		return (evalues->first.size() == 1 &&
			m_values.size() == 1 &&
			evalues->first.at(0).ptype() == m_values.begin()->ptype() &&
			evalues->first.at(0) > *(m_values.begin()));
	case CO_GE:
		return (evalues->first.size() == 1 &&
			m_values.size() == 1 &&
			evalues->first.at(0).ptype() == m_values.begin()->ptype() &&
			(evalues->first.at(0) > *(m_values.begin()) ||
			 evalues->first.at(0) == *(m_values.begin())));
		break;
	case CO_EXISTS:
		return (evalues->first.size() == 1 &&
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

void json_event_filter_check::add_extracted_value(const std::string &str)
{
	m_evalues.first.emplace_back(json_event_value(str));
	m_evalues.second.emplace(json_event_value(str));

	if(m_uses_paths)
	{
		m_prefix_search.add_search_path(str);
	}
}

void json_event_filter_check::add_extracted_value_num(int64_t val)
{
	m_evalues.first.emplace_back(json_event_value(val));
	m_evalues.second.emplace(json_event_value(val));
}

uint8_t *json_event_filter_check::extract(gen_event *evt, uint32_t *len, bool sanitize_strings)
{
	m_evalues.first.clear();
	m_evalues.second.clear();

	if (!extract_values((json_event *) evt))
	{
		m_evalues.first.clear();
		m_evalues.second.clear();
		add_extracted_value(no_value);
	}

	*len = sizeof(m_evalues);
	return (uint8_t *)&m_evalues;
}

bool json_event_filter_check::extract_values(json_event *jevt)
{
	try
	{
		if(m_extract)
		{
			if(!m_extract(jevt->jevt(), *this))
			{
				return false;
			}
		}
		else
		{
			if (!def_extract(jevt->jevt(), m_jptrs, m_jptrs.begin()))
			{
				return false;
			}

			if(! m_idx.empty())
			{
				// The default only knows how to index by numeric indices
				try {
					std::string::size_type ptr;
					std::string::size_type idx_num = std::stoll(m_idx, &ptr);

					if(ptr != m_idx.length())
					{
						return false;
					}

					if(idx_num >= m_evalues.first.size())
					{
						return false;
					}

					values_t new_values;
					new_values.push_back(m_evalues.first.at(idx_num));
					m_evalues.first = new_values;
				}
				catch (std::invalid_argument &e)
				{
					return false;
				}
			}
		}
	}
	catch(json::out_of_range &e)
	{
		return false;
	}

	return true;
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
		  "",
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
			m_idx = string(str + (s_jevt_value_field.size() + 1), (end - str - (s_jevt_value_field.size() + 1)));
			m_idx_ptr = json::json_pointer(m_idx);
		}
		catch(json::parse_error &e)
		{
			throw falco_exception(string("Could not parse filtercheck field \"") + str + "\". Invalid json selector (" + e.what() + ")");
		}

		m_field = s_jevt_value_field;

		// The +1 accounts for the closing ']'
		return (end - str + 1);
	}

	return 0;
}

bool jevt_filter_check::extract_values(json_event *jevt)
{
	std::string tstr;

	if(m_field == s_jevt_rawtime_field)
	{
		tstr = to_string(jevt->get_ts());
	}
	else if(m_field == s_jevt_time_field)
	{
		sinsp_utils::ts_to_string(jevt->get_ts(), &tstr, false, true);
	}
	else if(m_field == s_jevt_time_iso_8601_field)
	{
		sinsp_utils::ts_to_iso_8601(jevt->get_ts(), &tstr);
	}
	else if(m_field == s_jevt_obj_field)
	{
		tstr = jevt->jevt().dump();
	}
	else if (m_field == s_jevt_value_field)
	{
		try {
			const json &j = jevt->jevt().at(m_idx_ptr);
			tstr = json_as_string(j);
		}
		catch(json::out_of_range &e)
		{
			return false;
		}
	}
	else
	{
		return false;
	}

	add_extracted_value(tstr);
	return true;
}

json_event_filter_check *jevt_filter_check::allocate_new()
{
	jevt_filter_check *chk = new jevt_filter_check();

	return (json_event_filter_check *)chk;
}

bool k8s_audit_filter_check::extract_images(const json &j,
					    json_event_filter_check &jchk)
{
	static json::json_pointer containers_ptr = "/requestObject/spec/containers"_json_pointer;

	try
	{
		const json &containers = j.at(containers_ptr);

		for(auto &container : containers)
		{
			std::string image = container.at("image");

			// If the filtercheck ends with .repository, we want only the
			// repo name from the image.
			std::string suffix = ".repository";
			if(suffix.size() <= jchk.field().size() &&
			   std::equal(suffix.rbegin(), suffix.rend(), jchk.field().rbegin()))
			{
				std::string hostname, port, name, tag, digest;

				sinsp_utils::split_container_image(image,
								   hostname,
								   port,
								   name,
								   tag,
								   digest,
								   false);
				jchk.add_extracted_value(name);
			}
			else
			{
				jchk.add_extracted_value(image);
			}
		}
	}
	catch(json::out_of_range &e)
	{
		return false;
	}

	return true;
}

bool k8s_audit_filter_check::extract_query_param(const nlohmann::json &j,
						 json_event_filter_check &jchk)
{
	static json::json_pointer request_uri_ptr = "/requestURI"_json_pointer;

	string uri;
	std::vector<std::string> uri_parts, query_parts;

	try {
		uri = j.at(request_uri_ptr);
	}
	catch(json::out_of_range &e)
	{
		return false;
	}

	uri_parts = sinsp_split(uri, '?');

	if(uri_parts.size() != 2)
	{
		return false;
	}

	query_parts = sinsp_split(uri_parts[1], '&');

	for(auto &part : query_parts)
	{
		std::vector<std::string> param_parts = sinsp_split(part, '=');

		if(param_parts.size() == 2 && uri::decode(param_parts[0], true) == jchk.idx())
		{
			jchk.add_extracted_value(param_parts[1]);
			return true;
		}
	}

	return false;
}


bool k8s_audit_filter_check::extract_rule_attrs(const json &j,
						json_event_filter_check &jchk)
{
	static json::json_pointer rules_ptr = "/requestObject/rules"_json_pointer;

	// Use the suffix of the field to determine which property to
	// select from each object.
	std::string prop = jchk.field().substr(jchk.field().find_last_of(".") + 1);

	try
	{
		const json &rules = j.at(rules_ptr);

		for (auto &rule : rules)
		{
			if(rule.find(prop) != rule.end())
			{
				for (auto &item : rule.at(prop))
				{
					jchk.add_extracted_value(json_as_string(item));
				}
			}
		}
	}
	catch(json::out_of_range &e)
	{
		return false;
	}

	return true;
}

bool k8s_audit_filter_check::extract_volume_types(const json &j,
						  json_event_filter_check &jchk)
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
					jchk.add_extracted_value(it.key());
				}
			}
		}
	}
	catch(json::out_of_range &e)
	{
		return false;
	}

	return true;
}

bool k8s_audit_filter_check::extract_host_port(const json &j,
					       json_event_filter_check &jchk)
{
	static json::json_pointer containers_ptr = "/requestObject/spec/containers"_json_pointer;

	try {
		const json &containers = j.at(containers_ptr);

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
					jchk.add_extracted_value(json_as_string(cport.at("hostPort")));
				}
				else if (cport.find("containerPort") != cport.end())
				{
					// When hostNetwork is true, this will match the host port.
					jchk.add_extracted_value(json_as_string(cport.at("containerPort")));
				}
			}
		}
	}
	catch(json::out_of_range &e)
	{
		return false;
	}

	return true;
}

bool k8s_audit_filter_check::extract_effective_run_as(const json &j,
						      json_event_filter_check &jchk)
{
	static json::json_pointer spec_ptr = "/requestObject/spec"_json_pointer;
	static json::json_pointer containers_ptr = "/containers"_json_pointer;
	static json::json_pointer run_as_user_ptr = "/securityContext/runAsUser"_json_pointer;
	static json::json_pointer run_as_group_ptr = "/securityContext/runAsGroup"_json_pointer;

	try {
		const json &spec = j.at(spec_ptr);

		int64_t pod_id;

		if(jchk.field() == "ka.req.pod.containers.eff_run_as_user")
		{
			pod_id = spec.value(run_as_user_ptr, 0);
		}
		else
		{
			pod_id = spec.value(run_as_group_ptr, 0);
		}

		const json &containers = spec.at(containers_ptr);

		for(auto container : containers)
		{
			int64_t container_id;

			if(jchk.field() == "ka.req.pod.containers.eff_run_as_user")
			{
				container_id = container.value(run_as_user_ptr, pod_id);
			}
			else
			{
				container_id = container.value(run_as_group_ptr, pod_id);
			}

			jchk.add_extracted_value_num(container_id);
		}
	}
	catch(json::out_of_range &e)
	{
		return false;
	}

	return true;
}

k8s_audit_filter_check::k8s_audit_filter_check()
{
	m_info = {"ka",
		  "Access K8s Audit Log Events",
		  "Fields with an IDX_ALLOWED annotation can be indexed (e.g. ka.req.containers.image[k] returns the image for the kth container). The index is optional--without any index the field returns values for all items. The index must be numeric with an IDX_NUMERIC annotation, and can be any string with an IDX_KEY annotation. Fields with an IDX_REQUIRED annotation require an index.",
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
		   {"ka.req.pod.containers.image", "When the request object refers to a pod, the container's images.", IDX_ALLOWED, IDX_NUMERIC},
		   {"ka.req.pod.containers.image.repository", "The same as req.container.image, but only the repository part (e.g. sysdig/falco).", IDX_ALLOWED, IDX_NUMERIC},
		   {"ka.req.pod.host_ipc", "When the request object refers to a pod, the value of the hostIPC flag."},
		   {"ka.req.pod.host_network", "When the request object refers to a pod, the value of the hostNetwork flag."},
		   {"ka.req.pod.host_pid", "When the request object refers to a pod, the value of the hostPID flag."},
		   {"ka.req.pod.containers.host_port", "When the request object refers to a pod, all container's hostPort values.", IDX_ALLOWED, IDX_NUMERIC},
		   {"ka.req.pod.containers.privileged", "When the request object refers to a pod, the value of the privileged flag for all containers.", IDX_ALLOWED, IDX_NUMERIC},
		   {"ka.req.pod.containers.allow_privilege_escalation", "When the request object refers to a pod, the value of the allowPrivilegeEscalation flag for all containers", IDX_ALLOWED, IDX_NUMERIC},
		   {"ka.req.pod.containers.read_only_fs", "When the request object refers to a pod, the value of the readOnlyRootFilesystem flag for all containers", IDX_ALLOWED, IDX_NUMERIC},
		   {"ka.req.pod.run_as_user", "When the request object refers to a pod, the runAsUser uid specified in the security context for the pod. See ....containers.run_as_user for the runAsUser for individual containers"},
		   {"ka.req.pod.containers.run_as_user", "When the request object refers to a pod, the runAsUser uid for all containers", IDX_ALLOWED, IDX_NUMERIC},
		   {"ka.req.pod.containers.eff_run_as_user", "When the request object refers to a pod, the initial uid that will be used for all containers. This combines information from both the pod and container security contexts and uses 0 if no uid is specified", IDX_ALLOWED, IDX_NUMERIC},
		   {"ka.req.pod.run_as_group", "When the request object refers to a pod, the runAsGroup gid specified in the security context for the pod. See ....containers.run_as_group for the runAsGroup for individual containers"},
		   {"ka.req.pod.containers.run_as_group", "When the request object refers to a pod, the runAsGroup gid for all containers", IDX_ALLOWED, IDX_NUMERIC},
		   {"ka.req.pod.containers.eff_run_as_group", "When the request object refers to a pod, the initial gid that will be used for all containers. This combines information from both the pod and container security contexts and uses 0 if no gid is specified", IDX_ALLOWED, IDX_NUMERIC},
		   {"ka.req.pod.containers.proc_mount", "When the request object refers to a pod, the procMount types for all containers", IDX_ALLOWED, IDX_NUMERIC},
		   {"ka.req.role.rules", "When the request object refers to a role/cluster role, the rules associated with the role"},
		   {"ka.req.role.rules.apiGroups", "When the request object refers to a role/cluster role, the api groups associated with the role's rules", IDX_ALLOWED, IDX_NUMERIC},
		   {"ka.req.role.rules.nonResourceURLs", "When the request object refers to a role/cluster role, the non resource urls associated with the role's rules", IDX_ALLOWED, IDX_NUMERIC},
		   {"ka.req.role.rules.verbs", "When the request object refers to a role/cluster role, the verbs associated with the role's rules", IDX_ALLOWED, IDX_NUMERIC},
		   {"ka.req.role.rules.resources", "When the request object refers to a role/cluster role, the resources associated with the role's rules", IDX_ALLOWED, IDX_NUMERIC},
		   {"ka.req.pod.fs_group", "When the request object refers to a pod, the fsGroup gid specified by the security context."},
		   {"ka.req.pod.supplemental_groups", "When the request object refers to a pod, the supplementalGroup gids specified by the security context."},
		   {"ka.req.pod.containers.add_capabilities", "When the request object refers to a pod, all capabilities to add when running the container.", IDX_ALLOWED, IDX_NUMERIC},
		   {"ka.req.service.type", "When the request object refers to a service, the service type"},
		   {"ka.req.service.ports", "When the request object refers to a service, the service's ports", IDX_ALLOWED, IDX_NUMERIC},
		   {"ka.req.pod.volumes.hostpath", "When the request object refers to a pod, all hostPath paths specified for all volumes", IDX_ALLOWED, IDX_NUMERIC, true},
		   {"ka.req.pod.volumes.flexvolume_driver", "When the request object refers to a pod, all flexvolume drivers specified for all volumes", IDX_ALLOWED, IDX_NUMERIC},
		   {"ka.req.pod.volumes.volume_type", "When the request object refers to a pod, all volume types for all volumes", IDX_ALLOWED, IDX_NUMERIC},
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
			{"ka.uri.param", {extract_query_param}},
			{"ka.target.name", {{"/objectRef/name"_json_pointer}}},
			{"ka.target.namespace", {{"/objectRef/namespace"_json_pointer}}},
			{"ka.target.resource", {{"/objectRef/resource"_json_pointer}}},
			{"ka.target.subresource", {{"/objectRef/subresource"_json_pointer}}},
			{"ka.req.binding.subjects", {{"/requestObject/subjects"_json_pointer}}},
			{"ka.req.binding.role", {{"/requestObject/roleRef/name"_json_pointer}}},
			{"ka.req.configmap.name", {{"/objectRef/name"_json_pointer}}},
			{"ka.req.configmap.obj", {{"/requestObject/data"_json_pointer}}},
			{"ka.req.pod.containers.image", {extract_images}},
			{"ka.req.pod.containers.image.repository", {extract_images}},
			{"ka.req.pod.host_ipc", {{"/requestObject/spec/hostIPC"_json_pointer}}},
			{"ka.req.pod.host_network", {{"/requestObject/spec/hostNetwork"_json_pointer}}},
			{"ka.req.pod.host_pid", {{"/requestObject/spec/hostPID"_json_pointer}}},
			{"ka.req.pod.containers.host_port", {extract_host_port}},
			{"ka.req.pod.containers.privileged", {{"/requestObject/spec/containers"_json_pointer, "/securityContext/privileged"_json_pointer}}},
			{"ka.req.pod.containers.allow_privilege_escalation", {{"/requestObject/spec/containers"_json_pointer, "/securityContext/allowPrivilegeEscalation"_json_pointer}}},
			{"ka.req.pod.containers.read_only_fs", {{"/requestObject/spec/containers"_json_pointer, "/securityContext/readOnlyRootFilesystem"_json_pointer}}},
			{"ka.req.pod.run_as_user", {{"/requestObject/spec/securityContext/runAsUser"_json_pointer}}},
			{"ka.req.pod.containers.run_as_user", {{"/requestObject/spec/containers"_json_pointer, "/securityContext/runAsGroup"_json_pointer}}},
			{"ka.req.pod.containers.eff_run_as_user", {extract_effective_run_as}},
			{"ka.req.pod.run_as_group", {{"/requestObject/spec/securityContext/runAsGroup"_json_pointer}}},
			{"ka.req.pod.containers.run_as_group", {{"/requestObject/spec/containers"_json_pointer, "/securityContext/runAsGroup"_json_pointer}}},
			{"ka.req.pod.containers.eff_run_as_group", {extract_effective_run_as}},
			{"ka.req.pod.containers.proc_mount", {{"/requestObject/spec/containers"_json_pointer, "/securityContext/procMount"_json_pointer}}},
			{"ka.req.role.rules", {{"/requestObject/rules"_json_pointer}}},
			{"ka.req.role.rules.apiGroups", {extract_rule_attrs}},
			{"ka.req.role.rules.nonResourceURLs", {extract_rule_attrs}},
			{"ka.req.role.rules.verbs", {extract_rule_attrs}},
			{"ka.req.role.rules.resources", {extract_rule_attrs}},
			{"ka.req.pod.fs_group", {{"/requestObject/spec/securityContext/fsGroup"_json_pointer}}},
			{"ka.req.pod.supplemental_groups", {{"/requestObject/spec/securityContext/supplementalGroups"_json_pointer}}},
			{"ka.req.pod.containers.add_capabilities", {{"/requestObject/spec/containers"_json_pointer, "/securityContext/capabilities/add"_json_pointer}}},
			{"ka.req.service.type", {{"/requestObject/spec/type"_json_pointer}}},
			{"ka.req.service.ports", {{"/requestObject/spec/ports"_json_pointer}}},
                        {"ka.req.pod.volumes.hostpath", {{"/requestObject/spec/volumes"_json_pointer, "/hostPath/path"_json_pointer}}},
			{"ka.req.pod.volumes.flexvolume_driver", {{"/requestObject/spec/volumes"_json_pointer, "/flexVolume/driver"_json_pointer}}},
			{"ka.req.pod.volumes.volume_type", {extract_volume_types}},
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
	// todo(leodido, fntlnz) > assign tomap() result to ret (implicit conversion using = operator)

	std::list<std::pair<std::string, std::string>> resolved;

	resolve_tokens(ev, resolved);

	for(auto &res : resolved)
	{
		// Only include the fields and not the raw text blocks.
		if(!res.first.empty())
		{
			// todo(leodido, fntlnz) > do we want "<NA>" rather than empty res.second values?
			ret[res.first] = res.second;
		}
	}

	return ret.dump();
}

std::map<std::string, std::string> json_event_formatter::tomap(json_event *ev)
{
	std::map<std::string, std::string> ret;
	std::list<std::pair<std::string, std::string>> res;

	resolve_tokens(ev, res);

	for(auto &r : res)
	{
		// Only include the fields and not the raw text blocks.
		if(!r.first.empty())
		{
			if(r.second.empty())
			{
				r.second = "<NA>";
			}
			ret.insert(r);
		}
	}

	return ret;
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
			uint32_t len;

			(void) tok.check->extract(ev, &len);

			const json_event_filter_check::values_t &evals =
				tok.check->extracted_values();

			std::string res_str = json_event_filter_check::no_value;
			if(evals.size() == 1)
			{
				res_str = evals.at(0).as_string();
			}
			else if (evals.size() > 1)
			{
				res_str = "(";
				for(auto &val : evals)
				{
					if(res_str != "(")
					{
						res_str += ",";
					}
					res_str += val.as_string();
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
