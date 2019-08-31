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

std::string json_event_filter_check::no_value = "<NA>";

json_event_filter_check::values_t &def_extract(const nlohmann::json &, std::string &field)
{
	json_event_filter_check::values_t values;

	// Only add to evalues when the value was actually found in
	// the object.
	if(j.is_array())
	{
		for(auto &item : j)
		{
			values.push_back(json_as_string(j));
		}
	}
	else
	{
		values.push_back(json_as_string(j));
	}

	return values;
}

json_event_filter_check::values_t &json_event_filter_check::def_index(const values_t &values, std::string &field, std::string &idx)
{
	// The default index function only knows how to index by numeric values
	uint64_t idx_num = (idx.empty() ? 0 : stoi(idx));

	values_t new_values;

	if(idx_num < values.size())
	{
		new_values.push_back(values.at(idx));
	}
	else
	{
		new_values.push_back(json_event_filter_check::no_value);
	}

	return new_values;
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
	m_idx_mode(IDX_NONE), m_idx_type(IDX_NUMERIC)
{
}

json_event_filter_check::field_info::field_info(std::string name,
						std::string desc):
	m_name(name),
	m_desc(desc),
	m_idx_mode(IDX_NONE), m_idx_type(IDX_NUMERIC)
{
}

json_event_filter_check::field_info::field_info(std::string name,
						std::string desc,
						index_mode mode):
	m_name(name),
	m_desc(desc),
	m_idx_mode(mode), m_idx_type(IDX_NUMERIC)
{
}

json_event_filter_check::field_info::field_info(std::string name,
						std::string desc,
						index_mode mode,
						index_type itype):
	m_name(name),
	m_desc(desc),
	m_idx_mode(mode), m_idx_type(itype)
{
}

json_event_filter_check::field_info::~field_info()
{
}

json_event_filter_check::alias::alias()
{
}

json_event_filter_check::alias::alias(nlohmann::json::json_pointer ptr):
	m_jptr(ptr),
	m_extract(def_extract),
	m_index(def_index)
{
}

json_event_filter_check::alias::alias(nlohmann::json::json_pointer ptr,
				      extract_t extract)
	m_jptr(ptr),
	m_extract(extract),
	m_index(def_index)
{
}

json_event_filter_check::alias::alias(nlohmann::json::json_pointer ptr,
				      extract_t extract,
				      index_t index)
	m_jptr(ptr),
	m_extract(extract),
	m_index(index)
{
}

json_event_filter_check::alias::~alias()
{
}

json_event_filter_check::json_event_filter_check():
	m_extract(def_extract),
	m_index(def_index)
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
			m_jptr = al.m_jptr;
			m_field = info.m_name;
			m_format = al.m_format;
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

bool json_event_filter_check::compare_numeric(const std::string &value)
{
	try {
		int64_t nvalue = std::stoi(value);
		int64_t nval0 = std::stoi(m_values[0]);

		switch(m_cmpop)
		{
		case CO_LT:
			return (nvalue < nval0);
			break;
		case CO_LE:
			return (nvalue <= nval0);
			break;
		case CO_GT:
			return (nvalue > nval0);
			break;
		case CO_GE:
			return (nvalue >= nval0);
			break;
		default:
			return false;
		}
	}
	catch(std::invalid_argument &e)
	{
		return false;
	}
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
			evalues->first.compare(0, m_values[0].size(), m_values[0]) == 0);
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
	case CO_LE:
	case CO_GT:
	case CO_GE:
		return (evalues->first.size() == 1 &&
			m_values.size() == 1 &&
			compare_numeric(evalues->first.at(0)));
		return
		break;
	case CO_EXISTS:
		return (evalues->size() == 1 &&
			(evalues->first.at(0) != "" && evalues->first.at(0) != json_event_filter_check::no_value));
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
		const json &j = jevt->jevt().at(m_jptr);

		m_evalues.first = m_extract(j, m_field);

		if(! m_idx.empty())
		{
			m_evalues.first = m_index(m_evalues.first, m_field, m_idx);
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

json_event_filter_check::values_t &k8s_audit_filter_check::extract_images(const json &j, std::string &field)
{
	values_t vals;

	try
	{
		for(auto &spec : j)
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
				vals.push_back(name);
			}
			else
			{
				vals.push_back(image);
			}
		}
	}
	catch(json::out_of_range &e)
	{
		vals.clear();
		vals.push_back(json_event_filter_check::no_value);
	}

	return image;
}

json_event_filter_check::values_t &extract_query_params(const nlohmann::json &j, std::string &field)
{
	json_event_filter_check::values_t vals;

	string uri = j;
	std::vector<std::string> uri_parts, query_parts;

	uri_parts = sinsp_split(uri, '?');

	if(uri_parts.size() != 2)
	{
		vals.push_back(json_event_filter_check::no_value);
		return vals;
	}

	query_parts = sinsp_split(uri_parts[1], '&');

	for(auto &part : query_parts)
	{
		vals.push_back(part);
	}

	return vals;
}


json_event_filter_check::values_t & k8s_audit_filter_check::index_query_param(const values_t &values,
									      std::string &field,
									      std::string &idx)
{
	json_event_filter_check::values_t vals;

	for(auto &str : values)
	{
		std::vector<std::string> param_parts = sinsp_split(str, '=');

		if(param_parts.size() == 2 && uri::decode(param_parts[0], true) == idx)
		{
			vals.push_back(param_parts[1]);
			return vals;
		}
	}

	vals.push_back(no_value);
	return vals;
}

std::string k8s_audit_filter_check::index_generic(const json &j, std::string &field, std::string &idx)
{
	json item;

	if(idx.empty())
	{
		item = j;
	}
	else
	{
		uint64_t idx_num = (idx.empty() ? 0 : stoi(idx));

		try
		{
			item = j[idx_num];
		}
		catch(json::out_of_range &e)
		{
			return string(json_event_filter_check::no_value);
		}
	}

	return json_event_filter_check::json_as_string(item);
}

std::string k8s_audit_filter_check::index_select(const json &j, std::string &field, std::string &idx)
{
	json item;

	// Use the suffix of the field to determine which property to
	// select from each object.
	std::string prop = field.substr(field.find_last_of(".") + 1);

	std::string ret;

	if(idx.empty())
	{
		for(auto &obj : j)
		{
			if(ret != "")
			{
				ret += " ";
			}

			try
			{
				ret += json_event_filter_check::json_as_string(obj.at(prop));
			}
			catch(json::out_of_range &e)
			{
				ret += "N/A";
			}
		}
	}
	else
	{
		try
		{
			ret = j[stoi(idx)].at(prop);
		}
		catch(json::out_of_range &e)
		{
			ret = "N/A";
		}
	}

	return ret;
}

std::string k8s_audit_filter_check::index_privileged(const json &j, std::string &field, std::string &idx)
{
	nlohmann::json::json_pointer jpriv = "/securityContext/privileged"_json_pointer;

	return (array_get_bool_vals(j, jpriv, idx) ?
		string("true") :
		string("false"));
}

std::string k8s_audit_filter_check::index_allow_privilege_escalation(const json &j, std::string &field, std::string &idx)
{
	nlohmann::json::json_pointer jpriv = "/securityContext/allowPrivilegeEscalation"_json_pointer;

	return (array_get_bool_vals(j, jpriv, idx) ?
		string("true") :
		string("false"));
}

std::string k8s_audit_filter_check::index_read_write_fs(const json &j, std::string &field, std::string &idx)
{
	nlohmann::json::json_pointer jread_only = "/securityContext/readOnlyRootFilesystem"_json_pointer;

	bool read_write_fs = false;

	if(!idx.empty())
	{
		try {
			read_write_fs = !j[stoi(idx)].at(jread_only);
		}
		catch(json::out_of_range &e)
		{
			// If not specified, assume read/write
			read_write_fs = true;
		}
	}
	else
	{
		for(auto &container : j)
		{
			try {
				if(!container.at(jread_only))
				{
					read_write_fs = true;
				}
			}
			catch(json::out_of_range &e)
			{
				// If not specified, assume read/write
				read_write_fs = true;
			}
		}
	}

	return (read_write_fs ? string("true") : string("false"));
}

std::string k8s_audit_filter_check::index_has_run_as_user(const json &j, std::string &field, std::string &idx)
{
	static json::json_pointer run_as_user = "/securityContext/runAsUser"_json_pointer;

	try {
		auto val = j.at(run_as_user);

		// Would have thrown exception, so value exists
		return string("true");
	}
	catch(json::out_of_range &e)
	{
		// Continue to examining container array
	}

	try {
		for(auto &container : j.at("containers"))
		{
			try {
				auto val = container.at(run_as_user);

				// Would have thrown exception, so value exists
				return string("true");
			}
			catch(json::out_of_range &e)
			{
				// Try next container
			}
		}
	}
	catch(json::out_of_range &e)
	{
		// no containers, pass through
	}

	return string("false");
}

std::string k8s_audit_filter_check::index_run_as_user(const json &j, std::string &field, std::string &idx)
{
	static json::json_pointer run_as_user = "/securityContext/runAsUser"_json_pointer;

	// Prefer the security context over any container's runAsUser
	try {
		return j.at(run_as_user);
	}
	catch(json::out_of_range &e)
	{
		// Continue to per-container indexing
	}

	uint64_t uidx = 0;
	if(idx.empty())
	{
		try {
			uidx = stoi(idx);
		}
		catch(std::invalid_argument &e)
		{
			uidx = 0;
		}
	}

	try {
		return j.at("containers")[uidx].at(run_as_user);
	}
	catch(json::out_of_range &e)
	{
		return string("0");
	}
}

void k8s_audit_filter_check::get_all_run_as_users(const json &j, std::set<int64_t> &uids)
{
	uids.clear();

	static json::json_pointer run_as_user = "/securityContext/runAsUser"_json_pointer;

	// Prefer the security context over any container's runAsUser
	try {
		int64_t uid = j.at(run_as_user);
		uids.insert(uid);
		return;
	}
	catch(json::out_of_range &e)
	{
		// Continue to per-container indexing
	}

	try {
		for(auto &container : j.at("containers"))
		{
			try {
				int64_t uid = container.at(run_as_user);
				uids.insert(uid);
			}
			catch(json::out_of_range &e)
			{
				// This container has no runAsUser, assume 0
				uids.insert(0);
			}
		}
	}
	catch(json::out_of_range &e)
	{
		// No containers at all
		uids.insert(0);
	}
}

std::string k8s_audit_filter_check::check_run_as_user_within(const json &j, std::string &field, std::string &idx)
{
	std::list<std::pair<int64_t,int64_t>> allowed_uids;
	std::set<int64_t> all_run_as_users;

	if(!parse_value_ranges(idx, allowed_uids))
	{
		return string("false");
	}

	get_all_run_as_users(j, all_run_as_users);

	return (check_value_range_set(all_run_as_users, allowed_uids) ? string("true") : string("false"));
}

std::string k8s_audit_filter_check::check_run_as_user_any_within(const json &j, std::string &field, std::string &idx)
{
	std::list<std::pair<int64_t,int64_t>> allowed_uids;
	std::set<int64_t> all_run_as_users;

	if(!parse_value_ranges(idx, allowed_uids))
	{
		return string("false");
	}

	get_all_run_as_users(j, all_run_as_users);

	return (check_value_range_any_set(all_run_as_users, allowed_uids) ? string("true") : string("false"));
}

std::string k8s_audit_filter_check::index_has_run_as_group(const json &j, std::string &field, std::string &idx)
{
	static json::json_pointer run_as_group = "/securityContext/runAsGroup"_json_pointer;

	try {
		auto val = j.at(run_as_group);

		// Would have thrown exception, so value exists
		return string("true");
	}
	catch(json::out_of_range &e)
	{
		// Continue to examining container array
	}

	try {
		for(auto &container : j.at("containers"))
		{
			try {
				auto val = container.at(run_as_group);

				// Would have thrown exception, so value exists
				return string("true");
			}
			catch(json::out_of_range &e)
			{
				// Try next container
			}
		}
	}
	catch(json::out_of_range &e)
	{
		// no containers, pass through
	}

	return string("false");
}

std::string k8s_audit_filter_check::index_run_as_group(const json &j, std::string &field, std::string &idx)
{
	static json::json_pointer run_as_group = "/securityContext/runAsGroup"_json_pointer;

	// Prefer the security context over any container's runAsGroup
	try {
		return j.at(run_as_group);
	}
	catch(json::out_of_range &e)
	{
		// Continue to per-container indexing
	}

	uint64_t uidx = 0;
	if(idx.empty())
	{
		try {
			uidx = stoi(idx);
		}
		catch(std::invalid_argument &e)
		{
			uidx = 0;
		}
	}

	try {
		return j.at("containers")[uidx].at(run_as_group);
	}
	catch(json::out_of_range &e)
	{
		return string("0");
	}
}

void k8s_audit_filter_check::get_all_run_as_groups(const json &j, std::set<int64_t> &uids)
{
	uids.clear();

	static json::json_pointer run_as_group = "/securityContext/runAsGroup"_json_pointer;

	// Prefer the security context over any container's runAsGroup
	try {
		int64_t uid = j.at(run_as_group);
		uids.insert(uid);
		return;
	}
	catch(json::out_of_range &e)
	{
		// Continue to per-container indexing
	}

	try {
		for(auto &container : j.at("containers"))
		{
			try {
				int64_t uid = container.at(run_as_group);
				uids.insert(uid);
			}
			catch(json::out_of_range &e)
			{
				// This container has no runAsGroup, assume 0
				uids.insert(0);
			}
		}
	}
	catch(json::out_of_range &e)
	{
		// No containers at all
		uids.insert(0);
	}
}

std::string k8s_audit_filter_check::check_run_as_group_within(const json &j, std::string &field, std::string &idx)
{
	std::list<std::pair<int64_t,int64_t>> allowed_uids;
	std::set<int64_t> all_run_as_groups;

	if(!parse_value_ranges(idx, allowed_uids))
	{
		return string("false");
	}

	get_all_run_as_groups(j, all_run_as_groups);

	return (check_value_range_set(all_run_as_groups, allowed_uids) ? string("true") : string("false"));
}

std::string k8s_audit_filter_check::check_run_as_group_any_within(const json &j, std::string &field, std::string &idx)
{
	std::list<std::pair<int64_t,int64_t>> allowed_uids;
	std::set<int64_t> all_run_as_groups;

	if(!parse_value_ranges(idx, allowed_uids))
	{
		return string("false");
	}

	get_all_run_as_groups(j, all_run_as_groups);

	return (check_value_range_any_set(all_run_as_groups, allowed_uids) ? string("true") : string("false"));

}

std::string k8s_audit_filter_check::check_proc_mount_within(const json &j, std::string &field, std::string &idx)
{
	std::set<std::string> allowed_proc_mount_types;

	static json::json_pointer proc_mount = "/securityContext/procMount"_json_pointer;

	split_string_set(idx, ',', allowed_proc_mount_types);

	for(auto &container : j)
	{
		try {
			for(auto &mnt_type : container.at(proc_mount))
			{
				if(allowed_proc_mount_types.find(mnt_type) == allowed_proc_mount_types.end())
				{
					return string("false");
				}
			}
		}
		catch(json::out_of_range &e)
		{
			// No procMount, so is considered within the set
		}
	}

	return string("true");
}

std::string k8s_audit_filter_check::check_supplemental_groups_within(const json &j, std::string &field, std::string &idx)
{
	std::list<std::pair<int64_t,int64_t>> allowed_gids;

	static json::json_pointer supplemental_groups = "/securityContext/supplementalGroups"_json_pointer;

	if(!parse_value_ranges(idx, allowed_gids))
	{
		return string("false");
	}

	try {

		for(auto &gid : j.at(supplemental_groups))
		{
			if(!check_value_range(gid, allowed_gids))
			{
				return string("false");
			}
		}
	}
	catch(json::out_of_range &e)
	{
		// No groups, so not within
		return string("true");
	}

	return string("true");
}

std::string k8s_audit_filter_check::check_hostpath_vols(const json &j, std::string &field, std::string &idx)
{
	uint64_t num_volumes = 0;
	uint64_t num_volumes_match = 0;
	std::set<std::string> paths;

	if(j.find("volumes") != j.end())
	{
		const nlohmann::json &vols = j["volumes"];

		split_string_set(idx, ',', paths);

		nlohmann::json::json_pointer jpath = "/hostPath/path"_json_pointer;

		for(auto &vol : vols)
		{
			// The volume must be a hostPath volume to consider it
			if(vol.find("hostPath") != vol.end())
			{
				num_volumes++;

				string hostpath = vol.value(jpath, "N/A");

				for(auto &path : paths)
				{
					if(sinsp_utils::glob_match(path.c_str(), hostpath.c_str()))
					{
						num_volumes_match++;
						break;
					}
				}
			}
		}
	}

	if(field == "ka.req.volume.any_hostpath" ||
	   field == "ka.req.volume.hostpath")
	{
		return string((num_volumes_match > 0 ? "true" : "false"));
	}

	if(field == "ka.req.volume.all_hostpath")
	{
		return string(((num_volumes_match == num_volumes) ? "true" : "false"));
	}

	// Shouldn't occur
	return string("false");
}

std::string k8s_audit_filter_check::check_flexvolume_vols(const json &j, std::string &field, std::string &idx)
{
	uint64_t num_volumes = 0;
	uint64_t num_volumes_match = 0;
	std::set<std::string> drivers;

	if(j.find("volumes") == j.end())
	{
		// No volumes, matches
		return string("true");
	}

	const nlohmann::json &vols = j["volumes"];

	split_string_set(idx, ',', drivers);

	nlohmann::json::json_pointer jpath = "/flexVolume/driver"_json_pointer;

	for(auto &vol : vols)
	{
		// The volume must be a hostPath volume to consider it
		if(vol.find("flexVolume") != vol.end())
		{
			num_volumes++;

			string driver = vol.value(jpath, "N/A");

			if(drivers.find(driver) != drivers.end())
			{
				num_volumes_match++;
			}
		}
	}

	return string((num_volumes == num_volumes_match ? "true" : "false"));
}

std::string k8s_audit_filter_check::check_volume_types(const json &j, std::string &field, std::string &idx)
{
	std::set<std::string> allowed_volume_types;

	if(j.find("volumes") == j.end())
	{
		// No volumes, so no volumes within the set in the index
		return string("true");
	}

	const nlohmann::json &vols = j["volumes"];

	split_string_set(idx, ',', allowed_volume_types);

	for(auto &vol : vols)
	{
		for (auto it = vol.begin(); it != vol.end(); ++it)
		{
			// Any key other than "name" represents a volume type
			if(it.key() == "name")
			{
				continue;
			}

			if(allowed_volume_types.find(it.key()) == allowed_volume_types.end())
			{
				return string("false");
			}
		}
	}

	return string("true");
}

std::string k8s_audit_filter_check::check_added_capabilities(const json &j, std::string &field, std::string &idx)
{
	std::set<std::string> added_capabilities;

	static json::json_pointer capabilities_add = "/securityContext/capabilities/add"_json_pointer;

	split_string_set(idx, ',', added_capabilities);

	for(auto &container : j)
	{
		try {
			for(auto &cap : container.at(capabilities_add))
			{
				if(added_capabilities.find(cap) == added_capabilities.end())
				{
					return string("false");
				}
			}
		}
		catch(json::out_of_range &e)
		{
			// No added capabilities, so is considered within the set
		}
	}

	return string("true");
}

bool k8s_audit_filter_check::parse_value_ranges(const std::string &idx_range,
						std::list<std::pair<int64_t,int64_t>> &ranges)
{
	std::vector<std::string> pairs = sinsp_split(idx_range, ',');

	for(auto &pair : pairs)
	{
		size_t pos = pair.find_first_of(':');

		if(pos != std::string::npos)
		{
			int64_t imin, imax;
			std::string min = pair.substr(0, pos);
			std::string max = pair.substr(pos+1);
			std::string::size_type ptr;

			imin = std::stoll(min, &ptr);

			if(ptr != min.length())
			{
				return false;
			}

			imax = std::stoll(max, &ptr);

			if(ptr != max.length())
			{
				return false;
			}

			ranges.push_back(std::make_pair(imin, imax));
		}
	}

	return true;
}

bool k8s_audit_filter_check::check_value_range(const int64_t &val, const std::list<std::pair<int64_t,int64_t>> &ranges)
{
	for(auto &p : ranges)
	{
		if(val < p.first ||
		   val > p.second)
		{
			return false;
		}
	}

	return true;
}

bool k8s_audit_filter_check::check_value_range_array(const nlohmann::json &jarray,
						     const nlohmann::json::json_pointer &ptr,
						     const std::list<std::pair<int64_t,int64_t>> &ranges,
						     bool require_values)
{
	for(auto &item : jarray)
	{
		try {
			int64_t val = item.at(ptr);
			if(!check_value_range(val, ranges))
			{
				return false;
			}
		}
		catch(json::out_of_range &e)
		{
			if(require_values)
			{
				return false;
			}
		}
	}

	return true;
}

bool k8s_audit_filter_check::check_value_range_set(std::set<int64_t> &items,
						   const std::list<std::pair<int64_t,int64_t>> &ranges)
{
	for(auto &item : items)
	{
		if(!check_value_range(item, ranges))
		{
			return false;
		}
	}

	return true;
}

bool k8s_audit_filter_check::check_value_range_any_set(std::set<int64_t> &items,
						       const std::list<std::pair<int64_t,int64_t>> &ranges)
{
	for(auto &item : items)
	{
		if(check_value_range(item, ranges))
		{
			return true;
		}
	}

	return false;
}

bool k8s_audit_filter_check::array_get_bool_vals(const json &j, const json::json_pointer &ptr, const std::string &idx)
{
	bool val = false;

	if(!idx.empty())
	{
		try {
			val = j[stoi(idx)].at(ptr);
		}
		catch(json::out_of_range &e)
		{
		}
	}
	else
	{
		for(auto &item : j)
		{
			try {
				if(item.at(ptr))
				{
					val = true;
				}
			}
			catch(json::out_of_range &e)
			{
			}
		}
	}

	return val;
}

std::string k8s_audit_filter_check::check_host_port_within(const json &j, std::string &field, std::string &idx)
{
	std::list<std::pair<int64_t,int64_t>> allowed_ports;

	if(!parse_value_ranges(idx, allowed_ports))
	{
		return string("false");
	}

	for(auto &container : j)
	{
		if(container.find("ports") == container.end())
		{
			// This container doesn't have any ports, so it matches all ranges
			continue;
		}

		nlohmann::json ports = container["ports"];

		for(auto &cport : ports)
		{
			int64_t port;

			if(cport.find("hostPort") != cport.end())
			{
				port = cport.at("hostPort");
			}
			else if (cport.find("containerPort") != cport.end())
			{
				// When hostNetwork is true, this will match the host port.
				port = cport.at("containerPort");
			}
			else
			{
				// Shouldn't expect to see a port
				// object with neither hostPort nor
				// containerPort. Return false.
				return string("false");
			}

			if(!check_value_range(port, allowed_ports))
			{
				return string("false");
			}
		}
	}

	return string("true");
}

void k8s_audit_filter_check::split_string_set(const std::string &str, const char delim, std::set<std::string> &items)
{
	std::istringstream f(str);
	std::string ts;

	while(getline(f, ts, delim))
	{
		items.insert(ts);
	}
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
		   {"ka.req.container.host_port.within", "When the request object refers to a container, return true if all containers' hostPort values are within the list of provided min/max pairs. Example: ka.req.container.host_port.within[100:110,200:220] returns true if all containers' hostPort values are within the range 100:110 (inclusive) and 200:220 (inclusive).", IDX_REQUIRED, IDX_KEY},
		   {"ka.req.container.privileged", "When the request object refers to a container, whether or not any container is run privileged. With an index, return whether or not the ith container is run privileged.", IDX_ALLOWED, IDX_NUMERIC},
		   {"ka.req.container.allow_privilege_escalation", "When the request object refers to a container, whether or not any container has allowPrivilegeEscalation=true. With an index, return whether or not the ith container has allowPrivilegeEscalation=true.", IDX_ALLOWED, IDX_NUMERIC},
		   {"ka.req.container.read_write_fs", "When the request object refers to a container, whether or not any container is missing a readOnlyRootFilesystem annotation. With an index, return whether or not the ith container is missing a readOnlyRootFilesystem annotation.", IDX_ALLOWED, IDX_NUMERIC},
		   {"ka.req.container.has_run_as_user", "When the request object refers to a container, whether a runAsUser is specified either in the security context or in any container's spec"},
		   {"ka.req.container.run_as_user", "When the request object refers to a container, the user id that will be used for the container's entrypoint. Both the security context's runAsUser and the container's runAsUser are considered, with the security context taking precedence, and defaulting to uid 0 if neither are specified. With an index, return the uid for the ith container. With no index, returns the uid for the first container", IDX_ALLOWED, IDX_NUMERIC},
		   {"ka.req.container.run_as_user.within", "When the request object refers to a container, return true if all containers' uid values (see .run_as_user) are within the list of provided min/max pairs. Example: ka.req.container.run_as_user.within[100:110,200:220] returns true if all containers' uid values are within the range 100:110 (inclusive) and 200:220 (inclusive).", IDX_ALLOWED, IDX_KEY},
		   {"ka.req.container.run_as_user.any_within", "When the request object refers to a container, return true if any containers' uid values (see .run_as_user) are within the list of provided min/max pairs. Example: ka.req.container.run_as_user.any_within[100:110,200:220] returns true if any containers' uid values are within the range 100:110 (inclusive) and 200:220 (inclusive).", IDX_ALLOWED, IDX_KEY},
		   {"ka.req.container.has_run_as_group", "When the request object refers to a container, whether a runAsGroup is specified either in the security context or in any container's spec"},
		   {"ka.req.container.run_as_group", "When the request object refers to a container, the group id that will be used for the container's entrypoint. Both the security context's runAsGroup and the container's runAsGroup are considered, with the security context taking precedence, and defaulting to gid 0 if neither are specified. With an index, return the gid for the ith container. With no index, returns the gid for first container", IDX_ALLOWED, IDX_NUMERIC},
		   {"ka.req.container.run_as_group.within", "When the request object refers to a container, return true if all containers' gid values (see .run_as_group) are within the list of provided min/max pairs. Example: ka.req.container.run_as_group.within[100:110,200:220] returns true if all containers' gid values are within the range 100:110 (inclusive) and 200:220 (inclusive).", IDX_ALLOWED, IDX_KEY},
		   {"ka.req.container.run_as_group.any_within", "When the request object refers to a container, return true if any containers' gid values (see .run_as_group) are within the list of provided min/max pairs. Example: ka.req.container.run_as_group.any_within[100:110,200:220] returns true if any containers' gid values are within the range 100:110 (inclusive) and 200:220 (inclusive).", IDX_ALLOWED, IDX_KEY},
		   {"ka.req.container.proc_mount.within", "When the request object refers to a container, whether the procMount types specified for all containers are within the provided set. Example: ka.req.container.proc_mount.within[Unmasked,Default] returns true if all containers' procMount values are \"Unmasked\" or \"Default\".", IDX_ALLOWED, IDX_KEY},
		   {"ka.req.role.rules", "When the request object refers to a role/cluster role, the rules associated with the role"},
		   {"ka.req.role.rules.apiGroups", "When the request object refers to a role/cluster role, the api groups associated with the role's rules. With an index, return only the api groups from the ith rule. Without an index, return all api groups concatenated", IDX_ALLOWED, IDX_NUMERIC},
		   {"ka.req.role.rules.nonResourceURLs", "When the request object refers to a role/cluster role, the non resource urls associated with the role's rules. With an index, return only the non resource urls from the ith rule. Without an index, return all non resource urls concatenated", IDX_ALLOWED, IDX_NUMERIC},
		   {"ka.req.role.rules.verbs", "When the request object refers to a role/cluster role, the verbs associated with the role's rules. With an index, return only the verbs from the ith rule. Without an index, return all verbs concatenated", IDX_ALLOWED, IDX_NUMERIC},
		   {"ka.req.role.rules.resources", "When the request object refers to a role/cluster role, the resources associated with the role's rules. With an index, return only the resources from the ith rule. Without an index, return all resources concatenated", IDX_ALLOWED, IDX_NUMERIC},
		   {"ka.req.sec_ctx.fs_group", "When the request object refers to a pod, the fsGroup gid specified by the security context."},
		   {"ka.req.sec_ctx.supplemental_groups", "When the request object refers to a pod, the supplementalGroup gids specified by the security context."},
		   {"ka.req.sec_ctx.supplemental_groups.within", "When the request object refers to a pod, return true if all gids in supplementalGroups are within the provided range. For example, ka.req.sec_ctx.supplemental_groups.within[10:20] returns true if every gid in supplementalGroups is within 10 and 20.", IDX_REQUIRED, IDX_KEY},
		   {"ka.req.sec_ctx.added_capabilities.within", "When the request object refers to a pod, whether the set of added capabilities in the security context is within the provided list. For example, ka.req.sec_ctx.added_capabilities.within[CAP_KILL] would only allow pods to add the CAP_KILL capability and no other capability", IDX_REQUIRED, IDX_KEY},
		   {"ka.req.service.type", "When the request object refers to a service, the service type"},
		   {"ka.req.service.ports", "When the request object refers to a service, the service's ports. Can be indexed (e.g. ka.req.service.ports[0]). Without any index, returns all ports", IDX_ALLOWED, IDX_NUMERIC},
		   {"ka.req.volume.any_hostpath", "If the request object contains volume definitions, whether or not a hostPath volume exists that mounts the specified path(s) from the host (...hostpath[/etc]=true if a volume mounts /etc from the host). Multiple paths can be specified, separated by commas. The index can be a glob, in which case all volumes are considered to find any path matching the specified glob (...hostpath[/usr/*] would match either /usr/local or /usr/bin)", IDX_REQUIRED, IDX_KEY},
		   {"ka.req.volume.all_hostpath", "If the request object contains volume definitions, whether or not all hostPath volumes mount only the specified path(s) from the host (...hostpath[/etc]=true if a volume mounts /etc from the host). Multiple paths can be specified, separated by commas. The index can be a glob, in which case all volumes are considered to find any path matching the specified glob (...hostpath[/usr/*] would match either /usr/local or /usr/bin)", IDX_REQUIRED, IDX_KEY},
		   {"ka.req.volume.hostpath", "An alias for ka.req.volume.any_hostpath", IDX_REQUIRED, IDX_KEY},
		   {"ka.req.volume.all_flexvolume_drivers", "If the request object contains volume definitions, whether or not all Flexvolume drivers are in the provided set. Multiple drivers can be specified, separated by commas. For example, ka.req.volume.all_flexvolume_drivers[some-driver] returns true if all flexvolume volumes use only the driver called some-driver.", IDX_REQUIRED, IDX_KEY},
		   {"ka.req.volume_types.within", "If the request object contains volume definitions, return whether all volume types are in the provided set. Example: ka.req.volume_types.within[configMap,downwardAPI] returns true if the only volume types used are either configMap or downwardAPI", IDX_REQUIRED, IDX_KEY},
		   {"ka.resp.name", "The response object name"},
		   {"ka.response.code", "The response code"},
		   {"ka.response.reason", "The response reason (usually present only for failures)"},
		   {"ka.useragent", "The useragent of the client who made the request to the apiserver"}}};

	{
		m_aliases = {
			{"ka.auditid", {"/auditID"_json_pointer}},
			{"ka.stage", {"/stage"_json_pointer}},
			{"ka.auth.decision", {"/annotations/authorization.k8s.io~1decision"_json_pointer}},
			{"ka.auth.reason", {"/annotations/authorization.k8s.io~1reason"_json_pointer}},
			{"ka.user.name", {"/user/username"_json_pointer}},
			{"ka.user.groups", {"/user/groups"_json_pointer}},
			{"ka.impuser.name", {"/impersonatedUser/username"_json_pointer}},
			{"ka.verb", {"/verb"_json_pointer}},
			{"ka.uri", {"/requestURI"_json_pointer}},
			{"ka.uri.param", {"/requestURI"_json_pointer, extract_query_params, index_query_param}},
			{"ka.target.name", {"/objectRef/name"_json_pointer}},
			{"ka.target.namespace", {"/objectRef/namespace"_json_pointer}},
			{"ka.target.resource", {"/objectRef/resource"_json_pointer}},
			{"ka.target.subresource", {"/objectRef/subresource"_json_pointer}},
			{"ka.req.binding.subjects", {"/requestObject/subjects"_json_pointer}},
			{"ka.req.binding.role", {"/requestObject/roleRef/name"_json_pointer}},
			{"ka.req.configmap.name", {"/objectRef/name"_json_pointer}},
			{"ka.req.configmap.obj", {"/requestObject/data"_json_pointer}},
			{"ka.req.container.image", {"/requestObject/spec/containers"_json_pointer, extract_images}},
			{"ka.req.container.image.repository", {"/requestObject/spec/containers"_json_pointer, extract_images}},
			{"ka.req.container.host_ipc", {"/requestObject/spec/hostIPC"_json_pointer}},
			{"ka.req.container.host_network", {"/requestObject/spec/hostNetwork"_json_pointer}},
			{"ka.req.container.host_pid", {"/requestObject/spec/hostPID"_json_pointer}},
			{"ka.req.container.host_port.within", {"/requestObject/spec/containers"_json_pointer, check_host_port_within}},
			{"ka.req.container.privileged", {"/requestObject/spec/containers"_json_pointer, index_privileged}},
			{"ka.req.container.allow_privilege_escalation", {"/requestObject/spec/containers"_json_pointer, index_allow_privilege_escalation}},
			{"ka.req.container.read_write_fs", {"/requestObject/spec/containers"_json_pointer, index_read_write_fs}},
			{"ka.req.container.has_run_as_user", {"/requestObject/spec"_json_pointer, index_has_run_as_user}},
			{"ka.req.container.run_as_user", {"/requestObject/spec"_json_pointer, index_run_as_user}},
			{"ka.req.container.run_as_user.within", {"/requestObject/spec"_json_pointer, check_run_as_user_within}},
			{"ka.req.container.run_as_user.any_within", {"/requestObject/spec"_json_pointer, check_run_as_user_any_within}},
			{"ka.req.container.has_run_as_group", {"/requestObject/spec"_json_pointer, index_has_run_as_group}},
			{"ka.req.container.run_as_group", {"/requestObject/spec"_json_pointer, index_run_as_group}},
			{"ka.req.container.run_as_group.within", {"/requestObject/spec"_json_pointer, check_run_as_group_within}},
			{"ka.req.container.run_as_group.any_within", {"/requestObject/spec"_json_pointer, check_run_as_group_any_within}},
			{"ka.req.container.proc_mount.within", {"/requestObject/spec/containers"_json_pointer, check_proc_mount_within}},
			{"ka.req.role.rules", {"/requestObject/rules"_json_pointer}},
			{"ka.req.role.rules.apiGroups", {"/requestObject/rules"_json_pointer, index_select}},
			{"ka.req.role.rules.nonResourceURLs", {"/requestObject/rules"_json_pointer, index_select}},
			{"ka.req.role.rules.resources", {"/requestObject/rules"_json_pointer, index_select}},
			{"ka.req.sec_ctx.fs_group", {"/requestObject/spec/securityContext/fsGroup"_json_pointer}},
			{"ka.req.sec_ctx.supplemental_groups", {"/requestObject/spec/securityContext/supplementalGroups"_json_pointer}},
			{"ka.req.sec_ctx.supplemental_groups.within", {"/requestObject/spec"_json_pointer, check_supplemental_groups_within}},
			{"ka.req.sec_ctx.added_capabilities.within", {"/requestObject/spec/containers"_json_pointer, check_added_capabilities}},
			{"ka.req.role.rules.verbs", {"/requestObject/rules"_json_pointer, index_select}},
			{"ka.req.service.type", {"/requestObject/spec/type"_json_pointer}},
			{"ka.req.service.ports", {"/requestObject/spec/ports"_json_pointer, index_generic}},
			{"ka.req.volume.any_hostpath", {"/requestObject/spec"_json_pointer, check_hostpath_vols}},
			{"ka.req.volume.all_hostpath", {"/requestObject/spec"_json_pointer, check_hostpath_vols}},
                        {"ka.req.volume.hostpath", {"/requestObject/spec"_json_pointer, check_hostpath_vols}},
			{"ka.req.volume.all_flexvolume_drivers", {"/requestObject/spec"_json_pointer, check_flexvolume_vols}},
			{"ka.req.volume_types.within", {"/requestObject/spec"_json_pointer, check_volume_types}},
			{"ka.resp.name", {"/responseObject/metadata/name"_json_pointer}},
			{"ka.response.code", {"/responseStatus/code"_json_pointer}},
			{"ka.response.reason", {"/responseStatus/reason"_json_pointer}},
			{"ka.useragent", {"/userAgent"_json_pointer}}};
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
