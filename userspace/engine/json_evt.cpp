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

#include "utils.h"
#include "uri.h"

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

std::string json_event_filter_check::def_format(const json &j, std::string &field, std::string &idx)
{
	return json_as_string(j);
}

std::string json_event_filter_check::json_as_string(const json &j)
{
	if (j.type() == json::value_t::string)
	{
		return j;
	}
	else
	{
		return j.dump();
	}
}

json_event_filter_check::alias::alias()
	: m_idx_mode(IDX_NONE), m_idx_type(IDX_NUMERIC)
{
}

json_event_filter_check::alias::alias(nlohmann::json::json_pointer ptr)
	: m_jptr(ptr), m_format(def_format),
	  m_idx_mode(IDX_NONE), m_idx_type(IDX_NUMERIC)
{
}

json_event_filter_check::alias::alias(nlohmann::json::json_pointer ptr,
				      format_t format)
	: m_jptr(ptr), m_format(format),
	  m_idx_mode(IDX_NONE), m_idx_type(IDX_NUMERIC)
{
}

json_event_filter_check::alias::alias(nlohmann::json::json_pointer ptr,
				      format_t format,
				      index_mode mode,
				      index_type itype)
	: m_jptr(ptr), m_format(format),
	  m_idx_mode(mode), m_idx_type(itype)
{
}

json_event_filter_check::alias::~alias()
{
}

json_event_filter_check::json_event_filter_check()
	: m_format(def_format)
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

	for(auto &pair : m_aliases)
	{
		// What follows the match must not be alphanumeric or a dot
		if(strncmp(pair.first.c_str(), str, pair.first.size()) == 0 &&
		   !isalnum((int) str[pair.first.size()]) &&
		   str[pair.first.size()] != '.' &&
		   pair.first.size() > match_len)
		{
			m_jptr = pair.second.m_jptr;
			m_field = pair.first;
			m_format = pair.second.m_format;
			match_len = pair.first.size();

			const char *start = str + m_field.size();

			// Check for an optional index
			if(*start == '[')
			{
				start++;
				const char *end = strchr(start, ']');

				if(end != NULL)
				{
					m_idx = string(start, end-start);
				}

				idx_len = (end - start + 2);
			}

			if(m_idx.empty() && pair.second.m_idx_mode == alias::IDX_REQUIRED)
			{
				throw falco_exception(string("When parsing filtercheck ") + string(str) + string(": ") + m_field + string(" requires an index but none provided"));
			}

			if(!m_idx.empty() && pair.second.m_idx_mode == alias::IDX_NONE)
			{
				throw falco_exception(string("When parsing filtercheck ") + string(str) + string(": ") + m_field + string(" forbids an index but one provided"));
			}

			if(!m_idx.empty() &&
			   pair.second.m_idx_type == alias::IDX_NUMERIC &&
			   m_idx.find_first_not_of("0123456789") != string::npos)
			{
				throw falco_exception(string("When parsing filtercheck ") + string(str) + string(": ") + m_field + string(" requires a numeric index"));
			}
		}
	}

	return match_len + idx_len;
}

void json_event_filter_check::add_filter_value(const char* str, uint32_t len, uint32_t i)
{
	m_values.push_back(string(str));
}

bool json_event_filter_check::compare(gen_event *evt)
{
	json_event *jevt = (json_event *) evt;

	std::string value = extract(jevt);

	switch(m_cmpop)
	{
	case CO_EQ:
		return (value == m_values[0]);
		break;
	case CO_NE:
		return (value != m_values[0]);
		break;
	case CO_CONTAINS:
		return (value.find(m_values[0]) != string::npos);
		break;
	case CO_STARTSWITH:
		return (value.compare(0, m_values[0].size(), m_values[0]) == 0);
		break;
	case CO_IN:
		for(auto &val : m_values)
		{
			if (value == val)
			{
				return true;
			}
		}
		return false;
		break;
	case CO_EXISTS:
		// Any non-empty, non-"<NA>" value is ok
		return (value != "" && value != "<NA>");
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

uint8_t* json_event_filter_check::extract(gen_event *evt, uint32_t* len, bool sanitize_strings)
{
	json_event *jevt = (json_event *) evt;

	try {
		const json &j = jevt->jevt().at(m_jptr);

		// Only format when the value was actually found in
		// the object.
		m_tstr = m_format(j, m_field, m_idx);
	}
	catch(json::out_of_range &e)
	{
		m_tstr = "<NA>";
	}

	*len = m_tstr.size();

	return (uint8_t *) m_tstr.c_str();
}

std::string json_event_filter_check::extract(json_event *evt)
{
	uint8_t *res;
	uint32_t len;
	std::string ret;

	res = extract(evt, &len, true);

	if(res != NULL)
	{
		ret.assign((const char *) res, len);
	}

	return ret;
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
		  {
			  {s_jevt_time_field, "json event timestamp as a string that includes the nanosecond part"},
			  {s_jevt_time_iso_8601_field, "json event timestamp in ISO 8601 format, including nanoseconds and time zone offset (in UTC)"},
			  {s_jevt_rawtime_field, "absolute event timestamp, i.e. nanoseconds from epoch."},
			  {s_jevt_value_field, "General way to access single property from json object. The syntax is [<json pointer expression>]. The property is returned as a string"},
			  {s_jevt_obj_field, "The entire json object, stringified"}
		  }};
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
		if (*(str + s_jevt_value_field.size()) != '[' ||
		    ((end = strchr(str + 1, ']')) == NULL))

		{
			throw falco_exception(string("Could not parse filtercheck field \"") + str + "\". Did not have expected format with 'jevt.value[<json pointer>]'");
		}

		try {
			m_jptr = json::json_pointer(string(str + (s_jevt_value_field.size()+1), (end-str-(s_jevt_value_field.size()+1))));
		}
		catch (json::parse_error& e)
		{
			throw falco_exception(string("Could not parse filtercheck field \"") + str + "\". Invalid json selector (" + e.what() + ")");
		}

		// The +1 accounts for the closing ']'
		m_field = string(str, end-str + 1);
		return (end - str + 1);
	}

	return 0;
}

uint8_t* jevt_filter_check::extract(gen_event *evt, uint32_t* len, bool sanitize_stings)
{
	if(m_field == s_jevt_rawtime_field)
	{
		m_tstr = to_string(evt->get_ts());
		*len = m_tstr.size();
		return (uint8_t *) m_tstr.c_str();
	}
	else if(m_field == s_jevt_time_field)
	{
		sinsp_utils::ts_to_string(evt->get_ts(), &m_tstr, false, true);
		*len = m_tstr.size();
		return (uint8_t *) m_tstr.c_str();
	}
	else if(m_field == s_jevt_time_iso_8601_field)
	{
		sinsp_utils::ts_to_iso_8601(evt->get_ts(), &m_tstr);
		*len = m_tstr.size();
		return (uint8_t *) m_tstr.c_str();
	}
	else if(m_field == s_jevt_obj_field)
	{
		json_event *jevt = (json_event *) evt;
		m_tstr = jevt->jevt().dump();
		*len = m_tstr.size();
		return (uint8_t *) m_tstr.c_str();
	}

	return json_event_filter_check::extract(evt, len, sanitize_stings);
}

json_event_filter_check *jevt_filter_check::allocate_new()
{
	jevt_filter_check *chk = new jevt_filter_check();

	return (json_event_filter_check *) chk;
}

std::string k8s_audit_filter_check::index_image(const json &j, std::string &field, std::string &idx)
{
	uint64_t idx_num = (idx.empty() ? 0 : stoi(idx));

	string image;

	try {
		image  = j[idx_num].at("image");
	}
	catch(json::out_of_range &e)
	{
		return string("<NA>");
	}

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

		return name;
	}

	return image;
}

std::string k8s_audit_filter_check::index_has_name(const json &j, std::string &field, std::string &idx)
{
	for(auto &subject : j)
	{
		if(subject.value("name", "N/A") == idx)
		{
			return string("true");
		}
	}

	return string("false");
}


std::string k8s_audit_filter_check::index_query_param(const json &j, std::string &field, std::string &idx)
{
	string uri = j;
	std::vector<std::string> uri_parts, query_parts;

	uri_parts = sinsp_split(uri, '?');

	if(uri_parts.size() != 2)
	{
		return string("<NA>");
	}

	query_parts = sinsp_split(uri_parts[1], '&');

	for(auto &part : query_parts)
	{
		std::vector<std::string> param_parts = sinsp_split(part, '=');

		if(param_parts.size() == 2 && uri::decode(param_parts[0], true)==idx)
		{
			return uri::decode(param_parts[1]);
		}
	}

	return string("<NA>");
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

		try {
			item = j[idx_num];
		}
		catch(json::out_of_range &e)
		{
			return string("<NA>");
		}
	}

	return json_event_filter_check::json_as_string(item);
}

std::string k8s_audit_filter_check::index_select(const json &j, std::string &field, std::string &idx)
{
	json item;

	// Use the suffix of the field to determine which property to
	// select from each object.
	std::string prop = field.substr(field.find_last_of(".")+1);

	std::string ret;

	if(idx.empty())
	{
		for(auto &obj : j)
		{
			if(ret != "")
			{
				ret += " ";
			}

			try {
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
		try {
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

	bool privileged = false;

	if(!idx.empty())
	{
		try {
			privileged = j[stoi(idx)].at(jpriv);
		}
		catch(json::out_of_range &e)
		{
		}
	}
	else
	{
		for(auto &container : j)
		{
			try {
				if(container.at(jpriv))
				{
					privileged = true;
				}
			}
			catch(json::out_of_range &e)
			{
			}
		}
	}

	return (privileged ? string("true") : string("false"));
}

std::string k8s_audit_filter_check::check_hostpath_vols(const json &j, std::string &field, std::string &idx)
{

	nlohmann::json::json_pointer jpath = "/hostPath/path"_json_pointer;

	for(auto &vol : j)
	{
		string path = vol.value(jpath, "N/A");

		if(sinsp_utils::glob_match(idx.c_str(), path.c_str()))
		{
			return string("true");
		}
	}

	return string("false");
}

k8s_audit_filter_check::k8s_audit_filter_check()
{
	m_info = {"ka",
		  "Access K8s Audit Log Events",
		  {
			  {"ka.auditid", "The unique id of the audit event"},
			  {"ka.stage", "Stage of the request (e.g. RequestReceived, ResponseComplete, etc.)"},
			  {"ka.auth.decision", "The authorization decision"},
			  {"ka.auth.reason", "The authorization reason"},
			  {"ka.user.name", "The user name performing the request"},
			  {"ka.user.groups", "The groups to which the user belongs"},
			  {"ka.impuser.name", "The impersonated user name"},
			  {"ka.verb", "The action being performed"},
			  {"ka.uri", "The request URI as sent from client to server"},
			  {"ka.uri.param", "The value of a given query parameter in the uri (e.g. when uri=/foo?key=val, ka.uri.param[key] is val)."},
			  {"ka.target.name", "The target object name"},
			  {"ka.target.namespace", "The target object namespace"},
			  {"ka.target.resource", "The target object resource"},
			  {"ka.target.subresource", "The target object subresource"},
			  {"ka.req.binding.subjects", "When the request object refers to a cluster role binding, the subject (e.g. account/users) being linked by the binding"},
			  {"ka.req.binding.subject.has_name", "When the request object refers to a cluster role binding, return true if a subject with the provided name exists"},
			  {"ka.req.binding.role", "When the request object refers to a cluster role binding, the role being linked by the binding"},
			  {"ka.req.configmap.name", "If the request object refers to a configmap, the configmap name"},
			  {"ka.req.configmap.obj", "If the request object refers to a configmap, the entire configmap object"},
			  {"ka.req.container.image", "When the request object refers to a container, the container's images. Can be indexed (e.g. ka.req.container.image[0]). Without any index, returns the first image"},
			  {"ka.req.container.image.repository", "The same as req.container.image, but only the repository part (e.g. sysdig/falco)"},
			  {"ka.req.container.host_network", "When the request object refers to a container, the value of the hostNetwork flag."},
			  {"ka.req.container.privileged", "When the request object refers to a container, whether or not any container is run privileged. With an index, return whether or not the ith container is run privileged."},
			  {"ka.req.role.rules", "When the request object refers to a role/cluster role, the rules associated with the role"},
			  {"ka.req.role.rules.apiGroups", "When the request object refers to a role/cluster role, the api groups associated with the role's rules. With an index, return only the api groups from the ith rule. Without an index, return all api groups concatenated"},
			  {"ka.req.role.rules.nonResourceURLs", "When the request object refers to a role/cluster role, the non resource urls associated with the role's rules. With an index, return only the non resource urls from the ith rule. Without an index, return all non resource urls concatenated"},
			  {"ka.req.role.rules.verbs", "When the request object refers to a role/cluster role, the verbs associated with the role's rules. With an index, return only the verbs from the ith rule. Without an index, return all verbs concatenated"},
			  {"ka.req.role.rules.resources", "When the request object refers to a role/cluster role, the resources associated with the role's rules. With an index, return only the resources from the ith rule. Without an index, return all resources concatenated"},
			  {"ka.req.service.type", "When the request object refers to a service, the service type"},
			  {"ka.req.service.ports", "When the request object refers to a service, the service's ports. Can be indexed (e.g. ka.req.service.ports[0]). Without any index, returns all ports"},
			  {"ka.req.volume.hostpath", "If the request object contains volume definitions, whether or not a hostPath volume exists that mounts the specified path from the host (...hostpath[/etc]=true if a volume mounts /etc from the host). The index can be a glob, in which case all volumes are considered to find any path matching the specified glob (...hostpath[/usr/*] would match either /usr/local or /usr/bin)"},
			  {"ka.resp.name", "The response object name"},
			  {"ka.response.code", "The response code"},
			  {"ka.response.reason", "The response reason (usually present only for failures)"}
		  }};

	{
		using a = alias;

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
			{"ka.uri.param", {"/requestURI"_json_pointer, index_query_param, a::IDX_REQUIRED, a::IDX_KEY}},
			{"ka.target.name", {"/objectRef/name"_json_pointer}},
			{"ka.target.namespace", {"/objectRef/namespace"_json_pointer}},
			{"ka.target.resource", {"/objectRef/resource"_json_pointer}},
			{"ka.target.subresource", {"/objectRef/subresource"_json_pointer}},
			{"ka.req.binding.subjects", {"/requestObject/subjects"_json_pointer}},
			{"ka.req.binding.subject.has_name", {"/requestObject/subjects"_json_pointer, index_has_name, a::IDX_REQUIRED, a::IDX_KEY}},
			{"ka.req.binding.role", {"/requestObject/roleRef/name"_json_pointer}},
			{"ka.req.configmap.name", {"/objectRef/name"_json_pointer}},
			{"ka.req.configmap.obj", {"/requestObject/data"_json_pointer}},
			{"ka.req.container.image", {"/requestObject/spec/containers"_json_pointer, index_image, a::IDX_ALLOWED, a::IDX_NUMERIC}},
			{"ka.req.container.image.repository", {"/requestObject/spec/containers"_json_pointer, index_image, a::IDX_ALLOWED, a::IDX_NUMERIC}},
			{"ka.req.container.host_network", {"/requestObject/spec/hostNetwork"_json_pointer}},
			{"ka.req.container.privileged", {"/requestObject/spec/containers"_json_pointer, index_privileged, a::IDX_ALLOWED, a::IDX_NUMERIC}},
			{"ka.req.role.rules", {"/requestObject/rules"_json_pointer}},
			{"ka.req.role.rules.apiGroups", {"/requestObject/rules"_json_pointer, index_select, a::IDX_ALLOWED, a::IDX_NUMERIC}},
			{"ka.req.role.rules.nonResourceURLs", {"/requestObject/rules"_json_pointer, index_select, a::IDX_ALLOWED, a::IDX_NUMERIC}},
			{"ka.req.role.rules.resources", {"/requestObject/rules"_json_pointer, index_select, a::IDX_ALLOWED, a::IDX_NUMERIC}},
			{"ka.req.role.rules.verbs", {"/requestObject/rules"_json_pointer, index_select, a::IDX_ALLOWED, a::IDX_NUMERIC}},
			{"ka.req.service.type", {"/requestObject/spec/type"_json_pointer}},
			{"ka.req.service.ports", {"/requestObject/spec/ports"_json_pointer, index_generic, a::IDX_ALLOWED, a::IDX_NUMERIC}},
			{"ka.req.volume.hostpath", {"/requestObject/spec/volumes"_json_pointer, check_hostpath_vols, a::IDX_REQUIRED, a::IDX_KEY}},
			{"ka.resp.name", {"/responseObject/metadata/name"_json_pointer}},
			{"ka.response.code", {"/responseStatus/code"_json_pointer}},
			{"ka.response.reason", {"/responseStatus/reason"_json_pointer}}
		};
	}
}

k8s_audit_filter_check::~k8s_audit_filter_check()
{

}

json_event_filter_check *k8s_audit_filter_check::allocate_new()
{
	k8s_audit_filter_check *chk = new k8s_audit_filter_check();

	return (json_event_filter_check *) chk;
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

json_event_formatter::json_event_formatter(json_event_filter_factory &json_factory, std::string &format)
	: m_format(format),
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

	std::list<std::pair<std::string,std::string>> resolved;

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

	std::list<std::pair<std::string,std::string>> resolved;

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
			json_event_filter_check *chk = (json_event_filter_check *) m_json_factory.new_filtercheck(tformat.c_str());

			if(!chk)
			{
				throw falco_exception(string ("Could not parse format string \"") + m_format + "\": unknown filtercheck field " + tformat);
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
				throw falco_exception(string ("Could not parse format string \"" + m_format + "\": empty filtercheck field"));
			}
			continue;
		}

		tok.text = tformat.substr(0, size);
		m_tokens.push_back(tok);

		tformat.erase(0, size);
	}
}

void json_event_formatter::resolve_tokens(json_event *ev, std::list<std::pair<std::string,std::string>> &resolved)
{
	for(auto tok : m_tokens)
	{
		if(tok.check)
		{
			resolved.push_back(std::make_pair(tok.check->field(), tok.check->extract(ev)));
		}
		else
		{
			resolved.push_back(std::make_pair("", tok.text));
		}
	}
}
