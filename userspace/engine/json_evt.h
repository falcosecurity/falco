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

#pragma once

#include <memory>
#include <list>
#include <map>
#include <string>
#include <vector>
#include <set>
#include <utility>

#include <nlohmann/json.hpp>

#include "gen_filter.h"

class json_event : public gen_event
{
public:
	json_event();
	virtual ~json_event();

	void set_jevt(nlohmann::json &evt, uint64_t ts);
	const nlohmann::json &jevt();

	uint64_t get_ts();

	inline uint16_t get_source()
	{
		return ESRC_K8S_AUDIT;
	}

	inline uint16_t get_type()
	{
		// All k8s audit events have the single tag "1". - see falco_engine::process_k8s_audit_event
		return 1;
	}

protected:
	nlohmann::json m_jevt;

	uint64_t m_event_ts;
};

class json_event_filter_check : public gen_event_filter_check
{
public:

	// A struct describing a single filtercheck field ("ka.user")
	struct field_info {
		std::string name;
		std::string desc;
	};

	// A struct describing a group of filtercheck fields ("ka")
	struct check_info {
		std::string name;
		std::string desc;

		std::list<field_info> fields;
	};

	json_event_filter_check();
	virtual ~json_event_filter_check();

	virtual int32_t parse_field_name(const char* str, bool alloc_state, bool needed_for_filtering);
	void add_filter_value(const char* str, uint32_t len, uint32_t i = 0 );
	bool compare(gen_event *evt);
	virtual uint8_t* extract(gen_event *evt, uint32_t* len, bool sanitize_strings = true);

	// Simpler version that returns a string
	std::string extract(json_event *evt);

	const std::string &field();
	const std::string &idx();

	// The combined size of the field, index, and surrounding
	// brackets (e.g. ka.image[foo])
	size_t parsed_size();

	check_info &get_fields();

	//
	// Allocate a new check of the same type. Must be overridden.
	//
	virtual json_event_filter_check *allocate_new() = 0;

protected:

	static std::string def_format(const nlohmann::json &j, std::string &field, std::string &idx);
	static std::string json_as_string(const nlohmann::json &j);

	// Subclasses can define field names that act as aliases for
	// specific json pointer expressions e.g. ka.user ==
	// jevt.value[/user/username]. This struct represents one of
	// those aliases.

	typedef std::function<std::string (const nlohmann::json &, std::string &field, std::string &idx)> format_t;

	struct alias {

		// Whether this alias requires an index, allows an
		// index, or should not have an index.
		enum index_mode {
			IDX_REQUIRED,
			IDX_ALLOWED,
			IDX_NONE
		};

		enum index_type {
			IDX_KEY,
			IDX_NUMERIC
		};

		// The variants allow for brace-initialization either
		// with just the pointer or with both the pointer and
		// a format function.
		alias();
	        alias(nlohmann::json::json_pointer ptr);
	        alias(nlohmann::json::json_pointer ptr, format_t format);
	        alias(nlohmann::json::json_pointer ptr, format_t format, index_mode mode);
	        alias(nlohmann::json::json_pointer ptr, format_t format, index_mode mode, index_type itype);
		virtual ~alias();

		// A json pointer used to extract a referenced value
		// from a json object.
		nlohmann::json::json_pointer m_jptr;

		// A function that given the referenced value selected
		// above, formats and returns the appropriate string. This
		// function might do further selection (e.g. array
		// indexing, searches, etc.) or string reformatting to
		// trim unnecessary parts of the value.
		format_t m_format;

		index_mode m_idx_mode;

		index_type m_idx_type;
	};

	// This map defines the aliases defined by this filter check
	// class.
	//
	// The version of parse_field_name in this base class will
	// check a field specification against all the aliases.
	std::map<std::string, struct alias> m_aliases;

	check_info m_info;

	// The actual field name parsed in parse_field_name.
	std::string m_field;

	// The field name itself might include an index component
	// e.g. ka.value[idx]. This holds the index.
	std::string m_idx;

	// The actual json pointer value to use to extract from events.
	nlohmann::json::json_pointer m_jptr;

	// Temporary storage to hold extracted value
	std::string m_tstr;

	// Reformatting function
	format_t m_format;

private:

	std::vector<std::string> m_values;
};

class jevt_filter_check : public json_event_filter_check
{
public:
	jevt_filter_check();
	virtual ~jevt_filter_check();

	int32_t parse_field_name(const char* str, bool alloc_state, bool needed_for_filtering);

	virtual uint8_t* extract(gen_event *evt, uint32_t* len, bool sanitize_strings = true);

	json_event_filter_check *allocate_new();

private:

	static std::string s_jevt_time_field;
	static std::string s_jevt_time_iso_8601_field;
	static std::string s_jevt_rawtime_field;
	static std::string s_jevt_obj_field;
	static std::string s_jevt_value_field;
};

class k8s_audit_filter_check : public json_event_filter_check
{
public:
	k8s_audit_filter_check();
	virtual ~k8s_audit_filter_check();

	json_event_filter_check *allocate_new();

	// Index to the appropriate container and/or remove any repo,
	// port, and tag from the provided image name.
	static std::string index_image(const nlohmann::json &j, std::string &field, std::string &idx);

	// Extract the value of the provided query parameter
	static std::string index_query_param(const nlohmann::json &j, std::string &field, std::string &idx);

	// Return true if an object in the provided array has a name property with idx as value
	static std::string index_has_name(const nlohmann::json &j, std::string &field, std::string &idx);

	// Return whether the ith container (or any container, if an
	// index is not specified) is run privileged.
	static std::string index_privileged(const nlohmann::json &j, std::string &field, std::string &idx);

	// Return whether or not a hostpath mount exists matching the provided index.
	static std::string check_hostpath_vols(const nlohmann::json &j, std::string &field, std::string &idx);

	// Index to the ith value from the provided array. If no index is provided, return the entire array as a string.
	static std::string index_generic(const nlohmann::json &j, std::string &field, std::string &idx);

	// Index to the ith value from the provided array, and select
	// the property which is the last component of the provided
	// field.
	static std::string index_select(const nlohmann::json &j, std::string &field, std::string &idx);
};

class json_event_filter : public gen_event_filter
{
public:
	json_event_filter();
	virtual ~json_event_filter();

	std::string m_rule;
	uint32_t m_rule_idx;
	std::set<std::string> m_tags;
};


class json_event_filter_factory : public gen_event_filter_factory
{
public:
	json_event_filter_factory();
	virtual ~json_event_filter_factory();

	// Create a new filter
	gen_event_filter *new_filter();

	// Create a new filter_check
	gen_event_filter_check *new_filtercheck(const char *fldname);

	// All defined field names
	std::list<json_event_filter_check::check_info> &get_fields();

private:
	std::list<std::shared_ptr<json_event_filter_check>> m_defined_checks;
	std::list<json_event_filter_check::check_info> m_info;

};

// Unlike the other classes, this does not inherit from a shared class
// that's used both by json events and sinsp events. It might be
// worthwhile, but it would require a lot of additional work to pull
// up functionality into the generic filtercheck class.

class json_event_formatter
{
public:
	json_event_formatter(json_event_filter_factory &factory, std::string &format);
	virtual ~json_event_formatter();

	std::string tostring(json_event *ev);
	std::string tojson(json_event *ev);

	void resolve_tokens(json_event *ev, std::list<std::pair<std::string,std::string>> &resolved);

private:
	void parse_format();


	// A format token is either a combination of a filtercheck
	// name (ka.value) and filtercheck object as key, or an empty
	// key and a NULL filtercheck object, combined with a value (
	//
	// For example, given a format string:
	// "The value is %ka.value today"
	// The tokens would be:
	// [("The value is ", NULL), ("ka.value", <an object>), " today", NULL)]

	struct fmt_token
	{
		std::string text;
		std::shared_ptr<json_event_filter_check> check;
	};

	// The original format string
	std::string m_format;

	// The chunks that make up the format string, in order, broken
	// up between text chunks and filterchecks.
	std::list<fmt_token> m_tokens;

	// All the filterchecks required to resolve tokens in the format string
	json_event_filter_factory &m_json_factory;
};



