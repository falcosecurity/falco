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

#pragma once

#include <memory>
#include <list>
#include <map>
#include <string>
#include <vector>
#include <set>
#include <utility>

#include <nlohmann/json.hpp>

#include "prefix_search.h"
#include <sinsp.h>

class json_event : public gen_event
{
public:
	json_event();
	virtual ~json_event();

	void set_jevt(nlohmann::json &evt, uint64_t ts);
	const nlohmann::json &jevt();

	uint64_t get_ts() const;

	inline uint16_t get_source() const
	{
		return ESRC_K8S_AUDIT;
	}

	inline uint16_t get_type() const
	{
		// All k8s audit events have the single tag "1". - see falco_engine::process_k8s_audit_event
		return ppm_event_code::PPME_PLUGINEVENT_E;
	}

protected:
	nlohmann::json m_jevt;

	uint64_t m_event_ts;
};

namespace falco_k8s_audit {

	//
	// Given a raw json object, return a list of k8s audit event
	// objects that represent the object. This method handles
	// things such as EventList splitting.
	//
	// Returns true if the json object was recognized as a k8s
	// audit event(s), false otherwise.
	//
	bool parse_k8s_audit_json(nlohmann::json &j, std::list<json_event> &evts, bool top=true);
};

// A class representing an extracted value or a value on the rhs of a
// filter_check. This intentionally doesn't use the same types as
// ppm_events_public.h to take advantage of actual classes instead of
// lower-level pointers pointing to syscall events and to allow for
// efficient set comparisons.

class json_event_value
{
public:
	enum param_type {
		JT_STRING,
		JT_INT64,
		JT_INT64_PAIR
	};

	json_event_value();
	json_event_value(const std::string &val);
	json_event_value(int64_t val);
	virtual ~json_event_value();

	param_type ptype() const;

	std::string as_string() const;

	bool operator==(const json_event_value &val) const;
	bool operator!=(const json_event_value &val) const;
	bool operator<(const json_event_value &val) const;
	bool operator>(const json_event_value &val) const;

	// Only meaningful for string types
	bool startswith(const json_event_value &val) const;
	bool contains(const json_event_value &val) const;

private:
	param_type m_type;

	static bool parse_as_pair_int64(std::pair<int64_t,int64_t> &pairval, const std::string &val);
	static bool parse_as_int64(int64_t &intval, const std::string &val);

	// The number of possible types is small so far, so sticking
	// with separate vars

	std::string m_stringval;
	int64_t m_intval;
	std::pair<int64_t,int64_t> m_pairval;
};

class json_event_filter_check : public gen_event_filter_check
{
public:

	static std::string no_value;

	enum index_mode
	{
		IDX_REQUIRED,
		IDX_ALLOWED,
		IDX_NONE
	};

	static std::vector<std::string> s_index_mode_strs;

	enum index_type
	{
		IDX_KEY,
		IDX_NUMERIC
	};

	static std::vector<std::string> s_index_type_strs;

	// A struct describing a single filtercheck field ("ka.user")
	struct field_info
	{
		std::string m_name;
		std::string m_desc;

		index_mode m_idx_mode;
		index_type m_idx_type;

		bool m_uses_paths;

		// The variants allow for brace-initialization either
		// with just the name/desc or additionally with index
		// information
		field_info();
		field_info(std::string name, std::string desc);
		field_info(std::string name, std::string desc, index_mode mode);
		field_info(std::string name, std::string desc, index_mode mode, index_type itype);
		field_info(std::string name, std::string desc, index_mode mode, index_type itype, bool uses_paths);
		virtual ~field_info();
	};

	// A struct describing a group of filtercheck fields ("ka")
	struct check_info
	{
		std::string m_name;
		std::string m_shortdesc;
		std::string m_desc;

		std::list<field_info> m_fields;
	};

	json_event_filter_check();
	virtual ~json_event_filter_check() = 0;

	virtual int32_t parse_field_name(const char *str, bool alloc_state, bool needed_for_filtering);
	void add_filter_value(const char *str, uint32_t len, uint32_t i = 0);
	bool compare(gen_event *evt);

	// This is adapted to support the new extract() method signature that
	// supports extracting list of values, however json_evt was implemented
	// to support this feature in the first place through the
	// extracted_values_t structure. As such, for now this is only used for
	// signature compliance, and always pushes a single value. The value pushed
	// in the vector is a a const extracted_values_t* that points to the
	// internal m_evalues. This is a temporary workaround to sync with the
	// latest falcosecurity/libs development without re-designing the whole K8S
	// support, which will eventually be refactored as a plugin in the future anyway.
	bool extract(gen_event *evt, std::vector<extract_value_t>& values, bool sanitize_strings = true) final;

	const std::string &field();
	const std::string &idx();

	// The combined size of the field, index, and surrounding
	// brackets (e.g. ka.image[foo])
	size_t parsed_size();

	virtual const check_info &get_info() const = 0;

	//
	// Allocate a new check of the same type. Must be overridden.
	//
	virtual json_event_filter_check *allocate_new() = 0;

	// Subclasses or extraction functions can call this method to add each extracted value.
	void add_extracted_value(const std::string &val);
	void add_extracted_value_num(int64_t val);

	// After calling extract, you can call extracted_values to get
	// the values extracted from an event.
	typedef std::vector<json_event_value> values_t;
	const values_t &extracted_values();

protected:
	// Subclasses can override this method, calling
	// add_extracted_value to add extracted values.
	virtual bool extract_values(json_event *jevt);

	static std::string json_as_string(const nlohmann::json &j);

	// Subclasses can define field names that act as aliases for
	// specific json pointer expressions e.g. ka.user ==
	// jevt.value[/user/username]. This struct represents one of
	// those aliases.

	// An alias might define an alternative function to extract
	// values instead of using a json pointer. An example is
	// ka.uri.param, which parses the query string to extract
	// key=value parameters.
	typedef std::function<bool (const nlohmann::json &, json_event_filter_check &jchk)> extract_t;

	struct alias
	{
		// The variants allow for brace-initialization either
		// with just the pointer list or with a custom
		// extraction function.
		alias();
	        alias(std::list<nlohmann::json::json_pointer> ptrs);
	        alias(extract_t extract);

		virtual ~alias();

		// A json pointer used to extract a referenced value
		// from a json object. The pointers are applied in
		// order. After applying a pointer, if the resulting
		// object is an array, each array member is considered
		// for subsequent json pointers.
		//
		// This allows for "plucking" items out of an array
		// selected by an earlier json pointer.
		std::list<nlohmann::json::json_pointer> m_jptrs;

		extract_t m_extract;
	};

	// This map defines the aliases defined by this filter check
	// class.
	//
	// The version of parse_field_name in this base class will
	// check a field specification against all the aliases.
	virtual const std::unordered_map<std::string, alias> &get_aliases() const = 0;

	//check_info m_info;

	// The actual field name parsed in parse_field_name.
	std::string m_field;

	// The field name itself might include an index component
	// e.g. ka.value[idx]. This holds the index.
	std::string m_idx;

private:
	typedef std::set<json_event_value> values_set_t;
	typedef std::pair<values_t, values_set_t> extracted_values_t;

	// The default extraction function uses the list of pointers
	// in m_jptrs. Iterates over array elements between pointers if
	// found.
	bool def_extract(const nlohmann::json &j,
			 const std::list<nlohmann::json::json_pointer> &ptrs,
			 std::list<nlohmann::json::json_pointer>::iterator it);

	// The actual json pointer value to use to extract from
	// events. See alias struct for usage.
	std::list<nlohmann::json::json_pointer> m_jptrs;

	// The extraction function to use. May not be defined, in which
	// case the default function is used.
	extract_t m_extract;

	// All values specified on the right hand side of the operator
	// e.g. "ka.ns in ("one","two","three"), m_values has ("one",
	// "two", "three")
	values_set_t m_values;

	// All values extracted from the object by the field e.g. for
	// a field ka.req.container.image returns all container images
	// for all pods within a request.
	extracted_values_t m_evalues;

	// If true, this filtercheck works on paths, which enables
	// some extra bookkeeping to allow for path prefix searches.
	bool m_uses_paths = false;

	path_prefix_search m_prefix_search;
};

class jevt_filter_check : public json_event_filter_check
{
public:
	jevt_filter_check();
	virtual ~jevt_filter_check();

	int32_t parse_field_name(const char* str, bool alloc_state, bool needed_for_filtering) final;

	json_event_filter_check *allocate_new() override;
	const check_info &get_info() const override;

protected:

	bool extract_values(json_event *jevt) final;
	const std::unordered_map<std::string, alias> &get_aliases() const override
	{
		static std::unordered_map<std::string, alias> a;
		return a;
	};


private:

	// When the field is jevt_value, a json pointer representing
	// the index in m_idx
	nlohmann::json::json_pointer m_idx_ptr;

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

	json_event_filter_check *allocate_new() override;

	const check_info &get_info() const override;
	const std::unordered_map<std::string, alias> &get_aliases() const override;

		// Extract all images/image repositories from the provided containers
	static bool extract_images(const nlohmann::json &j,
				   json_event_filter_check &jchk);

	// Extract all query parameters
	static bool extract_query_param(const nlohmann::json &j,
					json_event_filter_check &jchk);

	// Extract some property from the set of rules in the request object
	static bool extract_rule_attrs(const nlohmann::json &j,
				       json_event_filter_check &jchk);

	// Determine if the provided path matches any volumes host path.
	static bool check_volumes_hostpath(const nlohmann::json &j,
					   json_event_filter_check &jchk);

	// Extract the volume types from volumes in the request object
	static bool extract_volume_types(const nlohmann::json &j,
					 json_event_filter_check &jchk);

	// Extract all hostPort values from containers in the request object
	static bool extract_host_port(const nlohmann::json &j,
				      json_event_filter_check &jchk);

	// Using both the pod and container security contexts, extract
	// the uid/gid that will be used for each container.
	static bool extract_effective_run_as(const nlohmann::json &j,
					     json_event_filter_check &jchk);

	// These are only used for compatibility with older rules files

	// Always return the string "N/A"
	static bool always_return_na(const nlohmann::json &j,
				     json_event_filter_check &jchk);


	// Return true if any container has privileged=true
	static bool extract_any_privileged(const nlohmann::json &j,
					   json_event_filter_check &jchk);
};


class json_event_filter : public sinsp_filter
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
	std::list<gen_event_filter_factory::filter_fieldclass_info> get_fields();

private:
	std::list<std::shared_ptr<json_event_filter_check>> m_defined_checks;
	std::list<json_event_filter_check::check_info> m_info;
};

class json_event_formatter : public gen_event_formatter
{
public:
	json_event_formatter(std::shared_ptr<gen_event_filter_factory> factory);
	virtual ~json_event_formatter();

	void set_format(output_format of, const std::string &format) override;
	bool tostring(gen_event *evt, std::string &output) override;
	bool tostring_withformat(gen_event *evt, std::string &output, gen_event_formatter::output_format of) override;
	bool get_field_values(gen_event *evt, std::map<std::string, std::string> &fields) override;
	output_format get_output_format() override;

	std::string tojson(json_event *ev);

	// Split the format string into a list of tuples, broken at
	// output fields, where each tuple is either a block of text
	// from the original format string, or a field value/pair from
	// the original format string.
	//
	// For example, given a format string "some output
	// (%proc.name)", this will fill in resolved with 3 tuples:
	// - ["", "some output ("]
	// - ["proc.name", "nginx"]
	// - ["", ")"]
	//
	// This can be used either to return a resolved output string
	// or a map of field name/value pairs.
        void resolve_format(json_event *ev, std::list<std::pair<std::string, std::string>> &resolved);

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

	gen_event_formatter::output_format m_output_format;

	// The original format string
	std::string m_format;

	// The chunks that make up the format string, in order, broken
	// up between text chunks and filterchecks.
	std::list<fmt_token> m_tokens;

	// All the filterchecks required to resolve tokens in the format string
	std::shared_ptr<gen_event_filter_factory> m_json_factory;
};

class json_event_formatter_factory : public gen_event_formatter_factory
{
public:
	json_event_formatter_factory(std::shared_ptr<gen_event_filter_factory> factory);
	virtual ~json_event_formatter_factory();

	void set_output_format(gen_event_formatter::output_format of) override;

	std::shared_ptr<gen_event_formatter> create_formatter(const std::string &format) override;

protected:
	// Maps from output string to formatter
	std::map<std::string, std::shared_ptr<gen_event_formatter>> m_formatters;

	gen_event_formatter::output_format m_output_format;

	// All the filterchecks required to resolve tokens in the format string
	std::shared_ptr<gen_event_filter_factory> m_json_factory;
};
