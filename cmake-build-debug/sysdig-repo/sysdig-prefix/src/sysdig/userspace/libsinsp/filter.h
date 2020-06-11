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

#include <set>
#include <vector>

#ifdef HAS_FILTERING

#include "gen_filter.h"

/** @defgroup filter Filtering events
 * Filtering infrastructure.
 *  @{
 */

/*!
  \brief This is the class that runs sysdig-type filters.
*/
class SINSP_PUBLIC sinsp_filter : public gen_event_filter
{
public:
	sinsp_filter(sinsp* inspector);
	~sinsp_filter();

private:
	sinsp* m_inspector;

	friend class sinsp_evt_formatter;
};


/*!
  \brief This is the class that compiles sysdig-type filters.
*/
class SINSP_PUBLIC sinsp_filter_compiler
{
public:
	/*!
	  \brief Constructs the compiler.

	  \param inspector Pointer to the inspector instance that will generate the
	   events to be filtered.
	  \param fltstr the filter string to compile.
	  \param ttable_only for internal use only.

	 \note Throws a sinsp_exception if the filter syntax is not valid.
	*/
	sinsp_filter_compiler(sinsp* inspector/* xxx needed? */, const string& fltstr, bool ttable_only=false);

	~sinsp_filter_compiler();

	sinsp_filter* compile();

private:
	enum state
	{
		ST_EXPRESSION_DONE,
		ST_NEED_EXPRESSION,
	};

	sinsp_filter* compile_();

	char next();
	bool compare_no_consume(const string& str);

	vector<char> next_operand(bool expecting_first_operand, bool in_clause);
	cmpop next_comparison_operator();
	void parse_check();

	static bool isblank(char c);
	static bool is_special_char(char c);
	static bool is_bracket(char c);

	sinsp* m_inspector;
	bool m_ttable_only;

	string m_fltstr;
	int32_t m_scanpos;
	int32_t m_scansize;
	state m_state;
	boolop m_last_boolop;
	int32_t m_nest_level;

	sinsp_filter* m_filter;

	friend class sinsp_evt_formatter;
};

/*!
  \brief This class represents a filter optimized using event
  types. It actually consists of collections of sinsp_filter objects
  grouped by event type.
*/

class SINSP_PUBLIC sinsp_evttype_filter
{
public:
	sinsp_evttype_filter();
	virtual ~sinsp_evttype_filter();

	void add(std::string &name,
		 std::set<uint32_t> &evttypes,
		 std::set<uint32_t> &syscalls,
		 std::set<string> &tags,
		 sinsp_filter* filter);

	// rulesets are arbitrary numbers and should be managed by the caller.
        // Note that rulesets are used to index into a std::vector so
        // specifying unnecessarily large rulesets will result in
        // unnecessarily large vectors.

	// Find those rules matching the provided pattern and set
	// their enabled status to enabled.
	void enable(const std::string &pattern, bool enabled, uint16_t ruleset = 0);

	// Find those rules that have a tag in the set of tags and set
	// their enabled status to enabled. Note that the enabled
	// status is on the rules, and not the tags--if a rule R has
	// tags (a, b), and you call enable_tags([a], true) and then
	// enable_tags([b], false), R will be disabled despite the
	// fact it has tag a and was enabled by the first call to
	// enable_tags.
	void enable_tags(const std::set<string> &tags, bool enabled, uint16_t ruleset = 0);

	// Match all filters against the provided event.
	bool run(sinsp_evt *evt, uint16_t ruleset = 0);

	// Populate the provided vector, indexed by event type, of the
	// event types associated with the given ruleset id. For
	// example, evttypes[10] = true would mean that this ruleset
	// relates to event type 10.
	void evttypes_for_ruleset(std::vector<bool> &evttypes, uint16_t ruleset);

	// Populate the provided vector, indexed by syscall code, of the
	// syscall codes associated with the given ruleset id. For
	// example, syscalls[10] = true would mean that this ruleset
	// relates to syscall code 10.
	void syscalls_for_ruleset(std::vector<bool> &syscalls, uint16_t ruleset);

private:

	struct filter_wrapper {
		sinsp_filter *filter;

		// Indexes from event type to enabled/disabled.
		std::vector<bool> evttypes;

		// Indexes from syscall code to enabled/disabled.
		std::vector<bool> syscalls;
	};

	// A group of filters all having the same ruleset
	class ruleset_filters {
	public:
		ruleset_filters();

		virtual ~ruleset_filters();

		void add_filter(filter_wrapper *wrap);
		void remove_filter(filter_wrapper *wrap);

		bool run(sinsp_evt *evt);

		void evttypes_for_ruleset(std::vector<bool> &evttypes);

		void syscalls_for_ruleset(std::vector<bool> &syscalls);

	private:
		// Maps from event type to filter. There can be multiple
		// filters per event type.
		std::list<filter_wrapper *> *m_filter_by_evttype[PPM_EVENT_MAX];

		// Maps from syscall number to filter. There can be multiple
		// filters per syscall number
		std::list<filter_wrapper *> *m_filter_by_syscall[PPM_SC_MAX];
	};

	std::vector<ruleset_filters *> m_rulesets;

	// Maps from tag to list of filters having that tag.
	std::map<std::string, std::list<filter_wrapper *>> m_filter_by_tag;

	// This holds all the filters passed to add(), so they can
	// be cleaned up.
	map<std::string,filter_wrapper *> m_filters;
};

/*@}*/

class sinsp_filter_factory : public gen_event_filter_factory
{
public:
	sinsp_filter_factory(sinsp *inspector);
	virtual ~sinsp_filter_factory();

	gen_event_filter *new_filter();

	gen_event_filter_check *new_filtercheck(const char *fldname);

protected:
	sinsp *m_inspector;
};

#endif // HAS_FILTERING
