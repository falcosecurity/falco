/*
Copyright (C) 2013-2018 Draios inc.

This file is part of sysdig.

sysdig is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License version 2 as
published by the Free Software Foundation.

sysdig is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with sysdig.  If not, see <http://www.gnu.org/licenses/>.
*/

#pragma once

#include <vector>

/*
 * Operators to compare events
 */
enum cmpop {
	CO_NONE = 0,
	CO_EQ = 1,
	CO_NE = 2,
	CO_LT = 3,
	CO_LE = 4,
	CO_GT = 5,
	CO_GE = 6,
	CO_CONTAINS = 7,
	CO_IN = 8,
	CO_EXISTS = 9,
	CO_ICONTAINS = 10,
	CO_STARTSWITH = 11,
	CO_GLOB = 12,
	CO_PMATCH = 13,
	CO_ENDSWITH = 14,
	CO_INTERSECTS = 15,
};

enum boolop
{
	BO_NONE = 0,
	BO_NOT = 1,
	BO_OR = 2,
	BO_AND = 4,

	// obtained by bitwise OR'ing with one of above ops
	BO_ORNOT = 3,
	BO_ANDNOT = 5,
};

enum evt_src
{
	ESRC_NONE = 0,
	ESRC_SINSP = 1,
	ESRC_K8S_AUDIT = 2,
	ESRC_MAX = 3,
};

class gen_event
{
public:
	gen_event();
	virtual ~gen_event();

	/*!
	  \brief Set an opaque "check id", corresponding to the id of the last filtercheck that matched this event.
	*/
	void set_check_id(int32_t id);

	/*!
	  \brief Get the opaque "check id" (-1 if not set).
	*/
	int32_t get_check_id();

	// Every event must expose a timestamp
	virtual uint64_t get_ts() = 0;

	/*!
	  \brief Get the source of the event.
	*/
	virtual uint16_t get_source() = 0;

	/*!
	  \brief Get the type of the event.
	*/
	virtual uint16_t get_type() = 0;

private:
	int32_t m_check_id = 0;

};


class gen_event_filter_check
{
public:
	gen_event_filter_check();
	virtual ~gen_event_filter_check();

	boolop m_boolop;
	cmpop m_cmpop;

	virtual int32_t parse_field_name(const char* str, bool alloc_state, bool needed_for_filtering) = 0;
	virtual void add_filter_value(const char* str, uint32_t len, uint32_t i = 0 ) = 0;
	virtual bool compare(gen_event *evt) = 0;
	virtual uint8_t* extract(gen_event *evt, uint32_t* len, bool sanitize_strings = true) = 0;

	//
	// Configure numeric id to be set on events that match this filter
	//
	void set_check_id(int32_t id);
	virtual int32_t get_check_id();

private:
	int32_t m_check_id = 0;

};

///////////////////////////////////////////////////////////////////////////////
// Filter expression class
// A filter expression contains multiple filters connected by boolean expressions,
// e.g. "check or check", "check and check and check", "not check"
///////////////////////////////////////////////////////////////////////////////

class gen_event_filter_expression : public gen_event_filter_check
{
public:
	gen_event_filter_expression();
	virtual ~gen_event_filter_expression();

	//
	// The following methods are part of the filter check interface but are irrelevant
	// for this class, because they are used only for the leaves of the filtering tree.
	//
	int32_t parse_field_name(const char* str, bool alloc_state, bool needed_for_filtering)
	{
		return 0;
	}

	void add_filter_value(const char* str, uint32_t len, uint32_t i = 0 )
	{
		return;
	}

	void add_check(gen_event_filter_check* chk);

	bool compare(gen_event *evt);

	uint8_t* extract(gen_event *evt, uint32_t* len, bool sanitize_strings = true);

	gen_event_filter_expression* m_parent;
	std::vector<gen_event_filter_check*> m_checks;
};



class gen_event_filter
{
public:
	gen_event_filter();

	virtual ~gen_event_filter();

	/*!
	  \brief Applies the filter to the given event.

	  \param evt Pointer that needs to be filtered.
	  \return true if the event is accepted by the filter, false if it's rejected.
	*/
	bool run(gen_event *evt);
	void push_expression(boolop op);
	void pop_expression();
	void add_check(gen_event_filter_check* chk);

protected:
	gen_event_filter_expression* m_curexpr;
	gen_event_filter_expression* m_filter;

};

class gen_event_filter_factory
{
public:

	gen_event_filter_factory() {};
	virtual ~gen_event_filter_factory() {};

	// Create a new filter
	virtual gen_event_filter *new_filter() = 0;

	// Create a new filtercheck
	virtual gen_event_filter_check *new_filtercheck(const char *fldname) = 0;
};


