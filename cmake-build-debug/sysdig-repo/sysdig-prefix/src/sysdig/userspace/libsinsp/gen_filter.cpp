/*
Copyright (C) 2013-2014 Draios inc.

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

#include <cstddef>
#include "stdint.h"
#include "gen_filter.h"
#include "sinsp.h"
#include "sinsp_int.h"

gen_event::gen_event()
{
}

gen_event::~gen_event()
{
}

void gen_event::set_check_id(int32_t id)
{
	if (id) {
		m_check_id = id;
	}
}

int32_t gen_event::get_check_id()
{
	return m_check_id;
}

gen_event_filter_check::gen_event_filter_check()
{
}

gen_event_filter_check::~gen_event_filter_check()
{
}

void gen_event_filter_check::set_check_id(int32_t id)
{
	m_check_id = id;
}

int32_t gen_event_filter_check::get_check_id()
{
	return m_check_id;
}

///////////////////////////////////////////////////////////////////////////////
// gen_event_filter_expression implementation
///////////////////////////////////////////////////////////////////////////////
gen_event_filter_expression::gen_event_filter_expression()
{
	m_parent = NULL;
}

gen_event_filter_expression::~gen_event_filter_expression()
{
	uint32_t j;

	for(j = 0; j < m_checks.size(); j++)
	{
		delete m_checks[j];
	}
}

void gen_event_filter_expression::add_check(gen_event_filter_check* chk)
{
	m_checks.push_back(chk);
}

bool gen_event_filter_expression::compare(gen_event *evt)
{
	uint32_t j;
	uint32_t size = (uint32_t)m_checks.size();
	bool res = true;
	gen_event_filter_check* chk = NULL;

	for(j = 0; j < size; j++)
	{
		chk = m_checks[j];
		ASSERT(chk != NULL);

		if(j == 0)
		{
			switch(chk->m_boolop)
			{
			case BO_NONE:
				res = chk->compare(evt);
				if (res) {
					evt->set_check_id(chk->get_check_id());
				}
				break;
			case BO_NOT:
				res = !chk->compare(evt);
				break;
			default:
				ASSERT(false);
				break;
			}
		}
		else
		{
			switch(chk->m_boolop)
			{
			case BO_OR:
				if(res)
				{
					goto done;
				}
				res = chk->compare(evt);
				if (res) {
					evt->set_check_id(chk->get_check_id());
				}
				break;
			case BO_AND:
				if(!res)
				{
					goto done;
				}
				res = chk->compare(evt);
				if (res) {
					evt->set_check_id(chk->get_check_id());
				}
				break;
			case BO_ORNOT:
				if(res)
				{
					goto done;
				}
				res = !chk->compare(evt);
				if (res) {
					evt->set_check_id(chk->get_check_id());
				}
				break;
			case BO_ANDNOT:
				if(!res)
				{
					goto done;
				}
				res = !chk->compare(evt);
				if (res) {
					evt->set_check_id(chk->get_check_id());
				}
				break;
			default:
				ASSERT(false);
				break;
			}
		}
	}
 done:

	return res;
}

uint8_t *gen_event_filter_expression::extract(gen_event *evt, uint32_t *len, bool sanitize_strings)
{
	return NULL;
}

///////////////////////////////////////////////////////////////////////////////
// sinsp_filter implementation
///////////////////////////////////////////////////////////////////////////////
gen_event_filter::gen_event_filter()
{
	m_filter = new gen_event_filter_expression();
	m_curexpr = m_filter;

}

gen_event_filter::~gen_event_filter()
{
	if(m_filter)
	{
		delete m_filter;
	}
}

void gen_event_filter::push_expression(boolop op)
{
	gen_event_filter_expression* newexpr = new gen_event_filter_expression();
	newexpr->m_boolop = op;
	newexpr->m_parent = m_curexpr;

	add_check((gen_event_filter_check*)newexpr);
	m_curexpr = newexpr;
}

void gen_event_filter::pop_expression()
{
	ASSERT(m_curexpr->m_parent != NULL);

	m_curexpr = m_curexpr->m_parent;
}

bool gen_event_filter::run(gen_event *evt)
{
	return m_filter->compare(evt);
}

void gen_event_filter::add_check(gen_event_filter_check* chk)
{
	m_curexpr->add_check((gen_event_filter_check *) chk);
}


