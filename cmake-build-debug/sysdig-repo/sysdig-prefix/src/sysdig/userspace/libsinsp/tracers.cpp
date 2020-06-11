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

#include <time.h>
#include "sinsp.h"
#include "sinsp_int.h"
#include "tracers.h"

sinsp_tracerparser::sinsp_tracerparser(sinsp *inspector)
{
	m_inspector = inspector;
	m_storage_size = 0;
	m_storage = NULL;
	m_res = sinsp_tracerparser::RES_OK;
	m_fragment_size = 0;
	m_enter_pae = NULL;
}

sinsp_tracerparser::~sinsp_tracerparser()
{
	if(m_storage)
	{
		free(m_storage);
	}
}

void sinsp_tracerparser::set_storage_size(uint32_t newsize)
{
	m_storage = (char*)realloc(m_storage, newsize);
	if(m_storage == NULL)
	{
		throw sinsp_exception("memory allocation error in sinsp_tracerparser::process_event_data.");
	}

	m_storage_size = newsize;
}

sinsp_tracerparser::parse_result sinsp_tracerparser::process_event_data(char *data, uint32_t datalen, uint64_t ts)
{
	ASSERT(data != NULL);
	m_storlen = m_fragment_size + datalen;

	//
	// Make sure we have enough space in the buffer and copy the data into it
	//
	if(m_storage_size < m_storlen + 1)
	{
		set_storage_size(m_storlen + 1);
	}

	memcpy(m_storage + m_fragment_size, data, datalen);
	m_storage[m_storlen] = 0;

	if(m_fragment_size != 0)
	{
		m_fullfragment_storage_str = m_storage;
	}

	//
	// Do the parsing
	//
	if(m_storlen > 0)
	{
		//
		// Reset the content
		//
		m_res = sinsp_tracerparser::RES_OK;
		m_tags.clear();
		m_argnames.clear();
		m_argvals.clear();
		m_taglens.clear();
		m_argnamelens.clear();
		m_argvallens.clear();
		m_tot_taglens = 0;
		m_tot_argnamelens = 0;
		m_tot_argvallens = 0;

		if(m_storage[0] == '>' || m_storage[0] == '<')
		{
			parse_simple(m_storage);
		}
		else
		{
			parse_json(m_storage);
		}
	}
	else
	{
		m_res = sinsp_tracerparser::RES_FAILED;
	}

	if(m_res == sinsp_tracerparser::RES_FAILED)
	{
		//
		// Invalid syntax
		//
		m_fragment_size = 0;
		m_fullfragment_storage_str.clear();
		return m_res;
	}
	else if(m_res == sinsp_tracerparser::RES_TRUNCATED)
	{
		//
		// Valid syntax, but the message is incomplete. Buffer it and wait for
		// more fragments.
		//
		if(m_fragment_size > MAX_USER_EVT_BUFFER)
		{
			//
			// Maximum buffering size reached, drop the event
			//
			m_fragment_size = 0;
			return m_res;
		}

		if(m_fullfragment_storage_str.length() == 0)
		{
			memcpy(m_storage, 
				data, 
				datalen);

			m_storage[datalen] = 0;
			m_fragment_size += datalen;
		}
		else
		{
			uint32_t tlen = (uint32_t)m_fullfragment_storage_str.length();

			memcpy(m_storage, 
				m_fullfragment_storage_str.c_str(), 
				tlen);

			m_fragment_size = tlen;
		}

		return m_res;
	}

	m_fragment_size = 0;
	m_fullfragment_storage_str.clear();

	//
	// Parser tests stop here
	//
	if(m_inspector == NULL)
	{
		return sinsp_tracerparser::RES_OK;
	}

	//
	// Event decoding done. We do state tracking only if explicitly requested
	// by one or more filters.
	//
	if(m_inspector->m_track_tracers_state == false)
	{
		return sinsp_tracerparser::RES_OK;
	}

	//
	// If this is an enter event, allocate a sinsp_partial_tracer object and
	// push it to the list
	//
	if(m_type_str[0] == '>')
	{
		sinsp_partial_tracer* pae = m_inspector->m_partial_tracers_pool->pop();
		if(pae == NULL)
		{
			//
			// The list is completely used. This likely means that there have been drops and 
			// the entries will be stuck there forever. Better clean the list, miss the 128
			// events it contains, and start fresh.
			//
			list<sinsp_partial_tracer*>* partial_tracers_list = &m_inspector->m_partial_tracers_list;
			list<sinsp_partial_tracer*>::iterator it;

			for(it = partial_tracers_list->begin(); it != partial_tracers_list->end(); ++it)
			{
				m_inspector->m_partial_tracers_pool->push(*it);
			}

			partial_tracers_list->clear();

			return sinsp_tracerparser::RES_OK;
		}

		init_partial_tracer(pae);
		pae->m_time = ts;
		m_inspector->m_partial_tracers_list.push_front(pae);
		m_enter_pae = pae;
	}
	else
	{
		list<sinsp_partial_tracer*>* partial_tracers_list = &m_inspector->m_partial_tracers_list;
		list<sinsp_partial_tracer*>::iterator it;

		init_partial_tracer(&m_exit_pae);

		for(it = partial_tracers_list->begin(); it != partial_tracers_list->end(); ++it)
		{
			if(m_exit_pae.compare(*it) == true)
			{
				m_exit_pae.m_time = ts;

				//
				// This is a bit tricky and deserves some explanation:
				// despite removing the pae and returning it to the available pool,
				// we link to it so that the filters will use it. We do that as an
				// optimization (it avoids making a copy or implementing logic for 
				// delayed list removal), and we base it on the assumption that,
				// since the processing is strictly sequential and single thread,
				// nobody will modify the pae until the event is fully processed.
				//
				m_enter_pae = *it;

				m_inspector->m_partial_tracers_pool->push(*it);
				partial_tracers_list->erase(it);
				return sinsp_tracerparser::RES_OK;
			}
		}

		m_enter_pae = NULL;
	}

	return sinsp_tracerparser::RES_OK;
}

sinsp_partial_tracer* sinsp_tracerparser::find_parent_enter_pae()
{
	list<sinsp_partial_tracer*>* partial_tracers_list = &m_inspector->m_partial_tracers_list;
	list<sinsp_partial_tracer*>::iterator it;

	char* tse = m_enter_pae->m_tags_storage + m_tot_taglens;
	if(*tse == 0 && tse > m_enter_pae->m_tags_storage)
	{
		--tse;
	}

	uint32_t len = 0;
	while(tse != m_enter_pae->m_tags_storage)
	{
		if(*tse == 0)
		{
			len = tse - m_enter_pae->m_tags_storage + 1; // 1 is for the traling zero
			break;
		}

		--tse;
	}

	for(it = partial_tracers_list->begin(); it != partial_tracers_list->end(); ++it)
	{
		if(m_enter_pae->compare(*it, len) == true)
		{
			return *it;
		}
	}

	return NULL;
}

inline void sinsp_tracerparser::parse_json(char* evtstr)
{
	char* p = m_storage;
	uint32_t delta;
	char* tstr;

	//
	// Skip the initial bracket
	//
	m_res = skip_spaces(p, &delta);
	if(m_res != sinsp_tracerparser::RES_OK)
	{
		return;
	}
	p += delta;

	if(*(p++) != '[')
	{
		m_res = sinsp_tracerparser::RES_FAILED;
		return;
	}

	//
	// type
	//
	m_res = parsestr(p, &m_type_str, &delta);
	if(m_res != sinsp_tracerparser::RES_OK)
	{
		return;
	}
	p += delta;

	//
	// ID
	//
	m_res = skip_spaces_and_commas(p, &delta, 1);
	if(m_res != sinsp_tracerparser::RES_OK)
	{
		return;
	}
	p += delta;

	if(*p == '"')
	{
		switch(*(++p))
		{
		case 't':
			m_id = m_tinfo->m_tid;
			delta = 2;
			break;
		case 'p':
			m_id = m_tinfo->m_pid;
			if(*(p + 1) == 'p')
			{
				m_id = m_tinfo->m_ptid;
				p++;
			}

			delta = 2;
			break;
		case ':':
			m_id = 0;
			delta = 1;
			break;
		case 'g':
			m_id = 0;
			delta = 2;
			break;
		default:
			m_res = sinsp_tracerparser::RES_FAILED;
			break;
		}
	}
	else
	{
		m_res = parsenumber(p, &m_id, &delta);
		if(m_res > sinsp_tracerparser::RES_COMMA)
		{
			return;
		}
	}

	p += delta;

	if(m_res == sinsp_tracerparser::RES_COMMA)
	{
		m_res = skip_spaces(p, &delta);
	}
	else
	{
		m_res = skip_spaces_and_commas(p, &delta, 1);
	}

	if(m_res != sinsp_tracerparser::RES_OK)
	{
		return;
	}
	p += delta;

	//
	// First tag
	//
	m_res = skip_spaces_and_char(p, &delta, '[');
	if(m_res != sinsp_tracerparser::RES_OK)
	{
		return;
	}
	p += delta;

	m_res = parsestr_not_enforce(p, &tstr, &delta);
	if(m_res != sinsp_tracerparser::RES_OK)
	{
		return;
	}
	p += delta;

	if(tstr != NULL)
	{
		m_tags.push_back(tstr);
		m_taglens.push_back(delta - 2);
		m_tot_taglens += delta - 2;

		//
		// Remaining tags
		//
		while(true)
		{
			m_res = skip_spaces_and_commas(p, &delta, 0);
			if(m_res != sinsp_tracerparser::RES_OK)
			{
				return;
			}
			p += delta;

			if(*p == ']')
			{
				break;
			}

			m_res = parsestr(p, &tstr, &delta);
			if(m_res != sinsp_tracerparser::RES_OK)
			{
				return;
			}
			p += delta;
			m_tags.push_back(tstr);
			m_taglens.push_back(delta - 2);
			m_tot_taglens += delta - 2;
		}
	}

	//
	// First argument
	//
	m_res = skip_spaces_and_commas_and_all_brakets(p, &delta);
	if(m_res != sinsp_tracerparser::RES_OK)
	{
		return;
	}
	p += delta;

	m_res = parsestr_not_enforce(p, &tstr, &delta);
	if(m_res != sinsp_tracerparser::RES_OK)
	{
		return;
	}
	p += delta;

	if(tstr != NULL)
	{
		m_argnames.push_back(tstr);
		m_argnamelens.push_back(delta - 2);
		m_tot_argnamelens += delta - 2;

		m_res = skip_spaces_and_char(p, &delta, ':');
		if(m_res != sinsp_tracerparser::RES_OK)
		{
			return;
		}
		p += delta;

		m_res = parsestr(p, &tstr, &delta);
		if(m_res != sinsp_tracerparser::RES_OK)
		{
			return;
		}
		p += delta;
		m_argvals.push_back(tstr);
		m_argvallens.push_back(delta - 2);
		m_tot_argvallens += delta - 2;

		//
		// Remaining arguments
		//
		while(true)
		{
			m_res = skip_spaces_and_commas_and_cr_brakets(p, &delta);
			if(m_res != sinsp_tracerparser::RES_OK)
			{
				return;
			}
			p += delta;

			if(*p == ']')
			{
				p++;
				break;
			}

			m_res = parsestr(p, &tstr, &delta);
			if(m_res != sinsp_tracerparser::RES_OK)
			{
				return;
			}
			p += delta;
			m_argnames.push_back(tstr);
			m_argnamelens.push_back(delta - 2);
			m_tot_argnamelens += delta - 2;

			m_res = skip_spaces_and_char(p, &delta, ':');
			if(m_res != sinsp_tracerparser::RES_OK)
			{
				return;
			}
			p += delta;

			m_res = parsestr(p, &tstr, &delta);
			if(m_res != sinsp_tracerparser::RES_OK)
			{
				return;
			}
			p += delta;
			m_argvals.push_back(tstr);
			m_argvallens.push_back(delta - 2);
			m_tot_argvallens += delta - 2;
		}
	}

	//
	// Terminating ]
	//
	m_res = skip_spaces(p, &delta);
	if(m_res != sinsp_tracerparser::RES_OK)
	{
		return;
	}
	p += delta;

	if(*p != ']')
	{
		if(*p == 0)
		{
			m_res = sinsp_tracerparser::RES_TRUNCATED;
		}
		else
		{
			m_res = sinsp_tracerparser::RES_FAILED;
		}
		return;
	}

	m_res = sinsp_tracerparser::RES_OK;
	return;
}

inline void sinsp_tracerparser::delete_char(char* p)
{
	while(*p != 0)
	{
		*p = *(p + 1);
		p++;
	}
}

inline void sinsp_tracerparser::parse_simple(char* evtstr)
{
	char* p = evtstr;
	uint32_t delta;

	//
	// Extract the type
	//
	m_type_str = p++;

	//
	// Skip to the scope/id
	//
	if(*p != ':')
	{
		if(*p == 0)
		{
			m_res = sinsp_tracerparser::RES_TRUNCATED;
		}
		else
		{
			m_res = sinsp_tracerparser::RES_FAILED;
		}
		return;
	}

	*p = 0;
	p++;

	//
	// Extract the scope
	//
	if(*p == '0')
	{
		m_res = sinsp_tracerparser::RES_TRUNCATED;
		return;
	}

	switch(*p)
	{
	case 't':
		m_id = m_tinfo->m_tid;
		delta = 2;
		break;
	case 'p':
		m_id = m_tinfo->m_pid;
		if(*(p + 1) == 'p')
		{
			m_id = m_tinfo->m_ptid;
			p++;
		}

		delta = 2;
		break;
	case ':':
		m_id = 0;
		delta = 1;
		break;
	case 'g':
		m_id = 0;
		delta = 2;
		break;
	default:
		m_res = parsenumber_colend(p, &m_id, &delta);
		if(m_res > sinsp_tracerparser::RES_COMMA)
		{
			return;
		}
		break;
	}

	p += delta;

	//
	// Extract the tags
	//
	if(*p == '0')
	{
		m_res = sinsp_tracerparser::RES_TRUNCATED;
		return;
	}

	if(*p != ':')
	{
		bool dont_interpret_next_char = false;

		while(true)
		{
			char* start = p;

			m_tags.push_back(p);

			while(*p != 0)
			{
				if(dont_interpret_next_char)
				{
					dont_interpret_next_char = false;
					++p;
					continue;
				}

				if(*p == '\\')
				{
					ASSERT(dont_interpret_next_char == false);
					dont_interpret_next_char = true;
					delete_char(p);
					continue;
				}

				if(*p == '.' || *p == ':')
				{
					break;
				}

				if(*p == '>' || *p == '<' || *p == '=' || *p == '\n')
				{
					m_res = sinsp_tracerparser::RES_FAILED;
					return;
				}

				++p;
			}

			m_taglens.push_back((uint32_t)(p - start));
			m_tot_taglens += (uint32_t)(p - start);

			if(*p == ':')
			{
				*p = 0;
				break;
			}
			else if(*p == 0)
			{
				m_res = sinsp_tracerparser::RES_TRUNCATED;
				return;
			}
			else
			{
				*p = 0;
				++p;
			}
		}
	}

	++p;

	//
	// Extract the arguments
	//
	if(*p == 0)
	{
		m_res = sinsp_tracerparser::RES_TRUNCATED;
		return;
	}

	if(*p != ':')
	{
		bool dont_interpret_next_char = false;

		while(true)
		{
			char* start = p;

			//
			// Arg name
			//
			m_argnames.push_back(p);

			while(*p != 0)
			{
				if(dont_interpret_next_char)
				{
					dont_interpret_next_char = false;
					++p;
					continue;
				}

				if(*p == '\\')
				{
					ASSERT(dont_interpret_next_char == false);
					dont_interpret_next_char = true;
					delete_char(p);
					continue;
				}

				if(*p == '=')
				{
					break;
				}

				if(*p == '>' || *p == '<' || *p == '\n')
				{
					m_res = sinsp_tracerparser::RES_FAILED;
					return;
				}

				++p;
			}

			m_argnamelens.push_back((uint32_t)(p - start));
			m_tot_argnamelens += (uint32_t)(p - start);

			if(*p == 0)
			{
				if(*(p - 1) == ':')
				{
					//
					// This means there was an argument without value, 
					// which we don't support
					//
					m_res = sinsp_tracerparser::RES_FAILED;
				}
				else
				{
					m_res = sinsp_tracerparser::RES_TRUNCATED;
				}
				break;
			}
			else
			{
				*p = 0;
				++p;
			}

			//
			// Arg vals
			//
			start = p;
			m_argvals.push_back(p);

			dont_interpret_next_char = false;

			while(*p != 0)
			{
				if(dont_interpret_next_char)
				{
					dont_interpret_next_char = false;
					++p;
					continue;
				}

				if(*p == '\\')
				{
					ASSERT(dont_interpret_next_char == false);
					dont_interpret_next_char = true;
					delete_char(p);
					continue;
				}

				if(*p == ',' || *p == ':' || *p == '=')
				{
					break;
				}

				++p;
			}

			m_argvallens.push_back((uint32_t)(p - start));
			m_tot_argvallens += (uint32_t)(p - start);

			if(*p == ':')
			{
				*p = 0;
				m_res = sinsp_tracerparser::RES_OK;
				break;
			}
			else if(*p == 0)
			{
				m_res = sinsp_tracerparser::RES_TRUNCATED;
				break;
			}
			else
			{
				*p = 0;
				++p;
			}
		}
	}

	//
	// All done
	//
	return;
}

inline sinsp_tracerparser::parse_result sinsp_tracerparser::skip_spaces(char* p, uint32_t* delta)
{
	char* start = p;

	while(*p == ' ')
	{
		if(*p == 0)
		{
			return sinsp_tracerparser::RES_TRUNCATED;
		}

		p++;
	}

	*delta = (uint32_t)(p - start);
	return sinsp_tracerparser::RES_OK;
}

inline sinsp_tracerparser::parse_result sinsp_tracerparser::skip_spaces_and_commas(char* p, uint32_t* delta, uint32_t n_expected_commas)
{
	char* start = p;
	uint32_t nc = 0;

	while(true)
	{
		if(*p == ' ')
		{
			p++;
			continue;
		}
		else if(*p == ',')
		{
			nc++;
		}
		else if(*p == 0)
		{
			return sinsp_tracerparser::RES_TRUNCATED;
		}
		else
		{
			break;
		}

		p++;
	}

	if(nc < n_expected_commas)
	{
		return sinsp_tracerparser::RES_FAILED;
	}

	*delta = (uint32_t)(p - start);
	return sinsp_tracerparser::RES_OK;
}

inline sinsp_tracerparser::parse_result sinsp_tracerparser::skip_spaces_and_char(char* p, uint32_t* delta, char char_to_skip)
{
	char* start = p;
	uint32_t nc = 0;

	while(*p == ' ' || *p == char_to_skip || *p == 0)
	{
		if(*p == 0)
		{
			return sinsp_tracerparser::RES_TRUNCATED;
		}
		else if(*p == char_to_skip)
		{
			nc++;
		}

		p++;
	}

	if(nc != 1)
	{
		return sinsp_tracerparser::RES_FAILED;
	}

	*delta = (uint32_t)(p - start);
	return sinsp_tracerparser::RES_OK;
}

inline sinsp_tracerparser::parse_result sinsp_tracerparser::skip_spaces_and_commas_and_sq_brakets(char* p, uint32_t* delta)
{
	char* start = p;
	uint32_t nc = 0;
	uint32_t nosb = 0;

	while(*p == ' ' || *p == ',' || *p == '[' || *p == ']' || *p == 0)
	{
		if(*p == 0)
		{
			return sinsp_tracerparser::RES_TRUNCATED;
		}
		else if(*p == ',')
		{
			nc++;
		}
		else if(*p == '[')
		{
			nosb++;
		}
		else if(*p == ']')
		{
			if(nosb != 0)
			{
				break;
			}
		}

		p++;
	}

	if(nc != 1 || nosb != 1)
	{
		return sinsp_tracerparser::RES_FAILED;
	}

	*delta = (uint32_t)(p - start);
	return sinsp_tracerparser::RES_OK;
}

inline sinsp_tracerparser::parse_result sinsp_tracerparser::skip_spaces_and_commas_and_cr_brakets(char* p, uint32_t* delta)
{
	char* start = p;
	uint32_t nc = 0;
	uint32_t nocb = 0;
	uint32_t nccb = 0;

	while(*p == ' ' || *p == ',' || *p == '{' || *p == '}' || *p == 0)
	{
		if(*p == 0)
		{
			return sinsp_tracerparser::RES_TRUNCATED;
		}
		else if(*p == ',')
		{
			nc++;
		}
		else if(*p == '{')
		{
			nocb++;
		}
		else if(*p == '}')
		{
			nccb++;
		}

		p++;
	}

	if(!((nc == 1 && nocb == 1) || (nc == 1 && nccb == 1) || (nccb == 1 && *p == ']')))
	{
		return sinsp_tracerparser::RES_FAILED;
	}

	*delta = (uint32_t)(p - start);
	return sinsp_tracerparser::RES_OK;
}

inline sinsp_tracerparser::parse_result sinsp_tracerparser::skip_spaces_and_commas_and_all_brakets(char* p, uint32_t* delta)
{
	char* start = p;
	uint32_t nc = 0;
	uint32_t nosb = 0;
	uint32_t nocb = 0;

	while(*p == ' ' || *p == ',' || *p == '[' || *p == ']' || *p == '{' || *p == '}' || (*p == 0))
	{
		if(*p == 0)
		{
			return sinsp_tracerparser::RES_TRUNCATED;
		}
		else if(*p == ',')
		{
			nc++;
		}
		else if(*p == '[')
		{
			nosb++;
		}
		else if(*p == ']')
		{
			if(nosb != 0)
			{
				break;
			}
		}
		else if(*p == '{')
		{
			nocb++;
		}

		p++;
	}

	if(nc != 1 || nosb != 1)
	{
		return sinsp_tracerparser::RES_FAILED;
	}
	else if(nocb != 1)
	{
		if(*p != ']')
		{
			return sinsp_tracerparser::RES_FAILED;
		}
	}

	*delta = (uint32_t)(p - start);
	return sinsp_tracerparser::RES_OK;
}

inline sinsp_tracerparser::parse_result sinsp_tracerparser::parsestr(char* p, char** res, uint32_t* delta)
{
	char* initial = p;
	*res = NULL;

	//
	// Make sure that we start with a \"
	//
	if(*p != '"')
	{
		*delta = (uint32_t)(p - initial + 1);
		if(*p == 0)
		{
			return sinsp_tracerparser::RES_TRUNCATED;
		}
		else
		{
			return sinsp_tracerparser::RES_FAILED;
		}
	}

	*res = p + 1;
	p++;

	//
	// Navigate to the end of the string
	//
	while(!(*p == '\"' && *(p - 1) != '\\'))
	{
		if(*p == 0)
		{
			*delta = (uint32_t)(p - initial + 1);
			return sinsp_tracerparser::RES_TRUNCATED;
		}

		p++;
	}

	*p = 0;

	*delta = (uint32_t)(p - initial + 1);
	return sinsp_tracerparser::RES_OK;
}

inline sinsp_tracerparser::parse_result sinsp_tracerparser::parsestr_not_enforce(char* p, char** res, uint32_t* delta)
{
	sinsp_tracerparser::parse_result psres = parsestr(p, res, delta);

	if(psres == sinsp_tracerparser::RES_FAILED)
	{
		if(*(p + *delta) == ']')
		{
			*res = NULL;
			return sinsp_tracerparser::RES_OK;
		}
	}
	else if(psres == sinsp_tracerparser::RES_TRUNCATED)
	{
		return psres;
	}

	return sinsp_tracerparser::RES_OK;
}

inline sinsp_tracerparser::parse_result sinsp_tracerparser::parsenumber(char* p, int64_t* res, uint32_t* delta)
{
	char* start = p;
	sinsp_tracerparser::parse_result retval = sinsp_tracerparser::RES_OK;
	int64_t val = 0;

	bool negative = false;

	if(*p == '-')
	{
		negative = true;
		p++;
	}

	while(*p >= '0' && *p <= '9')
	{
		val = val * 10 + (*p - '0');
		p++;
	}

	if(*p == ',')
	{
		retval = sinsp_tracerparser::RES_COMMA;
	}
	else if(*p != 0 && *p != ' ')
	{
		return sinsp_tracerparser::RES_FAILED;
	}
	else if(*p == 0)
	{
		return sinsp_tracerparser::RES_TRUNCATED;
	}


	*p = 0;

	if(negative)
	{
		*res = -val;
	}
	else
	{
		*res = val;
	}

	*delta = (uint32_t)(p - start + 1);
	return retval;
}

inline sinsp_tracerparser::parse_result sinsp_tracerparser::parsenumber_colend(char* p, int64_t* res, uint32_t* delta)
{
	char* start = p;
	int64_t val = 0;
	bool negative = false;

	if(*p == '-')
	{
		negative = true;
		p++;
	}

	while(*p >= '0' && *p <= '9')
	{
		val = val * 10 + (*p - '0');
		p++;
	}

	if(*p != ':')
	{
		if(*p == 0)
		{
			return sinsp_tracerparser::RES_TRUNCATED;
		}
		else
		{
			return sinsp_tracerparser::RES_FAILED;
		}
	}
	else
	{
		*delta = (uint32_t)(p - start + 1);
		if(negative)
		{
			*res = -val;
		}
		else
		{
			*res = val;
		}

		return sinsp_tracerparser::RES_OK;
	}
}

inline void sinsp_tracerparser::init_partial_tracer(sinsp_partial_tracer* pae)
{
	vector<char*>::iterator it;
	vector<uint32_t>::iterator sit;

	ASSERT(m_tinfo != NULL);
	pae->m_tid = m_tinfo->m_tid;

	//
	// Store the ID
	//
	pae->m_id = m_id;

	ASSERT(m_tags.size() == m_taglens.size());
	ASSERT(m_argnames.size() == m_argnamelens.size());
	ASSERT(m_argvals.size() == m_argvallens.size());

	//
	// Pack the tags
	//
	pae->m_tags.clear();
	pae->m_taglens.clear();
	pae->m_ntags = (uint32_t)m_tags.size();
	uint32_t encoded_tags_len = m_tot_taglens + pae->m_ntags + 1;

	if(pae->m_tags_storage_size < encoded_tags_len)
	{
		pae->m_tags_storage = (char*)realloc(pae->m_tags_storage, encoded_tags_len);
		pae->m_tags_storage_size = encoded_tags_len;
	}

	char* p = pae->m_tags_storage;
	for(it = m_tags.begin(), sit = m_taglens.begin(); 
	it != m_tags.end(); ++it, ++sit)
	{
		memcpy(p, *it, (*sit) + 1);
		pae->m_tags.push_back(p);
		pae->m_taglens.push_back(*sit);
		p += (*sit) + 1;
	}

	*p++ = 0;
	pae->m_tags_len = (uint32_t)(p - pae->m_tags_storage);

	//
	// Pack the argnames
	//
	pae->m_argnames.clear();
	pae->m_argnamelens.clear();
	pae->m_nargs = (uint32_t)m_argnames.size();
	uint32_t encoded_argnames_len = m_tot_argnamelens + pae->m_nargs + 1;

	if(pae->m_argnames_storage_size < encoded_argnames_len)
	{
		pae->m_argnames_storage = (char*)realloc(pae->m_argnames_storage, encoded_argnames_len);
		pae->m_argnames_storage_size = encoded_argnames_len;
	}

	p = pae->m_argnames_storage;
	for(it = m_argnames.begin(), sit = m_argnamelens.begin(); 
	it != m_argnames.end(); ++it, ++sit)
	{
		memcpy(p, *it, (*sit) + 1);
		pae->m_argnames.push_back(p);
		pae->m_argnamelens.push_back(*sit);
		p += (*sit) + 1;
	}

	*p++ = 0;
	pae->m_argnames_len = (uint32_t)(p - pae->m_argnames_storage);

	//
	// Pack the argvals
	//
	pae->m_argvals.clear();
	pae->m_argvallens.clear();
	uint32_t encoded_argvals_len = m_tot_argvallens + pae->m_nargs + 1;

	if(pae->m_argvals_storage_size < encoded_argvals_len)
	{
		pae->m_argvals_storage = (char*)realloc(pae->m_argvals_storage, encoded_argvals_len);
		pae->m_argvals_storage_size = encoded_argvals_len;
	}

	p = pae->m_argvals_storage;
	for(it = m_argvals.begin(), sit = m_argvallens.begin(); 
	it != m_argvals.end(); ++it, ++sit)
	{
		memcpy(p, *it, (*sit) + 1);
		pae->m_argvals.push_back(p);
		pae->m_argvallens.push_back(*sit);
		p += (*sit) + 1;
	}

	*p++ = 0;
	pae->m_argvals_len = (uint32_t)(p - pae->m_argvals_storage);
}

void sinsp_tracerparser::test()
{
	char doc1[] = "[\">\",     12345, [\"mysql\", \"query\", \"init\"], [{\"argname1\":\"argval1\"}, {\"argname2\":\"argval2\"}, {\"argname3\":\"argval3\"}]]";

	m_tinfo = new sinsp_threadinfo(nullptr);
	m_tinfo->m_ptid = 11;
	m_tinfo->m_pid = 22;
	m_tinfo->m_tid = 33;

	printf("1\n");

	float cpu_time = ((float)clock ()) / CLOCKS_PER_SEC;

	for(uint64_t j = 0; j < 30000000; j++)
	{
		process_event_data(doc1, sizeof(doc1) - 1, 10);

		if(m_res != sinsp_tracerparser::RES_OK)
		{
			printf("ERROR\n");
		}

		process_event_data(doc1, sizeof(doc1) - 1, 20);

		if(m_res != sinsp_tracerparser::RES_OK)
		{
			printf("ERROR\n");
		}
	}

	cpu_time = ((float)clock()/ CLOCKS_PER_SEC) - cpu_time;
	printf ("time: %5.2f\n", cpu_time);

	delete m_tinfo;
	m_tinfo = nullptr;
}
