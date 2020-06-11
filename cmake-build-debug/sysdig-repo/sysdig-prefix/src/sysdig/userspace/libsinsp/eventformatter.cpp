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

#include "sinsp.h"
#include "sinsp_int.h"
#include "filter.h"
#include "filterchecks.h"
#include "eventformatter.h"

///////////////////////////////////////////////////////////////////////////////
// rawstring_check implementation
///////////////////////////////////////////////////////////////////////////////
#ifdef HAS_FILTERING
extern sinsp_filter_check_list g_filterlist;

sinsp_evt_formatter::sinsp_evt_formatter(sinsp* inspector, const string& fmt)
{
	m_inspector = inspector;
	set_format(fmt);
}

sinsp_evt_formatter::~sinsp_evt_formatter()
{
	uint32_t j;

	for(j = 0; j < m_chks_to_free.size(); j++)
	{
		delete m_chks_to_free[j];
	}
}

void sinsp_evt_formatter::set_format(const string& fmt)
{
	uint32_t j;
	uint32_t last_nontoken_str_start = 0;
	string lfmt(fmt);

	if(lfmt == "")
	{
		throw sinsp_exception("empty formatting token");
	}

	//
	// If the string starts with a *, it means that we are ok with printing
	// the string even when not all the values it specifies are set.
	//
	if(lfmt[0] == '*')
	{
		m_require_all_values = false;
		lfmt.erase(0, 1);
	}
	else
	{
		m_require_all_values = true;
	}

	//
	// Parse the string and extract the tokens
	//
	const char* cfmt = lfmt.c_str();

	m_tokens.clear();
	uint32_t lfmtlen = (uint32_t)lfmt.length();

	for(j = 0; j < lfmtlen; j++)
	{
		if(cfmt[j] == '%')
		{
			int toklen = 0;

			if(last_nontoken_str_start != j)
			{
				rawstring_check* newtkn = new rawstring_check(lfmt.substr(last_nontoken_str_start, j - last_nontoken_str_start));
				m_tokens.emplace_back(make_pair("", newtkn));
				m_tokenlens.push_back(0);
				m_chks_to_free.push_back(newtkn);
			}

			if(j == lfmtlen - 1)
			{
				throw sinsp_exception("invalid formatting syntax: formatting cannot end with a %");
			}

			//
			// If the field specifier starts with a number, it means that we have a length modifier
			//
			if(isdigit(cfmt[j + 1]))
			{
				//
				// Parse the token length
				//
				sscanf(cfmt+ j + 1, "%d", &toklen);

				//
				// Advance until the beginning of the field name
				//
				while(true)
				{
					if(j == lfmtlen - 1)
					{
						throw sinsp_exception("invalid formatting syntax: formatting cannot end with a number");
					}
					else if(isdigit(cfmt[j + 1]))
					{
						j++;
						continue;
					}
					else
					{
						break;
					}
				}
			}

			sinsp_filter_check* chk = g_filterlist.new_filter_check_from_fldname(string(cfmt + j + 1),
				m_inspector,
				false);

			if(chk == NULL)
			{
				throw sinsp_exception("invalid formatting token " + string(cfmt + j + 1));
			}

			m_chks_to_free.push_back(chk);

			const char * fstart = cfmt + j + 1;
			uint32_t fsize = chk->parse_field_name(fstart, true, false);

			j += fsize;
			ASSERT(j <= lfmt.length());

			m_tokens.emplace_back(make_pair(string(fstart, fsize), chk));
			m_tokenlens.push_back(toklen);

			last_nontoken_str_start = j + 1;
		}
	}

	if(last_nontoken_str_start != j)
	{
		sinsp_filter_check * chk = new rawstring_check(lfmt.substr(last_nontoken_str_start, j - last_nontoken_str_start));
		m_tokens.emplace_back(make_pair("", chk));
		m_chks_to_free.push_back(chk);
		m_tokenlens.push_back(0);
	}
}

bool sinsp_evt_formatter::on_capture_end(OUT string* res)
{
	res->clear();
	return res->size() > 0;
}

bool sinsp_evt_formatter::resolve_tokens(sinsp_evt *evt, map<string,string>& values)
{
	bool retval = true;
	const filtercheck_field_info* fi;
	uint32_t j = 0;

	ASSERT(m_tokenlens.size() == m_tokens.size());

	for(j = 0; j < m_tokens.size(); j++)
	{
		char* str = m_tokens[j].second->tostring(evt);

		if(str == NULL)
		{
			if(m_require_all_values)
			{
				retval = false;
				break;
			}
			else
			{
				str = (char*)"<NA>";
			}
		}

		fi = m_tokens[j].second->get_field_info();
		if(fi)
		{
			values[m_tokens[j].first] = string(str);
		}
	}

	return retval;
}


bool sinsp_evt_formatter::tostring(sinsp_evt* evt, OUT string* res)
{
	bool retval = true;
	const filtercheck_field_info* fi;

	uint32_t j = 0;
	vector<sinsp_filter_check*>::iterator it;
	res->clear();

	ASSERT(m_tokenlens.size() == m_tokens.size());

	for(j = 0; j < m_tokens.size(); j++)
	{
		if(m_inspector->get_buffer_format() == sinsp_evt::PF_JSON
		   || m_inspector->get_buffer_format() == sinsp_evt::PF_JSONEOLS
		   || m_inspector->get_buffer_format() == sinsp_evt::PF_JSONHEX
		   || m_inspector->get_buffer_format() == sinsp_evt::PF_JSONHEXASCII
		   || m_inspector->get_buffer_format() == sinsp_evt::PF_JSONBASE64)
		{
			Json::Value json_value = m_tokens[j].second->tojson(evt);

			if(retval == false)
			{
				continue;
			}

			if(json_value == Json::nullValue && m_require_all_values)
			{
				retval = false;
				continue;
			}

			fi = m_tokens[j].second->get_field_info();

			if(fi)
			{
				m_root[m_tokens[j].first] = m_tokens[j].second->tojson(evt);
			}
		}
		else
		{
			char* str = m_tokens[j].second->tostring(evt);

			if(retval == false)
			{
				continue;
			}

			if(str == NULL)
			{
				if(m_require_all_values)
				{
					retval = false;
					continue;
				}
				else
				{
					str = (char*)"<NA>";
				}
			}

			uint32_t tks = m_tokenlens[j];

			if(tks != 0)
			{
				string sstr(str);
				sstr.resize(tks, ' ');
				(*res) += sstr;
			}
			else
			{
				(*res) += str;
			}
		}
	}

	if(m_inspector->get_buffer_format() == sinsp_evt::PF_JSON
	   || m_inspector->get_buffer_format() == sinsp_evt::PF_JSONEOLS
	   || m_inspector->get_buffer_format() == sinsp_evt::PF_JSONHEX
	   || m_inspector->get_buffer_format() == sinsp_evt::PF_JSONHEXASCII
	   || m_inspector->get_buffer_format() == sinsp_evt::PF_JSONBASE64)
	{
		(*res) = m_writer.write(m_root);
		(*res) = res->substr(0, res->size() - 1);
	}

	return retval;
}

#else  // HAS_FILTERING

sinsp_evt_formatter::sinsp_evt_formatter(sinsp* inspector, const string& fmt)
{
}

void sinsp_evt_formatter::set_format(const string& fmt)
{
	throw sinsp_exception("sinsp_evt_formatter unvavailable because it was not compiled in the library");
}

bool sinsp_evt_formatter::resolve_tokens(sinsp_evt *evt, map<string,string>& values)
{
	throw sinsp_exception("sinsp_evt_formatter unvavailable because it was not compiled in the library");
}

bool sinsp_evt_formatter::tostring(sinsp_evt* evt, OUT string* res)
{
	throw sinsp_exception("sinsp_evt_formatter unvavailable because it was not compiled in the library");
}
#endif // HAS_FILTERING

sinsp_evt_formatter_cache::sinsp_evt_formatter_cache(sinsp *inspector)
	: m_inspector(inspector)
{
}

sinsp_evt_formatter_cache::~sinsp_evt_formatter_cache()
{
}

std::shared_ptr<sinsp_evt_formatter>& sinsp_evt_formatter_cache::get_cached_formatter(string &format)
{
	auto it = m_formatter_cache.lower_bound(format);

	if(it == m_formatter_cache.end() ||
	   it->first != format)
	{
		it = m_formatter_cache.emplace_hint(it,
						    std::make_pair(format, make_shared<sinsp_evt_formatter>(m_inspector, format)));
	}

	return it->second;
}

bool sinsp_evt_formatter_cache::resolve_tokens(sinsp_evt *evt, string &format, map<string,string>& values)
{
	return get_cached_formatter(format)->resolve_tokens(evt, values);
}

bool sinsp_evt_formatter_cache::tostring(sinsp_evt *evt, string &format, OUT string *res)
{
	return get_cached_formatter(format)->tostring(evt, res);
}
