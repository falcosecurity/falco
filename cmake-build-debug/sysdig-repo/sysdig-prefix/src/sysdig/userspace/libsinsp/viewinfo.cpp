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
#include <algorithm>
#include "sinsp.h"
#include "sinsp_int.h"
#include "sinsp_errno.h"
#include "sinsp_signal.h"
#include "filter.h"
#include "filterchecks.h"
#include "chisel.h"
#include "protodecoder.h"

///////////////////////////////////////////////////////////////////////////////
// sinsp_view_column_info implementation
///////////////////////////////////////////////////////////////////////////////
string sinsp_view_column_info::get_field(uint32_t depth)
{
	// Trim the string
	replace_in_place(m_field, " ", "");
	replace_in_place(m_field, "\t", "");

	if(m_field.find("%depth-1") != string::npos)
	{
		string res = m_field;
		replace_in_place(res, "%depth-1", to_string(depth - 1));
		return res;
	}
	else if(m_field.find("%depth+1") != string::npos)
	{
		string res = m_field;
		replace_in_place(res, "%depth+1", to_string(depth - 1));
		return res;
	}
	else if(m_field.find("%depth") != string::npos)
	{
		string res = m_field;
		replace_in_place(res, "%depth", to_string(depth));
		return res;
	}
	else
	{
		return m_field;
	}
}

string sinsp_view_column_info::get_filter_field(uint32_t depth)
{
	//
	// If m_filterfield, return it as an override to m_field
	//
	if(m_filterfield != "")
	{
		return m_filterfield;
	}
	else
	{
		return get_field(depth);
	}
}

///////////////////////////////////////////////////////////////////////////////
// sinsp_view_info implementation
///////////////////////////////////////////////////////////////////////////////
sinsp_view_info::sinsp_view_info()
{
	m_valid = false;
}

sinsp_view_info::sinsp_view_info(viewtype type, 
	string id,
	string name,
	string description,
	vector<string> tags,
	vector<string> tips,
	vector<sinsp_view_column_info> columns,
	vector<string> applies_to,
	string filter,
	string drilldown_target,
	bool use_defaults,
	bool is_root,
	vector<sinsp_view_action_info> actions,
	bool drilldown_increase_depth,
	string spectro_type,
	bool propagate_filter)
{
	m_id = id;
	m_name = name;
	m_description = description;
	m_does_groupby = false;
	m_type = type;
	m_tags = tags;	
	m_tips = tips;
	m_columns = columns;
	m_drilldown_target = drilldown_target;
	m_is_root = is_root;
	m_applies_to = applies_to;
	m_drilldown_increase_depth = drilldown_increase_depth;
	m_spectro_type = spectro_type;
	m_propagate_filter = propagate_filter;

	m_use_defaults = use_defaults;
	
	//
	// Make sure the keys go at the beginning
	//
	move_key_to_front(TEF_IS_GROUPBY_KEY);
	move_key_to_front(TEF_IS_KEY);

	//
	// Determine the sorting and grouping columns
	//
	set_sorting_col();

	m_filter = filter;
	m_valid = true;
	m_actions = actions;
	// init the array for hotkeys for sorting columns
	set_col_sorting_hotkeys();
}

void sinsp_view_info::set_col_sorting_hotkeys()
{
	const char shift_number_keys [] = {'!', '@', '#', '$', '%', '^', '&', '*', '('};
	uint32_t size = sizeof(shift_number_keys) / sizeof(shift_number_keys[0]);
	for(uint32_t i=0; i<size; i++) 
	{
		m_col_sort_hotkeys.push_back(shift_number_keys[i]); 
	}
	max_col_sort_hotkeys = m_col_sort_hotkeys.size();
}

void sinsp_view_info::set_sorting_col()
{
	m_n_sorting_cols = 0;

	for(uint32_t j = 0; j < m_columns.size(); j++)
	{
		if((m_columns[j].m_flags & TEF_IS_SORT_COLUMN) != 0)
		{
			m_sortingcol = j;
			m_n_sorting_cols++;
		}

		if((m_columns[j].m_flags & TEF_IS_GROUPBY_KEY) != 0)
		{
			m_does_groupby = true;
		}
	}

	if(m_does_groupby)
	{
		m_sortingcol--;
	}

	if(m_n_sorting_cols == 0)
	{
		if(m_does_groupby)
		{
			m_sortingcol = 2;
		}
		else
		{
			m_sortingcol = 1;
		}
	}
	else if(m_n_sorting_cols > 1)
	{
		throw sinsp_exception("view format error: more than one sorting column");
	}

	if((int64_t)m_sortingcol < 0)
	{
		ASSERT(false);
		throw sinsp_exception("view sorting column configuration error");
	}
}

void sinsp_view_info::apply_tag(string tag)
{
	for(auto it = m_columns.begin(); it != m_columns.end();)
	{
		bool found = false;

		if(it->m_tags.size() != 0)
		{
			for(string t : it->m_tags)
			{
				if(t == tag)
				{
					found = true;
					break;
				}
			}

			if(!found)
			{
				it = m_columns.erase(it);
				continue;
			}
		}

		++it;
	}

	//
	// Make sure to recalculate the sorting and grouping columns, which could change
	// if we remove columns.
	//
	set_sorting_col();
}

void sinsp_view_info::get_col_names_and_sizes(OUT vector<string>* colnames, OUT vector<int32_t>* colsizes)
{
	if(m_type == viewtype::T_LIST)
	{
		colsizes->push_back(-1);
		colnames->push_back("");
	}

	for(auto fit : m_columns)
	{
		if(m_does_groupby)
		{
			if((fit.m_flags & TEF_IS_KEY) != 0)
			{
				continue;
			}

			if((fit.m_flags & TEF_IS_GROUPBY_KEY) != 0)
			{
				colsizes->insert(colsizes->begin(), fit.m_colsize);
				colnames->insert(colnames->begin(), fit.m_name);
				continue;
			}
		}

		colsizes->push_back(fit.m_colsize);
		colnames->push_back(fit.m_name);
	}
}

void sinsp_view_info::move_key_to_front(uint32_t keyflag)
{
	for(uint32_t j = 0; j < m_columns.size(); j++)
	{
		if((m_columns[j].m_flags & keyflag) != 0)
		{
			sinsp_view_column_info ci = m_columns[j];

			m_columns.erase(m_columns.begin() +j);
			m_columns.insert(m_columns.begin(), ci);
			return;
		}
	}
}

sinsp_view_column_info* sinsp_view_info::get_key()
{
	for(uint32_t j = 0; j < m_columns.size(); j++)
	{
		if((m_columns[j].m_flags & TEF_IS_GROUPBY_KEY) != 0)
		{
			return &m_columns[j];
		}
	}

	for(uint32_t j = 0; j < m_columns.size(); j++)
	{
		if((m_columns[j].m_flags & TEF_IS_KEY) != 0)
		{
			return &m_columns[j];
		}
	}

	// The *must* be a key
	return NULL;
}

string sinsp_view_info::get_filter(uint32_t depth)
{
	if(m_filter.find("%depth+1") != string::npos)
	{
		string res = m_filter;
		replace_in_place(res, "%depth+1", to_string(depth + 1));
		replace_in_place(res, "%depth + 1", to_string(depth + 1));
		return res;
	}
	else if(m_filter.find("%depth-1") != string::npos)
	{
		string res = m_filter;
		replace_in_place(res, "%depth-1", to_string(depth - 1));
		replace_in_place(res, "%depth - 1", to_string(depth - 1));
		return res;
	}
	else if(m_filter.find("%depth") != string::npos)
	{
		string res = m_filter;
		replace_in_place(res, "%depth", to_string(depth));
		return res;
	}
	else
	{
		return m_filter;
	}
}

///////////////////////////////////////////////////////////////////////////////
// sinsp_view_manager implementation
///////////////////////////////////////////////////////////////////////////////
void sinsp_view_manager::add(sinsp_view_info* vinfo)
{
	m_views.push_back(*vinfo);
}

typedef struct view_cmp
{
	bool operator()(const sinsp_view_info& src, const sinsp_view_info& dst)
	{
		return src.m_name < dst.m_name;
	}
}table_row_cmp;

void sinsp_view_manager::sort_views()
{
	view_cmp cc;

	//
	// Sort the list alphabetically
	//
	sort(m_views.begin(),
		m_views.end(),
		cc);

	//
	// Print the view list for debugging purposes
	//
	//for(uint32_t j = 0; j < m_views.size(); j++)
	//{
	//	g_logger.format("> %d) %s", j, m_views[j].m_name.c_str());
	//}
}

vector<sinsp_view_info>* sinsp_view_manager::get_views()
{
	sort_views();
	return &m_views;
}

uint32_t sinsp_view_manager::get_selected_view()
{
	sort_views();

	if(m_selected_view_id != "")
	{
		for(uint32_t j = 0; j < m_views.size(); j++)
		{
			if(m_views[j].m_id == m_selected_view_id)
			{
				return j;
			}
		}

		if(m_selected_view_id == "echo")
		{
			return VIEW_ID_SPY;
		}
		else if(m_selected_view_id == "dig")
		{
			return VIEW_ID_DIG;
		}
	}
	else
	{
		for(uint32_t j = 0; j < m_views.size(); j++)
		{
			if(m_views[j].m_is_root)
			{
				return j;
			}
		}
	}

	throw sinsp_exception("view " + m_selected_view_id + " not found");
	return 0;
}

void sinsp_view_manager::set_selected_view(string viewid)
{
	m_selected_view_id = viewid;
}
