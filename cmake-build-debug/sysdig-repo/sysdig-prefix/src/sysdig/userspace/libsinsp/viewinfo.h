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

#define VIEW_ID_SPY -1
#define VIEW_ID_DIG -2
#define VIEW_ID_INFO -3

//
// Aggregation type for table fields
//
typedef enum sinsp_field_aggregation
{
	A_NONE,
	A_SUM,
	A_AVG,
	A_TIME_AVG,
	A_MIN,
	A_MAX,		
}sinsp_field_aggregation;

//
// sinsp_view_column_info flags
//
#define TEF_NONE 0
#define TEF_IS_KEY 1
#define TEF_IS_SORT_COLUMN (1 << 1)
#define TEF_IS_GROUPBY_KEY (1 << 2)
#define TEF_FILTER_IN_CHILD_ONLY (1 << 3)

///////////////////////////////////////////////////////////////////////////////
// Column information
///////////////////////////////////////////////////////////////////////////////
class sinsp_view_column_info
{
public:
	sinsp_view_column_info()
	{
	}
	
	sinsp_view_column_info(string field,
		string name,
		string description,
		uint32_t colsize,
		uint32_t flags,
		sinsp_field_aggregation aggregation,
		sinsp_field_aggregation groupby_aggregation,
		vector<string> tags,
		string filterfield)
	{
		m_field = field;
		m_name = name;
		m_description = description;
		m_colsize = colsize;
		m_aggregation = aggregation;
		m_groupby_aggregation = groupby_aggregation;
		m_flags = flags;
		m_tags = tags;
		m_filterfield = filterfield;
	}

	string get_field(uint32_t depth);
	string get_filter_field(uint32_t depth);

	string m_field;
	string m_name;
	string m_description;
	uint32_t m_colsize;
	sinsp_field_aggregation m_aggregation;
	sinsp_field_aggregation m_groupby_aggregation;
	uint32_t m_flags;
	vector<string> m_tags;
	string m_filterfield;
};

///////////////////////////////////////////////////////////////////////////////
// action information
///////////////////////////////////////////////////////////////////////////////
class sinsp_view_action_info
{
public:
	sinsp_view_action_info(char hotkey,
		string command,
		string description,
		bool ask_confirmation,
		bool waitfinish)
	{
		m_hotkey = hotkey;
		m_command = command;
		m_description = description;
		m_ask_confirmation = ask_confirmation;
		m_waitfinish = waitfinish;
	}

	char m_hotkey;
	string m_command;
	string m_description;
	bool m_ask_confirmation;
	bool m_waitfinish;
};

///////////////////////////////////////////////////////////////////////////////
// View information
///////////////////////////////////////////////////////////////////////////////
class sinsp_view_info
{
public:
	enum viewtype
	{
		T_NONE = 0,
		T_TABLE,
		T_LIST,
		T_TEXT,
		T_SPECTRO,
	};

	sinsp_view_info();
	sinsp_view_info(viewtype type,
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
		bool propagate_filter);

	void get_col_names_and_sizes(OUT vector<string>* colnames, OUT vector<int32_t>* colsizes);
	sinsp_view_column_info* get_key();
	string get_filter(uint32_t depth);
	viewtype get_type()
	{
		return m_type;
	}

	bool does_groupby()
	{
		return m_does_groupby;
	}

	void apply_tag(string tag);

	void run_action(sinsp_view_action_info* action);
	string m_id;
	string m_name;
	string m_description;
	vector<string> m_tags;
	vector<string> m_tips;
	uint32_t m_sortingcol;
	vector<string> m_applies_to;
	vector<sinsp_view_column_info> m_columns;
	bool m_use_defaults;
	bool m_does_groupby;
	viewtype m_type;
	bool m_valid;
	string m_drilldown_target;
	bool m_is_root;
	vector<sinsp_view_action_info> m_actions;
	vector<char> m_col_sort_hotkeys;
	uint32_t max_col_sort_hotkeys;
	bool m_drilldown_increase_depth;
	bool m_propagate_filter;
	string m_spectro_type;
	string m_filter;

private:
	void set_sorting_col();
	void move_key_to_front(uint32_t keyflag);
	void set_col_sorting_hotkeys();

	uint32_t m_n_sorting_cols;
};


///////////////////////////////////////////////////////////////////////////////
// View manager
///////////////////////////////////////////////////////////////////////////////
class sinsp_view_manager
{
public:
	void add(sinsp_view_info* vinfo);
	vector<sinsp_view_info>* get_views();
	uint32_t get_selected_view();
	void set_selected_view(string viewid);
	size_t size()
	{
		return m_views.size();
	}
	sinsp_view_info* at(uint32_t viewnum)
	{
		return &m_views[viewnum];
	}

private:
	void sort_views();

	vector<sinsp_view_info> m_views;

	string m_selected_view_id;
};
