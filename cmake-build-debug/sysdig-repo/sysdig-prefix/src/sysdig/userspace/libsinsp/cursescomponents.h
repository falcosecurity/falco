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

class search_caller_interface
{
public:
	virtual bool on_search_key_pressed(string search_str) = 0;
	virtual bool on_search_next() = 0;
	virtual string* get_last_search_string() = 0;
};

class sidemenu_list_entry
{
public:
	sidemenu_list_entry(string name, uint32_t id)
	{
		m_name = name;
		m_id = id;
	}

	string m_name;
	uint32_t m_id;
};

#ifdef CSYSDIG
class sinsp_filter_check_reference;
class curses_table;
class sinsp_cursesui;
class ctext;
typedef struct ctext_search_struct ctext_search;
class sinsp_evt_formatter;

class spy_text_renderer
{
public:
	enum sysdig_output_type
	{
		OT_NORMAL,
		OT_LATENCY,
		OT_LATENCY_APP,
	};
	
	spy_text_renderer(sinsp* inspector, 
		sinsp_cursesui* parent, 
		int32_t viz_type, 
		sysdig_output_type sotype, 
		bool print_containers,
		sinsp_evt::param_fmt text_fmt);
	~spy_text_renderer();
	const char* process_event_spy(sinsp_evt* evt, int64_t* len);

	sinsp_evt_formatter* m_formatter;
	sinsp* m_inspector;
	int32_t m_viz_type;
	uint64_t m_linecnt;
};

#ifndef NOCURSESUI
#define TABLE_WIDTH 10000
#define TABLE_Y_START 2

#include <curses.h>

class sinsp_chart
{
public:
	virtual ~sinsp_chart()
	{
	}

	//
	// Returns false if this chart doesn't support returning the current position
	//
	virtual bool get_position(OUT int32_t* pos, 
		OUT int32_t* totlines, 
		OUT float* percent,
		OUT bool* truncated) = 0;
};

class curses_table_column_info
{
public:	
	curses_table_column_info()
	{
	}

	//
	// Use -1 as size for autosize
	//
	curses_table_column_info(IN filtercheck_field_info* info, int32_t size)
	{
		m_info = *info;
		m_size = size;
	}

//private:
	filtercheck_field_info m_info;
	int32_t m_size;
	string m_name;

	friend class curses_table;
};

class curses_scrollable_list
{
public:
	curses_scrollable_list();
	void sanitize_selection(int32_t datasize);
	void selection_up(int32_t datasize);
	void selection_down(int32_t datasize);
	void selection_pageup(int32_t datasize);
	void selection_pagedown(int32_t datasize);
	void selection_home(int32_t datasize);
	void selection_end(int32_t datasize);
	void selection_goto(int32_t datasize, int32_t row);

	int32_t m_selct;
	int32_t m_selct_ori;
	int32_t m_firstrow;
	uint32_t m_w;
	uint32_t m_h;
	bool m_lastrow_selected;
};

class curses_table_sidemenu : public curses_scrollable_list
{
public:
	enum sidemenu_type {
		ST_NONE,
		ST_VIEWS,
		ST_ACTIONS,
		ST_COLUMNS,
	};

	curses_table_sidemenu(sidemenu_type type, 
		sinsp_cursesui* parent, 
		uint32_t selct,
		uint32_t width);
	~curses_table_sidemenu();
	void set_entries(vector<sidemenu_list_entry>* entries)
	{
		m_entries = *entries;

		if(m_entries.size() == 0)
		{
			m_selct = 0;
		}
	}
	void set_title(string title)
	{
		m_title = title;
	}
	void render();
	sysdig_table_action handle_input(int ch);

	WINDOW* m_win;
	int32_t m_y_start;
	sinsp_cursesui* m_parent;
	vector<sidemenu_list_entry> m_entries;
	string m_title;
	MEVENT m_last_mevent;
	sidemenu_type m_type;

private:
	void update_view_info();
};

class curses_textbox : 
public sinsp_chart, public search_caller_interface
{
public:
	curses_textbox(sinsp* inspector, sinsp_cursesui* parent, int32_t viz_type, spy_text_renderer::sysdig_output_type sotype);
	~curses_textbox();
	void render();
	void set_filter(string filter);
	void print_no_data();
	void process_event(sinsp_evt* evt, int32_t next_res);
	void render_header();
	sysdig_table_action handle_input(int ch);
	void populate_sidemenu();
	void reset();
	bool get_position(OUT int32_t* pos, OUT int32_t* totlines, OUT float* percent, OUT bool* truncated);
	string* get_last_search_string();
	int8_t get_offset(int32_t* x, int32_t* y); 
	int8_t scroll_to(int32_t x, int32_t y);
	void up();
	bool on_search_key_pressed(string search_str);
	bool on_search_next();

	MEVENT m_last_mevent;

private:
	inline void process_event_spy(sinsp_evt* evt, int32_t next_res);
	inline void process_event_dig(sinsp_evt* evt, int32_t next_res);

	WINDOW *m_win;
	ctext* m_ctext;
	sinsp_cursesui* m_parent;
	sinsp* m_inspector;
	sinsp_filter* m_filter;
	uint32_t n_prints;
	bool m_paused;
	curses_table_sidemenu* m_sidemenu;
	vector<sidemenu_list_entry> m_entries;
//	int32_t m_viz_type;
//	sinsp_evt_formatter* m_formatter;
	string m_last_search_string;
	ctext_search* m_searcher;
	bool m_has_searched;
	bool m_search_type_is_goto;
	uint64_t m_last_progress_update_ts;
	spy_text_renderer* m_text_renderer;
};

class curses_mainhelp_page
{
public:
	curses_mainhelp_page(sinsp_cursesui* parent);
	~curses_mainhelp_page();
	sysdig_table_action handle_input(int ch);
	void render();

private:

	WINDOW* m_win;
	sinsp_cursesui* m_parent;
	ctext* m_ctext;
};

class curses_viewinfo_page
{
public:
	curses_viewinfo_page(sinsp_cursesui* parent, uint32_t viewnum, uint32_t starty, uint32_t startx, uint32_t h, uint32_t w);
	~curses_viewinfo_page();
	sysdig_table_action handle_input(int ch);
	void render();

private:

	WINDOW* m_win;
	sinsp_cursesui* m_parent;
	ctext* m_ctext;
};

#endif // NOCURSESUI
#endif // CSYSDIG
