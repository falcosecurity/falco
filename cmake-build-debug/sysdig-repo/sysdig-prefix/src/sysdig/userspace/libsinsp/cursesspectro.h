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

#ifdef CSYSDIG
#ifndef NOCURSESUI

class colpalette_entry
{
public:
	colpalette_entry(int color, char ch)
	{
		m_color = color;
		m_char = ch;
	}

	int m_color;
	char m_char;
};

class curses_spectro_history_row
{
public:
	void clear(uint64_t ts)
	{
		m_ts = ts;
		m_data.clear();
	}

	void push_back(uint32_t val)
	{
		m_data.push_back(val);
	}

	uint64_t m_ts;
	vector<uint32_t> m_data;
};

class curses_spectro : 
	public sinsp_chart
{
public:
	enum alignment
	{
		ALIGN_LEFT,
		ALIGN_RIGHT,
	};

	curses_spectro(sinsp_cursesui* parent, sinsp* inspector, bool is_tracer);
	~curses_spectro();

	void configure(sinsp_table* table);
	void update_data(vector<sinsp_sample_row>* data, bool force_selection_change = false);
	void render(bool data_changed);
	sysdig_table_action handle_input(int ch);
	void set_x_start(uint32_t x)
	{
		m_table_x_start = x;
	}
	void recreate_win(int h);
	uint32_t get_data_size()
	{
		if(m_table != NULL)
		{
			return m_data->size();
		}
		else
		{
			return 0;
		}
	}
	bool get_position(OUT int32_t* pos,	OUT int32_t* totlines, OUT float* percent, OUT bool* truncated)
	{
		return false;
	}

	sinsp_table_field_storage m_last_key;
	bool m_drilled_up;
	bool m_selection_changed;
	MEVENT m_last_mevent;
	string m_selection_filter;
	bool m_scroll_paused;
	
private:
	void print_error(string wstr);
	uint32_t mkcol(uint64_t n);
	void draw_axis();
	void draw_menu(bool there_is_more);
	int64_t get_history_value_from_coordinate(uint32_t y, uint32_t x);
	int64_t get_history_color_from_coordinate(uint32_t y, uint32_t x);
	curses_spectro_history_row* get_history_row_from_coordinate(uint32_t y);
	uint64_t latency_from_coordinate(uint32_t x);
	void draw_square(int32_t y1, int32_t x1, int32_t y2, int32_t x2, char c);

	sinsp* m_inspector;
	WINDOW* m_tblwin;
	sinsp_cursesui* m_parent;
	sinsp_table* m_table;
	int32_t m_table_x_start;
	uint32_t m_table_y_start;
	vector<curses_table_column_info> m_legend;
	vector<sinsp_sample_row>* m_data;
	uint32_t m_w;
	uint32_t m_h;
	vector<uint32_t> m_colpalette;
	sinsp_filter_check_reference* m_converter;
	uint64_t m_n_flushes;
	uint64_t m_n_flushes_with_data;
	vector<curses_spectro_history_row> m_history;
	curses_spectro_history_row m_t_row;
	bool m_mouse_masked;
	int32_t m_lastx, m_lasty;
	int32_t m_selstart_x, m_selstart_y;
	int32_t m_prev_sel_x1, m_prev_sel_x2;
	int32_t m_prev_sel_y1, m_prev_sel_y2;
	bool m_is_tracer;
	bool m_selecting;

	friend class curses_spectro_sidemenu;
};

#endif // NOCURSESUI
#endif // CSYSDIG
