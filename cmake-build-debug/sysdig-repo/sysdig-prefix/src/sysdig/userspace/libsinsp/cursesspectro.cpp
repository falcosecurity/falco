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

#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <stdint.h>
#include <math.h>
#ifndef _WIN32
#include <unistd.h>
#include <algorithm>
#endif
#include <string>
#include <unordered_map>
#include <map>
#include <queue>
#include <vector>
#include <set>
using namespace std;

#include "sinsp.h"
#include "sinsp_int.h"
#include "../../driver/ppm_ringbuffer.h"
#include "filter.h"
#include "filterchecks.h"

#ifdef CSYSDIG
#ifndef NOCURSESUI

#include <curses.h>
#include "table.h"
#include "ctext.h"
#include "cursescomponents.h"
#include "cursestable.h"
#include "cursesspectro.h"
#include "cursesui.h"

//
// The color palette that we will use for the chart
//
uint32_t g_colpalette[] = 
{
	22, 28, 64, 34, 2, 76, 46, 118, 154, 191, 227, 226, 11, 220, 209, 208, 202, 197, 9, 1
//	17, 18, 21, 26, 27, 32, 33, 38, 39, 45, 51, 87, 159, 195, 231, 7
//	238, 241, 243, 245, 246, 247, 39, 38, 33, 32, 27, 26, 21, 18, 17
//	236, 237, 238, 239, 240, 241, 242, 243, 244,245,246,247,248,249,250,251,252,253,254, 255,
//	236, 238, 240, 242, 243, 244,246,248,250,252,254,195,159,87,45, 39, 33, 27,21
};
uint32_t g_colpalette_size = sizeof(g_colpalette) / sizeof(g_colpalette[0]);

///////////////////////////////////////////////////////////////////////////////
// ANSI terminal helpers
///////////////////////////////////////////////////////////////////////////////
inline void ansi_movedown(int n)
{
	printf("\033[%dE", n);
}

inline void ansi_moveup(int n)
{
	printf("\033[%dF", n);
}

inline void ansi_hidecursor()
{
	printf("\033[?25l");
}

inline void ansi_showcursor()
{
	printf("\033[?25h");
}

inline void ansi_moveto(uint32_t y, uint32_t x)
{
	printf("\033[%d;%dH", y, x);
}

inline void ansi_clearline()
{
	printf("\033[2K");
}

inline void ansi_setcolor(int col)
{
	// Background
	printf("\033[48;5;%dm", col);

	// Foreground
	if(col != 0)
	{
		printf("\033[38;5;%dm", 0);
	}
	else
	{
		printf("\033[38;5;%dm", 255);		
	}
}

inline void ansi_reset_color()
{
	printf("\033[0m");
}

inline void ansi_clearscreen()
{
	printf("\033[2J");
}

///////////////////////////////////////////////////////////////////////////////
// curses_spectro implementation
///////////////////////////////////////////////////////////////////////////////
curses_spectro::curses_spectro(sinsp_cursesui* parent, sinsp* inspector, bool is_tracer)
{
	m_tblwin = NULL;
	m_data = NULL;
	m_table = NULL;
	m_table_x_start = 0;
	m_table_y_start = TABLE_Y_START;
	m_drilled_up = false;
	m_selection_changed = false;
	m_parent = parent;
	m_inspector = inspector;
	m_converter = new sinsp_filter_check_reference();
	m_n_flushes = 0;
	m_n_flushes_with_data = 0;
	m_mouse_masked = false;
	m_lastx = -1;
	m_lasty = -1;
	m_selstart_x = -1;
	m_selstart_y = -1;
	m_prev_sel_x1 = -1;
	m_prev_sel_x2 = -1;
	m_prev_sel_y1 = -1;
	m_prev_sel_y2 = -1;
	m_scroll_paused = false;
	m_is_tracer = is_tracer;
	m_selecting = false;

	//
	// Define the table size
	//
	m_w = m_parent->m_screenw;
	m_h = m_parent->m_screenh;

	//
	// Create the table window
	//
	refresh();
	m_tblwin = newwin(2, m_w, m_parent->m_screenh - 3, 0);

	//
	// Put the inspector in offline replay mode
	//
	if(!m_inspector->is_live())
	{
		parent->m_offline_replay = true;
	}
/*
	for(uint32_t j = 0; j < 256; j++)
	{
		ansi_setcolor(j);
		printf("%d ", (int)j);
	}
	exit(0);
*/	
}

curses_spectro::~curses_spectro()
{
	ansi_moveto(m_h, 0);
	printf("\n");


	//
	// Disable offline replay mode
	//
	if(!m_inspector->is_live())
	{
		m_parent->m_offline_replay = false;
	}

	if(m_tblwin)
	{
		delwin(m_tblwin);
	}

	delete m_converter;
}

void curses_spectro::configure(sinsp_table* table)
{
	uint32_t j;

	m_table = table;

	vector<filtercheck_field_info>* legend = m_table->get_legend();

	for(j = 1; j < legend->size(); j++)
	{
		curses_table_column_info ci;
		ci.m_info = legend->at(j);
		m_legend.push_back(ci);
	}
}

void curses_spectro::print_error(string wstr)
{
	wattrset(m_tblwin, m_parent->m_colors[sinsp_cursesui::FAILED_SEARCH]);

	mvwprintw(m_tblwin, 
		m_parent->m_screenh / 2,
		m_parent->m_screenw / 2 - wstr.size() / 2, 
		wstr.c_str());	
}

void curses_spectro::update_data(vector<sinsp_sample_row>* data, bool force_selection_change)
{
	m_data = data;
}

uint32_t curses_spectro::mkcol(uint64_t val)
{
	uint32_t refresh_per_sec = 2;
	uint32_t col = log10((int)val * refresh_per_sec + 1) / log10(1.6);

	if(col < 1)
	{
		col = 1;
	}

	if(col > g_colpalette_size - 1)
	{
		col = g_colpalette_size - 1;
	}

	return g_colpalette[col - 1];
}

void curses_spectro::draw_axis()
{
	uint64_t x = 0;

	while(true)
	{
		if(x >= m_w)
		{
			break;
		}

		uint32_t curtime = (uint32_t)((double)x * 11 / m_w);
		uint32_t prevtime = (uint32_t)(((double)x - 1) * 11 / m_w);

		if(x == 0 || curtime != prevtime)
		{
			uint64_t aval = (uint64_t)pow(10, curtime);

			m_converter->set_val(PT_RELTIME, 
				(uint8_t*)&aval,
				8,
				0,
				ppm_print_format::PF_DEC);

			string tstr = m_converter->tostring_nice(NULL, 0, 1000000000);
			printf("|%s", tstr.c_str());
			x += tstr.size() + 1;
		}
		else
		{
			printf(" ");
			x++;
		}
	}
}

void curses_spectro::draw_menu(bool there_is_more)
{
	printf("F1");
	ansi_setcolor(24);
	printf("Help  ");
	ansi_reset_color();

	printf("F2");
	ansi_setcolor(24);
	printf("Views ");
	ansi_reset_color();

	printf("p ");
	ansi_setcolor(24);
	printf("Pause ");
	ansi_reset_color();

	printf("BKSPACE");
	ansi_setcolor(24);
	printf("Back");
	ansi_reset_color();

	printf("MOUSE");
	ansi_setcolor(24);
	printf("DrillDown");
	ansi_reset_color();

	if(there_is_more)
	{
		printf("SPACE");
		ansi_setcolor(24);
		printf("More");
		ansi_reset_color();

	}
}

void curses_spectro::render(bool data_changed)
{
	//
	// Clear the screen
	//
	if(m_data == NULL)
	{
		return;
	}

	m_n_flushes++;

	if(m_data->size() != 0)
	{
		if(m_legend.size() != m_data->at(0).m_values.size())
		{
			ASSERT(false);
			throw sinsp_exception("corrupted curses table data");
		}
	}
	else
	{
		if(m_n_flushes < 2)
		{
			printf("\n");
		}
		else
		{
			return;
		}
	}

	if(data_changed)
	{
		unordered_map<uint64_t, uint32_t> freqs;

		m_n_flushes_with_data++;

		//
		// Create a map with the frequencies for every latency interval
		//
		for(auto d : *m_data)
		{
			sinsp_table_field* key = &(d.m_values[0]); 
			sinsp_table_field* data = &(d.m_values[1]); 
			if(key->m_len != 8)
			{
				throw sinsp_exception("the key of a spectrogram view must be a number");
			}

			uint64_t val = *(uint64_t*)key->m_val;
			freqs[val] = *(uint32_t*)data->m_val;
		}

		ansi_moveto(m_h - 2, 0);

		//
		// Render the line
		//
		m_t_row.clear(m_table->m_prev_flush_time_ns);

		for(uint32_t j = 0; j < m_w - 1; j++)
		{
			auto it = freqs.find(j);

			if(it != freqs.end())
			{
				m_t_row.push_back(it->second);
				uint32_t col = mkcol(it->second);
				ansi_setcolor(col);
				printf(" ");
			}
			else
			{
				m_t_row.push_back(0);
				ansi_setcolor(0);
				printf(" ");
			}
		}

		m_history.push_back(m_t_row);

		bool will_pause = !m_inspector->is_live() && m_n_flushes_with_data % (m_h - 3) == 0;
		
		ansi_reset_color();
		ansi_moveto(m_h - 1, 0);
		draw_axis();
		ansi_moveto(m_h, 0);
		draw_menu(will_pause);
		printf("\n");

		if(will_pause)
		{
			m_scroll_paused = true;
		}
	}
}

//
// Return false if the user wants us to exit
//
sysdig_table_action curses_spectro::handle_input(int ch)
{
	if(m_data == NULL)
	{
		return STA_PARENT_HANDLE;
	}

	switch(ch)
	{
		case KEY_F(2):
			clear();
			return STA_PARENT_HANDLE;
		case KEY_ENTER:
			return STA_DRILLDOWN;
		case KEY_BACKSPACE:
		case 127:
			return STA_DRILLUP;
		case KEY_MOUSE:
			{
				if(!m_parent->m_is_mousedrag_available)
				{
					string msgstr = "Mouse input not supported in this terminal";
					uint32_t xs = (msgstr.size() >= m_w)? 0 : (m_w / 2) - (msgstr.size() / 2);
					ansi_moveto(m_h / 2, xs);
					printf("%s\n", msgstr.c_str());

					return STA_NONE;
				}
/*
				if(!m_mouse_masked)
				{
					mousemask(ALL_MOUSE_EVENTS | REPORT_MOUSE_POSITION, NULL);
					m_mouse_masked = true;
				}
*/
				if(getmouse(&m_last_mevent) == OK)
				{
					if(m_last_mevent.bstate & BUTTON1_CLICKED)
					{
						g_logger.format("mouse clicked");

						if(m_last_mevent.y == (int)m_h - 2)
						{
							if(m_last_mevent.x >= 3 && m_last_mevent.x <= 7)
							{
								return m_parent->handle_input(KEY_F(1));
							}
							else if(m_last_mevent.x >= 10 && m_last_mevent.x <= 15)
							{
								return m_parent->handle_input(KEY_F(2));
							}
							else if(m_last_mevent.x >= 18 && m_last_mevent.x <= 23)
							{
								return m_parent->handle_input('p');
							}
							else if(m_last_mevent.x >= 31 && m_last_mevent.x <= 34)
							{
								return STA_DRILLUP;
							}
						}
						else
						{
							if(m_inspector->is_live())
							{
								break;
							}

							if(!m_selecting)
							{
								m_selecting = true;
								m_selstart_x = -1;
								m_selstart_y = -1;
							}
							else
							{
								m_selecting = false;

								curses_spectro_history_row* start_row = get_history_row_from_coordinate(m_selstart_y);
								curses_spectro_history_row* end_row = get_history_row_from_coordinate(m_prev_sel_y2 - 1);
								uint64_t start_latency = latency_from_coordinate(m_selstart_x);
								uint64_t end_latency = latency_from_coordinate(m_prev_sel_x2);

								if(start_row == NULL || end_row == NULL)
								{
									break;
								}

								string lat_fld_name;

								if(m_is_tracer)
								{
									lat_fld_name = "span.duration";
								}
								else
								{
									lat_fld_name = "evt.latency";
								}

								m_selection_filter = 
									"(evt.rawtime>="  + to_string(start_row->m_ts - m_table->m_refresh_interval_ns) + 
									" and evt.rawtime<=" + to_string(end_row->m_ts) + 
									") and (" + lat_fld_name + ">=" + to_string(start_latency) + 
									" and " + lat_fld_name + "<" + to_string(end_latency) + ")";

								g_logger.format("spectrogram drill down");
								g_logger.format("filter: %s", m_selection_filter.c_str());

								m_selstart_x = -1;
								m_selstart_y = -1;

								ansi_reset_color();

								if(m_is_tracer)
								{
									return STA_DRILLDOWN;
								}
								else
								{
									return STA_DIG;
								}
							}
						}
					}
					else
					{
						if(m_selecting)
						{
							if((m_last_mevent.y > (int)m_h - 4) || ((int)m_last_mevent.y <= (int)m_h - 3 - (int)m_history.size()))
							{
								break;
							}

							if(m_selstart_x == -1)
							{
								m_selstart_x = m_last_mevent.x;
								m_selstart_y = m_last_mevent.y;
							}

							if(m_prev_sel_x1 != -1)
							{
								draw_square(m_prev_sel_y1, m_prev_sel_x1, 
									m_prev_sel_y2, m_prev_sel_x2,
									' ');
							}

							m_prev_sel_y1 = m_selstart_y;
							m_prev_sel_x1 = m_selstart_x;
							m_prev_sel_y2 = m_last_mevent.y + 1;
							m_prev_sel_x2 = m_last_mevent.x + 1;

							draw_square(m_selstart_y, m_selstart_x, 
								m_last_mevent.y + 1, m_last_mevent.x + 1,
								'X');
						}
					}
				}
			}
			break;
		case 'c':
		case KEY_DC: // Del
			break;
		case KEY_F(7):
			return STA_NONE;
		default:
			break;
	}

	return STA_PARENT_HANDLE;
}

void curses_spectro::draw_square(int32_t y1, int32_t x1, int32_t y2, int32_t x2, char c)
{
	if(x2 < x1 || y2 < y1)
	{
		return;
	}

	for(int32_t j = y1; j < y2; j++)
	{
		ansi_moveto(j + 1, x1 + 1);

		if(j == y1 || j == y2 - 1)
		{
			for(int32_t k = x1; k < x2; k++)
			{
				int64_t col = get_history_color_from_coordinate(j, k);
				if(col == -1)
				{
					break;
				}

				ansi_setcolor(col);
				printf("%c", c);
			}
		}
		else
		{
			int64_t col = get_history_color_from_coordinate(j, x1);
			if(col == -1)
			{
				break;
			}

			ansi_setcolor(col);
			printf("%c", c);

			col = get_history_color_from_coordinate(j, x2 - 1);
			if(col == -1)
			{
				break;
			}

			ansi_moveto(j + 1, x2);
			ansi_setcolor(col);
			printf("%c", c);
		}

		printf("\n");
	}
}

int64_t curses_spectro::get_history_value_from_coordinate(uint32_t y, uint32_t x)
{
	if((m_h - y > 3) && 
		(m_h - y - 4) < m_history.size() - 1)
	{
		curses_spectro_history_row& row = m_history[m_history.size() - 1 - (m_h - y - 4)];

		ASSERT(x >= 0);
		ASSERT(row.m_data.size() == m_w - 1);
		if(x >= row.m_data.size())
		{
			return -1;
		}

		return row.m_data[x];
	}

	return -1;
}

int64_t curses_spectro::get_history_color_from_coordinate(uint32_t y, uint32_t x)
{
	int64_t hv = get_history_value_from_coordinate(y, x);

	if(hv != -1)
	{
		if(hv == 0)
		{
			return 0;
		}
		else
		{
			int64_t col = mkcol(hv);
			return col;
		}
	}
	else
	{
		return -1;
	}
}

curses_spectro_history_row* curses_spectro::get_history_row_from_coordinate(uint32_t y)
{
	if((y <= m_h - 4) && ((int)y > (int)m_h - 3 - (int)m_history.size()))
	{
		return &(m_history[m_history.size() - 1 - (m_h - y - 4)]);
	}
	else
	{
		return NULL;
	}
}

uint64_t curses_spectro::latency_from_coordinate(uint32_t x)
{
	double curtime = (double)x * 11 / m_w;
	return (uint64_t)pow(10, curtime);
}

void curses_spectro::recreate_win(int h)
{
	delwin(m_tblwin);
	
	m_tblwin = newwin(m_h - 3, m_w, m_table_y_start, m_table_x_start);
	render(true);
}

#endif // NOCURSESUI
#endif // CSYSDIG
