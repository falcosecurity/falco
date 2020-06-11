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
#include "table.h"
#include "cursescomponents.h"
#include "cursestable.h"
#include "viewinfo.h"
#include "cursesui.h"
#include "utils.h"

extern bool g_filterchecks_force_raw_times;

///////////////////////////////////////////////////////////////////////////////
// spy_text_renderer implementation
///////////////////////////////////////////////////////////////////////////////
spy_text_renderer::spy_text_renderer(sinsp* inspector, 
	sinsp_cursesui* parent,
	int32_t viz_type, 
	sysdig_output_type sotype, 
	bool print_containers,
	sinsp_evt::param_fmt text_fmt)
{
	m_formatter = NULL;
	m_inspector = inspector;
	m_viz_type = viz_type;
	m_linecnt = 0;
	g_filterchecks_force_raw_times = false;

	//
	// visualization-type inits
	//
	if(m_viz_type == VIEW_ID_DIG)
	{
		if(sotype == spy_text_renderer::OT_LATENCY)
		{
			if(print_containers)
			{
				m_formatter = new sinsp_evt_formatter(m_inspector,
					"*(latency=%evt.latency.human) (fd=%fd.name) %evt.num %evt.time %evt.cpu %container.name (%container.id) %proc.name (%thread.tid:%thread.vtid) %evt.dir %evt.type %evt.info");
			}
			else
			{
				m_formatter = new sinsp_evt_formatter(m_inspector,
					"*(latency=%evt.latency.human) (fd=%fd.name) %evt.num %evt.time %evt.cpu %proc.name %thread.tid %evt.dir %evt.type %evt.info");
			}
		}
		else if(sotype == spy_text_renderer::OT_LATENCY_APP)
		{
			if(print_containers)
			{
				m_formatter = new sinsp_evt_formatter(m_inspector,
					"*(latency=%tracer.latency.human) %evt.num %evt.time %evt.cpu %container.name (%container.id) %proc.name (%thread.tid:%thread.vtid) %evt.dir %evt.type %evt.info");
			}
			else
			{
				m_formatter = new sinsp_evt_formatter(m_inspector,
					"*(latency=%tracer.latency.human) %evt.num %evt.time %evt.cpu %proc.name %thread.tid %evt.dir %evt.type %evt.info");
			}
		}
		else
		{
			if(print_containers)
			{
				m_formatter = new sinsp_evt_formatter(m_inspector,
					"*%evt.num %evt.time %evt.cpu %container.name (%container.id) %proc.name (%thread.tid:%thread.vtid) %evt.dir %evt.type %evt.info");
			}
			else
			{
				m_formatter = new sinsp_evt_formatter(m_inspector, DEFAULT_OUTPUT_STR);
			}
		}
	}
	else
	{
		m_formatter = NULL;
	}

	m_inspector->set_buffer_format(text_fmt);
}

spy_text_renderer::~spy_text_renderer()
{ 
	if(m_formatter)
	{
		delete m_formatter;
	}
}

const char* spy_text_renderer::process_event_spy(sinsp_evt* evt, int64_t* len)
{
	//
	// Drop any non I/O event
	//
	ppm_event_flags eflags = evt->get_info_flags();

	if(!(eflags & EF_READS_FROM_FD || eflags & EF_WRITES_TO_FD))
	{
		return NULL;
	}

	//
	// Get and validate the length
	//
	sinsp_evt_param* parinfo = evt->get_param(0);
	ASSERT(parinfo->m_len == sizeof(int64_t));
	*len = *(int64_t*)parinfo->m_val;
	if(*len <= 0)
	{
		return NULL;
	}

	//
	// Get thread and fd
	//
	sinsp_threadinfo* m_tinfo =	evt->get_thread_info();
	if(m_tinfo == NULL)
	{
		return NULL;
	}

	sinsp_fdinfo_t* m_fdinfo = evt->get_fd_info();
	if(m_fdinfo == NULL)
	{
		return NULL;
	}
	string fdname = m_fdinfo->m_name;
	if(fdname == "")
	{
		fdname = "unnamed FD";
	}

	//
	// Get the buffer
	//
	const char* resolved_argstr;
	char* argstr;
	argstr = (char*)evt->get_param_value_str("data", &resolved_argstr, m_inspector->get_buffer_format());

	//
	// Trim initial or final \n
	//
	if(argstr)
	{
		uint32_t argstrlen = strlen(argstr);

		if(argstrlen >= 1)
		{
			if(*argstr == '\n')
			{
				argstr++;
				argstrlen--;
			}

			if(argstrlen >= 1)
			{
				if(argstr[argstrlen -1] == '\n')
				{
					argstr[argstrlen - 1] = 0;
				}
			}
		}
	}

	return argstr;
}

#ifndef NOCURSESUI
#include <curses.h>
#include "ctext.h"

///////////////////////////////////////////////////////////////////////////////
// curses_scrollable_list implementation
///////////////////////////////////////////////////////////////////////////////
curses_scrollable_list::curses_scrollable_list()
{
	m_selct = 0;
	m_firstrow = 0;
	m_lastrow_selected = true;
}

void curses_scrollable_list::sanitize_selection(int32_t datasize)
{
	if(m_firstrow > (datasize - (int32_t)m_h + 1))
	{
		m_firstrow = datasize - (int32_t)m_h + 1;
	}

	if(m_firstrow < 0)
	{
		m_firstrow = 0;
	}

	if(m_selct > datasize - 1)
	{
		m_selct = datasize - 1;
	}

	if(m_selct < 0)
	{
		m_selct = 0;
	}

	if(m_firstrow > m_selct)
	{
		m_firstrow = m_selct;
	}
}

void curses_scrollable_list::selection_up(int32_t datasize)
{
	if(m_selct > 0)
	{
		if(m_selct <= (int32_t)m_firstrow)
		{
			m_firstrow--;
		}

		m_selct--;
		sanitize_selection(datasize);
	}

	m_lastrow_selected = false;
}

void curses_scrollable_list::selection_down(int32_t datasize)
{
	if(m_selct < datasize - 1)
	{
		if(m_selct - m_firstrow > (int32_t)m_h - 3)
		{
			m_firstrow++;
		}

		m_selct++;
		sanitize_selection(datasize);
	}

	if(m_selct == datasize - 1)
	{
		m_lastrow_selected = true;
	}
}

void curses_scrollable_list::selection_pageup(int32_t datasize)
{
	m_firstrow -= (m_h - 1);
	m_selct -= (m_h - 1);

	sanitize_selection(datasize);

	m_lastrow_selected = false;
}

void curses_scrollable_list::selection_pagedown(int32_t datasize)
{
	m_firstrow += (m_h - 1);
	m_selct += (m_h - 1);

	sanitize_selection(datasize);

	if(m_selct == datasize - 1)
	{
		m_lastrow_selected = true;
	}
}

void curses_scrollable_list::selection_home(int32_t datasize)
{
	m_firstrow = 0;
	m_selct = 0;

	sanitize_selection(datasize);

	m_lastrow_selected = false;
}

void curses_scrollable_list::selection_end(int32_t datasize)
{
	m_firstrow = datasize - 1;
	m_selct = datasize - 1;

	sanitize_selection(datasize);

	m_lastrow_selected = true;
}

void curses_scrollable_list::selection_goto(int32_t datasize, int32_t row)
{
	if(row == -1 ||
		row >= datasize)
	{
		ASSERT(false);
		return;
	}

	m_firstrow = row - (m_h /2);
	m_selct = row;

	sanitize_selection(datasize);
}

///////////////////////////////////////////////////////////////////////////////
// curses_table_sidemenu implementation
///////////////////////////////////////////////////////////////////////////////
curses_table_sidemenu::curses_table_sidemenu(sidemenu_type type, sinsp_cursesui* parent, uint32_t selct, uint32_t width)
{
	ASSERT(parent != NULL);
	m_parent = parent;
	m_h = m_parent->m_screenh - TABLE_Y_START - 1;
	m_w = width;
	m_y_start = TABLE_Y_START;
	m_win = newwin(m_h, m_w, m_y_start, 0);
	m_selct = selct;
	m_selct_ori = m_selct;
	m_type = type;

	if(m_selct > (int32_t)(m_h - 2))
	{
		m_firstrow = m_selct - (int32_t)(m_h - 2);
	}
}

curses_table_sidemenu::~curses_table_sidemenu()
{
	delwin(m_win);
}

void curses_table_sidemenu::render()
{
	int32_t j, k;

	ASSERT(m_entries.size() != 0);

	//
	// Render window header
	//
	wattrset(m_win, m_parent->m_colors[sinsp_cursesui::PANEL_HEADER_FOCUS]);

	wmove(m_win, 0, 0);
	for(j = 0; j < (int32_t)m_w - 1; j++)
	{
		waddch(m_win, ' ');
	}

	// white space at the right
	wattrset(m_win, m_parent->m_colors[sinsp_cursesui::PROCESS]);
	waddch(m_win, ' ');

	ASSERT(m_title != "");
	wattrset(m_win, m_parent->m_colors[sinsp_cursesui::PANEL_HEADER_FOCUS]);
	mvwaddnstr(m_win, 0, 0, m_title.c_str(), m_w);

	//
	// Render the rows
	//
	for(j = m_firstrow; j < MIN(m_firstrow + (int32_t)m_h - 1, (int32_t)m_entries.size()); j++)
	{
		if(j == m_selct)
		{
			wattrset(m_win, m_parent->m_colors[sinsp_cursesui::PANEL_HIGHLIGHT_FOCUS]);
		}
		else
		{
			wattrset(m_win, m_parent->m_colors[sinsp_cursesui::PROCESS]);
		}

		// clear the line
		wmove(m_win, j - m_firstrow + 1, 0);
		for(k = 0; k < (int32_t)m_w - 1; k++)
		{
			waddch(m_win, ' ');
		}

		// add the new line
		mvwaddnstr(m_win, j - m_firstrow + 1, 0, m_entries.at(j).m_name.c_str(), m_w);
		// put sorting order indicator at the right end of this row
		if(m_parent->m_sidemenu_sorting_col == j)
		{
			wmove(m_win, j - m_firstrow + 1, m_w - 4);
			char sort_order = m_parent->m_datatable->is_sorting_ascending() ? '^' : 'V';
			waddch(m_win, '(');
			waddch(m_win, sort_order);
			waddch(m_win, ')');
		}

		// white space at the right
		wattrset(m_win, m_parent->m_colors[sinsp_cursesui::PROCESS]);
		wmove(m_win, j - m_firstrow + 1, m_w - 1);
		waddch(m_win, ' ');
	}

	wrefresh(m_win);
}

//
// Update the view info page in the parent
//
void curses_table_sidemenu::update_view_info()
{
	if(m_parent->m_viewinfo_page)
	{
		delete m_parent->m_viewinfo_page;

		ASSERT(m_selct < (int32_t)m_entries.size());

		m_parent->m_viewinfo_page = new curses_viewinfo_page(m_parent,
			m_entries.at(m_selct).m_id,
			TABLE_Y_START,
			m_w,
			m_parent->m_screenh - TABLE_Y_START - 1,
			m_parent->m_screenw - m_w);
	}
}

//
// Return true if the parent should handle the event
//
sysdig_table_action curses_table_sidemenu::handle_input(int ch)
{
	int32_t prev_select;
	int input;

	switch(ch)
	{
		case KEY_F(1):
		case KEY_F(4):
		case KEY_F(5):
		case KEY_F(6):
		case KEY_F(7):
		case 6:
			return STA_NONE;
		case '\n':
		case '\r':
		case KEY_ENTER:
			ASSERT(m_selct < (int32_t)m_entries.size());
			if(m_type == ST_VIEWS)
			{
				if(m_parent->m_spy_box == NULL)
				{
					m_parent->m_selected_view = m_entries.at(m_selct).m_id;
				}

				m_parent->m_selected_view_sidemenu_entry = m_selct;
			} else if(m_type == ST_COLUMNS) {
				m_parent->m_selected_view_sort_sidemenu_entry = m_selct;
			}
			else
			{
				m_parent->m_selected_action_sidemenu_entry = m_selct;
			}

			return STA_SWITCH_VIEW;
		case KEY_BACKSPACE:
		case 127:
		case 27: // ESC
		case KEY_RESIZE:
			ASSERT(m_selct < (int32_t)m_entries.size());

			if(m_type == ST_VIEWS)
			{
				if(m_parent->m_spy_box == NULL)
				{
					m_parent->m_selected_view = m_entries.at(m_selct).m_id;
				}

				m_parent->m_selected_view_sidemenu_entry = m_selct_ori;

				return STA_SWITCH_VIEW;
			}
			else if(m_type == ST_COLUMNS)
			{
				m_parent->m_selected_view_sort_sidemenu_entry = m_selct_ori;
				return STA_DESTROY_CHILD;
			}
			else
			{
				m_parent->m_selected_action_sidemenu_entry = m_selct_ori;
				return STA_DESTROY_CHILD;
			}

		case KEY_UP:
			if(m_entries.size() == 0)
			{
				return STA_NONE;
			}

			prev_select = m_selct;

			selection_up((int32_t)m_entries.size());

			input = getch();
			if(input != -1)
			{
				return handle_input(input);
			}

			if(m_selct != prev_select)
			{
				update_view_info();
			}

			render();
			return STA_NONE;
		case KEY_DOWN:
			if(m_entries.size() == 0)
			{
				return STA_NONE;
			}

			prev_select = m_selct;

			selection_down((int32_t)m_entries.size());

			input = getch();
			if(input != -1)
			{
				return handle_input(input);
			}

			if(m_selct != prev_select)
			{
				update_view_info();
			}

			render();
			return STA_NONE;
		case KEY_PPAGE:
			if(m_entries.size() == 0)
			{
				return STA_NONE;
			}

			prev_select = m_selct;

			selection_pageup((int32_t)m_entries.size());

			input = getch();
			if(input != -1)
			{
				return handle_input(input);
			}

			if(m_selct != prev_select)
			{
				update_view_info();
			}

			render();
			return STA_NONE;
		case KEY_NPAGE:
			if(m_entries.size() == 0)
			{
				return STA_NONE;
			}

			prev_select = m_selct;

			selection_pagedown((int32_t)m_entries.size());

			input = getch();
			if(input != -1)
			{
				return handle_input(input);
			}

			if(m_selct != prev_select)
			{
				update_view_info();
			}

			render();
			return STA_NONE;
		case KEY_HOME:
			if(m_entries.size() == 0)
			{
				return STA_NONE;
			}

			prev_select = m_selct;

			selection_home((int32_t)m_entries.size());

			input = getch();
			if(input != -1)
			{
				return handle_input(input);
			}

			if(m_selct != prev_select)
			{
				update_view_info();
			}

			render();
			return STA_NONE;
		case KEY_END:
			if(m_entries.size() == 0)
			{
				return STA_NONE;
			}

			prev_select = m_selct;

			selection_end((int32_t)m_entries.size());

			input = getch();
			if(input != -1)
			{
				return handle_input(input);
			}

			if(m_selct != prev_select)
			{
				update_view_info();
			}

			render();
			return STA_NONE;
		case KEY_MOUSE:
			{
				if(m_entries.size() == 0)
				{
					return STA_NONE;
				}

				if(getmouse(&m_last_mevent) == OK)
				{
					//
					// Bottom menu clicks are handled by the parent
					//
					if((uint32_t)m_last_mevent.y == m_parent->m_screenh - 1)
					{
						return STA_PARENT_HANDLE;
					}

					if(m_last_mevent.bstate & BUTTON1_CLICKED)
					{
						if((uint32_t)m_last_mevent.y > TABLE_Y_START &&
							(uint32_t)m_last_mevent.y < TABLE_Y_START + m_h - 1)
						{
							//
							// This is a click one of the menu entries. Update the selection.
							//
							m_selct = m_firstrow + (m_last_mevent.y - TABLE_Y_START - 1);
							sanitize_selection((int32_t)m_entries.size());
							update_view_info();
							render();
						}
					}
					else if(m_last_mevent.bstate & BUTTON1_DOUBLE_CLICKED)
					{
						if((uint32_t)m_last_mevent.y > TABLE_Y_START &&
							(uint32_t)m_last_mevent.y < TABLE_Y_START + m_h - 1)
						{
							//
							// This is a double click one of the menu entries.
							// Update the selection.
							//
							m_selct = m_firstrow + (m_last_mevent.y - TABLE_Y_START - 1);
							sanitize_selection((int32_t)m_entries.size());
							render();

							//
							// This delay is here just as a lazy way to give the user the
							// feeling that the row has been clicked
							//
							usleep(200000);

							//
							// Notify the parent that a selection has happened
							//
							ASSERT(m_selct < (int32_t)m_entries.size());
							if(m_parent->m_spy_box == NULL)
							{
								m_parent->m_selected_view = m_entries.at(m_selct).m_id;
							}

							if(m_type == ST_VIEWS)
							{
								m_parent->m_selected_view_sidemenu_entry = m_selct;
							}
							else if(m_type == ST_COLUMNS)
							{
								m_parent->m_selected_view_sort_sidemenu_entry = m_selct;
							}
							else
							{
								m_parent->m_selected_action_sidemenu_entry = m_selct;
							}

							return STA_SWITCH_VIEW;
						}
					}
				}
			}

			return STA_NONE;
		default:
			break;
	}

	return STA_PARENT_HANDLE;
}

///////////////////////////////////////////////////////////////////////////////
// curses_textbox implementation
///////////////////////////////////////////////////////////////////////////////
curses_textbox::curses_textbox(sinsp* inspector, sinsp_cursesui* parent, int32_t viz_type, spy_text_renderer::sysdig_output_type sotype)
{
	ASSERT(inspector != NULL);
	ASSERT(parent != NULL);

	m_parent = parent;
	m_win = NULL;
	m_ctext = NULL;
	m_filter = NULL;
	m_text_renderer = NULL;
	m_inspector = inspector;
	n_prints = 0;
	m_paused = false;
	m_sidemenu = NULL;
	m_searcher = NULL;
	m_has_searched = false;
	m_last_progress_update_ts = 0;

	ctext_config config;

	m_win = newwin(m_parent->m_screenh - 4, m_parent->m_screenw, TABLE_Y_START + 1, 0);
	m_ctext = new ctext(m_win);

	m_ctext->get_config(&config);

	config.m_buffer_size = 500000;
	config.m_scroll_on_append = true;
	config.m_bounding_box = true;

	m_text_renderer = new spy_text_renderer(inspector, 
		parent, 
		viz_type, 
		sotype, 
		m_parent->m_print_containers,
		sinsp_evt::PF_NORMAL);


	if(viz_type == VIEW_ID_DIG)
	{
		config.m_do_wrap = false;
	}
	else
	{
		config.m_do_wrap = true;
	}

	//
	// set the config back
	//
	m_ctext->set_config(&config);

	//
	// Allocate the searcher
	//
	m_searcher = new ctext_search();

	//
	// If we're offline, disable screen refresh until we've parsed the file
	//
	if(!m_inspector->is_live())
	{
		m_ctext->ob_start();
	}

	//
	// Initialize the inspector to capture longer buffers and format them in a
	// readable way
	//
	m_inspector->set_buffer_format(sinsp_evt::PF_NORMAL);
	m_inspector->set_snaplen(2000);

	//
	// Tell the parent to check for input more often
	//
	m_parent->m_input_check_period_ns = 100000;

	//
	// Initial screen refresh
	//
	render();
}

curses_textbox::~curses_textbox()
{
	if(m_sidemenu)
	{
		delete m_sidemenu;
	}

	delwin(m_win);

	delete m_ctext;

	if(m_searcher)
	{
		delete m_searcher;
	}

	if(m_filter != NULL)
	{
		delete m_filter;
	}

	if(m_text_renderer)
	{
		delete m_text_renderer;
	}

	//
	// Restore default snaplen and output formatting
	//
	m_inspector->set_snaplen(80);
	m_inspector->set_buffer_format(sinsp_evt::PF_EOLS);

	//
	// Tell the parent to check for input at the usual frequency
	//
	m_parent->m_input_check_period_ns = UI_USER_INPUT_CHECK_PERIOD_NS;
}

void curses_textbox::set_filter(string filter)
{
	sinsp_filter_compiler compiler(m_inspector, filter);
	m_filter = compiler.compile();
}

void curses_textbox::print_no_data()
{
	attrset(m_parent->m_colors[sinsp_cursesui::PROCESS]);

	string wstr = "No Data For This Selection";
	mvprintw(m_parent->m_screenh / 2,
		m_parent->m_screenw / 2 - wstr.size() / 2,
		wstr.c_str());

	refresh();
}

void curses_textbox::process_event_spy(sinsp_evt* evt, int32_t next_res)
{
	int64_t len;
	const char* argstr = m_text_renderer->process_event_spy(evt, &len);

	if(argstr == NULL)
	{
		return;
	}

	// Note: this can't be NULL because it's been validated by 
	//       m_text_renderer->process_event_spy
	sinsp_threadinfo* m_tinfo =	evt->get_thread_info();

	//
	// Create the info string
	//
	string info_str = "------ ";
	string dirstr;
	string cnstr;

	ppm_event_flags eflags = evt->get_info_flags();
	if(eflags & EF_READS_FROM_FD)
	{
		dirstr = "Read ";
		cnstr = "from ";
		wattrset(m_win, m_parent->m_colors[sinsp_cursesui::SPY_READ]);
	}
	else if(eflags & EF_WRITES_TO_FD)
	{
		wattrset(m_win, m_parent->m_colors[sinsp_cursesui::SPY_WRITE]);
		dirstr = "Write ";
		cnstr = "to ";
	}

	info_str += dirstr + to_string(len) +
		"B " +
		cnstr +
		evt->get_fd_info()->m_name +
		" (" + m_tinfo->m_comm.c_str() + ")";

	//
	// Sanitize the info string
	//
	sanitize_string(info_str);

	//
	// Print the whole thing
	//
	m_ctext->printf("%s", info_str.c_str());

	if(m_parent->m_print_containers)
	{
		wattrset(m_win, m_parent->m_colors[sinsp_cursesui::LED_COLOR]);

		m_ctext->printf(" [%s]", m_inspector->m_container_manager.get_container_name(m_tinfo).c_str());

		if(eflags & EF_READS_FROM_FD)
		{
			wattrset(m_win, m_parent->m_colors[sinsp_cursesui::SPY_READ]);
		}
		else if(eflags & EF_WRITES_TO_FD)
		{
			wattrset(m_win, m_parent->m_colors[sinsp_cursesui::SPY_WRITE]);
		}
	}

	m_ctext->printf("\n");
	m_ctext->printf("\n");
	m_ctext->printf("%s", argstr);

	m_ctext->printf("\n");
	m_ctext->printf("\n");

	n_prints++;

	if(n_prints == 1)
	{
		render();
	}
}

void curses_textbox::process_event_dig(sinsp_evt* evt, int32_t next_res)
{
	if(!m_inspector->is_debug_enabled() && evt->get_category() & EC_INTERNAL)
	{
		return;
	}

	string line;

	m_text_renderer->m_formatter->tostring(evt, &line);

	m_ctext->printf("%s\n", line.c_str());

	n_prints++;

	if(n_prints == 1)
	{
		render();
	}

	uint64_t ts = evt->get_ts();

	if(ts > (m_last_progress_update_ts + 100000000))
	{
		render();
		m_last_progress_update_ts = ts;
	}
}

void curses_textbox::process_event(sinsp_evt* evt, int32_t next_res)
{
	//
	// Check if this the end of the capture file, and if yes take note of that
	//
	if(next_res == SCAP_EOF)
	{
		m_parent->m_eof = 2;
		m_ctext->jump_to_first_line();
		m_ctext->ob_end();
		render();

		if(n_prints == 0)
		{
			print_no_data();
		}

		return;
	}

	//
	// If the user pressed 'p', skip the event
	//
	if(m_paused)
	{
		return;
	}

	//
	// Filter the event
	//
	if(m_filter)
	{
		if(!m_filter->run(evt))
		{
			return;
		}
	}

	if(m_text_renderer->m_viz_type == VIEW_ID_SPY)
	{
		process_event_spy(evt, next_res);
	}
	else
	{
		process_event_dig(evt, next_res);
	}
}

void curses_textbox::populate_sidemenu()
{
	ASSERT(m_sidemenu != NULL);
	m_entries.clear();
	m_entries.push_back(sidemenu_list_entry("Dotted ASCII", -1));
	m_entries.push_back(sidemenu_list_entry("Printable ASCII", -1));
	m_entries.push_back(sidemenu_list_entry("Hex", -1));

	m_sidemenu->set_entries(&m_entries);

	switch(m_parent->m_spybox_text_format)
	{
		case sinsp_evt::PF_NORMAL:
			m_sidemenu->m_selct = 0;
			break;
		case sinsp_evt::PF_EOLS:
			m_sidemenu->m_selct = 1;
			break;
		case sinsp_evt::PF_HEXASCII:
			m_sidemenu->m_selct = 2;
			break;
		case sinsp_evt::PF_JSON:
			m_sidemenu->m_selct = 3;
			break;
		default:
			ASSERT(false);
			m_sidemenu->m_selct = 0;
			break;
	}

	m_sidemenu->set_title("View As");
}

void curses_textbox::render_header()
{
	move(2, 0);
	attrset(m_parent->m_colors[sinsp_cursesui::FUNCTION_BAR]);

	for(uint32_t j = 0; j < m_parent->m_screenw; j++)
	{
		addch(' ');
	}

	refresh();
}

void curses_textbox::render()
{
	m_ctext->redraw();
	render_header();
	m_parent->render();

	if(m_paused)
	{
		string wstr = "   PAUSED   ";
		attrset(m_parent->m_colors[sinsp_cursesui::LARGE_NUMBER]);
		mvprintw(0,
			m_parent->m_screenw / 2 - wstr.size() / 2,
			wstr.c_str());
	}

	//
	// If required, draw the side menu
	//
	if(m_sidemenu)
	{
		m_sidemenu->render();
	}
}

//
// Return true if the parent should handle the event
//
sysdig_table_action curses_textbox::handle_input(int ch)
{
	if(m_sidemenu)
	{
		sysdig_table_action ta = m_sidemenu->handle_input(ch);
		if(ta == STA_SWITCH_VIEW)
		{
			switch(m_parent->m_selected_view_sidemenu_entry)
			{
				case 0:
					m_parent->m_spybox_text_format = sinsp_evt::PF_NORMAL;
					break;
				case 1:
					m_parent->m_spybox_text_format = sinsp_evt::PF_EOLS;
					break;
				case 2:
					m_parent->m_spybox_text_format = sinsp_evt::PF_HEXASCII;
					break;
				case 3:
					m_parent->m_spybox_text_format = sinsp_evt::PF_JSON;
					break;
				default:
					ASSERT(false);
					break;
			}
			return STA_SWITCH_SPY;
		}
		else if(ta != STA_PARENT_HANDLE)
		{
			return STA_NONE;
		}
	}

	switch(ch)
	{
		case KEY_F(1):
		case 'q':
		case KEY_RESIZE:
			return STA_PARENT_HANDLE;
		case 27: // ESC
		case KEY_BACKSPACE:
		case 127:
			return STA_DRILLUP;
		case KEY_UP:
			m_ctext->up();
			render();
			return STA_NONE;
		case '\n':
		case '\r':
		case KEY_ENTER:
		case KEY_DOWN:
			m_ctext->down();
			render();
			return STA_NONE;
		case KEY_LEFT:
			m_ctext->left();
			render();
			return STA_NONE;
		case KEY_RIGHT:
			m_ctext->right();
			render();
			return STA_NONE;
		case KEY_PPAGE:
			m_ctext->page_up();
			render();
			return STA_NONE;
		case ' ':
		case KEY_NPAGE:
			m_ctext->page_down();
			render();
			return STA_NONE;
		case KEY_HOME:
			m_ctext->jump_to_first_line();
			m_ctext->scroll_to(0, 0);
			render();
			return STA_NONE;
		case KEY_END:
			m_ctext->jump_to_last_line();
			render();
			return STA_NONE;
		case 'c':
		case KEY_DC:
			m_ctext->clear();
			render();
			return STA_NONE;
		case 'p':
			if(m_inspector->is_live())
			{
				m_paused = !m_paused;
			}
			m_ctext->jump_to_last_line();
			m_parent->render();
			render();
			return STA_NONE;
		case KEY_F(2):
			if(m_parent->m_screenw < 20)
			{
				return STA_NONE;
			}

			if(m_sidemenu == NULL)
			{
				m_sidemenu = new curses_table_sidemenu(curses_table_sidemenu::ST_VIEWS,
					this->m_parent, 0, VIEW_SIDEMENU_WIDTH);
				populate_sidemenu();
				clear();
				wresize(m_win, m_parent->m_screenh - 4, m_parent->m_screenw - 20);
				mvwin(m_win, TABLE_Y_START + 1, 20);
				wrefresh(m_win);
				m_parent->render();
				render();
				m_ctext->redraw();
			}
			else
			{
				delete m_sidemenu;
				m_sidemenu = NULL;

				wresize(m_win, m_parent->m_screenh - 4, m_parent->m_screenw);
				mvwin(m_win, TABLE_Y_START + 1, 0);
				wrefresh(m_win);
				m_parent->render();
				render();
				m_ctext->redraw();
			}

			return STA_NONE;
		case '/':
		case KEY_F(3):
			on_search_next();
			m_parent->render();
			break;
		case 6:	// CTRL+F
			m_search_type_is_goto = false;
			m_parent->turn_search_on(this, "Text");
			break;
		case 7:	// CTRL+G
			m_search_type_is_goto = true;
			m_parent->turn_search_on(this, "Line");
			break;
		case KEY_MOUSE:
			{
				if(getmouse(&m_last_mevent) == OK)
				{
					return STA_PARENT_HANDLE;
				}
			}

			break;
		default:
			break;
	}

	return STA_NONE;
}

void curses_textbox::reset()
{
	if(m_sidemenu != NULL)
	{
		delete m_sidemenu;
		m_sidemenu = NULL;

		wresize(m_win, m_parent->m_screenh - 4, m_parent->m_screenw);
		mvwin(m_win, TABLE_Y_START + 1, 0);
		wrefresh(m_win);
	}

	m_inspector->set_buffer_format(m_parent->m_spybox_text_format);

	//
	// If we're offline, disable screen refresh until we've parsed the file
	//
	if(!m_inspector->is_live())
	{
		m_ctext->ob_start();
	}

	//
	// Disable pause
	//
	m_paused = false;

	//
	// Clear the screen
	//
	m_ctext->clear();

	//
	// Redraw everything
	//
	m_parent->render();
	render();
	m_ctext->redraw();
	n_prints = 0;
}

bool curses_textbox::get_position(OUT int32_t* pos,
	OUT int32_t* totlines,
	OUT float* percent,
	OUT bool* truncated)
{
	int32_t ox;

	m_ctext->get_offset(&ox, pos);
	m_ctext->get_buf_size(totlines);
	m_ctext->get_offset_percent(percent);
	*truncated = (m_ctext->available_rows() <= 0);

	return true;
}

string* curses_textbox::get_last_search_string()
{
	return &m_last_search_string;
}

int8_t curses_textbox::get_offset(int32_t* x, int32_t* y)
{
	return m_ctext->get_offset(x, y);
}

int8_t curses_textbox::scroll_to(int32_t x, int32_t y)
{
	return m_ctext->scroll_to(x, y);
}

void curses_textbox::up()
{
	m_ctext->up();
}

bool curses_textbox::on_search_key_pressed(string search_str)
{
	m_last_search_string = search_str;

	if(m_search_type_is_goto)
	{
		uint32_t line;

		try
		{
			line = sinsp_numparser::parseu32(search_str);
		}
		catch(...)
		{
			return false;
		}

		int32_t totlines;
		m_ctext->get_buf_size(&totlines);

 		if(line > (uint32_t)totlines)
 		{
			return false;
 		}

		scroll_to(0, line);
		return true;
	}
	else
	{
		m_ctext->new_search(m_searcher,
			search_str,
			true);

		if(m_ctext->str_search(m_searcher) != 0)
		{
			return false;
		}
		else
		{
			m_has_searched = true;
			return true;
		}
	}
}

bool curses_textbox::on_search_next()
{
	if(!m_has_searched)
	{
		return false;
	}

	if(m_ctext->str_search(m_searcher) != 0)
	{
		return false;
	}
	else
	{
		return true;
	}
}

///////////////////////////////////////////////////////////////////////////////
// curses_viewinfo_page implementation
///////////////////////////////////////////////////////////////////////////////
curses_viewinfo_page::curses_viewinfo_page(sinsp_cursesui* parent,
	uint32_t viewnum,
	uint32_t starty,
	uint32_t startx,
	uint32_t h,
	uint32_t w)
{
	m_parent = parent;
	ctext_config config;
	int input;

	sinsp_view_info* vinfo = parent->m_views.at(viewnum);

	m_win = newwin(h, w, starty, startx);

	m_ctext = new ctext(m_win);

	m_ctext->get_config(&config);

	config.m_buffer_size = 50000;
	config.m_scroll_on_append = false;
	config.m_bounding_box = true;
	config.m_do_wrap = true;
	parent->m_selected_view_sort_sidemenu_entry = 0;
	m_ctext->set_config(&config);

	//
	// Print title and info
	//
	wattrset(m_win, parent->m_colors[sinsp_cursesui::HELP_BOLD]);
	m_ctext->printf("%s\n", vinfo->m_name.c_str());

	wattrset(m_win, parent->m_colors[sinsp_cursesui::PROCESS]);
	m_ctext->printf("%s\n\n", vinfo->m_description.c_str());

	// Stop and check for keyboard input
	input = getch();
	if(input != -1)
	{
		handle_input(input);
	}

	//
	// Print the tips if present
	//
	if(vinfo->m_tips.size() != 0)
	{
		wattrset(m_win, parent->m_colors[sinsp_cursesui::HELP_BOLD]);
		m_ctext->printf("Tips\n");

		for(uint32_t j = 0; j < vinfo->m_tips.size(); j++)
		{
			wattrset(m_win, parent->m_colors[sinsp_cursesui::PROCESS]);
			m_ctext->printf("%s\n\n", vinfo->m_tips[j].c_str());
		}
	}

	// Stop and check for keyboard input
	input = getch();
	if(input != -1)
	{
		handle_input(input);
	}

	//
	// Print columns info
	//
	wattrset(m_win, parent->m_colors[sinsp_cursesui::HELP_BOLD]);
	m_ctext->printf("Columns\n");

	uint32_t j;

	if(vinfo->get_type() == sinsp_view_info::T_TABLE)
	{
		j = vinfo->does_groupby()? 2 : 1;
	}
	else
	{
		j = 0;
	}

	for(; j < vinfo->m_columns.size(); j++)
	{
		auto c = &(vinfo->m_columns[j]);

		string desc;
		desc = c->m_description;

		wattrset(m_win, parent->m_colors[sinsp_cursesui::PROCESS_MEGABYTES]);
		m_ctext->printf("%s", c->m_name.c_str());
		wattrset(m_win, parent->m_colors[sinsp_cursesui::PROCESS]);
		m_ctext->printf(": %s", desc.c_str());
		m_ctext->printf("\n");

		// Stop and check for keyboard input
		input = getch();
		if(input != -1)
		{
			handle_input(input);
		}
	}

	m_ctext->printf("\n");

	//
	// Print the view ID
	//
	wattrset(m_win, parent->m_colors[sinsp_cursesui::HELP_BOLD]);
	m_ctext->printf("ID\n");

	wattrset(m_win, parent->m_colors[sinsp_cursesui::PROCESS]);
	m_ctext->printf("%s\n\n", vinfo->m_id.c_str());

	// Stop and check for keyboard input
	input = getch();
	if(input != -1)
	{
		handle_input(input);
	}

	//
	// If there's a filter, print it
	//
	if(vinfo->get_filter(m_parent->m_view_depth) != "")
	{
		wattrset(m_win, parent->m_colors[sinsp_cursesui::HELP_BOLD]);
		m_ctext->printf("Filter\n");

		wattrset(m_win, parent->m_colors[sinsp_cursesui::PROCESS]);
		m_ctext->printf("%s\n\n", vinfo->get_filter(m_parent->m_view_depth).c_str());
	}

	//
	// Print the actions if present
	//
	if(vinfo->m_actions.size() != 0)
	{
		wattrset(m_win, parent->m_colors[sinsp_cursesui::HELP_BOLD]);
		m_ctext->printf("Action Hotkeys\n");

		for(uint32_t j = 0; j < vinfo->m_actions.size(); j++)
		{
			wattrset(m_win, parent->m_colors[sinsp_cursesui::PROCESS_MEGABYTES]);
			m_ctext->printf("%c", vinfo->m_actions[j].m_hotkey);
			wattrset(m_win, parent->m_colors[sinsp_cursesui::PROCESS]);
			m_ctext->printf(": %s (%s)\n",
				vinfo->m_actions[j].m_description.c_str(),
				vinfo->m_actions[j].m_command.c_str());
		}
	}

	// Stop and check for keyboard input
	input = getch();
	if(input != -1)
	{
		handle_input(input);
	}

	//
	// Done. Refresh the screen
	//
	m_ctext->redraw();
}

curses_viewinfo_page::~curses_viewinfo_page()
{
	delete m_ctext;
	delwin(m_win);
}

void curses_viewinfo_page::render()
{
	m_ctext->redraw();
}

sysdig_table_action curses_viewinfo_page::handle_input(int ch)
{
	int32_t totlines;

	m_ctext->get_buf_size(&totlines);

	if(totlines < (int32_t)m_parent->m_screenh)
	{
		return STA_DESTROY_CHILD;
	}

	switch(ch)
	{
		case KEY_UP:
			m_ctext->up();
			render();
			return STA_NONE;
		case '\n':
		case '\r':
		case KEY_ENTER:
		case KEY_DOWN:
			m_ctext->down();
			render();
			return STA_NONE;
		case KEY_LEFT:
			m_ctext->left();
			render();
			return STA_NONE;
		case KEY_RIGHT:
			m_ctext->right();
			render();
			return STA_NONE;
		case KEY_PPAGE:
			m_ctext->page_up();
			render();
			return STA_NONE;
		case ' ':
		case KEY_NPAGE:
			m_ctext->page_down();
			render();
			return STA_NONE;
		case KEY_HOME:
			m_ctext->jump_to_first_line();
			m_ctext->scroll_to(0, 0);
			render();
			return STA_NONE;
		case KEY_END:
			m_ctext->jump_to_last_line();
			render();
			return STA_NONE;
		default:
		break;
	}

	return STA_DESTROY_CHILD;
}

///////////////////////////////////////////////////////////////////////////////
// curses_mainhelp_page implementation
///////////////////////////////////////////////////////////////////////////////
extern string g_version_string;

curses_mainhelp_page::curses_mainhelp_page(sinsp_cursesui* parent)
{
	m_parent = parent;
	ctext_config config;

	m_win = newwin(parent->m_screenh, parent->m_screenw, 0, 0);

	m_ctext = new ctext(m_win);

	m_ctext->get_config(&config);

	config.m_buffer_size = 50000;
	config.m_scroll_on_append = false;
	config.m_bounding_box = true;
	config.m_do_wrap = true;

	m_ctext->set_config(&config);

	//
	// Print title and info
	//
	wattrset(m_win, parent->m_colors[sinsp_cursesui::TASKS_RUNNING]);
	m_ctext->printf("csysdig %s. See man page for full documentation\n",
		g_version_string.c_str());

	wattrset(m_win, parent->m_colors[sinsp_cursesui::PROCESS]);
	m_ctext->printf("Note: you can scroll this page by using the keyboard arrows.\n\n");

	wattrset(m_win, parent->m_colors[sinsp_cursesui::HELP_BOLD]);
	m_ctext->printf("How to use csysdig\n",
		g_version_string.c_str());

	wattrset(m_win, parent->m_colors[sinsp_cursesui::PROCESS]);
	m_ctext->printf(
"1. you can either see real time data, or analyze a trace file by using the -r command line flag.\n"
"2. you can switch to a different view by using the F2 key.\n"
"3. You can drill down into a selection by clicking enter. You can navigate back by typing backspace.\n"
"4. you can observe reads and writes (F5) or see sysdig events (F6) for any selection.\n\n"
);

	wattrset(m_win, parent->m_colors[sinsp_cursesui::HELP_BOLD]);
	m_ctext->printf("Drilling down\n",
		g_version_string.c_str());

	wattrset(m_win, parent->m_colors[sinsp_cursesui::PROCESS]);
	m_ctext->printf(
"You drill down by selecting an element in a view and then clicking enter. Once inside a selection, you can switch to a different view, and the new view will be applied in the context of the selection. For example, if you drill down into a process called foo and then switch to the Connections view, the output will include only the connections made or received by foo.\n\n"
"To drill down multiple times, keep clicking enter. For example, you can click on a container in the Containers view to get the processes running inside it, and then click on one of the processes to see its threads.\n\n"
);

	wattrset(m_win, parent->m_colors[sinsp_cursesui::HELP_BOLD]);
	m_ctext->printf("Actions and Hotkeys\n",
		g_version_string.c_str());

	wattrset(m_win, parent->m_colors[sinsp_cursesui::PROCESS]);
	m_ctext->printf(
"Each view has a list of command lines that can be executed in the context of the current selection by pressing 'hotkeys'. For example, pressing 'k' in the Processes view kills the selected process, pressing 'b' in the Containers view opens a bash shell in the selected container.\n"
"Each view supports different actions. You can see which actions a view supports by pressing F8. You can customize the view's actions by editing the view's Lua file.\n\n"
);

	wattrset(m_win, parent->m_colors[sinsp_cursesui::HELP_BOLD]);
	m_ctext->printf("Containers Support\n",
		g_version_string.c_str());

	wattrset(m_win, parent->m_colors[sinsp_cursesui::PROCESS]);
	m_ctext->printf(
"Starting csysdig with the -pc command line switch will cause many of the views to include additional container information. For example, the _Processes_ will include a column showing the container the process belongs to. Similarly, the _Connections_ view will show which container each connection belongs to.\n\n"
);

	//
	// Explore window keys
	//
	wattrset(m_win, parent->m_colors[sinsp_cursesui::HELP_BOLD]);
	m_ctext->printf("\nKeyboard Shortcuts for the Views Window\n",
		g_version_string.c_str());

	wattrset(m_win, parent->m_colors[sinsp_cursesui::PROCESS_MEGABYTES]);
	m_ctext->printf(" Arrows");
	wattrset(m_win, parent->m_colors[sinsp_cursesui::PROCESS]);
	m_ctext->printf(": scroll the table         ");

	wattrset(m_win, parent->m_colors[sinsp_cursesui::PROCESS_MEGABYTES]);
	m_ctext->printf("CTRL+F /");
	wattrset(m_win, parent->m_colors[sinsp_cursesui::PROCESS]);
	m_ctext->printf(": search\n");

	wattrset(m_win, parent->m_colors[sinsp_cursesui::PROCESS_MEGABYTES]);
	m_ctext->printf("     F2");
	wattrset(m_win, parent->m_colors[sinsp_cursesui::PROCESS]);
	m_ctext->printf(": switch view                  ");

	wattrset(m_win, parent->m_colors[sinsp_cursesui::PROCESS_MEGABYTES]);
	m_ctext->printf("F4 \\");
	wattrset(m_win, parent->m_colors[sinsp_cursesui::PROCESS]);
	m_ctext->printf(": filter(freetext or sysdig)\n");

	wattrset(m_win, parent->m_colors[sinsp_cursesui::PROCESS_MEGABYTES]);
	m_ctext->printf("  Enter");
	wattrset(m_win, parent->m_colors[sinsp_cursesui::PROCESS]);
	m_ctext->printf(": drill down                  ");

	wattrset(m_win, parent->m_colors[sinsp_cursesui::PROCESS_MEGABYTES]);
	m_ctext->printf("F10 q");
	wattrset(m_win, parent->m_colors[sinsp_cursesui::PROCESS]);
	m_ctext->printf(": quit\n");

	wattrset(m_win, parent->m_colors[sinsp_cursesui::PROCESS_MEGABYTES]);
	m_ctext->printf("Bkspace");
	wattrset(m_win, parent->m_colors[sinsp_cursesui::PROCESS]);
	m_ctext->printf(": drill up                    ");

	wattrset(m_win, parent->m_colors[sinsp_cursesui::PROCESS_MEGABYTES]);
	m_ctext->printf("DEL c");
	wattrset(m_win, parent->m_colors[sinsp_cursesui::PROCESS]);
	m_ctext->printf(": clear the view content\n");

	wattrset(m_win, parent->m_colors[sinsp_cursesui::PROCESS_MEGABYTES]);
	m_ctext->printf("   F5 e");
	wattrset(m_win, parent->m_colors[sinsp_cursesui::PROCESS]);
	m_ctext->printf(": echo FDs for selection         ");

	wattrset(m_win, parent->m_colors[sinsp_cursesui::PROCESS_MEGABYTES]);
	m_ctext->printf("F7");
	wattrset(m_win, parent->m_colors[sinsp_cursesui::PROCESS]);
	m_ctext->printf(": see info page for the selected view\n");

	wattrset(m_win, parent->m_colors[sinsp_cursesui::PROCESS_MEGABYTES]);
	m_ctext->printf("   F6 d");
	wattrset(m_win, parent->m_colors[sinsp_cursesui::PROCESS]);
	m_ctext->printf(": sysdig output for selection     ");

	wattrset(m_win, parent->m_colors[sinsp_cursesui::PROCESS_MEGABYTES]);
	m_ctext->printf("p");
	wattrset(m_win, parent->m_colors[sinsp_cursesui::PROCESS]);
	m_ctext->printf(": pause screen updates\n");

	wattrset(m_win, parent->m_colors[sinsp_cursesui::PROCESS_MEGABYTES]);
	m_ctext->printf(" ? F1 h");
	wattrset(m_win, parent->m_colors[sinsp_cursesui::PROCESS]);
	m_ctext->printf(": show this help screen          ");

	wattrset(m_win, parent->m_colors[sinsp_cursesui::PROCESS_MEGABYTES]);
	m_ctext->printf("F8");
	wattrset(m_win, parent->m_colors[sinsp_cursesui::PROCESS]);
	m_ctext->printf(": open the view's actions panel\n");

	wattrset(m_win, parent->m_colors[sinsp_cursesui::PROCESS_MEGABYTES]);
	m_ctext->printf("<shift>1-9");
	wattrset(m_win, parent->m_colors[sinsp_cursesui::PROCESS]);
	m_ctext->printf(": sort column <n>           ");

	wattrset(m_win, parent->m_colors[sinsp_cursesui::PROCESS_MEGABYTES]);
	m_ctext->printf("F9 >");
	wattrset(m_win, parent->m_colors[sinsp_cursesui::PROCESS]);
	m_ctext->printf(": open the column sort panel\n");

	//
	// Text windows keys
	//
	wattrset(m_win, parent->m_colors[sinsp_cursesui::HELP_BOLD]);
	m_ctext->printf("\nKeyboard Shortcuts for the 'Echo' and 'Sysdig' Windows\n",
		g_version_string.c_str());

	wattrset(m_win, parent->m_colors[sinsp_cursesui::PROCESS_MEGABYTES]);
	m_ctext->printf(" Arrows");
	wattrset(m_win, parent->m_colors[sinsp_cursesui::PROCESS]);
	m_ctext->printf(": scroll the page          ");

	wattrset(m_win, parent->m_colors[sinsp_cursesui::PROCESS_MEGABYTES]);
	m_ctext->printf("CTRL+F /");
	wattrset(m_win, parent->m_colors[sinsp_cursesui::PROCESS]);
	m_ctext->printf(": search\n");

	wattrset(m_win, parent->m_colors[sinsp_cursesui::PROCESS_MEGABYTES]);
	m_ctext->printf("Bkspace");
	wattrset(m_win, parent->m_colors[sinsp_cursesui::PROCESS]);
	m_ctext->printf(": drill up                  ");

	wattrset(m_win, parent->m_colors[sinsp_cursesui::PROCESS_MEGABYTES]);
	m_ctext->printf("     F3");
	wattrset(m_win, parent->m_colors[sinsp_cursesui::PROCESS]);
	m_ctext->printf(": find next\n");

	wattrset(m_win, parent->m_colors[sinsp_cursesui::PROCESS_MEGABYTES]);
	m_ctext->printf("     F2");
	wattrset(m_win, parent->m_colors[sinsp_cursesui::PROCESS]);
	m_ctext->printf(": choose buffer print format      ");

	wattrset(m_win, parent->m_colors[sinsp_cursesui::PROCESS_MEGABYTES]);
	m_ctext->printf("p");
	wattrset(m_win, parent->m_colors[sinsp_cursesui::PROCESS]);
	m_ctext->printf(": pause visualization\n");

	wattrset(m_win, parent->m_colors[sinsp_cursesui::PROCESS_MEGABYTES]);
	m_ctext->printf("  DEL c");
	wattrset(m_win, parent->m_colors[sinsp_cursesui::PROCESS]);
	m_ctext->printf(": clear the screen           ");

	wattrset(m_win, parent->m_colors[sinsp_cursesui::PROCESS_MEGABYTES]);
	m_ctext->printf("CTRL+G");
	wattrset(m_win, parent->m_colors[sinsp_cursesui::PROCESS]);
	m_ctext->printf(": go to line\n");

	//
	// Spectrogram window keys
	//
	wattrset(m_win, parent->m_colors[sinsp_cursesui::HELP_BOLD]);
	m_ctext->printf("\nKeyboard Shortcuts for the Spectrogram Window\n",
		g_version_string.c_str());

	wattrset(m_win, parent->m_colors[sinsp_cursesui::PROCESS_MEGABYTES]);
	m_ctext->printf("     F2");
	wattrset(m_win, parent->m_colors[sinsp_cursesui::PROCESS]);
	m_ctext->printf(": switch view                     ");

	wattrset(m_win, parent->m_colors[sinsp_cursesui::PROCESS_MEGABYTES]);
	m_ctext->printf("p");
	wattrset(m_win, parent->m_colors[sinsp_cursesui::PROCESS]);
	m_ctext->printf(": pause\n");

	wattrset(m_win, parent->m_colors[sinsp_cursesui::PROCESS_MEGABYTES]);
	m_ctext->printf("Bkspace");
	wattrset(m_win, parent->m_colors[sinsp_cursesui::PROCESS]);
	m_ctext->printf(": drill up\n\n");

	//
	// Mouse
	//
	wattrset(m_win, parent->m_colors[sinsp_cursesui::HELP_BOLD]);
	m_ctext->printf("\nMouse Usage\n",
		g_version_string.c_str());

	wattrset(m_win, parent->m_colors[sinsp_cursesui::PROCESS]);
	m_ctext->printf("Clicking on column headers lets you sort the table.\n"
		"Double clicking on row entries performs a drill down.\n"
		"Clicking on the filter string at the top of the screen lets you change the sysdig filter.\n"
		"You can use the mouse on the entries in the menu at the bottom of the screen to perform their respective actions.\n");

	//
	// Customization
	//
	wattrset(m_win, parent->m_colors[sinsp_cursesui::HELP_BOLD]);
	m_ctext->printf("\nCustomizing csysdig\n",
		g_version_string.c_str());

	wattrset(m_win, parent->m_colors[sinsp_cursesui::PROCESS]);
	m_ctext->printf("csysdig is completely customizable. This means that you can modify any of the csysdig views, "
		"and even create your own views. Like sysdig chisels, csysdig views are Lua scripts. Full information can "
		"be found at the following github wiki page: https://github.com/draios/sysdig/wiki/csysdig-View-Format-Reference.\n");

	//
	// sysdig cloud
	//
	wattrset(m_win, parent->m_colors[sinsp_cursesui::HELP_BOLD]);
	m_ctext->printf("\nNeed a distributed csysdig?\n",
		g_version_string.c_str());

	wattrset(m_win, parent->m_colors[sinsp_cursesui::PROCESS]);
	m_ctext->printf("Sysdig cloud offers distributed csysdig functionality, a powerful web interface and much more.\nwww.sysdig.com.\n");

	//
	// Bottom padding to compensate for a ctext bug
	//
	uint64_t trlen = ((parent->m_screenh * 230 / parent->m_screenw)) / 10;

	for(uint32_t j = 0; j < trlen; j++)
	{
		m_ctext->printf("\n");
	}

	//
	// Done. Refresh the screen
	//
	m_ctext->redraw();
}

curses_mainhelp_page::~curses_mainhelp_page()
{
	delete m_ctext;
	delwin(m_win);
}

void curses_mainhelp_page::render()
{
	m_ctext->redraw();
}

sysdig_table_action curses_mainhelp_page::handle_input(int ch)
{
	int32_t totlines;

	m_ctext->get_buf_size(&totlines);

	if(totlines < (int32_t)m_parent->m_screenh)
	{
		return STA_DESTROY_CHILD;
	}

	switch(ch)
	{
		case KEY_RESIZE:
			return STA_DESTROY_CHILD;
		case KEY_F(1):
			return STA_NONE;
		case 'q':
		case KEY_F(10):
			return STA_PARENT_HANDLE;
		case KEY_UP:
			m_ctext->up();
			render();
			return STA_NONE;
		case '\n':
		case '\r':
		case KEY_ENTER:
		case KEY_DOWN:
			m_ctext->down();
			render();
			return STA_NONE;
		case KEY_PPAGE:
			m_ctext->page_up();
			render();
			return STA_NONE;
		case ' ':
		case KEY_NPAGE:
			m_ctext->page_down();
			render();
			return STA_NONE;
		case KEY_HOME:
			m_ctext->jump_to_first_line();
			m_ctext->scroll_to(0, 0);
			render();
			return STA_NONE;
		case KEY_END:
			m_ctext->jump_to_last_line();
			render();
			return STA_NONE;
		default:
		break;
	}

	return STA_DESTROY_CHILD;
}

#endif // NOCURSESUI
#endif // CSYSDIG
