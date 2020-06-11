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

#include <iostream>
#include "sinsp.h"
#include "sinsp_int.h"
#include "../../driver/ppm_ringbuffer.h"
#include "filter.h"
#include "filterchecks.h"

#ifdef CSYSDIG

#ifndef _WIN32
#include <curses.h>
#else
#include <conio.h>
#define getch _getch
#endif
#include "table.h"
#include "cursescomponents.h"
#include "cursestable.h"
#include "cursesspectro.h"
#include "ctext.h"
#include "cursesui.h"

extern int32_t g_csysdig_screen_w;
extern bool g_filterchecks_force_raw_times;

#ifndef NOCURSESUI
#define ColorPair(i,j) COLOR_PAIR((7-i)*8+j)
#endif

#ifndef _WIN32
static int do_sleep(useconds_t usec)
{
	return usleep(usec);
}
#else
int do_sleep(DWORD usec)
{
	ASSERT(usec >= 1000);
	Sleep(DWORD(usec / 1000));
	return 0;
}
#endif

///////////////////////////////////////////////////////////////////////////////
// json_spy_renderer implementation
///////////////////////////////////////////////////////////////////////////////
json_spy_renderer::json_spy_renderer(sinsp* inspector, 
	sinsp_cursesui* parent,
	int32_t viz_type, 
	spy_text_renderer::sysdig_output_type sotype, 
	bool print_containers,
	sinsp_evt::param_fmt text_fmt)
{
	m_inspector = inspector;
	m_filter = NULL;
	m_root = Json::Value(Json::arrayValue);
	m_linecnt = 0;

	m_json_spy_renderer = new spy_text_renderer(inspector, 
		parent,
		viz_type, 
		sotype, 
		print_containers,
		text_fmt);
}

json_spy_renderer::~json_spy_renderer()
{
	delete m_json_spy_renderer;

	if(m_filter != NULL)
	{
		delete m_filter;
	}
}

void json_spy_renderer::set_filter(string filter)
{
	if(filter != "")
	{
		sinsp_filter_compiler compiler(m_inspector, filter);
		m_filter = compiler.compile();
	}
}

void json_spy_renderer::process_event_spy(sinsp_evt* evt, int32_t next_res)
{
	int64_t len;
	const char* argstr = m_json_spy_renderer->process_event_spy(evt, &len);

	if(argstr != NULL)
	{
		Json::Value line;
		m_linecnt++;

		uint64_t ts = evt->get_ts(); 
		line["ta"] = to_string(ts);
		line["td"] = to_string(ts - m_inspector->m_firstevent_ts);

		ppm_event_flags eflags = evt->get_info_flags();
		if(eflags & EF_READS_FROM_FD)
		{
			line["d"] = "<";
		}
		else if(eflags & EF_WRITES_TO_FD)
		{
			line["d"] = ">";
		}

		line["v"] = argstr;
		line["l"] = to_string(len);

		string fdname = evt->get_fd_info()->m_name;
		string tc;
		tc.push_back(evt->get_fd_info()->get_typechar());
		int64_t fdnum = evt->get_fd_num();

		line["fd"] = to_string(fdnum);
		line["ft"] = string(tc);

		if(fdname != "")
		{
			sanitize_string(fdname);
			line["f"] = to_string(fdnum) + "(<" + string(tc) + ">" + fdname + ")";
			line["fn"] = fdname;
		}
		else
		{
			line["f"] = to_string(fdnum) + "(<" + string(tc) + ">)";
		}

		sinsp_threadinfo* tinfo = evt->get_thread_info();
		ASSERT(tinfo);

		line["p"] = tinfo->m_comm;

		if(!tinfo->m_container_id.empty())
		{
			const sinsp_container_info::ptr_t container_info =
				m_inspector->m_container_manager.get_container(tinfo->m_container_id);
			if(container_info)
			{
				if(!container_info->m_name.empty())
				{
					line["c"] = container_info->m_name;
				}
			}
		}

		m_root.append(line);
	}
}

void json_spy_renderer::process_event_dig(sinsp_evt* evt, int32_t next_res)
{
	if(!m_inspector->is_debug_enabled() && evt->get_category() & EC_INTERNAL)
	{
		return;
	}

	string line;

	m_json_spy_renderer->m_formatter->tostring(evt, &line);
	m_root.append(line);
	m_linecnt++;
}

void json_spy_renderer::process_event(sinsp_evt* evt, int32_t next_res)
{
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

	//
	// Render the output
	//
	if(m_json_spy_renderer->m_viz_type == VIEW_ID_SPY)
	{
		process_event_spy(evt, next_res);
	}
	else
	{
		process_event_dig(evt, next_res);
	}
}

string json_spy_renderer::get_data()
{
	Json::FastWriter writer;

	string res = writer.write(m_root);

	m_root.clear();

	return res;
}

uint64_t json_spy_renderer::get_count()
{
	return m_linecnt;
}

///////////////////////////////////////////////////////////////////////////////
// sinsp_cursesui implementation
///////////////////////////////////////////////////////////////////////////////
sinsp_cursesui::sinsp_cursesui(sinsp* inspector,
	string event_source_name,
	string cmdline_capture_filter,
	uint64_t refresh_interval_ns,
	bool print_containers,
	sinsp_table::output_type output_type,
	bool is_mousedrag_available,
	int32_t json_first_row, int32_t json_last_row,
	int32_t sorting_col,
	sinsp_evt::param_fmt json_spy_text_fmt)
{
	m_inspector = inspector;
	m_event_source_name = event_source_name;
	m_selected_view = 0;
	m_prev_selected_view = 0;
	m_selected_view_sidemenu_entry = 0;
	m_selected_action_sidemenu_entry = 0;
	m_datatable = NULL;
	m_cmdline_capture_filter = cmdline_capture_filter;
	m_paused = false;
	m_last_input_check_ts = 0;
	m_output_filtering = false;
	m_output_searching = false;
	m_is_filter_sysdig = false;
	m_eof = 0;
	m_offline_replay = false;
	m_last_progress_evt = 0;
	m_input_check_period_ns = UI_USER_INPUT_CHECK_PERIOD_NS;
	m_search_nomatch = false;
	m_chart = NULL;
	m_n_evts_in_file = 0;
	m_1st_evt_ts = 0;
	m_last_evt_ts = 0;
	m_evt_ts_delta = 0;
	m_timedelta_formatter = new sinsp_filter_check_reference();
	m_refresh_interval_ns = refresh_interval_ns;
	m_print_containers = print_containers;
	m_output_type = output_type;
	m_truncated_input = false;
	m_view_depth = 0;
	m_interactive = false;
	m_json_first_row = json_first_row;
	m_json_last_row = json_last_row;
	m_sorting_col = sorting_col;
	m_json_spy_renderer = NULL;
	m_json_spy_text_fmt = json_spy_text_fmt;

	if(output_type == sinsp_table::OT_JSON)
	{
		g_filterchecks_force_raw_times = true;
	}

#ifndef NOCURSESUI
	m_viz = NULL;
	m_spectro = NULL;
	m_spybox_text_format = sinsp_evt::PF_NORMAL;
	m_view_sidemenu = NULL;
	m_action_sidemenu = NULL;
	m_spy_box = NULL;
	m_search_caller_interface = NULL;
	m_viewinfo_page = NULL;
	m_mainhelp_page = NULL;
	m_is_mousedrag_available = is_mousedrag_available;

	for (int i = 0; i < 8; i++)
	{
		for (int j = 0; j < 8; j++)
		{
			init_pair((7-i)*8+j, i, (j==0?-1:j));
		}
	}

	m_view_sort_sidemenu = NULL;
	m_selected_view_sort_sidemenu_entry = 0;

	if(output_type == sinsp_table::OT_CURSES)
	{
		//
		// Colors initialization
		//
		m_colors[RESET_COLOR] = ColorPair(COLOR_WHITE,COLOR_BLACK);
		m_colors[DEFAULT_COLOR] = ColorPair(COLOR_WHITE,COLOR_BLACK);
		m_colors[FUNCTION_BAR] = ColorPair(COLOR_BLACK,COLOR_YELLOW);
		m_colors[FUNCTION_KEY] = ColorPair( COLOR_WHITE,COLOR_BLACK);
		m_colors[PANEL_HEADER_FOCUS] = ColorPair(COLOR_BLACK,COLOR_GREEN);
		m_colors[PANEL_HEADER_UNFOCUS] = ColorPair(COLOR_BLACK,COLOR_GREEN);
		m_colors[PANEL_HIGHLIGHT_FOCUS] = ColorPair(COLOR_BLACK,COLOR_CYAN);
		m_colors[PANEL_HIGHLIGHT_UNFOCUS] = ColorPair(COLOR_BLACK, COLOR_WHITE);
		m_colors[PANEL_HEADER_LIST_FOCUS] = ColorPair(COLOR_BLACK,COLOR_YELLOW);
		m_colors[PANEL_HEADER_LIST_HIGHLIGHT] = ColorPair(COLOR_BLACK,COLOR_GREEN);
		m_colors[FAILED_SEARCH] = ColorPair(COLOR_RED,COLOR_CYAN);
		m_colors[UPTIME] = A_BOLD | ColorPair(COLOR_CYAN,COLOR_BLACK);
		m_colors[BATTERY] = A_BOLD | ColorPair(COLOR_CYAN,COLOR_BLACK);
		m_colors[LARGE_NUMBER] = A_BOLD | ColorPair(COLOR_RED,COLOR_BLACK);
		m_colors[METER_TEXT] = ColorPair(COLOR_CYAN,COLOR_BLACK);
		m_colors[METER_VALUE] = A_BOLD | ColorPair(COLOR_CYAN,COLOR_BLACK);
		m_colors[LED_COLOR] = ColorPair(COLOR_GREEN,COLOR_BLACK);
		m_colors[TASKS_RUNNING] = A_BOLD | ColorPair(COLOR_GREEN,COLOR_BLACK);
		m_colors[PROCESS] = A_NORMAL;
		m_colors[PROCESS_SHADOW] = A_BOLD | ColorPair(COLOR_BLACK,COLOR_BLACK);
		m_colors[PROCESS_TAG] = A_BOLD | ColorPair(COLOR_YELLOW,COLOR_BLACK);
		m_colors[PROCESS_MEGABYTES] = ColorPair(COLOR_CYAN,COLOR_BLACK);
		m_colors[PROCESS_BASENAME] = A_BOLD | ColorPair(COLOR_CYAN,COLOR_BLACK);
		m_colors[PROCESS_TREE] = ColorPair(COLOR_CYAN,COLOR_BLACK);
		m_colors[PROCESS_R_STATE] = ColorPair(COLOR_GREEN,COLOR_BLACK);
		m_colors[PROCESS_D_STATE] = A_BOLD | ColorPair(COLOR_RED,COLOR_BLACK);
		m_colors[PROCESS_HIGH_PRIORITY] = ColorPair(COLOR_RED,COLOR_BLACK);
		m_colors[PROCESS_LOW_PRIORITY] = ColorPair(COLOR_RED,COLOR_BLACK);
		m_colors[PROCESS_THREAD] = ColorPair(COLOR_GREEN,COLOR_BLACK);
		m_colors[PROCESS_THREAD_BASENAME] = A_BOLD | ColorPair(COLOR_GREEN,COLOR_BLACK);
		m_colors[BAR_BORDER] = A_BOLD;
		m_colors[BAR_SHADOW] = A_BOLD | ColorPair(COLOR_BLACK,COLOR_BLACK);
		m_colors[SWAP] = ColorPair(COLOR_RED,COLOR_BLACK);
		m_colors[GRAPH_BLACK] = ColorPair(COLOR_BLACK,COLOR_BLACK);
		m_colors[GRAPH_WHITE] = ColorPair(COLOR_WHITE,COLOR_WHITE);
		m_colors[GRAPH_WHITE_D] = ColorPair(COLOR_GREEN,COLOR_WHITE);
		m_colors[GRAPH_GREEN_L] = ColorPair(COLOR_WHITE,COLOR_GREEN);
		m_colors[GRAPH_GREEN] = ColorPair(COLOR_WHITE,COLOR_GREEN);
		m_colors[GRAPH_GREEN_D] = ColorPair(COLOR_YELLOW,COLOR_GREEN);
		m_colors[GRAPH_YELLOW_L] = ColorPair(COLOR_GREEN,COLOR_YELLOW);
		m_colors[GRAPH_YELLOW] = ColorPair(COLOR_WHITE,COLOR_YELLOW);
		m_colors[GRAPH_YELLOW_D] = ColorPair(COLOR_RED,COLOR_YELLOW);
		m_colors[GRAPH_RED_L] = ColorPair(COLOR_YELLOW,COLOR_RED);
		m_colors[GRAPH_RED] = ColorPair(COLOR_WHITE,COLOR_RED);
		m_colors[GRAPH_RED_D] = ColorPair(COLOR_MAGENTA,COLOR_RED);
		m_colors[GRAPH_MAGENTA_L] = ColorPair(COLOR_RED,COLOR_MAGENTA);
		m_colors[GRAPH_MAGENTA] = ColorPair(COLOR_MAGENTA,COLOR_MAGENTA);
		m_colors[MEMORY_USED] = ColorPair(COLOR_GREEN,COLOR_BLACK);
		m_colors[MEMORY_BUFFERS] = ColorPair(COLOR_BLUE,COLOR_BLACK);
		m_colors[MEMORY_BUFFERS_TEXT] = A_BOLD | ColorPair(COLOR_BLUE,COLOR_BLACK);
		m_colors[MEMORY_CACHE] = ColorPair(COLOR_YELLOW,COLOR_BLACK);
		m_colors[LOAD_AVERAGE_FIFTEEN] = A_BOLD | ColorPair(COLOR_BLACK,COLOR_BLACK);
		m_colors[LOAD_AVERAGE_FIVE] = A_NORMAL;
		m_colors[LOAD_AVERAGE_ONE] = A_BOLD;
		m_colors[LOAD] = A_BOLD;
		m_colors[HELP_BOLD] = A_BOLD | ColorPair(COLOR_CYAN,COLOR_BLACK);
		m_colors[CLOCK] = A_BOLD;
		m_colors[CHECK_BOX] = ColorPair(COLOR_CYAN,COLOR_BLACK);
		m_colors[CHECK_MARK] = A_BOLD;
		m_colors[CHECK_TEXT] = A_NORMAL;
		m_colors[HOSTNAME] = A_BOLD;
		m_colors[CPU_NICE] = ColorPair(COLOR_BLUE,COLOR_BLACK);
		m_colors[CPU_NICE_TEXT] = A_BOLD | ColorPair(COLOR_BLUE,COLOR_BLACK);
		m_colors[CPU_NORMAL] = ColorPair(COLOR_GREEN,COLOR_BLACK);
		m_colors[CPU_KERNEL] = ColorPair(COLOR_RED,COLOR_BLACK);
		m_colors[CPU_IOWAIT] = A_BOLD | ColorPair(COLOR_BLACK, COLOR_BLACK);
		m_colors[CPU_IRQ] = ColorPair(COLOR_YELLOW,COLOR_BLACK);
		m_colors[CPU_SOFTIRQ] = ColorPair(COLOR_MAGENTA,COLOR_BLACK);
		m_colors[SPY_READ] = ColorPair(COLOR_RED,COLOR_BLACK);
		m_colors[SPY_WRITE] = ColorPair(COLOR_CYAN,COLOR_BLACK);

		//
		// Populate the main menu entries
		//
		m_menuitems.push_back(sinsp_menuitem_info("F1", "Help", sinsp_menuitem_info::ALL, KEY_F(1)));
		m_menuitems.push_back(sinsp_menuitem_info("F2", "Views", sinsp_menuitem_info::ALL, KEY_F(2)));
		m_menuitems.push_back(sinsp_menuitem_info("F4", "Filter", sinsp_menuitem_info::ALL, KEY_F(4)));
		m_menuitems.push_back(sinsp_menuitem_info("F5", "Echo", sinsp_menuitem_info::TABLE, KEY_F(5)));
		m_menuitems.push_back(sinsp_menuitem_info("F6", "Dig", sinsp_menuitem_info::TABLE, KEY_F(6)));
		m_menuitems.push_back(sinsp_menuitem_info("F7", "Legend", sinsp_menuitem_info::ALL, KEY_F(7)));
		m_menuitems.push_back(sinsp_menuitem_info("F8", "Actions", sinsp_menuitem_info::ALL, KEY_F(8)));
		m_menuitems.push_back(sinsp_menuitem_info("F9", "Sort", sinsp_menuitem_info::ALL, KEY_F(9)));
		m_menuitems.push_back(sinsp_menuitem_info("F12", "Spectro", sinsp_menuitem_info::ALL, KEY_F(12)));
		m_menuitems.push_back(sinsp_menuitem_info("CTRL+F", "Search", sinsp_menuitem_info::ALL, 6));
		m_menuitems.push_back(sinsp_menuitem_info("p", "Pause", sinsp_menuitem_info::ALL, 'p'));
		m_menuitems.push_back(sinsp_menuitem_info("c", "Clear", sinsp_menuitem_info::LIST, 'c'));

		m_menuitems_spybox.push_back(sinsp_menuitem_info("F1", "Help", sinsp_menuitem_info::ALL, KEY_F(1)));
		m_menuitems_spybox.push_back(sinsp_menuitem_info("F2", "View As", sinsp_menuitem_info::ALL, KEY_F(2)));
		m_menuitems_spybox.push_back(sinsp_menuitem_info("CTRL+F", "Search", sinsp_menuitem_info::ALL, 6));
		m_menuitems_spybox.push_back(sinsp_menuitem_info("p", "Pause", sinsp_menuitem_info::ALL, 'p'));
		m_menuitems_spybox.push_back(sinsp_menuitem_info("Bak", "Back", sinsp_menuitem_info::ALL, KEY_BACKSPACE));
		m_menuitems_spybox.push_back(sinsp_menuitem_info("c", "Clear", sinsp_menuitem_info::ALL, 'c'));
		m_menuitems_spybox.push_back(sinsp_menuitem_info("CTRL+G", "Goto", sinsp_menuitem_info::ALL, 7));

		//
		// Get screen dimensions
		//
		getmaxyx(stdscr, m_screenh, m_screenw);
		g_csysdig_screen_w = m_screenw;
	}
#endif
}

sinsp_cursesui::~sinsp_cursesui()
{
	if(m_datatable != NULL)
	{
		delete m_datatable;
	}

	if(m_json_spy_renderer != NULL)
	{
		delete m_json_spy_renderer;
	}

#ifndef NOCURSESUI
	if(m_output_type == sinsp_table::OT_CURSES)
	{
		if(m_viz != NULL)
		{
			delete m_viz;
		}

		if(m_spectro != NULL)
		{
			delete m_spectro;
		}

		if(m_view_sidemenu != NULL)
		{
			delete m_view_sidemenu;
		}

		if(m_action_sidemenu != NULL)
		{
			delete m_action_sidemenu;
		}

		if(m_viewinfo_page != NULL)
		{
			delete m_viewinfo_page;
		}

		if(m_mainhelp_page != NULL)
		{
			delete m_mainhelp_page;
		}

		if(m_spy_box)
		{
			delete m_spy_box;
		}
	}
#endif

	delete m_timedelta_formatter;
}

void sinsp_cursesui::configure(sinsp_view_manager* views)
{
	if(views == NULL)
	{
		ASSERT(false);
		throw sinsp_exception("trying to configure the command line UI with no views");
	}

	//
	// Copy the input views
	//
	m_views = *views;

	//
	// Determine which view is the starting one
	//
	m_selected_view = m_views.get_selected_view();
	m_selected_view_sidemenu_entry = m_selected_view;
	m_selected_action_sidemenu_entry = 0;
	m_selected_view_sort_sidemenu_entry = 0;
	m_sidemenu_sorting_col = -1;
}

void sinsp_cursesui::start(bool is_drilldown, bool is_spy_switch)
{
	//
	// Input validation
	//
	if(m_selected_view >= 0)
	{
		if(m_selected_view >= (int32_t)m_views.size())
		{
			if(m_views.size() == 0)
			{
				throw sinsp_exception("no views loaded");
			}
			else
			{
				ASSERT(false);
				throw sinsp_exception("invalid view");
			}
		}
	}

	//
	// Delete the previous table and visualizations
	//
	if(m_datatable != NULL)
	{
		delete m_datatable;
		m_datatable = NULL;
	}

	if(m_json_spy_renderer != NULL)
	{
		delete m_json_spy_renderer;
		m_json_spy_renderer = NULL;
	}

#ifndef NOCURSESUI
	spy_text_renderer::sysdig_output_type dig_otype = spy_text_renderer::OT_NORMAL;

	if(m_output_type == sinsp_table::OT_CURSES)
	{
		if(m_viz != NULL)
		{
			delete m_viz;
			m_viz = NULL;
		}

		if(m_spectro != NULL)
		{
			delete m_spectro;
			m_spectro = NULL;
			if(m_views.at(m_prev_selected_view)->m_drilldown_target == "dig_app")
			{
				dig_otype = spy_text_renderer::OT_LATENCY_APP;
			}
			else
			{
				dig_otype = spy_text_renderer::OT_LATENCY;
			}
		}

		if(m_spy_box && !is_spy_switch)
		{
			delete m_spy_box;
			m_spy_box = NULL;
		}

		m_chart = NULL;
	}
#endif

	//
	// Update the filter based on what's selected
	//
	create_complete_filter(false);

	//
	// If we need a new datatable, allocate it and set it up
	//
	sinsp_view_info* wi = NULL;
	sinsp_table::tabletype ty = sinsp_table::TT_NONE;

	if(m_selected_view >= 0)
	{
		wi = m_views.at(m_selected_view);

		if(wi->m_type == sinsp_view_info::T_TABLE)
		{
			ty = sinsp_table::TT_TABLE;
			m_datatable = new sinsp_table(m_inspector, ty, m_refresh_interval_ns, 
				m_output_type, m_json_first_row, m_json_last_row);
		}
		else if(wi->m_type == sinsp_view_info::T_LIST)
		{
			ty = sinsp_table::TT_LIST;
			m_datatable = new sinsp_table(m_inspector, ty, m_refresh_interval_ns, 
				m_output_type, m_json_first_row, m_json_last_row);
		}
		else if(wi->m_type == sinsp_view_info::T_SPECTRO)
		{
			ty = sinsp_table::TT_TABLE;

			//
			// Accelerate the refresh rate to 1/2s
			//
			if(m_refresh_interval_ns == 2000000000)
			{
				m_datatable = new sinsp_table(m_inspector, ty, m_refresh_interval_ns / 4, 
					m_output_type, m_json_first_row, m_json_last_row);
			}
			else
			{
				m_datatable = new sinsp_table(m_inspector, ty, m_refresh_interval_ns, 
					m_output_type, m_json_first_row, m_json_last_row);
			}
		}
		else
		{
			ASSERT(false);
		}

		try
		{
			m_datatable->configure(&wi->m_columns, 
				m_complete_filter,
				wi->m_use_defaults,
				m_view_depth);
		}
		catch(...)
		{
			delete m_datatable;
			m_datatable = NULL;
			throw;
		}

		if(m_sorting_col != -1 && m_sorting_col < (int32_t)wi->m_columns.size())
		{
			m_datatable->set_sorting_col(m_sorting_col);
		}
		else
		{
			m_datatable->set_sorting_col(wi->m_sortingcol);
		}
	}
	else
	{
		//
		// Create the visualization component
		//
		if(m_output_type == sinsp_table::OT_JSON)
		{
			m_json_spy_renderer= new json_spy_renderer(m_inspector,
				this,
				m_selected_view,
				spy_text_renderer::OT_NORMAL,
				m_print_containers,
				m_json_spy_text_fmt);

			m_json_spy_renderer->set_filter(m_complete_filter);
		}
#ifndef NOCURSESUI
		else
		{
			m_spy_box = new curses_textbox(m_inspector, this, m_selected_view, dig_otype);
			m_spy_box->reset();
			m_chart = m_spy_box;
			m_spy_box->set_filter(m_complete_filter);
		}
#endif
	}

#ifndef NOCURSESUI
	if(m_output_type != sinsp_table::OT_CURSES)
	{
		return;
	}

	//
	// If we need a table or spectrogram visualization, allocate it and set it up
	//
	if(m_output_type != sinsp_table::OT_JSON)
	{
		if(m_selected_view >= 0)
		{
			if(wi != NULL && wi->m_type == sinsp_view_info::T_SPECTRO)
			{
				ASSERT(ty == sinsp_table::TT_TABLE);
				m_spectro = new curses_spectro(this, 
					m_inspector, 
					m_views.at(m_selected_view)->m_id == "spectro_traces");
				m_viz = NULL;
				m_chart = m_spectro;
			}
			else
			{
				ASSERT(ty != sinsp_table::TT_NONE);
				m_viz = new curses_table(this, m_inspector, ty);
				m_spectro = NULL;
				m_chart = m_viz;
			}

			vector<int32_t> colsizes;
			vector<string> colnames;

			ASSERT(wi != NULL);

			wi->get_col_names_and_sizes(&colnames, &colsizes);

			if(m_viz)
			{
				ASSERT(m_spectro == NULL);
				m_viz->configure(m_datatable, &colsizes, &colnames);
			}
			else
			{
				ASSERT(m_spectro != NULL);
				m_spectro->configure(m_datatable);
			}

			if(!is_drilldown)
			{
				populate_view_sidemenu("", &m_sidemenu_viewlist);
			}
		}
	}
#endif

	m_prev_selected_view = m_selected_view;
}

#ifndef NOCURSESUI
void sinsp_cursesui::render_header()
{
	uint32_t j = 0;
	uint32_t k = 0;

	//
	// Show the 'viewing' line
	//
	attrset(m_colors[HELP_BOLD]);
	move(0, 0);
	for(j = 0; j < m_screenw; j++)
	{
		addch(' ');
	}

	mvaddstr(0, 0, "Viewing:");
	k += sizeof("Viewing: ") - 1;
 
	attrset(m_colors[sinsp_cursesui::PROCESS]);

	string vs;

	if(m_selected_view >= 0)
	{
		sinsp_view_info* sv = get_selected_view();
		const char* vcs = sv->m_name.c_str();
		vs = vcs;
	}
	else
	{
		if(m_selected_view == VIEW_ID_SPY)
		{
			vs = "I/O activity";
		}
		else if(m_selected_view == VIEW_ID_DIG)
		{
			vs = "sysdig output";
		}
		else
		{
			ASSERT(false);
		}
	}

	mvaddstr(0, k, vs.c_str());

	k+= vs.size() + 1;

	attrset(m_colors[HELP_BOLD]);
	mvaddstr(0, k, "For: ");
	k += sizeof("For: ") - 1;

	attrset(m_colors[sinsp_cursesui::PROCESS]);

	if(m_sel_hierarchy.size() != 0)
	{
		vs = "";

		for(j = 0; j < m_sel_hierarchy.size(); j++)
		{
			uint32_t pv = m_sel_hierarchy.at(j)->m_prev_selected_view;

			if(m_sel_hierarchy.at(j)->m_field == "")
			{
				continue;
			}

			if(m_views.at(pv)->m_type == sinsp_view_info::T_SPECTRO)
			{
				//vs += m_sel_hierarchy.at(j)->m_prev_manual_filter.c_str();
				vs += "spectrogram area";
			}
			else
			{
				vs += m_sel_hierarchy.at(j)->m_field;
				vs += "=";
				vs += m_sel_hierarchy.at(j)->m_val;
			}

			if(j < m_sel_hierarchy.size() - 1)
			{
				vs += " and ";
			}
		}

		if(vs == "")
		{
			vs = "whole machine";
		}
	}
	else
	{
		vs = "whole machine";
	}

	mvaddstr(0, k, vs.c_str());

	if(m_paused)
	{
		string wstr = "PAUSED";
		attrset(m_colors[sinsp_cursesui::LARGE_NUMBER]);
		mvprintw(0,
			m_screenw / 2 - wstr.size() / 2, 
			wstr.c_str());	
	}

	//
	// Show the 'filter' line
	//
	attrset(m_colors[HELP_BOLD]);

	move(1, 0);
	for(uint32_t j = 0; j < m_screenw; j++)
	{
		addch(' ');
	}

	attrset(m_colors[HELP_BOLD]);

	mvaddstr(1, 0, "Source:");
	k = sizeof("Source: ") - 1;

	attrset(m_colors[sinsp_cursesui::PROCESS]);
	
	string srcstr;
	
	if(m_inspector->is_live())
	{
		srcstr = "Live System";
	}
	else
	{
		if(m_n_evts_in_file == 0)
		{
			m_n_evts_in_file = m_inspector->get_num_events();
			m_evt_ts_delta = m_last_evt_ts - m_1st_evt_ts;
		}

		srcstr = m_inspector->get_input_filename();
		srcstr += " (" + to_string(m_n_evts_in_file) + " evts, ";

		if(m_truncated_input)
		{
			srcstr += " truncated, ";
		}

		m_timedelta_formatter->set_val(PT_RELTIME, 
			(uint8_t*)&m_evt_ts_delta,
			8,
			0,
			ppm_print_format::PF_DEC);

			srcstr += string(m_timedelta_formatter->tostring_nice(NULL, 0, 0)) + ")";
	}

	mvaddnstr(1, k, srcstr.c_str(), m_screenw - k - 1);

	k += srcstr.size() + 1;
	m_filterstring_start_x = k;

	attrset(m_colors[HELP_BOLD]);

	mvaddstr(1, k, "Filter:");
	k += sizeof("Filter: ") - 1;

	attrset(m_colors[sinsp_cursesui::PROCESS]);

	string sflt;
	if(m_complete_filter != "")
	{
		sflt = m_complete_filter.c_str();
	}
	else
	{
		sflt = "none";
	}

	mvaddnstr(1, k, sflt.c_str(), m_screenw - k - 1);
	
	k += sflt.size();
	m_filterstring_end_x = k;
}

void sinsp_cursesui::turn_search_on(search_caller_interface* ifc, string header_text)
{
	ASSERT(m_spy_box != NULL);
	m_search_header_text = header_text;
	m_spy_box->get_offset(&m_search_start_x, &m_search_start_y);

	m_search_caller_interface = ifc;
	m_output_searching = false;
	m_output_filtering = false;
	m_cursor_pos = 0;
	curs_set(1);
	render();
}

void sinsp_cursesui::draw_bottom_menu(vector<sinsp_menuitem_info>* items, bool istable)
{
	uint32_t j = 0;
	uint32_t k = 0;

	//
	// Clear the line
	//
	move(m_screenh - 1, 0);
	for(uint32_t j = 0; j < m_screenw; j++)
	{
		addch(' ');
	}

	m_mouse_to_key_list.clear();

	for(j = 0; j < items->size(); j++)
	{
		if(istable && ((items->at(j).m_type & sinsp_menuitem_info::TABLE) == 0))
		{
			continue;
		}

		if((!istable) && ((items->at(j).m_type & sinsp_menuitem_info::LIST) == 0))
		{
			continue;
		}

		uint32_t startx = k;

		attrset(m_colors[PROCESS]);
		string fks = items->at(j).m_key;
		mvaddnstr(m_screenh - 1, k, fks.c_str(), MAX(fks.size(), 2));
		k += MAX(fks.size(), 2);

		attrset(m_colors[PANEL_HIGHLIGHT_FOCUS]);
		fks = items->at(j).m_desc;
		
		if(fks.size() < 6)
		{
			fks.resize(6, ' ');
		}
		
		mvaddnstr(m_screenh - 1, k, fks.c_str(), fks.size());
		k += fks.size();
		
		m_mouse_to_key_list.add(sinsp_mouse_to_key_list_entry(startx,
			m_screenh - 1,
			k - 1,
			m_screenh - 1,
			items->at(j).m_keyboard_equivalent));
	}
}

void sinsp_cursesui::render_default_main_menu()
{
	bool istable;

	if(m_datatable != NULL && m_datatable->m_type == sinsp_table::TT_TABLE)
	{
		istable = true;
	}
	else
	{
		istable = false;
	}

	draw_bottom_menu(&m_menuitems, istable);
}

void sinsp_cursesui::render_spy_main_menu()
{
	draw_bottom_menu(&m_menuitems_spybox, false);
}

void sinsp_cursesui::render_filtersearch_main_menu()
{
	uint32_t k = 0;
	string* str = 0;

	//
	// Pick the right string based on what we're doing
	//
	if(m_output_filtering)
	{
		str = &m_manual_filter;

		if(*str == "" && m_is_filter_sysdig && m_complete_filter != "")
		{
			*str = m_complete_filter;
		}
	}
	else if(m_output_searching)
	{
		str = &m_manual_search_text;
	}
	else
	{
		if(m_search_caller_interface)
		{
			str = m_search_caller_interface->get_last_search_string();
		}
		else
		{
			ASSERT(false);
		}
	}

	//
	// Only clear the line if this is the first refresh, to prevent deleting the
	// text that the user is typing
	//
	if(m_cursor_pos == 0)
	{
		move(m_screenh - 1, 0);
		for(uint32_t j = 0; j < m_screenw; j++)
		{
			addch(' ');
		}
	}

	attrset(m_colors[PROCESS]);
	string fks = "F1";
	mvaddnstr(m_screenh - 1, k, fks.c_str(), 10);
	k += fks.size();
	attrset(m_colors[PANEL_HIGHLIGHT_FOCUS]);
	fks = "Help";
	fks.resize(6, ' ');
	mvaddnstr(m_screenh - 1, k, fks.c_str(), 6);
	k += 6;

	if(m_output_filtering)
	{
		attrset(m_colors[PROCESS]);
		fks = "F2";
		mvaddnstr(m_screenh - 1, k, fks.c_str(), 10);
		k += fks.size();
		attrset(m_colors[PANEL_HIGHLIGHT_FOCUS]);
		if(m_is_filter_sysdig)
		{
			fks = "Text";
		}
		else
		{
			fks = "sysdig";
		}
		fks.resize(6, ' ');
		mvaddnstr(m_screenh - 1, k, fks.c_str(), 6);
		k += 6;
	}

	attrset(m_colors[PROCESS]);
	fks = "Enter";
	mvaddnstr(m_screenh - 1, k, fks.c_str(), 10);
	k += fks.size();

	attrset(m_colors[PANEL_HIGHLIGHT_FOCUS]);
	fks = "Done";
	fks.resize(6, ' ');
	mvaddnstr(m_screenh - 1, k, fks.c_str(), 6);
	k += 6;

	attrset(m_colors[PROCESS]);
	fks = "Esc";
	mvaddnstr(m_screenh - 1, k, fks.c_str(), 10);
	k += fks.size();

	attrset(m_colors[PANEL_HIGHLIGHT_FOCUS]);
	fks = "Clear";
	fks.resize(6, ' ');
	mvaddnstr(m_screenh - 1, k, fks.c_str(), 6);
	k += 6;

	k++;
	attrset(m_colors[PANEL_HIGHLIGHT_FOCUS]);
	if(m_is_filter_sysdig)
	{
		fks = "Expression: ";
	}
	else
	{
		if(m_search_header_text == "")
		{
			fks = "Text to match: ";
		}
		else
		{
			fks = m_search_header_text + ": ";
		}
	}
	mvaddnstr(m_screenh - 1, k, fks.c_str(), 20);
	k += fks.size();

	uint32_t cursor_pos = k;

	if(m_cursor_pos == 0)
	{
		for(; k < m_screenw; k++)
		{
			addch(' ');
		}

		m_cursor_pos = cursor_pos;

		mvprintw(m_screenh - 1, m_cursor_pos, str->c_str());

		m_cursor_pos += str->size();
	}

	move(m_screenh - 1, m_cursor_pos);
}

void sinsp_cursesui::render_position_info()
{
	if(m_chart == NULL)
	{
		return;
	}

	int32_t pos;
	int32_t totlines;
	float percent;
	bool truncated;
	if(m_chart->get_position(&pos, &totlines, &percent, &truncated))
	{
		char prstr[128];
		string trs;
		uint32_t csize = 18;

		attrset(m_colors[sinsp_cursesui::PROCESS_MEGABYTES]);

		move(m_screenh - 1, m_screenw - csize);
		for(uint32_t k = 0; k < csize; k++)
		{
			addch(' ');
		}

		if(truncated)
		{
			trs = "(truncated)";
		}

		if(percent != 0)
		{
			sprintf(prstr, "%d/%d(%.1f%%)%s", (int)pos, (int)totlines, percent * 100, trs.c_str());
		}
		else
		{
			sprintf(prstr, "%d/%d(0.0%%)%s", (int)pos, (int)totlines, trs.c_str());
		}

		mvaddstr(m_screenh - 1, 
			m_screenw - strlen(prstr),
			prstr);
	}
}

void sinsp_cursesui::render_main_menu()
{
	if(m_output_filtering || m_output_searching || m_search_caller_interface != NULL)
	{
		render_filtersearch_main_menu();
	}
	else if(m_spy_box != NULL)
	{
		render_spy_main_menu();
	}
	else
	{
		render_default_main_menu();
	}
}

void sinsp_cursesui::render()
{
	if(m_spectro && !m_view_sidemenu)
	{
		return;
	}

	//
	// Draw the header at the top of the page
	//
	render_header();

	//
	// Print the position in the chart
	//
	if(m_output_filtering || m_output_searching || m_search_caller_interface != NULL)
	{
		render_position_info();
	}

	//
	// Draw the menu at the bottom of the screen
	//
	render_main_menu();

	//
	// If required, draw the side menu
	//
	if(m_view_sidemenu)
	{
		m_view_sidemenu->render();
	}

	if(m_view_sort_sidemenu)
	{
		m_view_sort_sidemenu->render();
	}

	if(m_action_sidemenu)
	{
		m_action_sidemenu->render();
	}

	//
	// Print the position in the chart
	//
	if(!(m_output_filtering || m_output_searching || m_search_caller_interface != NULL))
	{
		render_position_info();
	}
}
#endif

sinsp_view_info* sinsp_cursesui::get_selected_view()
{
	if(m_selected_view < 0)
	{
		return NULL;
	}

	ASSERT(m_selected_view < (int32_t)m_views.size());
	return m_views.at(m_selected_view);
}

sinsp_view_info* sinsp_cursesui::get_prev_selected_view()
{
	if(m_prev_selected_view < 0)
	{
		return NULL;
	}

	ASSERT(m_prev_selected_view < (int32_t)m_views.size());
	return m_views.at(m_prev_selected_view);
}

#ifndef NOCURSESUI
void sinsp_cursesui::populate_view_sidemenu(string field, vector<sidemenu_list_entry>* viewlist)
{
	uint32_t k = 0;

	viewlist->clear();
	uint64_t bpos = field.find('[');
	if(bpos != string::npos)
	{
		field = field.substr(0, bpos);
	}

	for(uint32_t j = 0; j < m_views.size(); ++j)
	{
		auto it = m_views.at(j);

		for(auto atit = it->m_applies_to.begin(); atit != it->m_applies_to.end(); ++atit)
		{
			if(*atit == field)
			{
				viewlist->push_back(sidemenu_list_entry(it->m_name, j));

				if(it->m_name == m_views.at(m_selected_view)->m_name)
				{
					m_selected_view_sidemenu_entry = k;

					if(m_view_sidemenu != NULL)
					{
						m_view_sidemenu->m_selct = k;
					}
				}

				k++;
			}
		}
	}

	if(m_view_sidemenu != NULL)
	{
		m_view_sidemenu->set_entries(viewlist);
	}
}

void sinsp_cursesui::populate_view_cols_sidemenu()
{
	int32_t k = 0;

	vector<sidemenu_list_entry> viewlist;
	sinsp_view_info* vinfo = get_selected_view();

	for(auto it : vinfo->m_columns)
	{
		if(it.m_name != "NA") 
		{
			if(m_sidemenu_sorting_col == k) 
			{
				viewlist.push_back(sidemenu_list_entry(it.m_name, k++));
				continue;
			}
			viewlist.push_back(sidemenu_list_entry(it.m_name, k++));
		}
	}

	if(viewlist.size() == 0)
	{
		viewlist.push_back(sidemenu_list_entry("<NO COLUMNS>", 0));
	}

	if(m_view_sort_sidemenu != NULL)
	{
		m_view_sort_sidemenu->set_entries(&viewlist);
	}
}



void sinsp_cursesui::populate_action_sidemenu()
{
	uint32_t k = 0;
	vector<sidemenu_list_entry> viewlist;

	m_selected_action_sidemenu_entry = 0;

	sinsp_view_info* vinfo = get_selected_view();

	for(auto hk : vinfo->m_actions)
	{
		string str = string("(") + hk.m_hotkey + ") " + hk.m_description;
		viewlist.push_back(sidemenu_list_entry(str, k++));
	}

	if(viewlist.size() == 0)
	{
		viewlist.push_back(sidemenu_list_entry("<NO ACTIONS>", 0));
	}

	if(m_action_sidemenu != NULL)
	{
		m_action_sidemenu->m_selct = 0;
		m_action_sidemenu->set_entries(&viewlist);
	}
}
#endif // NOCURSESUI

string combine_filters(string flt1, string flt2)
{
	if(flt1 == "")
	{
		return flt2;
	}
	else
	{
		if(flt2 == "")
		{
			return flt1;
		}
	}

	string res = "(" + flt1 + ") and (" + flt2 + ")";
	return res;
}

Json::Value sinsp_cursesui::generate_json_info_section()
{
	Json::Value jinfo;
	Json::Value jlegend;

	sinsp_view_info* wi = NULL;

	if(m_selected_view >= 0)
	{
		wi = m_views.at(m_selected_view);
		vector<int32_t> colsizes;
		vector<string> colnames;

		ASSERT(wi != NULL);

		jinfo["sortingCol"] = wi->m_sortingcol;

		for(auto av : wi->m_applies_to)
		{
			jinfo["appliesTo"].append(av);
		}

		sinsp_view_column_info* kinfo = wi->get_key();
		if(kinfo)
		{
			jinfo["drillDownKeyField"] = kinfo->m_field;
			jinfo["canDrillDown"] = true;
		}
		else
		{
			jinfo["canDrillDown"] = false;
		}

		wi->get_col_names_and_sizes(&colnames, &colsizes);

		uint32_t off;
		if(colnames.size() == m_datatable->m_types->size() - 1)
		{
			off = 1;
		}
		else
		{
			off = 0;
		}

		vector<filtercheck_field_info>* tlegend = m_datatable->get_legend();
		ASSERT(tlegend->size() == colnames.size());

		for(uint32_t j = 1; j < colnames.size(); j++)
		{
			Json::Value jcinfo;

			jcinfo["name"] = colnames[j];
			jcinfo["size"] = colsizes[j];
			jcinfo["type"] = param_type_to_string(m_datatable->m_types->at(j + off));
			jcinfo["format"] = print_format_to_string(tlegend->at(j).m_print_format);
			
			jlegend.append(jcinfo);
		}
	}

	jinfo["legend"] = jlegend;
	return jinfo;
}

void sinsp_cursesui::handle_end_of_sample(sinsp_evt* evt, int32_t next_res)
{
	vector<sinsp_sample_row>* sample;
	m_datatable->flush(evt);

	//
	// It's time to refresh the data for this chart.
	// First of all, create the data for the chart
	//
	if(m_output_type == sinsp_table::OT_JSON && (m_inspector->is_live() || (m_eof > 0)))
	{
		printf("{\"progress\": 100, ");

		sample = m_datatable->get_sample(get_time_delta());

		printf("\"count\": %" PRIu64 ", ", 
			m_datatable->m_json_output_lines_count);

		Json::Value root = generate_json_info_section();

		if(m_views.at(m_selected_view)->m_type == sinsp_view_info::T_TABLE)
		{
			bool res;
			execute_table_action(STA_DRILLDOWN_TEMPLATE, 0, &res);
			create_complete_filter(true);

			root["filterTemplateF"] = m_complete_filter;
			root["filterTemplate"] = m_complete_filter_noview;
		}

		Json::FastWriter writer;
		string jstr = writer.write(root);
		printf("\"info\": %s", jstr.substr(0, jstr.size() - 1).c_str());

		printf("}\n");
		//printf("%c", EOF);
	}
	else
	{
		if(m_output_type != sinsp_table::OT_JSON)
		{
			sample = m_datatable->get_sample(get_time_delta());
		}
	}

#ifndef NOCURSESUI
	if(m_output_type == sinsp_table::OT_CURSES)
	{
		//
		// If the help page has been shown, don't update the screen
		//
		if(m_viewinfo_page != NULL || m_mainhelp_page != NULL)
		{
			return;
		}

		//
		// Now refresh the UI.
		//
		if(!m_paused)
		{
			if(m_viz)
			{
				ASSERT(m_spectro == NULL);
				m_viz->update_data(sample);

				if(m_datatable->m_type == sinsp_table::TT_LIST && m_inspector->is_live())
				{
					m_viz->follow_end();
				}

				m_viz->render(true);
			}
			else if(m_spectro)
			{
				ASSERT(m_viz == NULL);
				m_spectro->update_data(sample);
				m_spectro->render(true);
			}
		}

		render();
	}
#endif
	//
	// If this is a trace file, check if we reached the end of the file.
	// Or, if we are in replay mode, wait for a key press before processing
	// the next sample.
	//
	if(!m_inspector->is_live())
	{
#ifndef NOCURSESUI
/*
		if(m_output_type == sinsp_table::OT_CURSES)
		{
			if(m_offline_replay)
			{
				while(getch() != ' ')
				{
					usleep(10000);
				}
			}
		}
*/		
#endif
	}
}

void sinsp_cursesui::restart_capture(bool is_spy_switch)
{
	if(!m_inspector->is_live() && m_n_evts_in_file == 0)
	{
		m_n_evts_in_file = m_inspector->get_num_events();
		m_evt_ts_delta = m_last_evt_ts - m_1st_evt_ts;
	}

	m_inspector->close();
	start(true, is_spy_switch);
	m_inspector->open(m_event_source_name);
}

void sinsp_cursesui::create_complete_filter(bool templated)
{
	if(m_is_filter_sysdig)
	{
		if(m_manual_filter != "")
		{
			m_complete_filter = m_manual_filter;
		}

		m_complete_filter_noview = m_complete_filter;
	}
	else
	{
		m_complete_filter = m_cmdline_capture_filter;
		m_complete_filter = combine_filters(m_complete_filter, m_sel_hierarchy.tofilter(templated));

		m_complete_filter_noview = m_complete_filter;

		//
		// Note: m_selected_view is smaller than 0 when there's no view, because we're doing
		//       non-view stuff like spying.
		//
		if(m_selected_view >= 0)
		{
			m_complete_filter = combine_filters(m_complete_filter, 
				m_views.at(m_selected_view)->get_filter(m_view_depth));
		}
	}
}

void sinsp_cursesui::switch_view(bool is_spy_switch)
{
#ifndef NOCURSESUI
	if(m_output_type == sinsp_table::OT_CURSES)
	{
		//
		// Clear the screen to make sure all the crap is removed
		//
		clear();

		//
		// If we're currently visualizing the spy box, reset it and return immediately
		//
		if(is_spy_switch)
		{
			if(m_spy_box)
			{
				m_spy_box->reset();
			}
		}
	}
#endif

	//
	// Put the current view in the hierarchy stack
	//
#if 1
	sinsp_view_info* psv = get_prev_selected_view();

	if(psv != NULL)
	{
		if(m_sel_hierarchy.size() > 0)
		{
			sinsp_ui_selection_info* psinfo = m_sel_hierarchy.at(m_sel_hierarchy.size() - 1);

			m_sel_hierarchy.push_back(psinfo->m_field, psinfo->m_val,
				psv->get_key(), psinfo->m_view_filter,
				m_prev_selected_view, m_selected_view_sidemenu_entry, 
				NULL, psv->m_sortingcol, m_manual_filter, m_is_filter_sysdig,
				m_datatable->is_sorting_ascending(), false);
		}
		else
		{
			m_sel_hierarchy.push_back("", "",
				psv->get_key(), "",
				m_prev_selected_view, m_selected_view_sidemenu_entry, 
				NULL, psv->m_sortingcol, m_manual_filter, m_is_filter_sysdig,
				m_datatable->is_sorting_ascending(), false);
		}
	}
#endif

	//
	// Clear the manual filter, but not if this is a sysdig filter and we're in the same
	// view (applying sysdig filters causes the same view to the reloaded, and in that
	// case we want to preserve the filter).
	//
	if(m_prev_selected_view != m_selected_view)
	{
		m_manual_filter = "";
	}

	//
	// If this is a file, we need to restart the capture.
	// If it's a live capture, we restart only if start() fails, which usually
	// happens in case one of the filter fields requested thread state.
	//
	if(!m_inspector->is_live())
	{
		m_eof = 0;
		m_last_progress_evt = 0;
		restart_capture(is_spy_switch);
	}
	else
	{
		//
		// When live, also make sure to unpause the viz, otherwise the screen 
		// will stay empty.
		//
		if(m_paused)
		{
			pause();
		}

		try
		{
			start(true, is_spy_switch);
		}
		catch(...)
		{
			restart_capture(is_spy_switch);
		}
	}

#ifndef NOCURSESUI
	if(m_output_type == sinsp_table::OT_CURSES)
	{
		delete m_view_sidemenu;
		m_view_sidemenu = NULL;

		delete m_action_sidemenu;
		m_action_sidemenu = NULL;
  
		delete m_view_sort_sidemenu;
		m_view_sort_sidemenu = NULL;

		if(m_viz != NULL)
		{
			m_viz->render(true);
		}
		else if(m_spectro != NULL)
		{
			m_spectro->render(true);
		}

		render();
	}
#endif
}

void sinsp_cursesui::spy_selection(string field, string val, 
	sinsp_view_column_info* column_info,
	bool is_dig)
{
	uint32_t srtcol;
	sinsp_table_field rowkeybak;

#ifdef NOCURSESUI
	if(true)
#else
	if(m_viz)
#endif
	{
#ifndef NOCURSESUI
		sinsp_table_field* rowkey = m_datatable->get_row_key(m_viz->m_selct);
#else
		sinsp_table_field* rowkey = NULL;
#endif
		if(rowkey != NULL)
		{
			rowkeybak.m_val = new uint8_t[rowkey->m_len];
			memcpy(rowkeybak.m_val, rowkey->m_val, rowkey->m_len);
			rowkeybak.m_len = rowkey->m_len;
		}

		srtcol = m_datatable->get_sorting_col();
	}
#ifndef NOCURSESUI
	else if(m_spectro)
	{
		m_is_filter_sysdig = true;
		m_manual_filter = m_spectro->m_selection_filter;
		srtcol = 0;
		rowkeybak.m_val = NULL;
		rowkeybak.m_len = 0;
		srtcol = 2;
	}
	else
	{
		ASSERT(false);
		return;
	}
#endif

	ASSERT(m_selected_view < (int32_t)m_views.size());

	if(m_views.at(m_selected_view)->m_drilldown_increase_depth)
	{
		m_view_depth++;
	}

	string vfilter;
	if(m_views.at(m_selected_view)->m_propagate_filter)
	{
		vfilter = m_views.at(m_selected_view)->get_filter(m_view_depth);
	}
	else
	{
		vfilter = "";
	}

	m_sel_hierarchy.push_back(field, val, column_info, 
		vfilter,
		m_selected_view, m_selected_view_sidemenu_entry, 
		&rowkeybak, srtcol, m_manual_filter, m_is_filter_sysdig, 
		m_datatable->is_sorting_ascending(), true);

	if(is_dig)
	{
		m_selected_view = VIEW_ID_DIG;
	}
	else
	{
		m_selected_view = VIEW_ID_SPY;
	}

	if(!m_inspector->is_live())
	{
		m_eof = 0;
		m_last_progress_evt = 0;
		restart_capture(false);
	}
	else
	{
		try
		{
			start(true, false);
		}
		catch(...)
		{
			restart_capture(false);
		}
	}

#ifndef NOCURSESUI
	render();
#endif
}

// returns false if there is no suitable drill down view for this field
bool sinsp_cursesui::do_drilldown(string field, string val, 
	sinsp_view_column_info* column_info,
	uint32_t new_view_num, filtercheck_field_info* info,
	bool dont_restart)
{
	//
	// unpause the thing if it's paused
	//
	if(m_paused)
	{
		pause();
	}

	//
	//	escape string parameters
	//
	if(info != NULL && info->m_type & PT_CHARBUF)
	{
		string escape = "\"";
		val = escape + val + escape;
	}

	//
	// Do the drilldown
	//
	sinsp_table_field* rowkey = NULL;

#ifndef NOCURSESUI
	if(m_viz != NULL)
	{
		rowkey = m_datatable->get_row_key(m_viz->m_selct);
	}
#endif
	sinsp_table_field rowkeybak;
	if(rowkey != NULL)
	{
		rowkeybak.m_val = new uint8_t[rowkey->m_len];
		memcpy(rowkeybak.m_val, rowkey->m_val, rowkey->m_len);
		rowkeybak.m_len = rowkey->m_len;
	}

	uint32_t srtcol;
	srtcol = m_datatable->get_sorting_col();

	if(m_views.at(m_selected_view)->m_drilldown_increase_depth)
	{
		if(m_views.at(new_view_num)->m_id != "spectro_tracers")
		{
			m_view_depth++;
		}
	}

	string vfilter;
	if(m_views.at(m_selected_view)->m_propagate_filter)
	{
		vfilter = m_views.at(m_selected_view)->get_filter(m_view_depth);
	}
	else
	{
		vfilter = "";
	}

	m_sel_hierarchy.push_back(field, val, 
		column_info, vfilter,
		m_selected_view, m_selected_view_sidemenu_entry, 
		&rowkeybak, srtcol, m_manual_filter, m_is_filter_sysdig,
		m_datatable->is_sorting_ascending(), true);

	m_selected_view = new_view_num;

	//
	// Reset the filter
	//
#ifndef NOCURSESUI
	if(m_output_type != sinsp_table::OT_JSON)
	{
		if(m_viz != NULL)
		{
			m_manual_filter = "";
			m_is_filter_sysdig = false;
		}
		else
		{
			ASSERT(m_spectro != NULL);
			m_is_filter_sysdig = true;
			m_manual_filter = m_spectro->m_selection_filter;
		}
	}
#endif

	if(!dont_restart)
	{
		if(!m_inspector->is_live())
		{
			m_eof = 0;
			m_last_progress_evt = 0;
			restart_capture(false);
		}
		else
		{
			try
			{
				start(true, false);
			}
			catch(...)
			{
				restart_capture(false);
			}
		}

#ifndef NOCURSESUI
		clear();
		populate_view_sidemenu(field, &m_sidemenu_viewlist);
		populate_action_sidemenu();

		if(m_viz)
		{
			m_viz->render(true);
		}
		else if(m_spectro)
		{
			m_spectro->render(true);
		}
		render();
#endif
	}

	return true;
}

// returns false if there is no suitable drill down view for this field
bool sinsp_cursesui::drilldown(string field, string val, 
	sinsp_view_column_info* column_info,
	filtercheck_field_info* info, bool dont_restart)
{
	uint32_t j = 0;

	for(j = 0; j < m_views.size(); ++j)
	{
		if(m_views.at(j)->m_id == m_views.at(m_selected_view)->m_drilldown_target)
		{
			return do_drilldown(field, val, column_info, j, info, dont_restart);			
		}
	}

	for(j = 0; j < m_views.size(); ++j)
	{
		auto it = m_views.at(j);

		for(auto atit = it->m_applies_to.begin(); atit != it->m_applies_to.end(); ++atit)
		{
			if(*atit == field)
			{
				return do_drilldown(field, val, column_info, j, info, dont_restart);
			}
		}
	}

	return false;
}

bool sinsp_cursesui::spectro_selection(string field, string val,
	sinsp_view_column_info* column_info,
	filtercheck_field_info* info, sysdig_table_action ta)
{
	uint32_t j = 0;
	string spectro_name;

 	if(m_views.at(m_selected_view)->m_spectro_type == "tracers")
 	{
		spectro_name = "spectro_traces";
 	}
 	else
 	{
		if(ta == STA_SPECTRO)
		{
			spectro_name = "spectro_all";
		}
		else
		{
			spectro_name = "spectro_file";
		}
	}

	for(j = 0; j < m_views.size(); ++j)
	{
		if(m_views.at(j)->m_id == spectro_name)
		{
			return do_drilldown(field, val, column_info, j, info, false);
		}
	}

	return false;
}

bool sinsp_cursesui::drillup()
{
	if(m_sel_hierarchy.size() > 0)
	{
		//
		// unpause the thing if it's paused
		//
		if(m_paused)
		{
			pause();
		}

		//
		// Do the drillup
		//
		string field;
		sinsp_ui_selection_info* psinfo = NULL;

		sinsp_ui_selection_info* sinfo = m_sel_hierarchy.at(m_sel_hierarchy.size() - 1);
		bool is_spctro_app = false;

		if(m_selected_view > 0 && m_views.at(m_selected_view)->m_id == "spectro_tracers")
		{
			is_spctro_app = true;
		}

		m_manual_filter = "";

		if(m_sel_hierarchy.size() > 1)
		{
			psinfo = m_sel_hierarchy.at(m_sel_hierarchy.size() - 2);
			field = psinfo->m_field;
		}

		sinsp_table_field rowkey = sinfo->m_rowkey;

		m_selected_view = sinfo->m_prev_selected_view;
		m_selected_view_sidemenu_entry = sinfo->m_prev_selected_sidemenu_entry;

		if(m_views.at(m_selected_view)->m_drilldown_increase_depth &&
			!is_spctro_app)
		{
			if(sinfo != NULL && sinfo->m_is_drilldown)
			{
				m_view_depth--;
			}
		}

		if(m_views.at(m_selected_view)->m_type == sinsp_view_info::T_SPECTRO)
		{
			m_is_filter_sysdig = false;
		}
		else
		{
			m_manual_filter = sinfo->m_prev_manual_filter;
			m_is_filter_sysdig = sinfo->m_prev_is_filter_sysdig;
		}
		
		bool is_sorting_ascending = sinfo->m_prev_is_sorting_ascending;

		ASSERT(m_selected_view < (int32_t)m_views.size());

		m_sel_hierarchy.pop_back();
		//m_views[m_selected_view].m_filter = m_sel_hierarchy.tofilter();

		m_complete_filter = m_cmdline_capture_filter;
		m_complete_filter = combine_filters(m_complete_filter, m_sel_hierarchy.tofilter(false));

		if(!m_inspector->is_live())
		{
			m_eof = 0;
			m_last_progress_evt = 0;
			restart_capture(false);
		}
		else
		{
			try
			{
				start(true, false);
			}
			catch(...)
			{
				restart_capture(false);
			}
		}
#ifndef NOCURSESUI
		if(m_viz)
		{
			if(rowkey.m_val != NULL)
			{
				m_viz->m_last_key.copy(&rowkey);
				m_viz->m_last_key.m_isvalid = true;
				m_viz->m_selection_changed = true;
			}
			else
			{
				m_viz->m_last_key.m_isvalid = false;
			}

			m_viz->m_drilled_up = true;
		}

		populate_view_sidemenu(field, &m_sidemenu_viewlist);
		populate_action_sidemenu();

		//
		// If sorting is different from the default one, restore it
		//
		if(sinfo->m_prev_sorting_col != m_views.at(m_selected_view)->m_sortingcol)
		{
			m_datatable->set_sorting_col(sinfo->m_prev_sorting_col);
		}

		m_datatable->set_is_sorting_ascending(is_sorting_ascending);

		//
		// If filtering is different from the default one, apply it
		//
		if(m_manual_filter != "" && !m_is_filter_sysdig)
		{
			m_datatable->set_freetext_filter(m_manual_filter);
		}

		clear();
		if(m_viz)
		{
			m_viz->render(true);
		}
		else if(m_spectro)
		{
			m_spectro->render(true);
		}

		render();
#endif

		if(rowkey.m_val)
		{
			delete[] rowkey.m_val;
		}
		return true;
	}

	return false;
}

void sinsp_cursesui::pause()
{
	m_paused = !m_paused;
	if(m_datatable != NULL)
	{
		m_datatable->set_paused(m_paused);
	}
#ifndef NOCURSESUI
	if(m_spectro == NULL)
	{
		render_header();
	}
#endif
}

#ifndef NOCURSESUI
void sinsp_cursesui::print_progress(double progress)
{
	attrset(m_colors[sinsp_cursesui::PROCESS]);

	string wstr = "Processing File";
	mvprintw(m_screenh / 2,
		m_screenw / 2 - wstr.size() / 2, 
		wstr.c_str());	

	//
	// Using sprintf because to_string doesn't support setting the precision 
	//
	char numbuf[64];
	sprintf(numbuf, "%.2lf", progress);
	wstr = "Progress: " + string(numbuf);
	mvprintw(m_screenh / 2 + 1,
		m_screenw / 2 - wstr.size() / 2, 
		wstr.c_str());

	refresh();
}

sysdig_table_action sinsp_cursesui::handle_textbox_input(int ch)
{
	bool closing = false;
	string* str = NULL;
	bool handled = true;

	//
	// Pick the right string based on what we're doing
	//
	if(m_output_filtering)
	{
		str = &m_manual_filter;
	}
	else if(m_output_searching)
	{
		str = &m_manual_search_text;
	}
	else
	{
		if(m_search_caller_interface)
		{
			str = m_search_caller_interface->get_last_search_string();
		}
		else
		{
			ASSERT(false);
		}
	}

	switch(ch)
	{
		case KEY_F(1):
			m_mainhelp_page = new curses_mainhelp_page(this);
			return STA_NONE;
		case KEY_F(2):
			m_is_filter_sysdig = !m_is_filter_sysdig;
			*str = "";
			m_cursor_pos = 0;
			render();
			return STA_NONE;
		case KEY_DOWN:
		case KEY_UP:
		case KEY_PPAGE:
		case KEY_NPAGE:
			if(m_spy_box != NULL)
			{
				m_spy_box->handle_input(ch);
			}
			else
			{
				if(m_viz)
				{
					m_viz->handle_input(ch);
				}
				else if(m_spectro)
				{
					ASSERT(false);
				}
			}
			return STA_NONE;
		case 27: // ESC
			*str = "";

			if(m_spy_box != NULL)
			{
				m_spy_box->scroll_to(m_search_start_x, m_search_start_y);
				m_spy_box->up();
			}
			// FALL THROUGH
		case '\n':
		case '\r':
		case KEY_ENTER:
		case 6:	// CTRL+F
		case KEY_F(4):
			closing = true;
			curs_set(0);

			if(m_is_filter_sysdig && !m_output_searching)
			{
				if(*str != "")
				{
					sinsp_filter_compiler compiler(m_inspector, *str);
					sinsp_filter* f;

					try
					{
						f = compiler.compile();
					}
					catch(const sinsp_exception& e)
					{
						//
						// Backup the cursor position
						//
						int cx, cy;
						getyx(stdscr, cy, cx);

						//
						// Print the error string
						//
						string wstr = "Invalid sysdig filter";

						attrset(m_colors[sinsp_cursesui::FAILED_SEARCH]);
						mvprintw(m_screenh / 2,
							m_screenw / 2 - wstr.size() / 2, 
							wstr.c_str());	

						//
						// Restore the cursor
						//
						attrset(m_colors[PANEL_HIGHLIGHT_FOCUS]);
						move(cy, cx);
						curs_set(1);
						closing = false;
						break;
					}

					delete f;
				}
			}

			break;
		case KEY_BACKSPACE:
		case 127:
			if(str->size() > 0)
			{
				m_cursor_pos--;
				move(m_screenh - 1, m_cursor_pos);
				addch(' ');
				move(m_screenh - 1, m_cursor_pos);
				*str = str->substr(0, str->size() - 1);

				if(str->size() < 2)
				{
					if(m_spy_box != NULL)
					{
						m_spy_box->scroll_to(m_search_start_x, m_search_start_y); 
					}
				}

				break;
			}
			else
			{
				return STA_NONE;
			}
		case KEY_F(3):
			if(m_search_caller_interface)
			{
				if(m_search_caller_interface->on_search_next())
				{
					render();
				}
				else
				{
					string wstr = "  NOT FOUND ";
					attrset(m_colors[sinsp_cursesui::FAILED_SEARCH]);

					mvprintw(m_screenh / 2,
						m_screenw / 2 - wstr.size() / 2, 
						wstr.c_str());

					render();
				}
			}

			break;
		default:
			handled = false;
			break;
	}

	if(ch >= ' ' && ch <= '~')
	{
		addch(ch);
		*str += ch;
		m_cursor_pos++;
	}
	else
	{
		if(!handled)
		{
			return STA_NONE;
		}
	}

	if(m_output_filtering)
	{
		if(!m_is_filter_sysdig)
		{
			//
			// Update the filter in the datatable
			//
			m_datatable->set_freetext_filter(*str);

			//
			// Refresh the data and the visualization
			//
			m_viz->update_data(m_datatable->get_sample(get_time_delta()), true);
			m_viz->render(true);
		}
	}
	else if(m_output_searching)
	{
		sinsp_table_field* skey = m_datatable->search_in_sample(*str);

		if(skey != NULL)
		{
			int32_t selct = m_datatable->get_row_from_key(skey);
			m_viz->goto_row(selct);
			m_search_nomatch = false;
		}
		else
		{
			m_search_nomatch = true;
			m_viz->render(true);
		}
	}
	else
	{
		if(m_search_caller_interface)
		{
			if(m_search_caller_interface->on_search_key_pressed(*str))
			{
				render();
			}
			else
			{
				string wstr = "  NOT FOUND ";
				attrset(m_colors[sinsp_cursesui::FAILED_SEARCH]);

				mvprintw(m_screenh / 2,
					m_screenw / 2 - wstr.size() / 2, 
					wstr.c_str());

				render();
			}

			render();
		}
		else
		{
			ASSERT(false);
		}
	}

	if(closing)
	{
		sysdig_table_action res = STA_NONE;

		if(m_is_filter_sysdig && !m_output_searching)
		{
			res = STA_SWITCH_VIEW;
		}

		m_search_nomatch = false;
		m_output_filtering = false;
		m_output_searching = false;
		m_search_caller_interface = NULL;
		render();

		if(res != STA_NONE)
		{
			return res;
		}
	}

	return STA_NONE;
}

sysdig_table_action sinsp_cursesui::handle_input(int ch)
{
	//
	// Avoid parsing keys during file load
	//
	if((!m_inspector->is_live()) && !is_eof() && 
		(m_spectro != NULL && !m_spectro->m_scroll_paused))
	{
		if(ch != KEY_BACKSPACE &&
			ch != 127 &&
			ch != 'q' &&
			ch != KEY_F(10))
		{
			return STA_NONE;
		}
	}

	if(m_mainhelp_page != NULL)
	{
		sysdig_table_action actn = m_mainhelp_page->handle_input(ch);

		if(actn == STA_DESTROY_CHILD)
		{
			delete m_mainhelp_page;
			m_mainhelp_page = NULL;

			if(m_spy_box)
			{
				m_spy_box->render();
			}

			if(m_viz != NULL)
			{
				m_viz->render(true);
			}
			else if(m_spectro)
			{
				switch_view(false);
			}

			if(m_viewinfo_page)
			{
				m_viewinfo_page->render();
			}

			render();
			return STA_NONE;
		}
		else if(actn != STA_PARENT_HANDLE)
		{
			return actn;			
		}
	}

	if(m_view_sidemenu != NULL)
	{
		ASSERT(m_action_sidemenu == NULL);

		sysdig_table_action ta = m_view_sidemenu->handle_input(ch);
		if(ta == STA_SWITCH_VIEW)
		{
			if(m_viewinfo_page)
			{
				delete m_viewinfo_page;
				m_viewinfo_page = NULL;
			}
			return ta;
		}
		else if(ta != STA_PARENT_HANDLE)
		{
			return STA_NONE;
		}
	}
	else
	{
		if(m_action_sidemenu != NULL)
		{
			sysdig_table_action ta = m_action_sidemenu->handle_input(ch);
			if(ta == STA_SWITCH_VIEW)
			{
				sinsp_view_info* vinfo = get_selected_view();

				g_logger.format("running action %d %s", m_selected_action_sidemenu_entry,
					vinfo->m_name.c_str());
				if(vinfo->m_actions.size() != 0)
				{
					ASSERT(m_selected_action_sidemenu_entry < vinfo->m_actions.size());
					run_action(&vinfo->m_actions[m_selected_action_sidemenu_entry]);
				}

				return ta;
			}
			else if(ta == STA_DESTROY_CHILD)
			{
				if(m_viz)
				{
					m_viz->set_x_start(0);
					delete m_action_sidemenu;
					m_action_sidemenu = NULL;
					m_viz->set_x_start(0);
					m_viz->recreate_win(m_screenh - 3);
					m_viz->render(true);
					m_viz->render(true);
				}
				else if(m_spectro)
				{
					delete m_action_sidemenu;
					m_action_sidemenu = NULL;
					m_spectro->recreate_win(m_screenh - 3);
					m_spectro->render(true);
					m_spectro->render(true);

				}				
				render();
			}
			else if(ta != STA_PARENT_HANDLE)
			{
				return STA_NONE;
			}
		}

		if(m_view_sort_sidemenu != NULL)
		{
			sysdig_table_action ta = m_view_sort_sidemenu->handle_input(ch);
			if(ta == STA_SWITCH_VIEW || ta == STA_DESTROY_CHILD)
			{
				if(ta == STA_SWITCH_VIEW) 
				{
					ASSERT(m_selected_view_sort_sidemenu_entry < get_selected_view()->m_columns.size());
					m_datatable->set_sorting_col(m_selected_view_sort_sidemenu_entry+1);
					m_datatable->sort_sample();
					m_viz->update_data(m_viz->m_data);
				}
				delete m_view_sort_sidemenu;
				m_view_sort_sidemenu = NULL;
				m_viz->set_x_start(0);
				m_viz->recreate_win(m_screenh - 3);
				m_viz->render(true);
				render();				
				if(ta == STA_SWITCH_VIEW) 
				{
					return STA_NONE;
				}
			}
			else if(ta != STA_PARENT_HANDLE)
			{
				return STA_NONE;
			}
		}

	}

	if(m_output_filtering || m_output_searching || m_search_caller_interface != NULL)
	{
		ASSERT(m_view_sidemenu == NULL);
		ASSERT(m_action_sidemenu == NULL);
		return handle_textbox_input(ch);
	}

	if(m_spy_box != NULL)
	{
		ASSERT(m_view_sidemenu == NULL);
		ASSERT(m_action_sidemenu == NULL);
		ASSERT(m_output_filtering == false);
		ASSERT(m_output_searching == false);
		sysdig_table_action actn = m_spy_box->handle_input(ch);

		if(actn != STA_PARENT_HANDLE)
		{
			return actn;
		}
	}

	//
	// Note: the info page doesn't handle input when the sidemenu is on, because in that
	//       case it's just going to passively show the info for the selected view
	//
	if(m_viewinfo_page && m_view_sidemenu == NULL)
	{
		ASSERT(m_view_sidemenu == NULL);

		sysdig_table_action actn = m_viewinfo_page->handle_input(ch);

		if(actn == STA_DESTROY_CHILD)
		{
			delete m_viewinfo_page;
			m_viewinfo_page = NULL;
			if(m_viz != NULL)
			{
				m_viz->render(true);
			}

			render();
			return STA_NONE;
		}

		return actn;
	}

	//
	// Pass the event to the table viz
	//
	if(m_viz)
	{
		sysdig_table_action actn = m_viz->handle_input(ch);
		if(actn != STA_PARENT_HANDLE)
		{
			return actn;
		}
	}
	else if(m_spectro)
	{
		sysdig_table_action actn = m_spectro->handle_input(ch);
		if(actn != STA_PARENT_HANDLE)
		{
			return actn;
		}
	}

	switch(ch)
	{
		case '?':
		case 'h':
		case KEY_F(1):
			m_mainhelp_page = new curses_mainhelp_page(this);
			break;
		case KEY_F(10):
		case 'q':
			return STA_QUIT;
		case 'p':
			pause();
			break;
		case KEY_F(2):
			if(m_action_sidemenu != NULL)
			{
				break;
			}

			if(m_view_sidemenu == NULL)
			{
				if(m_viz)
				{
					m_viz->set_x_start(VIEW_SIDEMENU_WIDTH);
				}
				else if(m_spectro)
				{
					m_spectro->set_x_start(VIEW_SIDEMENU_WIDTH);
				}

				m_view_sidemenu = new curses_table_sidemenu(curses_table_sidemenu::ST_VIEWS,
					this, m_selected_view_sidemenu_entry, VIEW_SIDEMENU_WIDTH);

				m_view_sidemenu->set_entries(&m_sidemenu_viewlist);
				m_view_sidemenu->set_title("Select View");
				render();

				m_viewinfo_page = new curses_viewinfo_page(this, 
					m_selected_view,
					TABLE_Y_START,
					VIEW_SIDEMENU_WIDTH,
					m_screenh - TABLE_Y_START - 1,
					m_screenw - VIEW_SIDEMENU_WIDTH);

				if(m_spectro)
				{
					render();
				}
			}
			else
			{
				if(m_viewinfo_page)
				{
					delete m_viewinfo_page;
					m_viewinfo_page = NULL;
				}

				delete m_view_sidemenu;
				m_view_sidemenu = NULL;

				if(m_viz)
				{
					m_viz->set_x_start(0);
					m_viz->recreate_win(m_screenh - 3);
				}
				else if(m_spectro)
				{
					switch_view(false);					
				}

				render();
			}

			break;
		case '/':
		case 6:	// CTRL+F
			m_search_caller_interface = NULL;
			m_output_searching = true;
			//m_manual_search_text = "";
			m_cursor_pos = 0;
			curs_set(1);
			render();
			break;
		case KEY_F(9):
		case '>':		// sort columns
			if(m_view_sidemenu != NULL)
			{
				break;
			}
			if(m_view_sort_sidemenu == NULL) 
			{
				m_viz->set_x_start(VIEW_SIDEMENU_WIDTH);
				m_sidemenu_sorting_col = m_datatable->get_sorting_col() -1;
				m_view_sort_sidemenu = new curses_table_sidemenu(curses_table_sidemenu::ST_COLUMNS,
				this, m_sidemenu_sorting_col, VIEW_SIDEMENU_WIDTH);

				populate_view_cols_sidemenu();
				m_view_sort_sidemenu->set_title("Select sort column");

				m_viz->set_x_start(VIEW_SIDEMENU_WIDTH);
				m_viz->recreate_win(m_screenh - 3);
				render();
				m_viewinfo_page = NULL;
			}
			else
			{
				m_viz->set_x_start(0);
				delete m_view_sort_sidemenu;
				m_view_sort_sidemenu = NULL;
				m_viz->set_x_start(0);
				m_viz->recreate_win(m_screenh - 3);
				m_viz->render(true);
				m_viz->render(true);
				render();
			}

			break;
		case '\\':
		case KEY_F(4):
			m_search_caller_interface = NULL;
			m_output_filtering = true;
			m_cursor_pos = 0;
			curs_set(1);
			render();
			break;
		case KEY_F(5):
		case 'e':
			if(m_datatable == NULL)
			{
				//
				// No F5 for non table displays
				//
				return STA_NONE;
			}
			else if(m_datatable->m_type == sinsp_table::TT_LIST)
			{
				//
				// No F5 for list tables
				//
				return STA_NONE;
			}

			if(m_datatable->m_sample_data != NULL && m_datatable->m_sample_data->size() != 0)
			{
				m_selected_view_sidemenu_entry = 0;
				m_selected_action_sidemenu_entry = 0;
				return STA_SPY;
			}
			break;
		case KEY_F(6):
		case 'd':
			if(m_datatable == NULL)
			{
				//
				// No F5 for non table displays
				//
				return STA_NONE;
			}
			else if(m_datatable->m_type == sinsp_table::TT_LIST)
			{
				//
				// No F5 for list tables
				//
				return STA_NONE;
			}

			if(m_datatable->m_sample_data != NULL && m_datatable->m_sample_data->size() != 0)
			{
				m_selected_view_sidemenu_entry = 0;
				m_selected_action_sidemenu_entry = 0;
				return STA_DIG;
			}

			break;
		case KEY_F(7):
			m_viewinfo_page = new curses_viewinfo_page(this,
				m_selected_view,
				0,
				0,
				m_screenh,
				m_screenw);
			break;
		case KEY_F(8):
			if(m_view_sidemenu != NULL)
			{
				break;
			}

			if(!m_viz)
			{
				ASSERT(false);
				break;
			}

			if(m_action_sidemenu == NULL)
			{
				m_viz->set_x_start(ACTION_SIDEMENU_WIDTH);
				m_action_sidemenu = new curses_table_sidemenu(curses_table_sidemenu::ST_ACTIONS, 
					this, m_selected_action_sidemenu_entry, ACTION_SIDEMENU_WIDTH);
				populate_action_sidemenu();
				m_action_sidemenu->set_title("Select Action");

				m_viz->set_x_start(ACTION_SIDEMENU_WIDTH);
				m_viz->recreate_win(m_screenh - 3);

				render();

				m_viewinfo_page = NULL;
			}
			else
			{
				m_viz->set_x_start(0);
				delete m_action_sidemenu;
				m_action_sidemenu = NULL;
				m_viz->set_x_start(0);
				m_viz->recreate_win(m_screenh - 3);
				m_viz->render(true);
				m_viz->render(true);
				render();
			}

			break;
		case KEY_RESIZE:
			getmaxyx(stdscr, m_screenh, m_screenw);
			
			render();

			if(m_spy_box)
			{
				m_spy_box->render();
				m_spy_box->render();
			}

			if(m_viz != NULL)
			{
				m_viz->recreate_win(m_screenh - 3);
				m_viz->render(true);
				m_viz->render(true);
			}
			else if(m_spectro)
			{
				m_spectro->recreate_win(m_screenh - 3);
				m_spectro->render(true);
				m_spectro->render(true);				
			}

			if(m_viewinfo_page)
			{
				m_viewinfo_page->render();
				m_viewinfo_page->render();
			}

			render();

			break;
		case KEY_MOUSE:
			{
				MEVENT* event = NULL;

				if(m_view_sidemenu != NULL)
				{
					event = &m_view_sidemenu->m_last_mevent;
				}
				else if(m_view_sort_sidemenu != NULL)
				{
					event = &m_view_sort_sidemenu->m_last_mevent;
				}
				else if(m_action_sidemenu != NULL)
				{
					event = &m_action_sidemenu->m_last_mevent;
				}
				else if(m_spy_box != NULL)
				{
					event = &m_spy_box->m_last_mevent;
				}
				else if(m_viz != NULL)
				{
					event = &m_viz->m_last_mevent;
				}
				else if(m_spectro != NULL)
				{
					event = &m_spectro->m_last_mevent;
				}

				if(event == NULL)
				{
					ASSERT(false);
					break;
				}

				if(event->bstate & BUTTON1_CLICKED ||
					event->bstate & BUTTON1_DOUBLE_CLICKED)
				{
					if((uint32_t)event->y == m_screenh - 1)
					{
						int keyc = m_mouse_to_key_list.get_key_from_coordinates(event->x, event->y);
						if(keyc != -1)
						{
							return handle_input(keyc);
						}
					}
					else if((uint32_t)event->y == 1 &&
						(uint32_t)event->x >= m_filterstring_start_x &&
						(uint32_t)event->x <= m_filterstring_end_x)
					{
						m_search_caller_interface = NULL;
						m_is_filter_sysdig = true;
						m_output_filtering = true;
						m_manual_filter = m_complete_filter;
						m_cursor_pos = 0;
						curs_set(1);
						render();
					}
				}
			}

			break;
		default:
			break;
	}

	return STA_NONE;
}

#endif // NOCURSESUI

int32_t sinsp_cursesui::get_viewnum_by_name(string name)
{
	for(uint32_t j = 0; j < m_views.size(); ++j)
	{
		if(m_views.at(j)->m_id == name)
		{
			return j;
		}
	}

	return -1;
}

//
// Note:
//  - The return value determines if the application should quit.
//  - res is set to false in case of error
//
bool sinsp_cursesui::handle_stdin_input(bool* res)
{
	string input;

	*res = true;

	//
	// Get the user json input
	//
	while(true)
	{
		std::getline(std::cin, input);
		if(input != "")
		{
			break;
		}
	}

	//
	// Parse the input
	//
	Json::Value root;
	Json::Reader reader;
	bool pres = reader.parse(input,
		root,
		false);

	if(!pres)
	{
		fprintf(stderr, "unable to parse the json input: %s",
			reader.getFormattedErrorMessages().c_str());
		*res = false;
		return false;
	}

	string astr = root["action"].asString();
	Json::Value args = root["args"];

	sysdig_table_action ta;
	uint32_t rownum = 0;

	if(astr == "apply")
	{
		ta = STA_SWITCH_VIEW;

		string vname = args["view"].asString();

		m_selected_view = get_viewnum_by_name(vname);
		if(m_selected_view == -1)
		{
			fprintf(stderr, "unknown view: %s", vname.c_str());
			*res = false;
			return false;
		}
	}
	else if(astr == "drilldown")
	{
		ta = STA_DRILLDOWN;

		rownum = args["rownum"].asInt();
	}
	else if(astr == "drillup")
	{
		ta = STA_DRILLUP;
	}
	else if(astr == "quit")
	{
		return true;
	}
	else
	{
		fprintf(stderr, "invalid action: %s", astr.c_str());
		*res = false;
		return false;
	}

	bool tres;
	execute_table_action(ta, rownum, &tres);
	return false;
}

uint64_t sinsp_cursesui::get_time_delta()
{
	if(m_inspector->is_live())
	{
		return m_refresh_interval_ns;
	}
	else
	{
		return m_last_evt_ts - m_1st_evt_ts;
	}
}

void sinsp_cursesui::run_action(sinsp_view_action_info* action)
{
	string resolved_command;
	bool replacing = false;
	string fld_to_replace;

#ifndef NOCURSESUI
	ASSERT(m_viz != NULL);
	ASSERT(m_spectro == NULL);

	if(m_viz->get_data_size() == 0)
	{
		//
		// No elements in the table means no selection
		//
		return;
	}
#endif // NOCURSESUI

	//
	// Scan the command string and replace the field names with the values from the selection
	//
	for(uint32_t j = 0; j < action->m_command.size(); j++)
	{
		char sc = action->m_command[j];

		if(sc == '%')
		{
			fld_to_replace = "";

			if(replacing)
			{
				throw sinsp_exception("the following command has the wrong syntax: " + action->m_command);
			}

			replacing = true;
		}
		else
		{
			if(replacing)
			{
				if(sc == ' ' || sc == '\t' || sc == '0')
				{
					replacing = false;
#ifndef NOCURSESUI
					string val = m_viz->get_field_val(fld_to_replace);
					resolved_command += val;
#endif // NOCURSESUI
					resolved_command += sc;
				}
				else
				{
					fld_to_replace += sc;
				}
			}
			else
			{
				resolved_command += sc;
			}
		}
	}

	if(replacing)
	{
#ifndef NOCURSESUI
		string  val = m_viz->get_field_val(fld_to_replace);
		resolved_command += val;
#endif // NOCURSESUI
	}

	g_logger.format("original command: %s", action->m_command.c_str());
	g_logger.format("running command: %s", resolved_command.c_str());

#ifndef NOCURSESUI
	//
	// Exit curses mode
	//
	endwin();
#endif // NOCURSESUI

	//
	// If needed, ask for confirmation
	//
	if(action->m_ask_confirmation)
	{
		printf("Confirm command '%s'? [y/N] ", resolved_command.c_str());
		fflush(stdout);

		//
		// Wait for the enter key
		// 
		while(int c = getch())
		{
			if(c == -1)
			{
				do_sleep(10000);
				continue;
			}
			else if(c == 'y' || c == 'Y')
			{
				break;
			}
			else
			{
				goto action_end;
			}
		}
	}

	//
	// Run the command
	//
	{
		int sret = system(resolved_command.c_str());
		if(sret == -1)
		{
			g_logger.format("command failed");
		}
	}

	//
	// If needed, wait for the command to complete
	//
	if(action->m_waitfinish)
	{
		printf("Command finished. Press ENTER to return to csysdig.");
		fflush(stdout);

		//
		// Wait for the enter key
		// 
		while(getch() == -1)
		{
			do_sleep(10000);
		}
	}

action_end:
	//
	// Empty the keyboard buffer
	//
	while(getch() != -1);

#ifndef NOCURSESUI
	//
	// Reenter curses mode
	//
	reset_prog_mode();

	//
	// Refresh the screen
	//
	render();
#endif //  NOCURSESUI
}

#ifndef NOCURSESUI
bool sinsp_cursesui::is_spectro_paused(int input)
{
	if(m_spectro == NULL)
	{
		return false;
	}

	if(input == ' ')
	{
		m_spectro->m_scroll_paused = false;
	}

	return m_spectro->m_scroll_paused;
}
#endif //  NOCURSESUI

//
// Returns true if the caller should return immediatly after calling us. 
// In that case, res is filled with the result.
//
bool sinsp_cursesui::execute_table_action(sysdig_table_action ta, uint32_t rownumber, bool* res)
{
	//
	// Some events require that we perform additional actions
	//
	switch(ta)
	{
	case STA_QUIT:
		*res = true;
		return true;
	case STA_SWITCH_VIEW:
		switch_view(false);
		*res = false;
		return true;
	case STA_SWITCH_SPY:
		switch_view(true);
		*res = false;
		return true;
	case STA_DRILLDOWN:
		{
#ifndef NOCURSESUI
			if(m_viz != NULL)
			{
				sinsp_view_column_info* kinfo = get_selected_view()->get_key();

				//
				// Note: kinfo is null for list views, which currently don't support
				//       drill down
				//
				if(kinfo != NULL)
				{
					auto res = m_datatable->get_row_key_name_and_val(m_viz->m_selct, false);
					if(res.first != NULL)
					{
						drilldown(kinfo->get_filter_field(m_view_depth),
							res.second.c_str(), 
							kinfo,
							res.first,
							false);
					}
				}
			}
			else
#endif
			{
				if(m_output_type == sinsp_table::OT_CURSES)
				{
					drilldown("", "", NULL, NULL, false);
				}
				else
				{
					sinsp_view_column_info* kinfo = get_selected_view()->get_key();
					auto res = m_datatable->get_row_key_name_and_val(rownumber, false);
					if(res.first != NULL)
					{
						drilldown(kinfo->get_filter_field(m_view_depth),
							res.second.c_str(), 
							kinfo,
							res.first, 
							false);
					}
				}
			}
		}

		*res = false;
		return true;
	case STA_DRILLDOWN_TEMPLATE:
		{
			sinsp_view_column_info* kinfo = get_selected_view()->get_key();
			auto res = m_datatable->get_row_key_name_and_val(0, true);
			if(res.first != NULL)
			{
				drilldown(kinfo->get_filter_field(m_view_depth),
					res.second.c_str(), 
					kinfo,
					res.first,
					true);
			}
		}

		*res = false;
		return true;
	case STA_DRILLUP:
		drillup();
		
		*res = false;
		return true;
#ifndef NOCURSESUI
	case STA_SPECTRO:
	case STA_SPECTRO_FILE:
		{
			sinsp_view_column_info* kinfo = get_selected_view()->get_key();

			//
			// Note: kinfo is null for list views, that currently don't support
			//       drill down
			//
			if(kinfo != NULL)
			{
				auto res = m_datatable->get_row_key_name_and_val(m_viz->m_selct, false);
				if(res.first != NULL)
				{
					spectro_selection(get_selected_view()->get_key()->get_filter_field(m_view_depth), 
						res.second.c_str(),
						get_selected_view()->get_key(),
						res.first, ta);
				}
			}
		}
		
		*res = false;
		return true;
#endif
	case STA_SPY:
		{
			pair<filtercheck_field_info*, string> res;
#ifndef NOCURSESUI
			if(m_output_type == sinsp_table::OT_CURSES)
			{
				res = m_datatable->get_row_key_name_and_val(m_viz->m_selct, false);
			}
			else
#endif
			{
				res = m_datatable->get_row_key_name_and_val(rownumber, false);
			}

			if(res.first != NULL)
			{
				spy_selection(get_selected_view()->get_key()->get_filter_field(m_view_depth), 
					res.second.c_str(),
					get_selected_view()->get_key(),
					false);
			}
		}
		
		*res = false;
		return true;
	case STA_DIG:
		{
#ifndef NOCURSESUI
			if(m_viz)
			{
				auto res = m_datatable->get_row_key_name_and_val(m_viz->m_selct, false);
				if(res.first != NULL)
				{
					spy_selection(get_selected_view()->get_key()->get_filter_field(m_view_depth), 
						res.second.c_str(),
						get_selected_view()->get_key(),
						true);
				}
			}
			else
#endif
			{
				if(m_output_type == sinsp_table::OT_CURSES)
				{
					spy_selection("", "", NULL, true);
				}
				else
				{
					auto res = m_datatable->get_row_key_name_and_val(rownumber, false);
					if(res.first != NULL)
					{
						spy_selection(get_selected_view()->get_key()->get_filter_field(m_view_depth), 
							res.second.c_str(),
							get_selected_view()->get_key(),
							true);
					}
				}
			}
		}
		
		*res = false;
		return true;
	case STA_NONE:
		break;
	default:
		ASSERT(false);
		break;
	}

	return false;
}

#endif // CSYSDIG
