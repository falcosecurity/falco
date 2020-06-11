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
#include "cursescomponents.h"
#include "cursestable.h"
#include "cursesui.h"

///////////////////////////////////////////////////////////////////////////////
// curses_table implementation
///////////////////////////////////////////////////////////////////////////////
curses_table::curses_table(sinsp_cursesui* parent, sinsp* inspector, sinsp_table::tabletype type)
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
	m_type = type;

	m_converter = new sinsp_filter_check_reference();

	//
	// Column sizes initialization
	//
	m_colsizes[PT_NONE] = 0;
	m_colsizes[PT_INT8] = 8;
	m_colsizes[PT_INT16] = 8;
	m_colsizes[PT_INT32] = 8;
	m_colsizes[PT_INT64] = 8;
	m_colsizes[PT_UINT8] = 8;
	m_colsizes[PT_UINT16] = 8;
	m_colsizes[PT_UINT32] = 8;
	m_colsizes[PT_UINT64] = 8;
	m_colsizes[PT_CHARBUF] = 32;
	m_colsizes[PT_BYTEBUF] = 32;
	m_colsizes[PT_ERRNO] = 8;
	m_colsizes[PT_SOCKADDR] = 16;
	m_colsizes[PT_SOCKTUPLE] = 16;
	m_colsizes[PT_FD] = 32;
	m_colsizes[PT_PID] = 16;
	m_colsizes[PT_FDLIST] = 16;
	m_colsizes[PT_FSPATH] = 32;
	m_colsizes[PT_SYSCALLID] = 8;
	m_colsizes[PT_SIGTYPE] = 8;
	m_colsizes[PT_RELTIME] = 16;
	m_colsizes[PT_ABSTIME] = 16;
	m_colsizes[PT_PORT] = 8;
	m_colsizes[PT_L4PROTO] = 8;
	m_colsizes[PT_SOCKFAMILY] = 8;
	m_colsizes[PT_BOOL] = 8;
	m_colsizes[PT_IPV4ADDR] = 8;
	m_colsizes[PT_IPV6ADDR] = 16;
	m_colsizes[PT_DYN] = 8;
	m_colsizes[PT_FLAGS8] = 32;
	m_colsizes[PT_FLAGS16] = 32;
	m_colsizes[PT_FLAGS32] = 32;
	m_colsizes[PT_MODE] = 32;
	m_colsizes[PT_UID] = 12;
	m_colsizes[PT_GID] = 12;
	m_colsizes[PT_DOUBLE] = 8;
	m_colsizes[PT_SIGSET] = 32;

	//
	// Define the table size
	//
	m_w = TABLE_WIDTH;
	m_h = m_parent->m_screenh - 3;
	m_scrolloff_x = 0;

	//
	// Create the table window
	//
	refresh();
	m_tblwin = newwin(m_h, m_w, m_table_y_start, 0);
}

curses_table::~curses_table()
{
	if(m_tblwin)
	{
		delwin(m_tblwin);
	}

	delete m_converter;
}

void curses_table::configure(sinsp_table* table, 
	vector<int32_t>* colsizes, vector<string>* colnames)
{
	uint32_t j;

	m_table = table;

	vector<filtercheck_field_info>* legend = m_table->get_legend();

	if(colsizes)
	{
		if(colsizes->size() != 0 && colsizes->size() != legend->size())
		{
			throw sinsp_exception("invalid table legend for view " + m_parent->m_views.at(m_parent->m_selected_view)->m_name + 
				" : column sizes doesn't match (" + 
				to_string(colsizes->size()) + " column sizes, " + 
				to_string(legend->size()) + " entries in legend)");
		}
	}

	if(colnames)
	{
		if(colnames->size() != 0 && colnames->size() != legend->size())
		{
			throw sinsp_exception("invalid table legend for view " + m_parent->m_views.at(m_parent->m_selected_view)->m_name + 
				" : column names doesn't match (" + 
				to_string(colnames->size()) + " column names, " + 
				to_string(legend->size()) + " entries in legend)");
		}
	}

	for(j = 1; j < legend->size(); j++)
	{
		curses_table_column_info ci;
		ci.m_info = legend->at(j);

		if(colsizes->size() == 0 || colsizes->at(j) == -1)
		{
			ci.m_size = m_colsizes[legend->at(j).m_type];
		}
		else
		{
			ci.m_size = colsizes->at(j);		
		}

		if(colnames->size() == 0)
		{
			ci.m_name = ci.m_info.m_name;
		}
		else
		{
			ci.m_name = colnames->at(j);	
		}

/*
		int32_t namelen = strlen(ci.m_info.m_name);
		
		if(ci.m_size < namelen + 1)
		{
			ci.m_size = namelen + 1;
		}
*/
		m_legend.push_back(ci);
	}
}

void curses_table::update_rowkey(int32_t row)
{
	sinsp_table_field* rowkey = m_table->get_row_key(row);

	if(rowkey != NULL)
	{
		m_last_key.copy(rowkey);
		m_last_key.m_isvalid = true;
	}
	else
	{
		m_last_key.m_isvalid = false;
	}
}

void curses_table::update_data(vector<sinsp_sample_row>* data, bool force_selection_change)
{
	m_data = data;

	if(m_selection_changed && (m_last_key.m_isvalid || m_drilled_up || force_selection_change))
	{
		int32_t selct = m_table->get_row_from_key(&m_last_key);
		if(selct == -1)
		{
			m_selct--;
			m_last_key.m_isvalid = false;
		}
		else
		{
			m_selct = selct;
			
//			if(m_drilled_up)
			{
				selection_goto((int32_t)m_data->size(), m_selct);
			}

			render(true);
//m_drilled_up = false;
		}

		sanitize_selection((int32_t)m_data->size());
	}
	else
	{
		update_rowkey(m_selct);
	}
}

void curses_table::print_line_centered(string line, int32_t off)
{
	wattrset(m_tblwin, m_parent->m_colors[sinsp_cursesui::PROCESS]);

	if(line.size() < m_parent->m_screenw)
	{
		mvwprintw(m_tblwin, 
			m_parent->m_screenh / 2 + off,
			m_parent->m_screenw / 2 - line.size() / 2, 
			line.c_str());
	}
	else
	{
		uint32_t spos = 0;

		for(uint32_t j = 0;; j++)
		{
			string ss = line.substr(spos, spos + m_parent->m_screenw);
glogf("2, %d %s\n", spos, ss.c_str());

			mvwprintw(m_tblwin, 
				m_parent->m_screenh / 2 + off + j,
				0,
				ss.c_str());

			spos += m_parent->m_screenw;
			if(spos >= line.size())
			{
				break;
			}
		}
	}
}

void curses_table::print_wait()
{
	string wstr;
	bool is_tracer_view = false;

	sinsp_view_info* vinfo = m_parent->get_selected_view();
	if(vinfo)
	{
		if(vinfo->m_id == "tracers" ||
			vinfo->m_id == "tracer_ids")
		{
			is_tracer_view = true;
		}
	}
	else
	{
		ASSERT(false);
	}

	if(is_tracer_view)
	{
		print_line_centered("No data for this view.");
		print_line_centered("Note: in order to see any data here, you need to push tracers to sysdig from your app as described here: XXX.", 2);
	}
	else
	{
		if(m_inspector->is_live())
		{
			wstr = "Collecting Data";
		}
		else
		{
			if(m_parent->is_eof())
			{
				wstr = "No Data For This View";
			}
		}
	
		print_line_centered(wstr);
	}
}

void curses_table::print_error(string wstr)
{
	wattrset(m_tblwin, m_parent->m_colors[sinsp_cursesui::FAILED_SEARCH]);

	mvwprintw(m_tblwin, 
		m_parent->m_screenh / 2,
		m_parent->m_screenw / 2 - wstr.size() / 2, 
		wstr.c_str());	
}

void curses_table::render(bool data_changed)
{
	uint32_t j, k;
	int32_t l, m;
	wclear(m_tblwin);

	//
	// Clear the screen
	//
	if(m_data == NULL)
	{
		print_wait();
		goto render_end;
	}

	if(m_data->size() != 0)
	{
		if(m_legend.size() != m_data->at(0).m_values.size())
		{
			ASSERT(false);
			throw sinsp_exception("corrupted curses table data");
		}
	}

	if(data_changed)
	{
		m_column_startx.clear();

		if(m_selct < 0)
		{
			m_selct = 0;
		}
		else if(m_selct > (int32_t)m_data->size() - 1)
		{
			m_selct = (int32_t)m_data->size() - 1;
		}

		wattrset(m_tblwin, m_parent->m_colors[sinsp_cursesui::PANEL_HEADER_FOCUS]);

		//
		// Render the column headers
		//
		wmove(m_tblwin, 0, 0);

		for(j = 0; j < m_w; j++)
		{
			if(m_type == sinsp_table::TT_TABLE)
			{
				wattrset(m_tblwin, m_parent->m_colors[sinsp_cursesui::PANEL_HEADER_FOCUS]);
			}
			else
			{
				wattrset(m_tblwin, m_parent->m_colors[sinsp_cursesui::PANEL_HEADER_LIST_FOCUS]);
			}

			waddch(m_tblwin, ' ');
		}

		for(j = 0, k = 0; j < m_legend.size(); j++)
		{
			if(j == m_table->get_sorting_col() - 1)
			{
				if(m_type == sinsp_table::TT_TABLE)
				{
					wattrset(m_tblwin, m_parent->m_colors[sinsp_cursesui::PANEL_HIGHLIGHT_FOCUS]);
				}
				else
				{
					wattrset(m_tblwin, m_parent->m_colors[sinsp_cursesui::PANEL_HEADER_LIST_HIGHLIGHT]);					
				}
			}
			else
			{
				if(m_type == sinsp_table::TT_TABLE)
				{
					wattrset(m_tblwin, m_parent->m_colors[sinsp_cursesui::PANEL_HEADER_FOCUS]);
				}
				else
				{
					wattrset(m_tblwin, m_parent->m_colors[sinsp_cursesui::PANEL_HEADER_LIST_FOCUS]);
				}
			}
			
			m_column_startx.push_back(k);

			string coltext = m_legend[j].m_name;
			if((int32_t)coltext.size() > m_legend[j].m_size - 1)
			{
				coltext = coltext.substr(0, m_legend[j].m_size - 1);
			}

			uint32_t tindex = m_table->m_do_merging? j + 2 : j + 1;

			curses_table::alignment al = get_field_alignment(m_table->m_types->at(tindex));
			if(al == curses_table::ALIGN_RIGHT)
			{
				coltext.insert(0, m_legend[j].m_size - coltext.size() - 1, ' ');
			}

			mvwaddnstr(m_tblwin, 0, k, coltext.c_str(), m_legend[j].m_size - 1);

			for(l = strlen(m_legend[j].m_name.c_str()); l < m_legend[j].m_size; l++)
			{
				waddch(m_tblwin, ' ');
			}

			k += m_legend[j].m_size;
		}

		//
		// If there is no data, print the "waiting for data" message
		//
		if(m_data->size() == 0)
		{
			if(!m_parent->is_searching())
			{
				print_wait();
				goto render_end;
			}
		}

		//
		// Render the rows
		//
		vector<sinsp_table_field>* row;

		for(l = 0; l < (int32_t)MIN(m_data->size(), m_h - 1); l++)
		{
			if(l + m_firstrow >= (int32_t)m_data->size())
			{
				break;
			}

			row = &(m_data->at(l + m_firstrow).m_values);

			//
			// Pick the proper color based on the selection
			//
			if(l == m_selct - (int32_t)m_firstrow)
			{
				wattrset(m_tblwin, m_parent->m_colors[sinsp_cursesui::PANEL_HIGHLIGHT_FOCUS]);
			}
			else
			{
				wattrset(m_tblwin, m_parent->m_colors[sinsp_cursesui::PROCESS]);
			}

			//
			// Render the row
			//
			wmove(m_tblwin, l + 1, 0);
			for(j = 0; j < m_w; j++)
			{
				waddch(m_tblwin, ' ');
			}

			for(j = 0, k = 0; j < m_legend.size(); j++)
			{
				sinsp_filter_check* extractor = m_table->m_extractors->at(j + 1);
				uint64_t td = 0;

				if(extractor->m_aggregation == A_TIME_AVG || 
					extractor->m_merge_aggregation == A_TIME_AVG)
				{
					td = m_parent->get_time_delta();
				}

				m_converter->set_val(m_legend[j].m_info.m_type, 
					row->at(j).m_val, 
					row->at(j).m_len,
					row->at(j).m_cnt,
					m_legend[j].m_info.m_print_format);

				uint32_t size = m_legend[j].m_size - 1;
				
				//
				// size=0 means "use the whole available space"
				//
				if(size == 0)
				{
					size = m_w - k - 1;
				}

				mvwaddnstr(m_tblwin,
					l + 1,
					k,
					m_converter->tostring_nice(NULL, size, td),
					size);

				k += m_legend[j].m_size;
			}
		}

		wattrset(m_tblwin, m_parent->m_colors[sinsp_cursesui::PROCESS]);

		if(l < (int32_t)m_h - 1)
		{
			for(m = l; m < (int32_t)m_h - 1; m++)
			{
				wmove(m_tblwin, m + 1, 0);

				for(j = 0; j < m_w; j++)
				{
					waddch(m_tblwin, ' ');
				}
			}
		}
	}

render_end:
	if(m_data && m_data->size() == 0)
	{
		if(m_parent->is_searching())
		{
			print_error(string(" NO MATCH "));
		}
	}

	if(m_parent->m_search_nomatch)
	{
		print_error(string(" NOT FOUND "));
	}

	if(m_scrolloff_x != 0)
	{
		chtype chstr[m_w];
		for(j = 0; j < m_h; j++)
		{
			mvwinchnstr(m_tblwin, j, 0, chstr, m_parent->m_screenw + m_scrolloff_x);
			mvwaddchnstr(m_tblwin, j, 0, chstr + m_scrolloff_x, m_parent->m_screenw);
		}
	}

	wrefresh(m_tblwin);
	m_parent->render();
	refresh();
}

string curses_table::get_field_val(string fldname)
{
	uint32_t j;
	vector<sinsp_table_field>* row;
	string res;

	row = &(m_data->at(m_selct).m_values);

	vector<filtercheck_field_info>* legend;

	if(m_parent->m_datatable->m_postmerge_legend.size() != 0)
	{
		legend = &m_parent->m_datatable->m_postmerge_legend;
	}
	else
	{
		legend = &m_parent->m_datatable->m_premerge_legend;
	}

	for(j = 1; j < legend->size(); j++)
	{
		auto le = legend->at(j);

		if(le.m_name == fldname)
		{
			uint32_t k = j - 1;
			m_converter->set_val(m_legend[k].m_info.m_type, 
				row->at(k).m_val, 
				row->at(k).m_len,
				row->at(k).m_cnt,
				m_legend[k].m_info.m_print_format);

			res = m_converter->tostring_nice(NULL, 0, 0);

			break;
		}
	}

	if(j == legend->size())
	{
		throw sinsp_exception("field '" + fldname + "'' not found in this view");
	}

	return res;
}

//
// Return false if the user wants us to exit
//
sysdig_table_action curses_table::handle_input(int ch)
{
	if(m_data == NULL)
	{
		return STA_PARENT_HANDLE;
	}


	switch(ch)
	{
		case KEY_LEFT:
			if(m_scrolloff_x > 0)
			{
				m_scrolloff_x -= 4;
				render(true);
			}
			break;
		case KEY_RIGHT:
			if(m_scrolloff_x < m_w - m_parent->m_screenw)
			{
				m_scrolloff_x += 4;
				render(true);
			}
			break;
		case KEY_UP:
			m_selection_changed = true;
			selection_up((int32_t)m_data->size());
			update_rowkey(m_selct);
			render(true);
			break;
		case KEY_DOWN:
			m_selection_changed = true;
			selection_down((int32_t)m_data->size());
			update_rowkey(m_selct);
			render(true);
			break;
		case KEY_PPAGE:
			m_selection_changed = true;
			selection_pageup((int32_t)m_data->size());
			update_rowkey(m_selct);
			render(true);
			break;
		case KEY_NPAGE:
			m_selection_changed = true;
			selection_pagedown((int32_t)m_data->size());
			update_rowkey(m_selct);
			render(true);
			break;
		case KEY_HOME:
			m_selection_changed = true;
			selection_home((int32_t)m_data->size());
			update_rowkey(m_selct);
			render(true);
			break;
		case KEY_END:
			m_selection_changed = true;
			selection_end((int32_t)m_data->size());
			update_rowkey(m_selct);
			render(true);
			break;
		case '\n':
		case '\r':
		case KEY_ENTER:
			return STA_DRILLDOWN;
		case KEY_F(12):
			return STA_SPECTRO;
		case 288:
			return STA_SPECTRO_FILE;
		case KEY_BACKSPACE:
		case 127:
			return STA_DRILLUP;
		case KEY_MOUSE:
			{
				uint32_t j;

				if(getmouse(&m_last_mevent) == OK)
				{
					if(m_last_mevent.bstate & BUTTON1_CLICKED)
					{
						//
						// Bottom menu clicks are handled by the parent
						//
						if((uint32_t)m_last_mevent.y == m_parent->m_screenh - 1)
						{
							return STA_PARENT_HANDLE;
						}

						ASSERT((m_data->size() == 0) || (m_column_startx.size() == m_data->at(0).m_values.size()));

						if((uint32_t)m_last_mevent.y == m_table_y_start)
						{
							//
							// This is a click on a column header. Change the sorting accordingly.
							//
							for(j = 0; j < m_column_startx.size() - 1; j++)
							{
								if((uint32_t)m_last_mevent.x >= m_column_startx[j] && (uint32_t)m_last_mevent.x < m_column_startx[j + 1])
								{
									m_table->set_sorting_col(j + 1);
									break;
								}
							}

							if(j == m_column_startx.size() - 1)
							{
								m_table->set_sorting_col(j + 1);
							}

							m_table->sort_sample();
							update_data(m_data);
							render(true);
						}
						else if((uint32_t)m_last_mevent.y > m_table_y_start &&
							(uint32_t)m_last_mevent.y < m_table_y_start + m_h - 1)
						{
							//
							// This is a click on a row. Update the selection.
							//
							m_selection_changed = true;
							m_selct = m_firstrow + (m_last_mevent.y - m_table_y_start - 1);
							sanitize_selection((int32_t)m_data->size());
							update_rowkey(m_selct);
							render(true);
						}
					}
					else if(m_last_mevent.bstate & BUTTON1_DOUBLE_CLICKED)
					{
						if((uint32_t)m_last_mevent.y > m_table_y_start &&
							(uint32_t)m_last_mevent.y < m_table_y_start + m_h - 1)
						{
							//
							// Update the selection
							//
							m_selection_changed = true;
							m_selct = m_firstrow + (m_last_mevent.y - m_table_y_start - 1);
							sanitize_selection((int32_t)m_data->size());
							update_rowkey(m_selct);
							render(true);

							//
							// This delay is here just as a lazy way to give the user the
							// feeling that the row has been clicked 
							//
							usleep(200000);

							//
							// Let the ui manager know that a drill down needs to happen
							//
							return STA_DRILLDOWN;
						}
					}
				}
			}
			break;
		case 'c':
		case KEY_DC:
			if(m_type == sinsp_table::TT_LIST)
			{
				m_table->clear();
				render(true);
				m_lastrow_selected = true;
			}
			break;
		default:
			break;
	}

	//
	// Check if this view has any action configured, and if yes find if this key
	// is one of the view hotkeys
	//
	sinsp_view_info* vinfo = m_parent->get_selected_view();

	for(auto hk : vinfo->m_actions)
	{
		if(hk.m_hotkey == ch)
		{
			m_parent->run_action(&hk);
			return STA_NONE;
		}
	}

	for(uint32_t i = 0; i < vinfo->max_col_sort_hotkeys; i++)
	{
		if(vinfo->m_col_sort_hotkeys[i] == ch) 
		{
			if(i < vinfo->m_columns.size()) 
			{
				m_table->set_sorting_col(i + 1);
				m_table->sort_sample();
				update_data(m_data);
				set_x_start(0);
				recreate_win(m_parent->m_screenh - 3);
				render(true);
				break;
			}
		}
	}
	return STA_PARENT_HANDLE;
}

curses_table::alignment curses_table::get_field_alignment(ppm_param_type type)
{
	switch(type)
	{
	case PT_INT8:
	case PT_INT16:
	case PT_INT32:
	case PT_INT64:
	case PT_UINT8:
	case PT_UINT16:
	case PT_UINT32:
	case PT_UINT64:
	case PT_RELTIME:
	case PT_ABSTIME:
	case PT_DOUBLE:
		return ALIGN_RIGHT;
	default:
		return ALIGN_LEFT;
	}
}

void curses_table::recreate_win(int h)
{
	delwin(m_tblwin);
	
	if(h != 0)
	{
		m_h = h;
	}
	
	m_tblwin = newwin(m_h, m_w, m_table_y_start, m_table_x_start);
	render(true);
}

void curses_table::goto_row(int32_t row)
{
	m_selection_changed = true;
	selection_goto((int32_t)m_data->size(), row);
	update_rowkey(row);
	render(true);
}

bool curses_table::get_position(OUT int32_t* pos, 
	OUT int32_t* totlines, 
	OUT float* percent, 
	OUT bool* truncated)
{
	if(m_data == NULL || m_data->size() == 0)
	{
		return false;
	}

	*pos = m_selct + 1;
	*totlines = (int32_t)m_data->size();
	*percent = (float)(m_selct + 1) / (float)m_data->size();
	*truncated = false;

	return true;
}

void curses_table::follow_end()
{
	if(m_lastrow_selected)
	{
		m_selection_changed = true;
		selection_end((int32_t)m_data->size());
		update_rowkey(m_selct);
		render(true);
	}
}

#endif // NOCURSESUI
#endif // CSYSDIG
