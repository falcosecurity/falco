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

#ifndef _WIN32

#include "ctext.h"
#include <unistd.h>
#include <string.h>
#include <algorithm>
#include <climits>

using namespace std;

#define CTEXT_UNDER_X		0x01
#define CTEXT_OVER_X		0x02
#define CTEXT_UNDER_Y		0x04
#define CTEXT_OVER_Y		0x08

#define CTEXT_OVER			(CTEXT_OVER_Y | CTEXT_OVER_X)
#define CTEXT_UNDER			(CTEXT_UNDER_Y | CTEXT_UNDER_X)

ctext_config config_default;

void search_copy(ctext_search *dst, ctext_search *src)
{
	// Because c++ makes life impossibly difficult.
	memcpy(dst, src, sizeof(ctext_search) - sizeof(string));
	dst->_query = src->_query;
}

ctext::ctext(WINDOW *win, ctext_config *config)
{
	this->m_win = win;

	config_default.m_buffer_size = CTEXT_DEFAULT_BUFFER_SIZE;
	config_default.m_bounding_box = CTEXT_DEFAULT_BOUNDING_BOX;
	config_default.m_do_wrap = CTEXT_DEFAULT_DO_WRAP;
	config_default.m_append_top = CTEXT_DEFAULT_APPEND_TOP;
	config_default.m_scroll_on_append = CTEXT_DEFAULT_SCROLL_ON_APPEND;
	config_default.m_auto_newline = CTEXT_DEFAULT_AUTO_NEWLINE;

	/*
	this->m_debug = new ofstream();
	this->m_debug->open("debug1.txt");
	*/
	
	this->m_do_draw = true;
	
	if(config) 
	{
		memcpy(&this->m_config, config, sizeof(ctext_config));
	} 
	else 
	{
		memcpy(&this->m_config, &config_default, sizeof(ctext_config));
	}

	this->m_pos_start.x = this->m_pos_start.y = 0;

	this->m_attr_mask = 0;
	this->m_last_search = 0;
	this->m_event_counter = 0;

	this->m_max_y = 0;

	// initialized the buffer with the empty row
	this->add_row();
}

int8_t ctext::search_off()
{
	int8_t ret = (this->m_last_search != 0);
	this->m_last_search = 0;
	return ret; 
}

int8_t ctext::set_config(ctext_config *config)
{
	memcpy(&this->m_config, config, sizeof(ctext_config));
	return this->redraw();
}

int8_t ctext::get_config(ctext_config *config)
{
	return !memcpy(config, &this->m_config, sizeof(ctext_config));
}

int8_t ctext::attach_curses_window(WINDOW *win)
{
	this->m_win = win;
	return this->redraw();
}

int8_t ctext::highlight(ctext_search *context, int32_t mask)
{
	this->m_attr_mask |= mask;
	this->redraw_partial(&context->pos, context->_query.size());
	this->m_attr_mask &= ~mask;

	return 0;
}

int8_t ctext::set_query(ctext_search *p_search, string new_query)
{
	this->get_offset(&p_search->pos);
	this->get_offset(&p_search->_start_pos);

	p_search->_query = new_query;
	p_search->_last_match.y = -1;
	p_search->_last_event = this->m_event_counter;
	p_search->_match_count = 0;

	return 0;
}

ctext_search *ctext::new_search(ctext_search *you_manage_this_memory, string to_search, bool is_case_insensitive, bool is_forward, bool do_wrap)
{
	ctext_search *p_search = you_manage_this_memory;

	if(!p_search)
	{
		return NULL;
	}

	p_search->is_case_insensitive = is_case_insensitive;
	p_search->do_wrap = do_wrap;
	p_search->is_forward = is_forward;

	this->set_query(p_search, to_search);
	
	return p_search;
}

int8_t ctext::highlight_matches(ctext_search *to_search)
{
	int8_t search_ret;
	int32_t mask = A_BOLD | A_UNDERLINE;

	if(!to_search)
	{
		to_search = this->m_last_search;

		if(!to_search) 
		{
			return 0;
		}
	}

	// We move the viewport pointer through the current viewport,
	// highlighting all matching instances.
	ctext_search in_viewport;
	ctext_pos limit;

	search_copy(&in_viewport, to_search);

	// We will say the limit is the viewport height ... this makes sure we go over
	// the maximum extent possible.  We also make sure we do this after our first match
	// otherwise this would reflect our current viewport, shameful!
	limit.y = min(this->m_pos_start.y + this->m_win_height, (int32_t)this->m_buffer.size());

	// Now we iterate through the viewport highlighting all of the instances, using the 
	// limit and the in_viewport pointer
	if(this->m_event_counter != in_viewport._last_event) 
	{
		search_ret = this->str_search_single(&in_viewport, &in_viewport, &limit);
	}

	do 
	{
		this->highlight(&in_viewport, mask);
		search_ret = this->str_search_single(&in_viewport, &in_viewport, &limit);
		mask = A_REVERSE;
	} while(search_ret >= 0);

	return 0;
}

int8_t ctext::str_search(ctext_search *to_search)
{
	int8_t search_ret, scroll_ret;

	this->m_last_search = to_search;

	// This makes sure that we scroll to a new y row
	// if multiple matches are on the same viewport row.
	for(;;)
	{
		search_ret = this->str_search_single(to_search, to_search);
		if(search_ret == -1) 
		{
			break;
		}

		if(this->m_config.m_do_wrap) 
		{
			scroll_ret = this->direct_scroll(&to_search->pos);
		} 
		else
		{
			scroll_ret = this->direct_scroll(0, to_search->pos.y);
		}

		// This makes sure we move forward ... but we only do this
		// if we didn't push the event forward
		if(!scroll_ret || to_search->_match_count == 1)
		{
			break;
		}
	}

	// This means that it was found somewhere and our
	// pointer has been moved forward
	if(search_ret >= 0) 
	{
		// We can do a general scroll_to and redraw.
		this->redraw();
	}

	return search_ret;
}

int8_t ctext::str_search_single(ctext_search *to_search_in, ctext_search *new_pos_out, ctext_pos *limit)
{
	int32_t size = (int32_t)this->m_buffer.size();
	size_t found;
	string haystack;
	ctext_search res, *out;

	if(!to_search_in)
	{
		return -1;
	}

	string query = to_search_in->_query;

	if(!new_pos_out) 
	{
		search_copy(&res, to_search_in);
		out = &res;
	} 
	else 
	{
		out = new_pos_out;
	}

	// If a (scroll) event has happened since we last ran this,
	// then we need to update exactly where we want to start
	// the search from.
	if(to_search_in->_last_event < this->m_event_counter)
	{
		out->pos.y = this->m_pos_start.y;
		out->pos.x = this->m_pos_start.x;
		out->_last_event = this->m_event_counter;
		out->_match_count = 0;
	}

	if(to_search_in->is_case_insensitive)
	{
		transform(query.begin(), query.end(), query.begin(), ::tolower);
	} 

	for(;;) 
	{
		haystack = this->m_buffer[out->pos.y].data;
		if(to_search_in->is_case_insensitive)
		{
			transform(haystack.begin(), haystack.end(), haystack.begin(), ::tolower);
		}

		if(out->is_forward)
		{
			found = haystack.find(query, (size_t)( (out->pos.x == -2) ? out->pos.x + 2 : out->pos.x + 1));
		}
		else
		{
			found = haystack.rfind(query, (size_t)( (out->pos.x == (int32_t)haystack.size()) ? out->pos.x : out->pos.x - 1));
		}

		if(found == string::npos) 
		{
			if(out->is_forward)
			{
				out->pos.y = (out->pos.y + 1) % size;
				out->pos.x = -2;
			}
			else
			{
				out->pos.y--;

				// Wrap if we are going backwards.
				if(out->pos.y == -1)
				{
					out->pos.y = size - 1;
				}
				out->pos.x = (int32_t)this->m_buffer[out->pos.y].data.size();
			}

			//
			// The edge case here is if there are no matches and we ARE wrapping,
			// we don't want the idiot case of going through the haystack endlessly
			// like a chump and locking up the application.
			//
			if(
					(out->pos.y == out->_start_pos.y && (out->do_wrap == false || out->_last_match.y == -1)) ||
					(limit && out->pos.y > limit->y)
			)
			{
				return -1;
			}
		}
		else
		{
			// This is all we really care about, we don't need
			// to look at the x value
			out->_last_match.y = out->pos.y;
			out->pos.x = (int32_t)found;
			out->_match_count++;
			break;
		}
	}

	return 0;
}

int32_t ctext::clear(int32_t row_count)
{
	int32_t ret = 0;

	if(row_count == -1) 
	{
		ret = this->m_buffer.size();
		this->m_buffer.clear();
		this->add_row();
	}
	else if(this->m_buffer.size()) 
	{
		ret = this->m_buffer.size();
		this->m_buffer.erase(this->m_buffer.begin(), this->m_buffer.begin() + row_count);
		ret -= this->m_buffer.size();
	}

	// We do the same logic when removing content
	// .. perhaps forcing things down or upward
	if(this->m_config.m_scroll_on_append)
	{
		this->get_win_size();

		// Now we force it.
		this->direct_scroll(0, this->m_buffer.size() - this->m_win_height);
	}

	this->redraw();
	return ret;
}

int8_t ctext::ob_start()
{
	int8_t ret = this->m_do_draw;
	this->m_do_draw = false;
	return ret;
}

int8_t ctext::ob_end()
{
	int8_t ret = !this->m_do_draw;
	this->m_do_draw = true;
	this->redraw();
	return ret;
}

int8_t ctext::direct_scroll(ctext_pos*p)
{
	return this->direct_scroll(p->x, p->y);
}

int8_t ctext::direct_scroll(int32_t x, int32_t y)
{
	ctext_pos start;
	memcpy(&start, &this->m_pos_start, sizeof(ctext_pos));

	this->get_win_size();

	if(this->m_config.m_bounding_box) 
	{
		y = min(y, this->m_max_y - this->m_win_height);
		x = max(0, x);
		y = max(0, y);
	}

	// Under this context we should only be x-scrolling
	// to a modulus of a windows width
	if(this->m_config.m_do_wrap)
	{
		// We always go *under* to make sure that the
		// content appears in the viewport.
		x -= x % this->m_win_width;
	}

	this->m_pos_start.x = x;
	this->m_pos_start.y = y;

	// If the values have changed and we have actively scrolled,
	// return 0, otherwise return -1.
	return (start.x != x || start.y != y) ? 0 : -1;
}

int8_t ctext::scroll_to(ctext_pos *pos)
{
	return this->scroll_to(pos->x, pos->y);
}

int8_t ctext::scroll_to(int32_t x, int32_t y)
{
	this->direct_scroll(x, y);
	this->m_event_counter++;
	return this->redraw();
}

int8_t ctext::get_offset(ctext_pos *pos)
{
	return this->get_offset(&pos->x, &pos->y);
}

int8_t ctext::get_offset(int32_t*x, int32_t*y)
{
	*x = this->m_pos_start.x;
	*y = this->m_pos_start.y;

	return 0;
}

int8_t ctext::get_offset_percent(float*percent)
{
	this->get_win_size();
	*percent = (float)(this->m_pos_start.y) / (this->m_max_y - this->m_win_height);

	return 0;
}

int8_t ctext::get_buf_size(int32_t*buf_size)
{
	*buf_size = this->m_max_y;

	return 0;
}

int32_t ctext::available_rows()
{
	// Since our buffer clearing scheme permits us to overflow,
	// we have to bind this to make sure that we return >= 0 values
	if(this->m_config.m_buffer_size == -1)
	{
		return (int32_t)LONG_MAX;
	}
	return max(this->m_config.m_buffer_size - this->m_max_y - 1, 0);
}

int32_t ctext::up(int32_t amount) 
{
	return this->down(-amount);
}

int32_t ctext::page_down(int32_t page_count) 
{
	this->get_win_size();
	return this->down(page_count * this->m_win_height);
}

int32_t ctext::page_up(int32_t page_count) 
{
	this->get_win_size();
	return this->down(-page_count * this->m_win_height);
}

// Let's do this real fast.
int8_t ctext::map_to_win(int32_t buffer_x, int32_t buffer_y, ctext_pos*win)
{
	int8_t ret = 0;

	// This is the trivial case.
	if(!this->m_config.m_do_wrap)
	{
		// These are trivial.
		win->y = buffer_y - this->m_pos_start.y;
		win->x = buffer_x - this->m_pos_start.x;

		return ((buffer_x < this->m_pos_start.x)) | ((buffer_x > this->m_pos_start.x + this->m_win_width) << 1)
			| ((buffer_y < this->m_pos_start.y) << 2) | ((buffer_y > this->m_pos_start.y + this->m_win_height) << 3);
	}
	// Otherwise it's much more challenging.
	else
	{
		// If we are below the fold or we are at the first line and before
		// the start of where we ought to be drawing
		if(buffer_y < this->m_pos_start.y || (buffer_y == this->m_pos_start.y && buffer_x < this->m_pos_start.x))
		{
			// We omit win calculations here since they
			// would be more expensive then we'd like
			win->x = win->y = -1;

			ret |= CTEXT_UNDER_Y;
		}
		else 
		{
			// To see if it's an overflow y is a bit harder
			int32_t new_y = this->m_pos_start.y;

			int32_t new_offset = this->m_pos_start.x;

			string *data = &this->m_buffer[new_y].data;

			for(win->y = 0; win->y < this->m_win_height; win->y++)
			{
				new_offset += this->m_win_width;

				//
				// There's an edge case that requires this
				// twice due to a short circuit exit that 
				// would be triggered at the end of a buffer, 
				// see below.
				//
				if(buffer_y == new_y && buffer_x < new_offset)
				{
					win->x = buffer_x - (new_offset - this->m_win_width);
					return ret;
				}

				if(new_offset > (int32_t)data->size()) 
				{
					new_offset = 0;
					new_y ++;
					if(new_y > this->m_max_y)
					{
						break;
					}
					data = &this->m_buffer[new_y].data;
				}

				if(
					// We've passed it and we know it's not
					// an underflow, so we're done.
					(buffer_y < new_y) ||

					// We are at the end line and our test point
					// is below the offset that we just flew past
					(buffer_y == new_y && buffer_x < new_offset)
				)
				{
					win->x = buffer_x - (new_offset - this->m_win_width);
					return ret;
				}
			}

			// Keep the y at the end
			// win->y = -1;

			// If we get here that means that we went all the way through
			// a "generation" and didn't reach our hit point ... that means
			// it's an overflow.
			ret |= CTEXT_OVER_Y;	
		}
	}

	return ret;
}

int8_t ctext::y_scroll_calculate(int32_t amount, ctext_pos *pos)
{
	if(this->m_config.m_do_wrap)
	{
		int32_t new_y = this->m_pos_start.y;
		int32_t new_offset = this->m_pos_start.x;
		ctext_row *p_row = &this->m_buffer[this->m_pos_start.y];	

		this->get_win_size();

		while(amount > 0)
		{
			new_offset += this->m_win_width;
			amount --;
			if(new_offset > (int32_t)p_row->data.size())
			{
				if((new_y + this->m_win_height + 1) >= (int32_t)this->m_buffer.size())
				{
					//
					// This means that forwarding our buffer was a mistake
					// so we undo our work and get out of here.
					//
					new_offset -= this->m_win_width;
					break;
				}
				new_offset = 0;
				new_y++;
				p_row = &this->m_buffer[new_y];
			}
		} 

		while(amount < 0)
		{
			new_offset -= this->m_win_width;
			amount ++;
			if(new_offset < 0)
			{
				if(new_y - 1 < 0)
				{
					break;
				}
				new_y--;
				p_row = &this->m_buffer[new_y];
				new_offset = p_row->data.size() - p_row->data.size() % this->m_win_width;
			}
		}
		pos->x = new_offset;
		pos->y = new_y;
	}
	else
	{
		pos->x = this->m_pos_start.x;
		pos->y = this->m_pos_start.y + amount;
	}

	return 0;
}

int32_t ctext::down(int32_t amount) 
{
	ctext_pos new_pos;
	this->y_scroll_calculate(amount, &new_pos);
	return this->scroll_to(&new_pos);
}

int32_t ctext::jump_to_first_line()
{
	int32_t current_line = this->m_pos_start.y;

	//
	// Now we try to scroll above the first
	// line.	the bounding box rule will
	// take care of the differences for us.
	//
	this->scroll_to(this->m_pos_start.x, 0 - this->m_win_height + 1);

	return current_line - this->m_pos_start.y;
}

int32_t ctext::jump_to_last_line()
{
	int32_t current_line = this->m_pos_start.y;

	this->get_win_size();
	this->scroll_to(this->m_pos_start.x, this->m_max_y - 1);
	return current_line - this->m_pos_start.y;
}

int32_t ctext::left(int32_t amount) 
{
	return this->right(-amount);
}

int32_t ctext::right(int32_t amount) 
{
	return this->scroll_to(this->m_pos_start.x + amount, this->m_pos_start.y);
}

void ctext::get_win_size() 
{
	int32_t width = 0, height = 0;

	if(this->m_win)
	{
		getmaxyx(this->m_win, height, width);
	}
	this->m_win_width = width;
	this->m_win_height = height;
}

int8_t ctext::rebuf()
{
	// Memory management is expensive, so we only do this occasionally
	if(this->m_config.m_buffer_size != -1 && (int32_t)this->m_buffer.size() > (this->m_config.m_buffer_size * 11 / 10))
	{
		this->m_buffer.erase(this->m_buffer.begin(), this->m_buffer.end() - this->m_config.m_buffer_size);
	}
	
	this->m_max_y = this->m_buffer.size() - 1;
	
	//
	// Since we've changed the bounding box of the content we have to
	// issue a rescroll on exactly our previous parameters. This may
	// force us inward or may retain our position.
	// 
	return this->direct_scroll(this->m_pos_start.x, this->m_pos_start.y);
}

void ctext::add_format_if_needed()
{
	attr_t attrs; 
	int16_t color_pair;

	if(!this->m_win) 
	{
		return;
	}

	if(this->m_buffer.empty())
	{
		return;
	}

	// Get the most current row.
	ctext_row *p_row = &this->m_buffer.back();

	ctext_format p_format = {0,0,0};
	if(!p_row->format.empty()) 
	{
		// And the most current format
		p_format = p_row->format.back();
	} 

	wattr_get(this->m_win, &attrs, &color_pair, 0);

	if(attrs != p_format.attrs || color_pair != p_format.color_pair)
	{
		// Our properties have changed so we need to record this.
		ctext_format new_format;

		// This is our offset
		new_format.offset = (int32_t)p_row->data.size();
		new_format.attrs = attrs;
		new_format.color_pair = color_pair;

		//
		// If the new thing we are adding has the same
		// offset as the previous, then we dump the
		// previous.
		//
		if(p_format.offset == new_format.offset && !p_row->format.empty())
		{
			p_row->format.pop_back();
		}
		p_row->format.push_back(new_format);
	}
}

ctext_row* ctext::add_row()
{
	ctext_row row;

	// If there is an existing line, then
	// we carry over the format from the
	// last line..
	if(!this->m_buffer.empty())
	{
		ctext_row p_row = this->m_buffer.back();

		if(!p_row.format.empty()) 
		{
			ctext_format p_format( p_row.format.back() );

			// Set the offset to the initial.
			p_format.offset = 0;
			row.format.push_back(p_format);
		}
	}

	this->m_buffer.push_back(row);

	return &this->m_buffer.back();
}

char* next_type(char* search, const char delim) 
{
	while(*search && *search != delim)
	{
 		search ++;
	}
	return search;
}

int8_t ctext::vprintf(const char*format, va_list ap)
{
	char *p_line, *n_line;
	char large_buffer[CTEXT_BUFFER_SIZE];

	this->add_format_if_needed();
	ctext_row *p_row = &this->m_buffer.back();

	vsnprintf(large_buffer, CTEXT_BUFFER_SIZE, format, ap);

	p_line = large_buffer;
	do 
	{
		n_line = next_type(p_line, '\n');

		string wstr(p_line, n_line - p_line);
		p_row->data += wstr;

		if(*n_line)
		{
			p_row = this->add_row();
		}
		p_line = n_line + 1;
	} 
	while (*n_line);

	if(this->m_config.m_auto_newline)
	{
		this->add_row();
	}
	
	// Since we are adding content we need to see if we are
	// to force on scroll.
	if(this->m_config.m_scroll_on_append)
	{
		this->get_win_size();

		// Now we force it.
		this->direct_scroll(0, this->m_buffer.size() - this->m_win_height);
	}

	return this->redraw();
}

int cprintf(ctext*win, const char *format, ...)
{
	int ret;
	va_list args;
	va_start(args, format);
	ret = win->vprintf(format, args);
	va_end(args);
	return ret;
}

int8_t ctext::printf(const char*format, ...)
{
	int8_t ret;

	va_list args;
	va_start(args, format);
	ret = this->vprintf(format, args);

	va_end(args);
	return ret;
}

int8_t ctext::nprintf(const char*format, ...)
{
	int8_t ret;
	va_list args;

	// First turn off the rerdaw flag
	this->ob_start();

	// Then call the variadic version
	va_start(args, format);
	ret = this->vprintf(format, args);

	va_end(args);

	//
	// Then manually untoggle the flag
	// (this is necessary because ob_end
	// does TWO things, breaking loads of
	// anti-patterns I'm sure.)
	//
	this->m_do_draw = true;

	return ret;
}

#if 0
int8_t ctext::redraw_partial_test()
{
	attr_t res_attrs; 
	int16_t res = 0;
	int16_t res_color_pair;
	int32_t x, y, end_x;
	string *data;

	this->get_win_size();
	wattr_get(this->m_win, &res_attrs, &res_color_pair, 0);
	wattr_off(this->m_win, COLOR_PAIR(res_color_pair), 0);
	
	this->rebuf();
	werase(this->m_win);

	x = this->m_pos_start.x;
	y = this->m_pos_start.y;
	data = &this->m_buffer[y].data;

	while(!(res & CTEXT_OVER_Y)) 
	{
		this->m_attr_mask ^= A_REVERSE;
		end_x = min(x + rand() % 9 + 1, (int32_t)data->size());	
		res = this->redraw_partial(x, y, end_x, y);
		wrefresh(this->m_win);
		usleep(1000 * 500);

		x = end_x;
		
		if(end_x == (int32_t)data->size() || (res & CTEXT_OVER_X)) 
		{
			y++;
			x = 0;
			if(y > this->m_max_y)
			{
				break;
			}
			data = &this->m_buffer[y].data;
		}
	}

	wrefresh(this->m_win);
	wattr_set(this->m_win, res_attrs, res_color_pair, 0);

	return 0;
}
#endif

int16_t ctext::redraw_partial(ctext_pos *pos, size_t len)
{
	return this->redraw_partial(pos->x, pos->y, pos->x + len, pos->y);
}

// 
// redraw_partial takes a buffer offset and sees if it is
// to be drawn within the current view port, which is specified
// by m_pos_start.x and m_pos_start.y. 
//
int16_t ctext::redraw_partial(
		int32_t buf_start_x, int32_t buf_start_y, 
		int32_t buf_end_x, int32_t buf_end_y)
{
	bool b_format = false;
	string to_add;
	ctext_row *p_source;
	vector<ctext_format>::iterator p_format;
	bool is_first_line = true;
	int16_t ret = 0;
	int32_t num_added_x = 0;
	int32_t num_to_add = 0;
	int32_t win_current_x;
	int32_t win_current_end_x;
	int32_t buf_offset_x;

	// We need to get relative start and end positions.
	ctext_pos win_start, win_end;

	buf_start_x = max(0, buf_start_x);

	ret = this->map_to_win(buf_start_x, buf_start_y, &win_start);

	// This means that none of this will map to screen, 
	// return the overflow and bail.
	if(ret & CTEXT_OVER_Y)
	{
		return ret;
	}

	ret = this->map_to_win(buf_end_x, buf_end_y, &win_end);

	// This also means that none of this will map to screen, 
	// return the underflow and bail.
	if(ret & CTEXT_UNDER_Y)
	{
		return ret;
	}

	//
	// We start as m_pos_start.y in our list and move up to
	// m_pos_start.y + m_win_height except in the case of 
	// wrap around.  Because of this special case,
	// we compute when to exit slightly differently.
	//
	// This is the current line of output, which stays
	// below m_win_height
	//
	int32_t win_current_y = win_start.y;
	int32_t buf_current_y = buf_start_y;

	// This is for horizontal scroll.
	int32_t start_char = max(0, this->m_pos_start.x);
	
	while(win_current_y <= win_end.y)
	{
		win_current_end_x = this->m_win_width;

		// If we are at the last line to generate
		if(win_current_y == win_end.y)
		{
			// Then we make sure that we end
			// where we are supposed to.
			win_current_end_x = win_end.x;
		}

		wredrawln(this->m_win, win_current_y, 1);
		
		if((buf_current_y < this->m_max_y) && (buf_current_y >= 0))
		{
			// We only buf_current_y into the object if we have the
			// data to do so.
			p_source = &this->m_buffer[buf_current_y];
			p_format = p_source->format.begin();

			// Reset the offset.
			win_current_x = -min(0, (int32_t)this->m_pos_start.x);

			if(is_first_line)
			{
				buf_offset_x = buf_start_x;
				win_current_x += win_start.x;
			}
			else 
			{
				buf_offset_x = start_char;
			}

			for(;;) 
			{
				// Our initial num_to_add is the remainder of window space
				// - our start (end of the screen - starting position)
				num_to_add = win_current_end_x - win_current_x;
				b_format = false;

				wstandend(this->m_win);

				// If we have a format to account for and we haven't yet,
				if(!p_source->format.empty() && p_format->offset <= buf_offset_x)
				{
					// Then we add it 
					wattr_set(this->m_win, p_format->attrs | this->m_attr_mask, p_format->color_pair, 0);

					// and tell ourselves below that we've done this.
					b_format = true;

					// see if there's another num_to_add point
					if((p_format + 1) != p_source->format.end())
					{
						//
						// If it's before our newline then we'll have to do something
						// with with that.
						//
						// The first one is the characters we are to print this time,
						// the second is how many characters we would have asked for
						// if there was no format specified.
						//
						num_to_add = min((p_format + 1)->offset - buf_offset_x, num_to_add); 
					}
				} 
				else if(this->m_attr_mask)
				{
					wattr_set(this->m_win, this->m_attr_mask, 0, 0);
				}

				//
				// If we can get that many characters than we grab them
				// otherwise we do the empty string
				//
				if(buf_offset_x < (int32_t)p_source->data.size())
				{
					to_add = p_source->data.substr(buf_offset_x, num_to_add);

					mvwaddstr(this->m_win, win_current_y, win_current_x, to_add.c_str());
					is_first_line = false;
				}
				else
				{
					to_add = "";
				}

				// This is the number of characters we've placed into
				// the window.
				num_added_x = to_add.size();
				buf_offset_x += num_added_x;

				// See if we need to reset our format
				if(b_format) 
				{
					//
					// If the amount of data we tried to grab is less than
					// the width of the window - win_offset then we know to
					// turn off our attributes and push our format forward 
					// if necessary.
					//
					if( (p_format + 1) != p_source->format.end() && (p_format + 1)->offset >= buf_offset_x )
					{
						p_format ++;
					}
				}

				// if we are at the end of the string, we break out
				if((int32_t)p_source->data.size() <= buf_offset_x || (num_added_x == 0 && p_source->data.size() > 0))
				{
					break;
				}

				// Otherwise, move win_current_x forward
				win_current_x += num_added_x;
				
				// Otherwise, if we are wrapping, then we do that here.
				if(win_current_x == win_current_end_x)
				{
					//
					// If we've hit the vertical bottom
					// of our window then we break out
					// of this
					//
					// Otherwise if we are not wrapping then
					// we also break out of this.
					//
					if(win_current_y == win_end.y)
					{
						break;
					}

					// Otherwise move our line forward
					win_current_y++;

					// If we are at the last line to generate
					if(win_current_y == win_end.y)
					{
						// Then we make sure that we end
						// where we are supposed to.
						win_current_end_x = win_end.x;
					}

					// We reset the win_current_x back to its
					// initial state
					win_current_x = 0;

					// and we loop again.
				}
			}
		}
		buf_current_y++;
		win_current_y++;
	}

	return ret;
}

int8_t ctext::redraw() 
{
	//
	// Bail out if we aren't supposed to draw
	// this time.
	//
	// Calculate the bounds of everything first.
	//
	this->rebuf();
	if(!this->m_do_draw)
	{
		return 0;
	}

	if(!this->m_win)
	{
		// Not doing anything without a window.
		return -1;
	}

	attr_t res_attrs; 
	int16_t res_color_pair;
	bool is_first_line = true;
	wattr_get(this->m_win, &res_attrs, &res_color_pair, 0);
	wattr_off(this->m_win, COLOR_PAIR(res_color_pair), 0);
	
	this->get_win_size();

	//
	// By this time, if we are bounded by a box,
	// it has been accounted for.
	//
	// Really our only point of interest is
	// whether we need to append to bottom
	// or append to top.
	//
	// We will assume that we can
	// populate the window quick enough
	// to avoid linear updating or paging.
	//	... it's 2015 after all.
	//
	werase(this->m_win);

	//
	// Regardless of whether this is append to top
	// or bottom we generate top to bottom.
	// 
	int32_t start_char = max(0, this->m_pos_start.x);
	int32_t buf_offset = start_char;
	// the endchar will be in the substr
	
	//
	// We start as m_pos_start.y in our list and move up to
	// m_pos_start.y + m_win_height except in the case of 
	// wrap around.  Because of this special case,
	// we compute when to exit slightly differently.
	//
	// This is the current line of output, which stays
	// below m_win_height
	//
	int32_t line = 0;

	// Start at the beginning of the buffer.
	int32_t index = this->m_pos_start.y;
	int32_t directionality = +1;
	int32_t cutoff;
	int32_t num_added = 0;
	int32_t win_offset = 0;
	bool b_format = false;
	string to_add;
	ctext_row *p_source;
	vector<ctext_format>::iterator p_format;

	// If we are appending to the top then we start
	// at the end and change our directionality.
	if(this->m_config.m_append_top)
	{
		directionality = -1;
		index = this->m_pos_start.y + this->m_win_height - 1;
	}

	while(line <= this->m_win_height)
	{
		wredrawln(this->m_win, line, 1);
		
		if((index < this->m_max_y) && (index >= 0))
		{
			// We only index into the object if we have the
			// data to do so.
			p_source = &this->m_buffer[index];
			p_format = p_source->format.begin();

			// Reset the offset.
			win_offset = -min(0, (int32_t)this->m_pos_start.x);
			buf_offset = start_char;

			if(this->m_config.m_do_wrap)
			{
				buf_offset = is_first_line ? this->m_pos_start.x : 0;
			}

			for(;;) 
			{
				// Our initial cutoff is the remainder of window space
				// - our start
				cutoff = this->m_win_width - win_offset;
				b_format = false;

				wstandend(this->m_win);

				// If we have a format to account for and we haven't yet,
				if(!p_source->format.empty() && p_format->offset <= buf_offset)
				{
					// then we add it 
					wattr_set(this->m_win, p_format->attrs, p_format->color_pair, 0);

					// and tell ourselves below that we've done this.
					b_format = true;

					// See if there's another cutoff point
					if((p_format + 1) != p_source->format.end())
					{
						//
						// If it's before our newline then we'll have to do something
						// with with that.
						//
						// The first one is the characters we are to print this time,
						// the second is how many characters we would have asked for
						// if there was no format specified.
						//
						cutoff = min((p_format + 1)->offset - buf_offset, cutoff); 
					}
				}

				// If we can get that many characters than we grab them
				// otherwise we do the empty string
				if(buf_offset < (int32_t)p_source->data.size())
				{
					to_add = p_source->data.substr(buf_offset, cutoff);

					mvwaddstr(this->m_win, line, win_offset, to_add.c_str());
					is_first_line = false;
				}
				else
				{
					to_add = "";
				}

				// This is the number of characters we've placed into
				// the window.
				num_added = to_add.size();
				buf_offset += num_added;

				// See if we need to reset our format
				if(b_format) 
				{
					//
					// If the amount of data we tried to grab is less than
					// the width of the window - win_offset then we know to
					// turn off our attributes and push our format forward if 
					// necessary.
					//
					if( (p_format + 1) != p_source->format.end() &&
							(p_format + 1)->offset >= buf_offset 
						)
					{
						p_format ++;
					}
				}

				// If we are at the end of the string, we break out
				if((int32_t)p_source->data.size() <= buf_offset || (num_added == 0 && p_source->data.size() > 0))
				{
					break;
				}

				// otherwise, move win_offset forward
				win_offset += num_added;
				
				// otherwise, if we are wrapping, then we do that here.
				if(win_offset == this->m_win_width)
				{
					//
					// If we've hit the vertical bottom
					// of our window then we break out
					// of this otherwise if we are not 
					// wrapping then we also break out 
					// of this.
					//
					if(line == this->m_win_height || !this->m_config.m_do_wrap)
					{
						break;
					}

					// Otherwise move our line forward
					line++;

					// We reset the win_offset back to its
					// initial state
					win_offset = 0;

					// And we loop again.
				}
			}
		}
		index += directionality;
		line++;
	}

	this->highlight_matches();
	wrefresh(this->m_win);
	wattr_set(this->m_win, res_attrs, res_color_pair, 0);

	return 0;
}

#endif // _WIN32
