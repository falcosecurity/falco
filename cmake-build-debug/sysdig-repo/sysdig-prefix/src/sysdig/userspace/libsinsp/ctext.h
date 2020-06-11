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
#include <fstream>
#include <iostream>
#include <string>
#include <vector>
#include <curses.h>
#include <stdint.h>

#ifndef __83a9222a_c8b9_4f36_9721_5dfbaccb28d0_CTEXT
#define __83a9222a_c8b9_4f36_9721_5dfbaccb28d0_CTEXT
#define CTEXT_BUFFER_SIZE (4096)

using namespace std;

class ctext;

struct ctext_config_struct
{
	//
	// This specifies how many lines are kept
	// in the ring-buffer.	
	//
	// A value of -1 means to keep it completely
	// unregulated.
	//
	int32_t m_buffer_size;
#define CTEXT_DEFAULT_BUFFER_SIZE 500

	//
	// The bounding box bool specifies whether
	// we are allowed to move outside where the
	// content exists.	Pretend there's the 
	// following content and window (signified
	// by the + marks)
	//
	//	+			+
	//	 xxxx
	//	 xxx
	//	 xxxxx
	//	+			+
	//
	// If we were to move say, 3 units right and
	// had no bounding box (false) you'd see this:
	//
	//	+			+
	//	 x
	//
	//	 xx
	//	+			+
	//
	// In other words, we could potentially scroll
	// well beyond our content.
	//
	// A bounding box set to true would prevent this,
	// making sure that the viewport doesn't extend
	// beyond the existing content.
	//
	bool m_bounding_box;
#define CTEXT_DEFAULT_BOUNDING_BOX false

	// 
	// Sometimes content can be extremely lengthy 
	// on one line, overwhelming any other content
	// in view, losing the context of what the content
	// means.
	//
	// In these cases, we can truncate long text from
	// occupying the next row of text, and instead extend
	// beyond the viewport of our window.  Under these cases
	// the user will have to scroll the viewport in order
	// to see the remainder of the text.
	//
	bool m_do_wrap;
#define CTEXT_DEFAULT_DO_WRAP false

	//
	// In most user interfaces, new text appears 
	// underneath previous text on a new line.
	//
	// However, sometimes it's more natural to see
	// new entries come in ON TOP of old ones, pushing
	// the old ones downward.
	//
	// m_append_top deals with this duality
	//
	bool m_append_top;
#define CTEXT_DEFAULT_APPEND_TOP false

	//
	// Sometimes seeing new content is of the utmost
	// importance and takes precendence over analysis
	// of any historical data.
	//
	// In that case, the scroll_on_append will forcefully
	// scroll the text so that the new content is 
	// visible.
	//
	bool m_scroll_on_append;
#define CTEXT_DEFAULT_SCROLL_ON_APPEND false

	//
	// The auto_newline boolean will specify whether
	// a newline is appended at the end of every printf
	// call automatically for you ... as opposed to
	// the more traditional printf where it is not.
	//
	// Our definition of newline is unixes, that is
	// the single character of 0x0A, or \n.
	//
	bool m_auto_newline;
#define CTEXT_DEFAULT_AUTO_NEWLINE false
};

typedef struct ctext_config_struct ctext_config;

typedef struct ctext_format_struct
{
	int32_t offset;
	attr_t attrs;
	int16_t color_pair;
} ctext_format;

typedef struct ctext_pos_struct
{
	int32_t x;
	int32_t y;
} ctext_pos;

typedef struct ctext_search_struct
{
	// The current position of the 
	// search. ... you could do
	//
	// ct.get_offset(&search.pos);
	//
	// in order to initialize it to
	// the current point.
	//
	ctext_pos pos;

	// Should we wrap around when
	// we are done.
	bool do_wrap;

	// True if we are searching forward
	// false if we aren't.
	bool is_forward;

	// Case insensitivity is defined in the 
	// classic (c >= 'A' ? c | 0x20) manner.
	bool is_case_insensitive;

	// This is used internally,
	// please don't modify.
	ctext_pos _start_pos;
	ctext_pos _last_match;
	uint64_t _last_event;
	int16_t _match_count;

	// The string to match
	string _query;

} ctext_search;

typedef struct ctext_row_struct
{
	string data;
	vector<ctext_format> format;
} ctext_row;

typedef vector<ctext_row> ctext_buffer;

class ctext 
{
	public:
		ctext(WINDOW *win = 0, ctext_config *config = 0);

		//
		// A ctext instance has a configuration specified through
		// the ctext_config structure above
		//
		// When this function is called, a copy of the structure
		// is made so that further modifications are not reflected
		// in a previously instantiated instance.
		//
		// Returns 0 on success
		//
		int8_t set_config(ctext_config *config);

		//
		// get_config allows you to change a parameter in the 
		// configuration of a ctext instance and to duplicate
		// an existing configuration in a new instance.
		//
		// Returns 0 on success
		//
		int8_t get_config(ctext_config *config);

		// 
		// At most 1 curses window may be attached at a time.
		//
		// This function specifies the curses window which 
		// will be attached given this instance.
		//
		// If one is already attached, it will be detached and
		// potentially orphaned.
		//
		// Returns 0 on success
		//
		int8_t attach_curses_window(WINDOW *win);

		//
		// Under normal circumstances, a user would like to
		// remove all the existing content with a clear, starting
		// anew.
		//
		// However, if you'd like to only remove part of the content,
		// then you can pass a row_count in and clear will truncate 
		// row_count units of the oldest content.
		//
		// The return code is how many rows were cleared from the 
		// buffer.
		//
		int32_t clear(int32_t row_count = -1);

		// 
		// Scroll_to when appending to the bottom in the traditional
		// default sense, will specify the top x and y coordinate 
		// of the viewport.
		//
		// However, if we are appending to the top, then since new
		// content goes above the previous one, scroll_to specifies
		// the lower left coordinate.
		//
		// Returns 0 on success
		//
		int8_t scroll_to(int32_t x, int32_t y);
		int8_t scroll_to(ctext_pos *pos);

		// get_offset returns the current coordinates of the view port.
		// The values from get_offset are complementary to those 
		// of scroll_to
		// 
		// Returns 0 on success
		//
		int8_t get_offset(int32_t*x, int32_t*y); 
		int8_t get_offset(ctext_pos *pos);

		//
		// get_offset_percent is a courtesy function returning
		// a percentage value corresponding to the Y amount of 
		// scroll within the window.
		// 
		// Returns 0 on success
		//
		int8_t get_offset_percent(float*percent);

		// 
		// get_buf_size returns the number of rows of content
		// for y in the current buffer.
		//
		// Returns 0 on success
		//
		int8_t get_buf_size(int32_t*buf_size);

		//
		// available_rows communicates how many rows
		// are left given the buffer size specified
		// in the config with respect to the amount
		// of content placed in the buffer.
		//
		// If that sounds overly complex, I assure
		// you this function does pretty much exactly
		// what you'd expect ... it tells you how
		// much space you have left in the buffer
		// before its full and starts dropping 
		// content.
		//
		// Returns number of available rows
		//
		int32_t available_rows();

		//
		// Each of the directional functions,
		// up, down, left, and right, can be
		// called without an argument to move
		// 1 unit in their respective direction.
		//
		// The return code is how far the movement
		// happened.
		//
		int32_t up(int32_t amount = 1);
		int32_t down(int32_t amount = 1);
		int32_t left(int32_t amount = 1);
		int32_t right(int32_t amount = 1);

		// 
		// Identical to the above functions but this
		// time by an entire page of content (that
		// is to say, the height of the current curses
		// window.)
		//
		int32_t page_up(int32_t page_count = 1);
		int32_t page_down(int32_t page_count = 1);

		//
		// The jump_to_first_line and jump_to_last_line
		// can conveniently be mapped to home/end keys
		// and do what they say under the following
		// condition:
		//
		// 	If the bounding_box is set to true, 
		// 	then the "first" and "last" line corresponds 
		// 	to an entire screen full of data.
		//
		// 	If the bounding box is set to false, then
		// 	the screen will be empty except for 1 line
		// 	corresponding to the first or last line.
		//
		// 	That is to say that with a bounding box off,
		// 	you'd see something like
		//
		//	+			+
		//	 
		//	
		//	 xxxxx
		//	+			+
		//
		//	when we are doing jump_to_first_line.
		//
		//	With a bounding_box on you'd see
		//
		//	+			+
		//	 xxxxx
		//	 xx
		//	 xxx
		//	+			+
		//
		// The return code is how many vertical lines
		// were scrolled in order to accomplish the 
		// action.
		//
		int32_t jump_to_first_line();
		int32_t jump_to_last_line();

		//
		// printf is identical to printf(3) and can be called
		// from the function at the end of this file, cprintf,
		// with an instance variable.  It places text into the
		// buffer specified.
		//
		// You can take the function pointer of printf from 
		// an existing application and point it to this printf
		// inside of an instance in order to migrate an existing
		// application to this library seamlessly.
		//
		int8_t printf(const char*format, ...);
		int8_t vprintf(const char*format, va_list ap);

		//
		// nprintf is identical to the printf above EXCEPT for
		// the fact that it doesn't refresh (redraw) the screen. 
		//
		// In order to do that, a redraw (below) must be called
		// manually.
		//
		int8_t nprintf(const char*format, ...);

		//
		// Under normal (printf) conditions, this does not
		// need to be called explicitly and is instead called
		// each time a printf is called.
		//
		int8_t redraw();

		// 
		// A naming convention inspired from php's ob_start,
		// this function stops refreshing the screen until
		// ob_end is called, upon which a refresh is done.
		//
		// Internally, a binary flag is flipped.	That is
		// to say that multiple ob_start calls will only
		// set the flag to TRUE, all to be undone by a single
		// ob_end call.
		//
		// Returns 0 if the call was meaningful (that is, 
		// it toggled state) - otherwise -1.
		//
		int8_t ob_start();
		int8_t ob_end();

		//
		// This highlights a search context given a mask.
		// A few big mask options are A_REVERSE, A_UNDERLINE,
		// A_BLINK, and A_BOLD. They can be binary ORed.
		//
		int8_t highlight(ctext_search *context = 0, int32_t mask = A_REVERSE);

		//
		// This is how you initialize a search.
		//
		// You are free to toggle the properties of the object
		// at your own pleasure or peril.
		//
		// Returns you_manage_this_memory back at you or NULL
		// on an error.
		//
		ctext_search *new_search(ctext_search *you_manage_this_memory, string to_search, bool is_case_insensitive = false, bool is_forward = true, bool do_wrap = false);

		//
		// If you want to modify the query of an existing search then you
		// should call this function directly instead of trying to modify
		// the parameter yourself.
		//
		// Returns 0 on success
		//
		int8_t set_query(ctext_search *p_search, string new_query);

		//
		// After you've initiated your search you can then go over
		// the body of text by re-executing the str_search function.
		//
		// You don't have to worry about incrementing any silly variables
		// to avoid an infinite loop on the previous match or any of those
		// annoyances that the base c/c++ libraries decided to make YOUR
		// problem every time.
		//
		// This function will go to the "next" match (based on your parameters)
		// and then highlight all the matches in the viewport.  You can
		// "turn off" this highlighting by running search_off (see below).
		//
		// Returns 0 every time a valid search is found and something
		// "happened".  Otherwise you get something non-zero, signifying that
		// the search is "done".
		//
		int8_t str_search(ctext_search *to_search);

		// Turn off syntax highlighting from search.
		int8_t search_off();

	private:
		//
		// This function answers the question "where on the screen would
		// the buffer at line X, character Y appear?" The *win gets populated
		// with the answer or a value is returned if there's an overflow.
		//
		int8_t map_to_win(int32_t buffer_x, int32_t buffer_y, ctext_pos *win);

		int8_t y_scroll_calculate(int32_t amount, ctext_pos *pos);
		int16_t redraw_partial(int32_t buf_start_x, int32_t buf_start_y, int32_t buf_end_x, int32_t buf_end_y);
		int16_t redraw_partial(ctext_pos *pos, size_t len);

		// This is just a test function to make sure everything works.
		int8_t redraw_partial_test();

		ctext_row* add_row();
		void add_format_if_needed();
		int8_t rebuf();
		void get_win_size();
		
		// Highlights the matches in he current vieport without
		// doing any scrolling.
		int8_t highlight_matches(ctext_search *context = 0);

		// 
		// Directly scroll to an x/y location with respect to
		// the buffer without any redraw or other calculation.
		//
		// This just moves the internal pointers forward with 
		// respect to the internal configuration.
		//
		// The return value is 0 iff the value of the scroll
		// was changed.  Otherwise, if nothing changed in the
		// request, -1 is returned.
		//
		int8_t direct_scroll(int32_t x, int32_t y);
		int8_t direct_scroll(ctext_pos *pos);

		// A mast to apply to the text being rendered.
		attr_t m_attr_mask;

		//
		// Leave the new_pos_out as null for an idempotent version of this function -
		// as in one that doesn't modify the to_search_in variable in returning a value.
		//
		// It's perfectly acceptable to pass the same variable as both to_search_in and
		// new_pos_out if you want to execute it with a side-effect - as much of the
		// implementation actually does.
		//
		int8_t str_search_single(ctext_search *to_search_in, ctext_search *new_pos_out = 0, ctext_pos *limit = 0);

		// Whether or not to draw when new text comes in or to skip the step.
		bool m_do_draw;
		WINDOW *m_win;
		ctext_config m_config;
		ctext_buffer m_buffer;
		ctext_search *m_last_search;

		// The start point of the buffer with
		// respect to the current viewport
		ctext_pos m_pos_start;
		
		int32_t m_max_y;
		int32_t m_win_width;
		int32_t m_win_height;
		uint64_t m_event_counter;

		ofstream *m_debug;
};

int cprintf(ctext*win, const char *format, ...);

#endif

#endif // _WIN32
