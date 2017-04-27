/*
Copyright (C) 2016 Draios inc.

This file is part of falco.

falco is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License version 2 as
published by the Free Software Foundation.

falco is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with falco.  If not, see <http://www.gnu.org/licenses/>.
*/

#pragma once

#include <cstdint>

// A simple token bucket that accumulates tokens at a fixed rate and allows
// for limited bursting in the form of "banked" tokens.
class token_bucket
{
public:
	token_bucket();
	virtual ~token_bucket();

	//
	// Initialize the token bucket and start accumulating tokens
	//
	void init(double rate, double max_tokens);

	//
	// Returns true if a token can be claimed. Also updates
	// internal metrics.
	//
	bool claim(uint64_t now = 0);

	// Return the current number of tokens available
	double get_tokens();

private:

	//
	// The number of tokens generated per second.
	//
	double m_rate;

	//
	// The maximum number of tokens that can be banked for future
	// claim()s.
	//
	double m_max_tokens;

	//
	// The current number of tokens
	//
	double m_tokens;

	//
	// The last time claim() was called (or the object was created).
	// Nanoseconds since the epoch.
	//
	uint64_t m_last_seen;
};

