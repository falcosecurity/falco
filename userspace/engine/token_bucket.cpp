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

#include <cstddef>
#include <sys/time.h>

#include "utils.h"
#include "token_bucket.h"

token_bucket::token_bucket()
{
	init(1, 1);
}

token_bucket::~token_bucket()
{
}

void token_bucket::init(double rate, double max_tokens)
{
	m_rate = rate;
	m_max_tokens = max_tokens;
	m_tokens = max_tokens;
	m_last_seen = sinsp_utils::get_current_time_ns();
}

bool token_bucket::claim(uint64_t now)
{
	// Determine the number of tokens gained. Delta between
	// last_seen and now, divided by the rate.
	if(now == 0)
	{
		now = sinsp_utils::get_current_time_ns();
	}

	double tokens_gained = m_rate * ((now - m_last_seen) / (1000000000.0));
	m_last_seen = now;

	m_tokens += tokens_gained;

	//
	// Cap at max_tokens
	//
	if(m_tokens > m_max_tokens)
	{
		m_tokens = m_max_tokens;
	}

	//
	// If tokens is < 1, can't claim.
	//
	if(m_tokens < 1)
	{
		return false;
	}

	m_tokens--;

	return true;
}

double token_bucket::get_tokens()
{
	return m_tokens;
}
