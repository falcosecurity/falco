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

void token_bucket::init(double rate, double max_tokens, uint64_t now)
{
	m_rate = rate;
	m_max_tokens = max_tokens;
	m_tokens = max_tokens;

	if(now == 0)
	{
		now = sinsp_utils::get_current_time_ns();
	}

	m_last_seen = now;
}

bool token_bucket::claim()
{
	uint64_t now = sinsp_utils::get_current_time_ns();

	return claim(1, now);
}

bool token_bucket::claim(double tokens, uint64_t now)
{
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
	// If m_tokens is < tokens, can't claim.
	//
	if(m_tokens < tokens)
	{
		return false;
	}

	m_tokens -= tokens;

	return true;
}

double token_bucket::get_tokens()
{
	return m_tokens;
}

uint64_t token_bucket::get_last_seen()
{
	return m_last_seen;
}
