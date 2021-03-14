/*
Copyright (C) 2019 The Falco Authors.

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

#include <cstddef>
#include <functional>
#include <sys/time.h>

#include "token_bucket.h"
#include <chrono>
#include "banned.h" // This raises a compilation error when certain functions are used

void raw_token_bucket::init(double rate, double max_tokens, uint64_t now)
{
	m_rate = rate;
	m_max_tokens = max_tokens;
	m_tokens = max_tokens;
	m_last_seen = now;
}

bool raw_token_bucket::claim(double tokens, uint64_t now)
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

double raw_token_bucket::get_tokens()
{
	return m_tokens;
}

uint64_t raw_token_bucket::get_last_seen()
{
	return m_last_seen;
}

// get_monotonic_clock_time_ns returns the monotonic clock time in ns.
// Note that the returned value is only useful for computing the elapsed time
// between two intervals, it should ne be interpreted as real time.
uint64_t get_monotonic_clock_time_ns()
{
	return std::chrono::duration_cast<std::chrono::nanoseconds>(
		       std::chrono::steady_clock::now().time_since_epoch())
		.count();
}

token_bucket::token_bucket(double rate, double max_tokens, time_getter timer):
	m_timer(timer)
{
	init(rate, max_tokens, m_timer());
}

token_bucket::token_bucket(double rate, double max_tokens):
	m_timer(get_monotonic_clock_time_ns)
{
	init(rate, max_tokens, m_timer());
}

bool token_bucket::claim(double n)
{
	return raw_token_bucket::claim(n, m_timer());
}
