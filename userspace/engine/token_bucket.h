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

#pragma once

#include <cstdint>
#include <functional>

// A token bucket that accumulates tokens at a fixed rate and allows
// for limited bursting in the form of "banked" tokens.
//
// It is up to the caller to provide the time when init and claim methods are
// invoked, prefer using token_bucket when possible.
//
// This class is not thread safe.
class raw_token_bucket
{
public:
	raw_token_bucket() = default;
	virtual ~raw_token_bucket() = default;

	//
	// Initialize the token bucket and start accumulating tokens
	//
	void init(double rate, double max_tokens, uint64_t now);

	//
	// Try to claim tokens from the token bucket, using a
	// timestamp of now. Returns true if the tokens could be
	// claimed. Also updates internal metrics.
	//
	bool claim(double tokens, uint64_t now);

	// Return the current number of tokens available
	double get_tokens();

	// Return the last time someone tried to claim a token.
	uint64_t get_last_seen();

private:
	//
	// The number of tokens generated per second.
	//
	double m_rate{1};

	//
	// The maximum number of tokens that can be banked for future
	// claim()s.
	//
	double m_max_tokens{1};

	//
	// The current number of tokens
	//
	double m_tokens{1};

	//
	// The last time claim() was called (or the object was created).
	// Nanoseconds since the epoch.
	//
	uint64_t m_last_seen;
};

// time_getter returns current time in ns.
using time_getter = std::function<uint64_t()>;

// A facade for raw_token_bucket hiding timestamp handling to the caller.
// The token bucket is initialized and thus starts accumulating tokens at
// construction time.
class token_bucket : private raw_token_bucket
{
public:
	token_bucket(double rate, double max_tokens);
	token_bucket(double rate, double max_tokens, time_getter timer);
	virtual ~token_bucket() = default;

	// Claims n tokens.
	bool claim(double n = 1);

	using raw_token_bucket::get_last_seen;
	using raw_token_bucket::get_tokens;

private:
	time_getter m_timer;
};
