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

#pragma once

#include <string.h>
#include <utility>

// Used for CO_IN/CO_PMATCH filterchecks using PT_CHARBUFs to allow
// for quick multi-value comparisons. Should also work for any
// filtercheck with a buffer and length. When compiling with gnu
// compilers, use the built in but not standard _hash_impl::hash
// function, which uses murmurhash2 and is quite fast. Otherwise, uses
// http://www.cse.yorku.ca/~oz/hash.html.

typedef std::pair<uint8_t *, uint32_t> filter_value_t;

struct g_hash_membuf
{
	size_t operator()(filter_value_t val) const
	{
#if defined(__GNUC__) && !defined(__clang__)
		return std::_Hash_impl::hash(val.first, val.second);
#else
		size_t hash = 5381;
		for(uint8_t *p = val.first; (uint32_t)(p-val.first) < val.second; p++)
		{
			int c = *p;
			hash = ((hash << 5) + hash) + c; /* hash * 33 + c */
		}
		return hash;
#endif
	}
};

struct g_equal_to_membuf
{
	bool operator()(filter_value_t a, filter_value_t b) const
	{
		return (a.second == b.second &&
			memcmp(a.first, b.first, a.second) == 0);
	}
};

