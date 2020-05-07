/*
Copyright (C) 2020 The Falco Authors.

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
#include <thread>
#include <vector>
#include <mutex>
#include <hedley.h>

#define CHUNK_ELEMENTS 5
#define CHUNK_SIZE ((1 << 20) * CHUNK_ELEMENTS) // 5 MiB
#define LABEL_MASK 0x80000000			// Largest positive int32 + 1

struct cursor
{
	uint32_t* current;
	uint32_t* end;
};

struct chunk
{
	uint32_t* begin;
	uint32_t* end;
	std::thread::id thread;
};

struct label
{
	uint32_t label;
	std::string file;
	std::string func;
	int line;
};

thread_local cursor c;
std::vector<label> labels;
std::vector<chunk> chunks;
std::mutex mu;

HEDLEY_NEVER_INLINE void alloc_chunk()
{
	auto d = new uint32_t[CHUNK_SIZE];
	c.current = d;
	c.end = d + CHUNK_SIZE;

	mu.lock();
	chunks.push_back({d, d + CHUNK_SIZE, std::this_thread::get_id()});
	mu.unlock();
}

HEDLEY_NEVER_INLINE uint32_t create_label(char const* file, int line, char const* func)
{
	label l;
	l.label = labels.size() | LABEL_MASK;
	l.file = file;
	l.func = func;
	l.line = line;
	mu.lock();
	labels.push_back(l);
	mu.unlock();
	return l.label;
}

struct profiler
{
	uint32_t* pd;

	explicit profiler(uint32_t label)
	{
		pd = c.current;
		auto next = pd + 5;

		if(HEDLEY_LIKELY(next != c.end))
			c.current = next;
		else
			alloc_chunk();

		pd[0] = label;

		unsigned int lo, hi;
		__asm__ __volatile__("rdtsc"
				     : "=a"(lo), "=d"(hi));
		pd[1] = hi;
		pd[2] = lo;
	}

	~profiler()
	{
		unsigned int lo, hi;
		__asm__ __volatile__("rdtsc"
				     : "=a"(lo), "=d"(hi));
		pd[3] = hi;
		pd[4] = lo;
	}
};

#define PROFILEME()                                                                        \
	static uint32_t _label##__LINE__ = create_label(__FILE__, __LINE__, __FUNCTION__); \
	profiler _trace_##__LINE__(_label##__LINE__);

// cycles_at_end = (unsigned long long)chunks[0].begin[4])|( ((unsigned long long)chunks[0].begin[3])<<32)
// cycles_at_start = (unsigned long long)chunks[0].begin[2])|( ((unsigned long long)chunks[0].begin[1])<<32)
// weight = cycles_at_end-cycles_at_start