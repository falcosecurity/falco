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
#include <memory>
#include <hedley.h>

namespace profiler
{

#define CHUNK_ELEMENTS 7
#define CHUNK_SIZE ((1 << 20) * CHUNK_ELEMENTS) // 20 MiB = 5242880 * sizeof(uint32_t)
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
size_t nchunks;
std::mutex mu;

HEDLEY_NEVER_INLINE void alloc_chunk()
{
	auto d = new uint32_t[CHUNK_SIZE];
	c.current = d;
	c.end = d + CHUNK_SIZE;

	mu.lock();
	chunks.push_back({d, d + CHUNK_SIZE, std::this_thread::get_id()});
	nchunks += 1;
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

struct profile
{
	uint32_t* data;
	int n;
	int epochs; // (max) depth at the moment of execution

	explicit profile(uint32_t label)
	{
		data = c.current;
		auto next = data + CHUNK_ELEMENTS;
		n = nchunks;
		epochs = (next - chunks[n - 1].begin) / CHUNK_ELEMENTS; // (next - start) / data size

		if(HEDLEY_LIKELY(next != c.end))
			c.current = next; // adds 28 bytes
		else
			alloc_chunk(); // note: changes `c` values (current and end)

		data[0] = label;
		data[5] = 0; // unknown parent
		data[6] = 0; // mark current instance as init

		unsigned int lo, hi;
		__asm__ __volatile__("rdtsc"
				     : "=a"(lo), "=d"(hi));
		data[1] = hi;
		data[2] = lo;
	}

	~profile()
	{
		unsigned int lo, hi;
		__asm__ __volatile__("rdtsc"
				     : "=a"(lo), "=d"(hi));
		data[3] = hi;
		data[4] = lo;

		if(HEDLEY_LIKELY(epochs > 1))
		{
			for(int i = 0; i < epochs - 1; i++)
			{
				// Check whether the i-th destructor before this has been called (>0) or not (0)
				if(data[-1 - (i * CHUNK_ELEMENTS)] == 0)
				{
					// The head of the first destructor which has not been called yet is the parent of the current one
					data[5] = data[-((i + 1) * CHUNK_ELEMENTS)];
					break;
				}
			}
		}
		else if(n > 1)
		{
			// TODO: make it span across more chunks (until n - 2 == 0)
			uint32_t* cdata = chunks[n - 2].end;
			for(int i = 0; i < (CHUNK_SIZE / CHUNK_ELEMENTS); i++)
			{
				if(cdata[-1 - (i * CHUNK_ELEMENTS)] == 0)
				{
					data[5] = cdata[-((i + 1) * CHUNK_ELEMENTS)];
					break;
				}
			}
		}
		if(n > 1 && data[5] == 0)
		{
			// TODO: same as above
			// TODO: make it span across more chunks (until n - 2 == 0)
			uint32_t* cdata = chunks[n - 2].end;
			for(int i = 0; i < (CHUNK_SIZE / CHUNK_ELEMENTS); i++)
			{
				if(cdata[-1 - (i * CHUNK_ELEMENTS)] == 0)
				{
					data[5] = cdata[-((i + 1) * CHUNK_ELEMENTS)];
					break;
				}
			}
		}
		data[6] = n; // mark current instance as done storing the chunk index (+ 1)
	}
};

#define PROFILE_VARIABLE_IMPL(arg1, arg2) arg1##arg2
#define PROFILE_VARIABLE(arg1, arg2) PROFILE_VARIABLE_IMPL(arg1, arg2)

#define PROFILEME()                                                                                                    \
	static uint32_t PROFILE_VARIABLE(_label, __LINE__) = profiler::create_label(__FILE__, __LINE__, __FUNCTION__); \
	profiler::profile PROFILE_VARIABLE(_profile_, __LINE__)(PROFILE_VARIABLE(_label, __LINE__));

}; // namespace profiler
