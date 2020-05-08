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

#define CHUNK_ELEMENTS 7
#define CHUNK_SIZE ((1 << 3) * CHUNK_ELEMENTS) // 20 MiB = 5242880 * sizeof(uint32_t)
// #define CHUNK_SIZE ((1 << 20) * CHUNK_ELEMENTS) // 20 MiB = 5242880 * sizeof(uint32_t)
#define LABEL_MASK 0x80000000 // Largest positive int32 + 1

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

struct profiler
{
	uint32_t* data;
	int n;
	int epochs; // (max) depth at the moment of execution

	explicit profiler(uint32_t label)
	{
		data = c.current;
		auto next = data + CHUNK_ELEMENTS;
		n = nchunks;
		epochs = (next - chunks[n - 1].begin) / CHUNK_ELEMENTS; // (next - start) / data size

		// printf("curr: %p\n", c.current);
		// printf("next: %p\n", next);

		if(HEDLEY_LIKELY(next != c.end))
			c.current = next;
		else
			alloc_chunk(); // note: changes `c` values (current and end)

		// printf("nchunks: %ld\n", nchunks);
		// printf("curr: %p\n", data);
		// printf("next: %p\n", next);
		// printf("next - data: %ld\n", next - data);
		// printf("ch begin: %p\n", chunks[nchunks - 1].begin);
		// printf("max depth: %d\n", epochs);

		// printf("ctor | data addr: %p | label: %d\n", data, label);

		data[0] = label;
		data[5] = 0; // unknown parent
		data[6] = 0; // mark current instance as init

		unsigned int lo, hi;
		__asm__ __volatile__("rdtsc"
				     : "=a"(lo), "=d"(hi));
		data[1] = hi;
		data[2] = lo;
	}

	~profiler()
	{
		unsigned int lo, hi;
		__asm__ __volatile__("rdtsc"
				     : "=a"(lo), "=d"(hi));
		data[3] = hi;
		data[4] = lo;

		// if(n == 2)
		// {
		// 	printf("\ndtor | data addr: %p | label: %d\n", data, data[0]);
		// 	printf("max backtrack: %d\n", epochs);
		// 	printf("nchunk: %d\n", n);
		// }

		if(HEDLEY_LIKELY(epochs > 1))
		{
			for(int i = 0; i < epochs - 1; i++)
			{
				// if(n == 2)
				// {
				// 	printf("idx: %d, flag: %d, flag2: %d, flag3: %d\n", -1 - (i * CHUNK_ELEMENTS), data[-1 - (i * CHUNK_ELEMENTS)], ((epochs - 1) * 7) - 1, chunks[n - 1].begin[((epochs - 1) * 7) - 1]);
				// }
				// Check whether the i-th destructor before this has been called (>0) or not (0)
				if(data[-1 - (i * CHUNK_ELEMENTS)] == 0)
				{
					// if(n == 2)
					// {
					// 	printf("VAL: %d\n", data[-((i + 1) * CHUNK_ELEMENTS)]);
					// }
					// The head of the first destructor which has not been called yet is the parent of the current one
					data[5] = data[-((i + 1) * CHUNK_ELEMENTS)];
					break;
				}
			}
		}
		else if(n > 1)
		{
			// TODO: make it span across more chunks
			uint32_t* cdata = chunks[n - 2].end;
			for(int i = 0; i < (CHUNK_SIZE / CHUNK_ELEMENTS); i++)
			{
				// printf("idx: %d, flag: %d\n", -1 - (i * CHUNK_ELEMENTS), cdata[-1 - (i * CHUNK_ELEMENTS)]);
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
			// TODO: make it span across more chunks
			uint32_t* cdata = chunks[n - 2].end;
			for(int i = 0; i < (CHUNK_SIZE / CHUNK_ELEMENTS); i++)
			{
				// printf("idx: %d, flag: %d\n", -1 - (i * CHUNK_ELEMENTS), cdata[-1 - (i * CHUNK_ELEMENTS)]);
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

#define MACRO_JOIN_IMPL(arg1, arg2) arg1##arg2
#define MACRO_JOIN(arg1, arg2) MACRO_JOIN_IMPL(arg1, arg2)

#define PROFILEME()                                                                                    \
	static uint32_t MACRO_JOIN(_label, __LINE__) = create_label(__FILE__, __LINE__, __FUNCTION__); \
	profiler MACRO_JOIN(_profile_, __LINE__)(MACRO_JOIN(_label, __LINE__));

// cycles_at_end = (unsigned long long)chunks[0].begin[4])|( ((unsigned long long)chunks[0].begin[3])<<32)
// cycles_at_start = (unsigned long long)chunks[0].begin[2])|( ((unsigned long long)chunks[0].begin[1])<<32)
// weight = cycles_at_end-cycles_at_start
