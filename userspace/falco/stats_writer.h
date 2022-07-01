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

#include <fstream>
#include <string>
#include <map>

#include <sinsp.h>

#include "tbb/concurrent_queue.h"

// Periodically collects scap stats files and writes them to a file as
// json.

class stats_writer
{
public:
	struct state
	{	
		inline state(): samples(0) { }

		uint64_t samples;
		uint16_t last_tick;
		scap_stats last_stats;
	};

	stats_writer();
	explicit stats_writer(const std::string &filename);
	~stats_writer();

	void handle(const std::shared_ptr<sinsp>& inspector, stats_writer::state& s);

	static bool set_timer(uint32_t interval_msec, std::string &err);

private:
	struct msg
	{
		bool stop;
		scap_stats delta;
		scap_stats stats;
	};

	void worker() noexcept;
	void stop_worker();
	inline void push(const stats_writer::msg& m);

	bool m_initialized;
	uint64_t m_total_samples;
	std::thread m_worker;
	std::ofstream m_output;
	tbb::concurrent_bounded_queue<stats_writer::msg> m_queue;	
};