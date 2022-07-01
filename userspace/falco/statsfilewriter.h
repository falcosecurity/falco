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

class StatsFileWriter {
public:
	StatsFileWriter();
	virtual ~StatsFileWriter();

	// Returns success as bool. On false fills in errstr.
	bool init(std::shared_ptr<sinsp> inspector, std::string &filename,
		  uint32_t interval_msec,
		  string &errstr);

	// Should be called often (like for each event in a sinsp
	// loop).
	void handle();

protected:
	uint32_t m_num_stats;
	std::shared_ptr<sinsp> m_inspector;
	std::ofstream m_output;
	scap_stats m_last_stats;
};

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
	
	static bool set_timer(uint32_t interval_msec, std::string &err);

	void handle(const std::shared_ptr<sinsp>& inspector, state& s);

private:
	struct worker_msg
	{
		bool stop;
		scap_stats delta;
		scap_stats stats;
	};

	void worker() noexcept;
	void stop_worker();
	inline void push(const worker_msg& m);

	bool m_initialized;
	uint64_t m_total_samples;
	std::thread m_worker;
	std::ofstream m_output;
	tbb::concurrent_bounded_queue<worker_msg> m_queue;	
};