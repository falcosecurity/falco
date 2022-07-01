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

/*!
	\brief Writes stats samples collected from inspectors into a given output.
	Users must use a stats_writer::collector in order to collect and write stats
	into a given stats_writer. This class is thread-safe, and can be shared
	across multiple stats_writer::collector instances from different threads.
*/
class stats_writer
{
public:
	/*!
		\brief Value of a ticker that dictates when stats are collected
	*/
	typedef uint16_t ticker_t;

	/*!
		\brief Collects stats samples from an inspector and uses a writer
		to print them in a given output. Stats are collected periodically every
		time the value of stats_writer::get_ticker() changes.
		This class is not thread-safe.
	*/
	class collector
	{	
	public:
		/*!
			\brief Initializes the collector with the given writer
		*/
		explicit collector(std::shared_ptr<stats_writer> writer);

		/*!
			\brief Collects one stats sample from an inspector
		*/
		void collect(std::shared_ptr<sinsp> inspector);

	private:
		std::shared_ptr<stats_writer> m_writer;
		stats_writer::ticker_t m_last_tick;
		uint64_t m_samples;
		scap_stats m_last_stats;
	};

	stats_writer(const stats_writer&) = delete;

	stats_writer(stats_writer&&) = delete;

	stats_writer& operator=(const stats_writer&) = delete;

	stats_writer& operator=(stats_writer&&) = delete;

	~stats_writer();

	/*!
		\brief Initializes a writer without any output.
		With this contructor, has_output() always returns false
	*/
	stats_writer();

	/*!
		\brief Initializes a writer that prints to a file at the given filename.
		With this contructor, has_output() always returns true
	*/
	explicit stats_writer(const std::string &filename);
	
	/*!
		\brief Returns true if the writer is configured with a valid output
	*/
	inline bool has_output() const;

	/*!
		\brief Initializes the ticker with a given interval period defined
		in milliseconds. Subsequent calls to init_ticker will dismiss the
		previously-initialized ticker. Internally, this uses a timer
		signal handler.
	*/
	static bool init_ticker(uint32_t interval_msec, std::string &err);

	/*!
		\brief Returns the current value of the ticker.
		This function is thread-safe.
	*/
	inline static ticker_t get_ticker();

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

	// note: in this way, only collectors can push into the queue
	friend class stats_writer::collector;
};