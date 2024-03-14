// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2023 The Falco Authors.

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
#include <unordered_map>

#include <libsinsp/sinsp.h>

#ifndef __EMSCRIPTEN__
#include "tbb/concurrent_queue.h"
#endif
#include "falco_outputs.h"
#include "configuration.h"

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
		explicit collector(const std::shared_ptr<stats_writer>& writer);

		/*!
			\brief Collects one stats sample from an inspector
			and for the given event source name
		*/
		void collect(const std::shared_ptr<sinsp>& inspector, const std::string& src, uint64_t num_evts);

	private:
		/*!
			\brief Collect snapshot metrics wrapper fields as internal rule formatted output fields.
		*/
		void get_metrics_output_fields_wrapper(nlohmann::json& output_fields, const std::shared_ptr<sinsp>& inspector, const std::string& src, uint64_t num_evts, uint64_t now, double stats_snapshot_time_delta_sec);

		/*!
			\brief Collect the configurable snapshot metrics as internal rule formatted output fields.
		*/
		void get_metrics_output_fields_additional(nlohmann::json& output_fields, double stats_snapshot_time_delta_sec);

		std::shared_ptr<stats_writer> m_writer;
		stats_writer::ticker_t m_last_tick = 0;
		uint64_t m_last_now = 0;
		uint64_t m_last_n_evts = 0;
		uint64_t m_last_n_drops = 0;
		uint64_t m_last_num_evts = 0;
	};

	stats_writer(const stats_writer&) = delete;

	stats_writer(stats_writer&&) = default;

	stats_writer& operator=(const stats_writer&) = delete;

	stats_writer& operator=(stats_writer&&) = default;

	~stats_writer();

	/*!
		\brief Initializes a writer.
	*/
	stats_writer(const std::shared_ptr<falco_outputs>& outputs,
		const std::shared_ptr<const falco_configuration>& config);

	/*!
		\brief Returns true if the writer is configured with a valid output.
	*/
	inline bool has_output() const
	{
		return m_initialized;
	}

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
		msg() {}
		msg(msg&&) = default;
		msg& operator = (msg&&) = default;
		msg(const msg&) = default;
		msg& operator = (const msg&) = default;

		bool stop = false;
		uint64_t ts = 0;
		std::string source;
		nlohmann::json output_fields;
	};

	void worker() noexcept;
	void stop_worker();
	inline void push(const stats_writer::msg& m);

	bool m_initialized = false;
	uint64_t m_total_samples = 0;
	std::thread m_worker;
	std::ofstream m_file_output;
#ifndef __EMSCRIPTEN__
	tbb::concurrent_bounded_queue<stats_writer::msg> m_queue;
#endif
#if defined(__linux__) and !defined(MINIMAL_BUILD) and !defined(__EMSCRIPTEN__)
	std::unique_ptr<libs::metrics::libs_metrics_collector> m_libs_metrics_collector;
	std::unique_ptr<libs::metrics::output_rule_metrics_converter> m_output_rule_metrics_converter;
#endif
	std::shared_ptr<falco_outputs> m_outputs;
	std::shared_ptr<const falco_configuration> m_config;
	// note: in this way, only collectors can push into the queue
	friend class stats_writer::collector;
};
