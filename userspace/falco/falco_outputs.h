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

#include <memory>
#include <map>

#include "gen_filter.h"
#include "falco_common.h"
#include "falco_engine.h"
#include "outputs.h"
#include "formats.h"
#ifndef __EMSCRIPTEN__
#include "tbb/concurrent_queue.h"
#endif

/*!
	\brief This class acts as the primary interface between a program and the
	falco output engine. The falco rules engine is implemented by a
	separate class falco_engine.

	All methods in this class are thread-safe. The output framework supports
	a multi-producer model where messages are stored in a queue and consumed
	by each configured output asynchrounously.
*/
class falco_outputs
{
public:
	falco_outputs(
		std::shared_ptr<falco_engine> engine,
		const std::vector<falco::outputs::config>& outputs,
		bool json_output,
		bool json_include_output_property,
		bool json_include_tags_property,
		uint32_t timeout,
		bool buffered,
		bool time_format_iso_8601,
		const std::string& hostname);

	virtual ~falco_outputs();

	/*!
		\brief Format then send the event to all configured outputs (`evt`
		is an event that has matched some rule).
	*/
	void handle_event(gen_event *evt, std::string &rule, std::string &source,
			  falco_common::priority_type priority, std::string &format, std::set<std::string> &tags);

	/*!
		\brief Format then send a generic message to all outputs.
		Not necessarily associated with any event.
	*/
	void handle_msg(uint64_t now,
			falco_common::priority_type priority,
			std::string &msg,
			std::string &rule,
			nlohmann::json &output_fields);

	/*!
		\brief Sends a cleanup message to all outputs.
		Each output can have an implementation-specific behavior.
		In general, this is used to flush or clean output buffers.
	*/
	void cleanup_outputs();

	/*!
		\brief Sends a message to all outputs that causes them to be closed and
		reopened. Each output can have an implementation-specific behavior.
	*/
	void reopen_outputs();

private:
	std::unique_ptr<falco_formats> m_formats;

	std::vector<falco::outputs::abstract_output *> m_outputs;

	bool m_buffered;
	bool m_json_output;
	bool m_time_format_iso_8601;
	std::chrono::milliseconds m_timeout;
	std::string m_hostname;

	enum ctrl_msg_type
	{
		CTRL_MSG_STOP = 0,
		CTRL_MSG_OUTPUT = 1,
		CTRL_MSG_CLEANUP = 2,
		CTRL_MSG_REOPEN = 3,
	};

	struct ctrl_msg : falco::outputs::message
	{
		ctrl_msg_type type;
	};

#ifndef __EMSCRIPTEN__
	typedef tbb::concurrent_bounded_queue<ctrl_msg> falco_outputs_cbq;
	falco_outputs_cbq m_queue;
#endif

	std::thread m_worker_thread;
	inline void push(const ctrl_msg& cmsg);
	inline void push_ctrl(ctrl_msg_type cmt);
	void worker() noexcept;
	void stop_worker();
	void add_output(falco::outputs::config oc);
	inline void process_msg(falco::outputs::abstract_output* o, const ctrl_msg& cmsg);
};
