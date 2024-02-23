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

#if !defined(_WIN32) && !defined(__EMSCRIPTEN__) && !defined(MINIMAL_BUILD)
#include <google/protobuf/util/time_util.h>
#endif

#include "falco_outputs.h"
#include "config_falco.h"

#include "formats.h"
#include "logger.h"
#include "watchdog.h"

#include "outputs_file.h"
#include "outputs_stdout.h"
#if !defined(_WIN32)
#include "outputs_program.h"
#include "outputs_syslog.h"
#endif
#if !defined(_WIN32) && !defined(__EMSCRIPTEN__) && !defined(MINIMAL_BUILD)
#include "outputs_http.h"
#include "outputs_grpc.h"
#endif

static const char* s_internal_source = "internal";

falco_outputs::falco_outputs(
	std::shared_ptr<falco_engine> engine,
	const std::vector<falco::outputs::config>& outputs,
	bool json_output,
	bool json_include_output_property,
	bool json_include_tags_property,
	uint32_t timeout,
	bool buffered,
	size_t outputs_queue_capacity,
	bool time_format_iso_8601,
	const std::string& hostname)
{
	m_formats.reset(new falco_formats(engine, json_include_output_property, json_include_tags_property));

	m_json_output = json_output;

	m_timeout = std::chrono::milliseconds(timeout);

	m_buffered = buffered;
	m_time_format_iso_8601 = time_format_iso_8601;
	m_hostname = hostname;

	for(const auto& output : outputs)
	{
		add_output(output);
	}
	m_outputs_queue_num_drops = 0;
#ifndef __EMSCRIPTEN__
	m_queue.set_capacity(outputs_queue_capacity);
	m_worker_thread = std::thread(&falco_outputs::worker, this);
#endif
}

falco_outputs::~falco_outputs()
{
#ifndef __EMSCRIPTEN__
	this->stop_worker();
#endif
}

// This function is called only at initialization-time by the constructor
void falco_outputs::add_output(const falco::outputs::config &oc)
{
	std::unique_ptr<falco::outputs::abstract_output> oo;

	if(oc.name == "file")
	{
		oo = std::make_unique<falco::outputs::output_file>();
	}
#ifndef _WIN32
	else if(oc.name == "program")
	{
		oo = std::make_unique<falco::outputs::output_program>();
	}
#endif
	else if(oc.name == "stdout")
	{
		oo = std::make_unique<falco::outputs::output_stdout>();
	}
#ifndef _WIN32
	else if(oc.name == "syslog")
	{
		oo = std::make_unique<falco::outputs::output_syslog>();
	}
#endif
#if !defined(_WIN32) && !defined(__EMSCRIPTEN__) && !defined(MINIMAL_BUILD)
	else if(oc.name == "http")
	{
		oo = std::make_unique<falco::outputs::output_http>();
	}
	else if(oc.name == "grpc")
	{
		oo = std::make_unique<falco::outputs::output_grpc>();
	}
#endif
	else
	{
		throw falco_exception("Output not supported: " + oc.name);
	}

	std::string init_err;
	if (oo->init(oc, m_buffered, m_hostname, m_json_output, init_err))
	{
		m_outputs.push_back(std::move(oo));
	}
	else
	{
		falco_logger::log(falco_logger::level::ERR, "Failed to init output: " + init_err);
	}
}

void falco_outputs::handle_event(sinsp_evt *evt, const std::string &rule, const std::string &source,
				 falco_common::priority_type priority, const std::string &format, std::set<std::string> &tags)
{
	falco_outputs::ctrl_msg cmsg = {};
	cmsg.ts = evt->get_ts();
	cmsg.priority = priority;
	cmsg.source = source;
	cmsg.rule = rule;

	std::string sformat;
	if(m_time_format_iso_8601)
	{
		sformat = "*%evt.time.iso8601: ";
	}
	else
	{
		sformat = "*%evt.time: ";
	}
	sformat += falco_common::format_priority(priority);

	// if format starts with a *, remove it, as we added our own prefix
	if(format[0] == '*')
	{
		sformat += " " + format.substr(1, format.length() - 1);
	}
	else
	{
		sformat += " " + format;
	}

	cmsg.msg = m_formats->format_event(
		evt, rule, source, falco_common::format_priority(priority), sformat, tags, m_hostname
	);
	cmsg.fields = m_formats->get_field_values(evt, source, sformat);
	cmsg.tags.insert(tags.begin(), tags.end());

	cmsg.type = ctrl_msg_type::CTRL_MSG_OUTPUT;
	this->push(cmsg);
}

void falco_outputs::handle_msg(uint64_t ts,
			       falco_common::priority_type priority,
			       const std::string &msg,
			       const std::string &rule,
			       nlohmann::json &output_fields)
{
	if (!output_fields.is_object())
	{
		throw falco_exception("falco_outputs: output fields must be key-value maps");
	}

	falco_outputs::ctrl_msg cmsg = {};
	cmsg.ts = ts;
	cmsg.priority = priority;
	cmsg.source = s_internal_source;
	cmsg.rule = rule;
	cmsg.fields = output_fields;

	if(m_json_output)
	{
		nlohmann::json jmsg;

		// Convert the time-as-nanoseconds to a more json-friendly ISO8601.
		time_t evttime = ts / 1000000000;
		char time_sec[20]; // sizeof "YYYY-MM-DDTHH:MM:SS"
		char time_ns[12];  // sizeof ".sssssssssZ"
		std::string iso8601evttime;

		strftime(time_sec, sizeof(time_sec), "%FT%T", gmtime(&evttime));
		snprintf(time_ns, sizeof(time_ns), ".%09luZ", ts % 1000000000);
		iso8601evttime = time_sec;
		iso8601evttime += time_ns;

		jmsg["output"] = msg;
		jmsg["priority"] = falco_common::format_priority(priority);
		jmsg["rule"] = rule;
		jmsg["time"] = iso8601evttime;
		jmsg["output_fields"] = output_fields;
		jmsg["hostname"] = m_hostname;
		jmsg["source"] = s_internal_source;

		cmsg.msg = jmsg.dump();
	}
	else
	{
		std::string timestr;
		bool first = true;

		sinsp_utils::ts_to_string(ts, &timestr, false, true);
		cmsg.msg = timestr + ": " + falco_common::format_priority(priority) + " " + msg + " (";
		for(auto &pair : output_fields.items())
		{
			if(first)
			{
				first = false;
			}
			else
			{
				cmsg.msg += " ";
			}
			if (!pair.value().is_primitive())
			{
				throw falco_exception("falco_outputs: output fields must be key-value maps");
			}
			cmsg.msg += pair.key() + "=" + pair.value().dump();
		}
		cmsg.msg += ")";
	}

	cmsg.type = ctrl_msg_type::CTRL_MSG_OUTPUT;
	this->push(cmsg);
}

void falco_outputs::cleanup_outputs()
{
	this->push_ctrl(falco_outputs::ctrl_msg_type::CTRL_MSG_CLEANUP);
}

void falco_outputs::reopen_outputs()
{
	this->push_ctrl(falco_outputs::ctrl_msg_type::CTRL_MSG_REOPEN);
}

void falco_outputs::stop_worker()
{
	watchdog<void *> wd;
	wd.start([&](void *) -> void {
		falco_logger::log(falco_logger::level::NOTICE, "output channels still blocked, discarding all remaining notifications\n");
#ifndef __EMSCRIPTEN__
		m_queue.clear();
#endif
		this->push_ctrl(falco_outputs::ctrl_msg_type::CTRL_MSG_STOP);
	});
	wd.set_timeout(m_timeout, nullptr);

	this->push_ctrl(falco_outputs::ctrl_msg_type::CTRL_MSG_STOP);
	if(m_worker_thread.joinable())
	{
		m_worker_thread.join();
	}
}

inline void falco_outputs::push_ctrl(ctrl_msg_type cmt)
{
	falco_outputs::ctrl_msg cmsg = {};
	cmsg.type = cmt;
	this->push(cmsg);
}

inline void falco_outputs::push(const ctrl_msg& cmsg)
{
#ifndef __EMSCRIPTEN__
	if (!m_queue.try_push(cmsg))
	{
		if(m_outputs_queue_num_drops.load() == 0)
		{
			falco_logger::log(falco_logger::level::ERR, "Outputs queue out of memory. Drop event and continue on ...");
		}
		m_outputs_queue_num_drops++;
	}
#else
	for (const auto& o : m_outputs)
	{
		process_msg(o.get(), cmsg);
	}
#endif
}

// todo(leogr,leodido): this function is not supposed to throw exceptions, and with "noexcept",
// the program is terminated if that occurs. Although that's the wanted behavior,
// we still need to improve the error reporting since some inner functions can throw exceptions.
void falco_outputs::worker() noexcept
{
	watchdog<std::string> wd;
	wd.start([&](const std::string& payload) -> void {
		falco_logger::log(falco_logger::level::CRIT, "\"" + payload + "\" output timeout, all output channels are blocked\n");
	});

	auto timeout = m_timeout;

	falco_outputs::ctrl_msg cmsg;
	do
	{
		// Block until a message becomes available.
#ifndef __EMSCRIPTEN__
		m_queue.pop(cmsg);
#endif

		for(const auto& o : m_outputs)
		{
			wd.set_timeout(timeout, o->get_name());
			try
			{
				process_msg(o.get(), cmsg);
			}
			catch(const std::exception &e)
			{
				falco_logger::log(falco_logger::level::ERR, o->get_name() + ": " + std::string(e.what()) + "\n");
			}
		}
		wd.cancel_timeout();
	} while(cmsg.type != ctrl_msg_type::CTRL_MSG_STOP);
}

inline void falco_outputs::process_msg(falco::outputs::abstract_output* o, const ctrl_msg& cmsg)
{
	switch(cmsg.type)
	{
		case ctrl_msg_type::CTRL_MSG_OUTPUT:
			o->output(&cmsg);
			break;
		case ctrl_msg_type::CTRL_MSG_CLEANUP:
		case ctrl_msg_type::CTRL_MSG_STOP:
			o->cleanup();
			break;
		case ctrl_msg_type::CTRL_MSG_REOPEN:
			o->reopen();
			break;
		default:
			falco_logger::log(falco_logger::level::DEBUG, "Outputs worker received an unknown message type\n");
	}
}

uint64_t falco_outputs::get_outputs_queue_num_drops()
{
	return m_outputs_queue_num_drops.load();
}
