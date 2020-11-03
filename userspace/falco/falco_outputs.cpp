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

#ifndef MINIMAL_BUILD
#include <google/protobuf/util/time_util.h>
#endif

#include "falco_outputs.h"

#include "config_falco.h"

#include "formats.h"
#include "logger.h"
#include "watchdog.h"

#include "outputs_file.h"
#include "outputs_program.h"
#include "outputs_stdout.h"
#include "outputs_syslog.h"
#ifndef MINIMAL_BUILD
#include "outputs_http.h"
#include "outputs_grpc.h"
#endif

#include "banned.h" // This raises a compilation error when certain functions are used

using namespace std;

falco_outputs::falco_outputs():
	m_initialized(false),
	m_buffered(true),
	m_json_output(false),
	m_time_format_iso_8601(false),
	m_hostname("")
{
}

falco_outputs::~falco_outputs()
{
	if(m_initialized)
	{
		this->cleanup_outputs();
		this->stop_worker();
		if(m_worker_thread.joinable())
		{
			m_worker_thread.join();
		}
	}
}

void falco_outputs::init(bool json_output,
			 bool json_include_output_property,
			 uint32_t rate, uint32_t max_burst, bool buffered,
			 bool time_format_iso_8601, string hostname)
{
	// Cannot be initialized more than one time.
	if(m_initialized)
	{
		throw falco_exception("falco_outputs already initialized");
	}

	m_json_output = json_output;

	// Note that falco_formats is already initialized by the engine,
	// and the following json options are not used within the engine.
	// So we can safely update them.
	falco_formats::s_json_output = json_output;
	falco_formats::s_json_include_output_property = json_include_output_property;

	m_notifications_tb.init(rate, max_burst);

	m_buffered = buffered;
	m_time_format_iso_8601 = time_format_iso_8601;
	m_hostname = hostname;

	m_worker_thread = std::thread(&falco_outputs::worker, this);

	m_initialized = true;
}

// todo(leogr): when the worker has started, adding an outputs is not thread-safe
void falco_outputs::add_output(falco::outputs::config oc)
{

	falco::outputs::abstract_output *oo;

	if(oc.name == "file")
	{
		oo = new falco::outputs::output_file();
	}
	else if(oc.name == "program")
	{
		oo = new falco::outputs::output_program();
	}
	else if(oc.name == "stdout")
	{
		oo = new falco::outputs::output_stdout();
	}
	else if(oc.name == "syslog")
	{
		oo = new falco::outputs::output_syslog();
	}
#ifndef MINIMAL_BUILD
	else if(oc.name == "http")
	{
		oo = new falco::outputs::output_http();
	}
	else if(oc.name == "grpc")
	{
		oo = new falco::outputs::output_grpc();
	}
#endif
	else
	{
		throw falco_exception("Output not supported: " + oc.name);
	}

	oo->init(oc, m_buffered, m_hostname);
	m_outputs.push_back(oo);
}

void falco_outputs::handle_event(gen_event *evt, string &rule, string &source,
				 falco_common::priority_type priority, string &format)
{
	if(!m_notifications_tb.claim())
	{
		falco_logger::log(LOG_DEBUG, "Skipping rate-limited notification for rule " + rule + "\n");
		return;
	}

	falco_outputs::ctrl_msg cmsg = {};
	cmsg.ts = evt->get_ts();
	cmsg.priority = priority;
	cmsg.source = source;
	cmsg.rule = rule;

	string sformat;
	if(source == "syscall")
	{
		if(m_time_format_iso_8601)
		{
			sformat = "*%evt.time.iso8601: " + falco_common::priority_names[priority];
		}
		else
		{
			sformat = "*%evt.time: " + falco_common::priority_names[priority];
		}
	}
	else
	{
		if(m_time_format_iso_8601)
		{
			sformat = "*%jevt.time.iso8601: " + falco_common::priority_names[priority];
		}
		else
		{
			sformat = "*%jevt.time: " + falco_common::priority_names[priority];
		}
	}

	// if format starts with a *, remove it, as we added our own prefix
	if(format[0] == '*')
	{
		sformat += " " + format.substr(1, format.length() - 1);
	}
	else
	{
		sformat += " " + format;
	}

	cmsg.msg = falco_formats::format_event(evt, rule, source, falco_common::priority_names[priority], sformat);
	cmsg.fields = falco_formats::resolve_tokens(evt, source, sformat);

	cmsg.type = ctrl_msg_type::CTRL_MSG_OUTPUT;
	m_queue.push(cmsg);
}

void falco_outputs::handle_msg(uint64_t ts,
			       falco_common::priority_type priority,
			       std::string &msg,
			       std::string &rule,
			       std::map<std::string, std::string> &output_fields)
{
	falco_outputs::ctrl_msg cmsg = {};
	cmsg.ts = ts;
	cmsg.priority = priority;
	cmsg.source = "internal";
	cmsg.rule = rule;
	cmsg.fields = output_fields;

	if(m_json_output)
	{
		nlohmann::json jmsg;

		// Convert the time-as-nanoseconds to a more json-friendly ISO8601.
		time_t evttime = ts / 1000000000;
		char time_sec[20]; // sizeof "YYYY-MM-DDTHH:MM:SS"
		char time_ns[12];  // sizeof ".sssssssssZ"
		string iso8601evttime;

		strftime(time_sec, sizeof(time_sec), "%FT%T", gmtime(&evttime));
		snprintf(time_ns, sizeof(time_ns), ".%09luZ", ts % 1000000000);
		iso8601evttime = time_sec;
		iso8601evttime += time_ns;

		jmsg["output"] = msg;
		jmsg["priority"] = falco_common::priority_names[priority];
		jmsg["rule"] = rule;
		jmsg["time"] = iso8601evttime;
		jmsg["output_fields"] = output_fields;

		cmsg.msg = jmsg.dump();
	}
	else
	{
		std::string timestr;
		bool first = true;

		sinsp_utils::ts_to_string(ts, &timestr, false, true);
		cmsg.msg = timestr + ": " + falco_common::priority_names[priority] + " " + msg + " (";
		for(auto &pair : output_fields)
		{
			if(first)
			{
				first = false;
			}
			else
			{
				cmsg.msg += " ";
			}
			cmsg.msg += pair.first + "=" + pair.second;
		}
		cmsg.msg += ")";
	}

	cmsg.type = ctrl_msg_type::CTRL_MSG_OUTPUT;
	m_queue.push(cmsg);
}

void falco_outputs::cleanup_outputs()
{
	this->push(falco_outputs::ctrl_msg_type::CTRL_MSG_CLEANUP);
}

void falco_outputs::reopen_outputs()
{
	this->push(falco_outputs::ctrl_msg_type::CTRL_MSG_REOPEN);
}

void falco_outputs::stop_worker()
{
	this->push(falco_outputs::ctrl_msg_type::CTRL_MSG_STOP);
}

inline void falco_outputs::push(ctrl_msg_type cmt)
{
	falco_outputs::ctrl_msg cmsg = {};
	cmsg.type = cmt;
	m_queue.push(cmsg);
}

void falco_outputs::worker()
{
	Watchdog<std::string> wd;

	wd.start([&](std::string payload) -> void {
		falco_logger::log(LOG_CRIT, "\"" + payload + "\" output deadline exceeded, all output channels are blocked.\n");
	});

	falco_outputs::ctrl_msg cmsg;
	while(true)
	{
		// Block until a message becomes available.
		m_queue.pop(cmsg);

		if (cmsg.type == ctrl_msg_type::CTRL_MSG_STOP)
			return;

		for(auto it = m_outputs.cbegin(); it != m_outputs.cend(); ++it)
		{
			wd.set_timeout(std::chrono::milliseconds(2000), (*it)->get_name());
			try
			{
				switch(cmsg.type)
				{
					case ctrl_msg_type::CTRL_MSG_OUTPUT:
							(*it)->output(&cmsg);
						break;
					case ctrl_msg_type::CTRL_MSG_CLEANUP:
							(*it)->cleanup();
						break;
					case ctrl_msg_type::CTRL_MSG_REOPEN:
							(*it)->reopen();
						break;
					default:
						falco_logger::log(LOG_DEBUG, "Outputs worker received an unknown message type\n");	
				}
			}
			catch(const exception &e)
			{
				falco_logger::log(LOG_ERR, (*it)->get_name() + ": " + string(e.what()) + "\n");
			}
		}
		wd.cancel_timeout();
	}
}
