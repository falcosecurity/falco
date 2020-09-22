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

#include <memory>
#include <map>

#include "gen_filter.h"
#include "json_evt.h"
#include "falco_common.h"
#include "token_bucket.h"
#include "falco_engine.h"
#include "falco_output.h"

//
// This class acts as the primary interface between a program and the
// falco output engine. The falco rules engine is implemented by a
// separate class falco_engine.
//

class falco_outputs : public falco_common
{
public:
	falco_outputs(falco_engine *engine);
	virtual ~falco_outputs();

	void init(bool json_output,
		  bool json_include_output_property,
		  uint32_t rate, uint32_t max_burst, bool buffered,
		  bool time_format_iso_8601, std::string hostname,
		  const std::string& alternate_lua_dir);

	void add_output(falco::outputs::output::config oc);

	//
	// ev is an event that has matched some rule. Pass the event
	// to all configured outputs.
	//
	void handle_event(gen_event *evt, std::string &rule, std::string &source,
			  falco_common::priority_type priority, std::string &format);

	// Send a generic message to all outputs. Not necessarily associated with any event.
	void handle_msg(uint64_t now,
			falco_common::priority_type priority,
			std::string &msg,
			std::string &rule,
			std::map<std::string, std::string> &output_fields);

	void reopen_outputs();

private:
	falco_engine *m_falco_engine;

	bool m_initialized;

	std::vector<falco::outputs::output *> m_outputs;

	// Rate limits notifications
	token_bucket m_notifications_tb;

	bool m_buffered;
	bool m_json_output;
	bool m_time_format_iso_8601;
	std::string m_hostname;
};
