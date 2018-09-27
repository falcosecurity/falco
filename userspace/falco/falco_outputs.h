/*
Copyright (C) 2016-2018 Draios Inc dba Sysdig.

This file is part of falco.

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

#include "falco_common.h"
#include "token_bucket.h"

//
// This class acts as the primary interface between a program and the
// falco output engine. The falco rules engine is implemented by a
// separate class falco_engine.
//

class falco_outputs : public falco_common
{
public:
	falco_outputs();
	virtual ~falco_outputs();

	// The way to refer to an output (file, syslog, stdout,
	// etc). An output has a name and set of options.
	struct output_config
	{
		std::string name;
		std::map<std::string, std::string> options;
	};

	void init(bool json_output,
		  bool json_include_output_property,
		  uint32_t rate, uint32_t max_burst, bool buffered);

	void add_output(output_config oc);

	//
	// ev is an event that has matched some rule. Pass the event
	// to all configured outputs.
	//
	void handle_event(sinsp_evt *ev, std::string &rule, falco_common::priority_type priority, std::string &format);

	void reopen_outputs();

private:
	bool m_initialized;

	// Rate limits notifications
	token_bucket m_notifications_tb;

	bool m_buffered;

	std::string m_lua_add_output = "add_output";
	std::string m_lua_output_event = "output_event";
	std::string m_lua_output_cleanup = "output_cleanup";
	std::string m_lua_output_reopen = "output_reopen";
	std::string m_lua_main_filename = "output.lua";
};
