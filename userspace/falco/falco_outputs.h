/*
Copyright (C) 2016 Draios inc.

This file is part of falco.

falco is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License version 2 as
published by the Free Software Foundation.

falco is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with falco.  If not, see <http://www.gnu.org/licenses/>.
*/

#pragma once

#include "falco_common.h"

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

	void init(bool json_output);

	void add_output(output_config oc);

	//
	// ev is an event that has matched some rule. Pass the event
	// to all configured outputs.
	//
	void handle_event(sinsp_evt *ev, std::string &rule, std::string &priority, std::string &format);

private:
	bool m_initialized;

	std::string m_lua_add_output = "add_output";
	std::string m_lua_output_event = "output_event";
	std::string m_lua_output_cleanup = "output_cleanup";
	std::string m_lua_main_filename = "output.lua";
};
