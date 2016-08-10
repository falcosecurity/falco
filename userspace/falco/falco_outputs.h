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
	void handle_event(sinsp_evt *ev, std::string &level, std::string &priority, std::string &format);

private:
	std::string m_lua_add_output = "add_output";
	std::string m_lua_output_event = "output_event";
	std::string m_lua_main_filename = "output.lua";
};
