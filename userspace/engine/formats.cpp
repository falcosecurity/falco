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

#include <json/json.h>

#include "formats.h"
#include "falco_engine.h"

falco_formats::falco_formats(std::shared_ptr<const falco_engine> engine,
			     bool json_include_output_property,
			     bool json_include_tags_property)
	: m_falco_engine(engine),
	m_json_include_output_property(json_include_output_property),
	m_json_include_tags_property(json_include_tags_property)
{
}

falco_formats::~falco_formats()
{
}

std::string falco_formats::format_event(sinsp_evt *evt, const std::string &rule, const std::string &source,
				   const std::string &level, const std::string &format, const std::set<std::string> &tags,
				   const std::string &hostname) const
{
	std::string line;

	std::shared_ptr<sinsp_evt_formatter> formatter;

	formatter = m_falco_engine->create_formatter(source, format);

	// Format the original output string, regardless of output format
	formatter->tostring_withformat(evt, line, sinsp_evt_formatter::OF_NORMAL);

	if(formatter->get_output_format() == sinsp_evt_formatter::OF_JSON)
	{
		std::string json_line;

		// Format the event into a json object with all fields resolved
		formatter->tostring(evt, json_line);

		// The formatted string might have a leading newline. If it does, remove it.
		if(json_line[0] == '\n')
		{
			json_line.erase(0, 1);
		}

		// For JSON output, the formatter returned a json-as-text
		// object containing all the fields in the original format
		// message as well as the event time in ns. Use this to build
		// a more detailed object containing the event time, rule,
		// severity, full output, and fields.
		Json::Value event;
		Json::Value rule_tags;
		Json::FastWriter writer;
		std::string full_line;
		unsigned int rule_tags_idx = 0;

		// Convert the time-as-nanoseconds to a more json-friendly ISO8601.
		time_t evttime = evt->get_ts() / 1000000000;
		char time_sec[20]; // sizeof "YYYY-MM-DDTHH:MM:SS"
		char time_ns[12];  // sizeof ".sssssssssZ"
		std::string iso8601evttime;

		strftime(time_sec, sizeof(time_sec), "%FT%T", gmtime(&evttime));
		snprintf(time_ns, sizeof(time_ns), ".%09luZ", evt->get_ts() % 1000000000);
		iso8601evttime = time_sec;
		iso8601evttime += time_ns;
		event["time"] = iso8601evttime;
		event["rule"] = rule;
		event["priority"] = level;
		event["source"] = source;
		event["hostname"] = hostname;

		if(m_json_include_output_property)
		{
			// This is the filled-in output line.
			event["output"] = line;
		}

		if(m_json_include_tags_property)
		{
			if (tags.size() == 0)
			{
				// This sets an empty array
				rule_tags = Json::arrayValue;
			}
			else
			{
				for (const auto &tag : tags)
				{
					rule_tags[rule_tags_idx++] = tag;
				}
			}
			event["tags"] = rule_tags;
		}

		full_line = writer.write(event);

		// Json::FastWriter may add a trailing newline. If it
		// does, remove it.
		if(full_line[full_line.length() - 1] == '\n')
		{
			full_line.resize(full_line.length() - 1);
		}

		// Cheat-graft the output from the formatter into this
		// string. Avoids an unnecessary json parse just to
		// merge the formatted fields at the object level.
		full_line.pop_back();
		full_line.append(", \"output_fields\": ");
		full_line.append(json_line);
		full_line.append("}");
		line = full_line;
	}

	return line;
}

std::map<std::string, std::string> falco_formats::get_field_values(sinsp_evt *evt, const std::string &source,
						    const std::string &format) const
{
	std::shared_ptr<sinsp_evt_formatter> formatter;

	formatter = m_falco_engine->create_formatter(source, format);

	std::map<std::string, std::string> ret;

	if (! formatter->get_field_values(evt, ret))
	{
		throw falco_exception("Could not extract all field values from event");
	}

	return ret;
}
