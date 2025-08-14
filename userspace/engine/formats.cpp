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

#include <nlohmann/json.hpp>

#include "formats.h"
#include "falco_engine.h"

falco_formats::falco_formats(std::shared_ptr<const falco_engine> engine,
                             bool json_include_output_property,
                             bool json_include_tags_property,
                             bool json_include_message_property,
                             bool json_include_output_fields_property,
                             bool time_format_iso_8601):
        m_falco_engine(engine),
        m_json_include_output_property(json_include_output_property),
        m_json_include_tags_property(json_include_tags_property),
        m_json_include_message_property(json_include_message_property),
        m_json_include_output_fields_property(json_include_output_fields_property),
        m_time_format_iso_8601(time_format_iso_8601) {}

falco_formats::~falco_formats() {}

std::string falco_formats::format_event(sinsp_evt *evt,
                                        const std::string &rule,
                                        const std::string &source,
                                        const std::string &level,
                                        const std::string &format,
                                        const std::set<std::string> &tags,
                                        const std::string &hostname,
                                        const extra_output_field_t &extra_fields) const {
	std::string prefix_format;
	std::string message_format = format;

	if(m_time_format_iso_8601) {
		prefix_format = "*%evt.time.iso8601: ";
	} else {
		prefix_format = "*%evt.time: ";
	}
	prefix_format += level;

	if(message_format[0] != '*') {
		message_format = "*" + message_format;
	}

	auto prefix_formatter = m_falco_engine->create_formatter(source, prefix_format);
	auto message_formatter = m_falco_engine->create_formatter(source, message_format);

	// The classic Falco output prefix with time and priority e.g. "13:53:31.726060287: Critical"
	std::string prefix;
	prefix_formatter->tostring_withformat(evt, prefix, sinsp_evt_formatter::OF_NORMAL);

	// The formatted rule message/output
	std::string message;
	message_formatter->tostring_withformat(evt, message, sinsp_evt_formatter::OF_NORMAL);

	// The complete Falco output, e.g. "13:53:31.726060287: Critical Some Event Description
	// (proc_exe=bash)..."
	std::string output = prefix + " " + message;

	if(message_formatter->get_output_format() == sinsp_evt_formatter::OF_NORMAL) {
		return output;
	} else if(message_formatter->get_output_format() == sinsp_evt_formatter::OF_JSON) {
		std::string json_fields_message;
		std::string json_fields_prefix;

		// Resolve message fields
		if(m_json_include_output_fields_property) {
			message_formatter->tostring(evt, json_fields_message);
		}
		// Resolve prefix (e.g. time) fields
		prefix_formatter->tostring(evt, json_fields_prefix);

		// For JSON output, the formatter returned a json-as-text
		// object containing all the fields in the original format
		// message as well as the event time in ns. Use this to build
		// a more detailed object containing the event time, rule,
		// severity, full output, and fields.
		nlohmann::json event;

		// Convert the time-as-nanoseconds to a more json-friendly ISO8601.
		time_t evttime = evt->get_ts() / 1000000000;
		char time_sec[20];  // sizeof "YYYY-MM-DDTHH:MM:SS"
		char time_ns[12];   // sizeof ".sssssssssZ"
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

		if(m_json_include_output_property) {
			event["output"] = output;
		}

		if(m_json_include_tags_property) {
			event["tags"] = tags;
		}

		if(m_json_include_message_property) {
			event["message"] = message;
		}

		if(m_json_include_output_fields_property) {
			event["output_fields"] = nlohmann::json::parse(json_fields_message);

			auto prefix_fields = nlohmann::json::parse(json_fields_prefix);
			if(prefix_fields.is_object()) {
				for(auto const &el : prefix_fields.items()) {
					event["output_fields"][el.key()] = el.value();
				}
			}

			for(auto const &ef : extra_fields) {
				std::string fformat = ef.second.first;
				if(fformat.size() == 0) {
					continue;
				}

				if(!(fformat[0] == '*')) {
					fformat = "*" + fformat;
				}

				if(ef.second.second)  // raw field
				{
					std::string json_field_map;
					auto field_formatter = m_falco_engine->create_formatter(source, fformat);
					field_formatter->tostring_withformat(evt,
					                                     json_field_map,
					                                     sinsp_evt_formatter::OF_JSON);
					auto json_obj = nlohmann::json::parse(json_field_map);
					event["output_fields"][ef.first] = json_obj[ef.first];
				} else {
					event["output_fields"][ef.first] = format_string(evt, fformat, source);
				}
			}
		}

		return event.dump();
	}

	// should never get here until we only have OF_NORMAL and OF_JSON
	return "INVALID_OUTPUT_FORMAT";
}

std::string falco_formats::format_string(sinsp_evt *evt,
                                         const std::string &format,
                                         const std::string &source) const {
	std::string line;
	std::shared_ptr<sinsp_evt_formatter> formatter;

	formatter = m_falco_engine->create_formatter(source, format);
	formatter->tostring_withformat(evt, line, sinsp_evt_formatter::OF_NORMAL);

	return line;
}

std::map<std::string, std::string> falco_formats::get_field_values(
        sinsp_evt *evt,
        const std::string &source,
        const std::string &format) const {
	std::shared_ptr<sinsp_evt_formatter> formatter;

	std::string fformat = format;
	if(fformat[0] != '*') {
		fformat = "*" + fformat;
	}

	formatter = m_falco_engine->create_formatter(source, fformat);

	std::map<std::string, std::string> ret;

	if(!formatter->get_field_values(evt, ret)) {
		throw falco_exception("Could not extract all field values from event");
	}

	return ret;
}
