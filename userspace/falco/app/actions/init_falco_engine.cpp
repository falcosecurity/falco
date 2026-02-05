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

#include "actions.h"
#include <libsinsp/plugin_manager.h>
#include <falco_common.h>
#include <algorithm>

using namespace falco::app;
using namespace falco::app::actions;

static inline std::string format_suggested_field(const filtercheck_field_info* info) {
	std::ostringstream out;

	// Replace "foo.bar" with "foo_bar"
	auto name = info->m_name;
	std::replace(name.begin(), name.end(), '.', '_');

	// foo_bar=%foo.bar
	out << name << "=%" << info->m_name;
	return out.str();
}

static void add_suggested_output(const falco::app::state& s,
                                 const std::string& src,
                                 const falco_configuration::append_output_config& eo) {
	auto src_info = s.source_infos.at(src);
	if(!src_info) {
		return;
	}
	auto& filterchecks = *src_info->filterchecks;
	std::vector<const filter_check_info*> fields;
	filterchecks.get_all_fields(fields);
	for(const auto& fld : fields) {
		for(int i = 0; i < fld->m_nfields; i++) {
			const auto* fldinfo = &fld->m_fields[i];
			if(fldinfo->is_format_suggested()) {
				s.engine->add_extra_output_format(format_suggested_field(fldinfo),
				                                  src,
				                                  eo.m_tags,
				                                  eo.m_rule);
			}
		}
	}
}

void configure_output_format(falco::app::state& s) {
	for(auto& eo : s.config->m_append_output) {
		if(eo.m_format != "") {
			s.engine->add_extra_output_format(eo.m_format, eo.m_source, eo.m_tags, eo.m_rule);
		}

		// Add suggested filtercheck formats to each source output
		if(eo.m_suggested_output) {
			if(eo.m_source.empty()) {
				for(auto& src : s.loaded_sources) {
					add_suggested_output(s, src, eo);
				}
			} else {
				add_suggested_output(s, eo.m_source, eo);
			}
		}

		for(auto const& ff : eo.m_formatted_fields) {
			s.engine->add_extra_output_formatted_field(ff.first,
			                                           ff.second,
			                                           eo.m_source,
			                                           eo.m_tags,
			                                           eo.m_rule);
		}

		for(auto const& rf : eo.m_raw_fields) {
			s.engine->add_extra_output_raw_field(rf, eo.m_source, eo.m_tags, eo.m_rule);
		}
	}

	if(!s.options.print_additional.empty()) {
		falco_logger::log(falco_logger::level::WARNING,
		                  "The -p/--print option is deprecated and will be removed. Use -o "
		                  "append_output=... instead.\n");

		if(s.options.print_additional == "c" || s.options.print_additional == "container" ||
		   s.options.print_additional == "k" || s.options.print_additional == "kubernetes") {
			// Don't do anything, we don't need these anymore
			// since container plugin takes care of suggesting the output format fields itself.
		} else {
			s.engine->add_extra_output_format(s.options.print_additional, "", {}, "");
		}
	}
}

void add_source_to_engine(falco::app::state& s, const std::string& src) {
	auto src_info = s.source_infos.at(src);
	auto& filterchecks = *src_info->filterchecks;
	auto* inspector = src_info->inspector.get();

	auto filter_factory = std::make_shared<sinsp_filter_factory>(inspector, filterchecks);
	auto formatter_factory = std::make_shared<sinsp_evt_formatter_factory>(inspector, filterchecks);

	if(s.config->m_json_output) {
		formatter_factory->set_output_format(sinsp_evt_formatter::OF_JSON);
	}

	src_info->engine_idx = s.engine->add_source(src, filter_factory, formatter_factory);
}

falco::app::run_result falco::app::actions::init_falco_engine(falco::app::state& s) {
	// add syscall as first source, this is also what each inspector do
	// in their own list of registered event sources
	add_source_to_engine(s, falco_common::syscall_source);

	// add all non-syscall event sources in engine
	for(const auto& src : s.loaded_sources) {
		// we skip the syscall source because we already added it
		if(src != falco_common::syscall_source) {
			add_source_to_engine(s, src);
		}
	}

	// note: in capture mode, we can assume that the plugin source index will
	// be the same in both the falco engine and the sinsp plugin manager.
	// This assumption stands because the plugin manager stores sources in a
	// vector, and the syscall source is appended in the engine *after* the sources
	// coming from plugins. The reason why this can't work with live mode,
	// is because in that case event sources are scattered across different
	// inspectors. Since this is an implementation-based assumption, we
	// check this and return an error to spot regressions in the future.
	if(s.is_capture_mode()) {
		auto manager = s.offline_inspector->get_plugin_manager();
		for(const auto& p : manager->plugins()) {
			if((p->caps() & CAP_SOURCING) == 0 || p->id() == 0) {
				continue;
			}
			bool added = false;
			auto source_idx = manager->source_idx_by_plugin_id(p->id(), added);
			auto engine_idx = s.source_infos.at(p->event_source())->engine_idx;
			if(!added || source_idx != engine_idx) {
				return run_result::fatal("Could not add event source in the engine: " +
				                         p->event_source());
			}
		}
	}

	configure_output_format(s);
	s.engine->set_min_priority(s.config->m_min_priority);

	return run_result::ok();
}
