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
#include "helpers.h"

#include <unordered_set>

#include <libsinsp/plugin_manager.h>
#include <libsinsp/sinsp_filtercheck_static.h>

using namespace falco::app;
using namespace falco::app::actions;

static void init_syscall_inspector(falco::app::state& s, std::shared_ptr<sinsp> inspector) {
	sinsp_evt::param_fmt event_buffer_format = sinsp_evt::PF_NORMAL;
	if(s.config->m_buffer_format_base64) {
		event_buffer_format = sinsp_evt::PF_BASE64;
	}

	inspector->set_buffer_format(event_buffer_format);

	//
	// If required, set the snaplen.
	//
	if(s.config->m_falco_libs_snaplen != 0) {
		inspector->set_snaplen(s.config->m_falco_libs_snaplen);
	}

	if(s.is_driver_drop_failed_exit_enabled()) {
		falco_logger::log(falco_logger::level::INFO,
		                  "Failed syscall exit events are dropped in the kernel driver\n");
		inspector->set_dropfailed(true);
	}

	inspector->set_hostname_and_port_resolution_mode(false);
}

static bool populate_filterchecks(const std::shared_ptr<sinsp>& inspector,
                                  const std::string& source,
                                  filter_check_list& filterchecks,
                                  std::unordered_set<std::string>& used_plugins,
                                  std::map<std::string, std::string> static_fields,
                                  std::string& err) {
	// Add static filterchecks loaded from config
	if(!static_fields.empty()) {
		filterchecks.add_filter_check(std::make_unique<sinsp_filter_check_static>(static_fields));
	}

	// Add plugin-defined filterchecks, checking that they do not overlap any internal filtercheck
	std::vector<const filter_check_info*> infos;
	for(const auto& plugin : inspector->get_plugin_manager()->plugins()) {
		if(!(plugin->caps() & CAP_EXTRACTION)) {
			continue;
		}

		// check if some fields are overlapping on this event sources
		infos.clear();
		filterchecks.get_all_fields(infos);
		for(const auto& info : infos) {
			for(int32_t i = 0; i < info->m_nfields; i++) {
				// check if one of the fields extractable by the plugin
				// is already provided by another filtercheck for this source
				std::string fname = info->m_fields[i].m_name;
				for(const auto& field : plugin->fields()) {
					if(field.m_name == fname) {
						err = "Plugin '" + plugin->name() + "' supports extraction of field '" +
						      fname + "' that is overlapping for source '" + source + "'";
						return false;
					}
				}
			}
		}

		// add plugin filterchecks to the event source
		filterchecks.add_filter_check(sinsp_plugin::new_filtercheck(plugin));
		used_plugins.insert(plugin->name());
	}

	return true;
}

falco::app::run_result falco::app::actions::init_inspectors(falco::app::state& s) {
	std::string err;
	std::unordered_set<std::string> used_plugins;
	const auto& all_plugins = s.offline_inspector->get_plugin_manager()->plugins();
	const bool is_capture_mode = s.is_capture_mode();

	for(const auto& src : s.loaded_sources) {
		auto src_info = s.source_infos.at(src);

		// in capture mode, every event source uses the offline inspector.
		// in live mode, we create a new inspector for each event source
		if(is_capture_mode) {
			src_info->inspector = s.offline_inspector;
		} else {
			src_info->inspector =
			        std::make_shared<sinsp>(s.config->m_metrics_flags & METRICS_V2_STATE_COUNTERS);
		}

		// do extra preparation for the syscall source
		if(src == falco_common::syscall_source) {
			init_syscall_inspector(s, src_info->inspector);
		}

		// load and init all plugins compatible with this event source
		// (if in capture mode, all plugins will be inited on the same inspector)
		for(const auto& p : all_plugins) {
			std::shared_ptr<sinsp_plugin> plugin = nullptr;
			auto config = s.plugin_configs.at(p->name());
			auto is_input = (p->caps() & CAP_SOURCING) &&
			                ((p->id() != 0 && src == p->event_source()) ||
			                 (p->id() == 0 && src == falco_common::syscall_source));

			if(is_capture_mode) {
				// in capture mode, every plugin is already registered
				// in the offline inspector by the load_plugins action
				plugin = p;
			} else {
				// in live mode, for the inspector assigned to the given event source, we must
				// register a plugin if one of the following condition applies to it:
				// - it has event sourcing capability for the given event source
				// - it has one among field extraction, event parsing and async events capabilities
				//   and is compatible (with respect to that capability) with the given event source
				if(is_input ||
				   (p->caps() & CAP_EXTRACTION &&
				    sinsp_plugin::is_source_compatible(p->extract_event_sources(), src)) ||
				   (p->caps() & CAP_PARSING &&
				    sinsp_plugin::is_source_compatible(p->parse_event_sources(), src)) ||
				   (p->caps() & CAP_ASYNC &&
				    sinsp_plugin::is_source_compatible(p->async_event_sources(), src))) {
					plugin = src_info->inspector->register_plugin(config->m_library_path);
				}
			}

			if(!plugin) {
				continue;
			}

			// init the plugin only if we registered it into an inspector (in capture mode, this is
			// true for every plugin). Avoid initializing the same plugin twice in the same
			// inspector if we're in capture mode
			if(!is_capture_mode || used_plugins.find(p->name()) == used_plugins.end()) {
				if(!plugin->init(config->m_init_config, err)) {
					return run_result::fatal(err);
				}
			}
			if(is_input) {
				auto gen_check = src_info->inspector->new_generic_filtercheck();
				src_info->filterchecks->add_filter_check(std::move(gen_check));
			}
			used_plugins.insert(plugin->name());
		}

		// populate filtercheck list for this inspector
		if(!populate_filterchecks(src_info->inspector,
		                          src,
		                          *src_info->filterchecks,
		                          used_plugins,
		                          s.config->m_static_fields,
		                          err)) {
			return run_result::fatal(err);
		}

		if(is_capture_mode) {
			continue;
		}

		// in live mode, each inspector should have registered at most two event sources: the
		// "syscall" on, loaded at default at index 0, and optionally another one defined by a
		// plugin, at index 1
		const auto& sources = src_info->inspector->event_sources();
		if(sources.size() == 0 || sources.size() > 2 ||
		   sources[0] != falco_common::syscall_source) {
			err.clear();
			for(const auto& source : sources) {
				err += (err.empty() ? "" : ", ") + source;
			}
			return run_result::fatal("Illegal sources setup in live inspector for source '" + src +
			                         "': " + err);
		}
	}

	// check if some plugin remains unused
	for(const auto& p : all_plugins) {
		if(used_plugins.find(p->name()) == used_plugins.end()) {
			return run_result::fatal(
			        "Plugin '" + p->name() +
			        "' is loaded but unused as not compatible with any known event source");
		}
	}

	return run_result::ok();
}
