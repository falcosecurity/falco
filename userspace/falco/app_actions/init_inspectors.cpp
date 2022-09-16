/*
Copyright (C) 2022 The Falco Authors.

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

#include "application.h"
#include <unordered_set>
#include <plugin_manager.h>

using namespace falco::app;

void application::init_syscall_inspector(
		std::shared_ptr<sinsp> inspector,
		const falco::app::cmdline_options& opts)
{
	inspector->set_buffer_format(opts.event_buffer_format);

	// If required, set the CRI paths
	for (auto &p : opts.cri_socket_paths)
	{
		if (!p.empty())
		{
			inspector->add_cri_socket_path(p);
		}
	}

	// Decide whether to do sync or async for CRI metadata fetch
	inspector->set_cri_async(!opts.disable_cri_async);

	//
	// If required, set the snaplen
	//
	if(opts.snaplen != 0)
	{
		inspector->set_snaplen(opts.snaplen);
	}

	if(!opts.all_events)
	{
		m_state->ppm_sc_of_interest = inspector->enforce_simple_ppm_sc_set();
		m_state->tp_of_interest = inspector->enforce_sinsp_state_tracepoints();
		// We are not interested in sched_switch tracepoint,
		// highly noisy and not useful for state/events enrichment.
		m_state->tp_of_interest.erase(SCHED_SWITCH);
	}

	inspector->set_hostname_and_port_resolution_mode(false);
}

static bool populate_filterchecks(
		std::shared_ptr<sinsp> inspector,
		const std::string& source,
		filter_check_list& filterchecks,
		std::unordered_set<std::string>& used_plugins,
		std::string& err)
{
	std::vector<const filter_check_info*> info;
	for(const auto& p : inspector->get_plugin_manager()->plugins())
	{
		if (!(p->caps() & CAP_EXTRACTION))
		{
			continue;
		}

		// check if some fields are overlapping on this event sources
		info.clear();
		filterchecks.get_all_fields(info);
		for (auto &info : info)
		{
			for (int32_t i = 0; i < info->m_nfields; i++)
			{
				// check if one of the fields extractable by the plugin
				// is already provided by another filtercheck for this source
				std::string fname = info->m_fields[i].m_name;
				for (auto &f : p->fields())
				{
					if (std::string(f.m_name) == fname)
					{
						err = "Plugin '" + p->name()
							+ "' supports extraction of field '" + fname
							+ "' that is overlapping for source '" + source + "'";
						return false;
					}
				}
			}
		}

		// add plugin filterchecks to the event source
		filterchecks.add_filter_check(sinsp_plugin::new_filtercheck(p));
		used_plugins.insert(p->name());
	}
	return true;
}

application::run_result application::init_inspectors()
{
	std::string err;
	std::unordered_set<std::string> used_plugins;
	const auto& all_plugins = m_state->offline_inspector->get_plugin_manager()->plugins();
	
	for (const auto &src : m_state->loaded_sources)
	{
		auto src_info = m_state->source_infos.at(src);

		// in capture mode, every event source uses the offline inspector.
		// in live mode, we create a new inspector for each event source
		src_info->inspector = is_capture_mode()
			? m_state->offline_inspector
			: std::make_shared<sinsp>();

		// handle syscall and plugin sources differently
		// todo(jasondellaluce): change this once we support extracting plugin fields from syscalls too
		if (src == falco_common::syscall_source)
		{
			init_syscall_inspector(src_info->inspector, m_options);
			continue;
		}

		// load and init all plugins compatible with this event source
		// (if in capture mode, all plugins will be inited on the same inspector)
		for (const auto& p : all_plugins)
		{
			std::shared_ptr<sinsp_plugin> plugin = nullptr;
			auto config = m_state->plugin_configs.at(p->name());
			auto is_input = p->caps() & CAP_SOURCING && p->event_source() == src;

			if (is_capture_mode())
			{
				// in capture mode, every plugin is already registered
				// in the offline inspector by the load_plugins action
				plugin = p;
			}
			else
			{
				// in live mode, for the inspector assigned to the given
				// event source, we must register the plugin supporting
				// that event source and also plugins with field extraction
				// capability that are compatible with that event source
				if (is_input || (p->caps() & CAP_EXTRACTION && p->is_source_compatible(src)))
				{
					plugin = src_info->inspector->register_plugin(config->m_library_path);
				}
			}

			// init the plugin, if we registered it into an inspector
			// (in capture mode, this is true for every plugin)
			if (plugin)
			{
				if (!plugin->init(config->m_init_config, err))
				{
					return run_result::fatal(err);
				}
				if (is_input)
				{
					auto gen_check = src_info->inspector->new_generic_filtercheck();
					src_info->filterchecks.add_filter_check(gen_check);
				}
				used_plugins.insert(plugin->name());
			}
		}

		// populate filtercheck list for this inspector
		if (!populate_filterchecks(
				src_info->inspector,
				src,
				src_info->filterchecks,
				used_plugins,
				err))
		{
			return run_result::fatal(err);
		}	

	}

	// check if some plugin with field extraction capability remains unused
	for (const auto& p : all_plugins)
	{
		if(used_plugins.find(p->name()) == used_plugins.end() 
			&& p->caps() & CAP_EXTRACTION
			&& !(p->caps() & CAP_SOURCING && p->is_source_compatible(p->event_source())))
		{
			return run_result::fatal("Plugin '" + p->name()
				+ "' has field extraction capability but is not compatible with any known event source");
		}
	}

	return run_result::ok();
}
