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
#include <plugin_manager.h>

using namespace falco::app;

application::run_result application::load_plugins()
{
#ifdef MUSL_OPTIMIZED
	if (!m_state->config->m_plugins.empty())
	{
		return run_result::fatal("Can not load/use plugins with musl optimized build");
	}
#endif

	// By default only the syscall event source is loaded and enabled
	m_state->loaded_sources = {falco_common::syscall_source};
	m_state->enabled_sources = {falco_common::syscall_source};

	std::string err = "";
	std::shared_ptr<sinsp_plugin> loaded_plugin = nullptr;
	for(auto &p : m_state->config->m_plugins)
	{
		falco_logger::log(LOG_INFO, "Loading plugin (" + p.m_name + ") from file " + p.m_library_path + "\n");
		auto plugin = m_state->inspector->register_plugin(p.m_library_path);
		if (!plugin->init(p.m_init_config, err))
		{
			return run_result::fatal(err);
		}

		if(plugin->caps() & CAP_SOURCING)
		{
			if (!is_capture_mode())
			{
				// todo(jasondellaluce): change this once we support multiple enabled event sources
				if(loaded_plugin)
				{
					return run_result::fatal("Can not load multiple plugins with event sourcing capability: '"
						+ loaded_plugin->name()
						+ "' already loaded");
				}
				loaded_plugin = plugin;
				m_state->inspector->set_input_plugin(p.m_name, p.m_open_params);

				m_state->loaded_sources.insert(plugin->event_source());
				// todo(jasondellaluce): change this once we support multiple enabled event sources
				m_state->enabled_sources = {plugin->event_source()};
			}

			// Init filtercheck list for the plugin's source and add the
			// event-generic filterchecks
			auto &filterchecks = m_state->plugin_filter_checks[plugin->event_source()];
			filterchecks.add_filter_check(m_state->inspector->new_generic_filtercheck());

			// Factories that can create filters/formatters for the event source of the plugin.
			std::shared_ptr<gen_event_filter_factory> filter_factory(new sinsp_filter_factory(m_state->inspector.get(), filterchecks));
			std::shared_ptr<gen_event_formatter_factory> formatter_factory(new sinsp_evt_formatter_factory(m_state->inspector.get(), filterchecks));
			if(m_state->config->m_json_output)
			{
				formatter_factory->set_output_format(gen_event_formatter::OF_JSON);
			}

			// note: here we assume that the source index will be the same in
			// both the falco engine and the sinsp plugin manager. This assumption
			// stands because the plugin manager stores sources in a vector, and
			// the syscall source is appended in the engine *after* the sources
			// coming from plugins. Since this is an implementation-based
			// assumption, we check this and return an error to spot
			// regressions in the future. We keep it like this for to avoid the
			// overhead of additional mappings at runtime, but we may consider
			// mapping the two indexes under something like std::unordered_map in the future.
			bool added = false;
			auto source_idx = m_state->inspector->get_plugin_manager()->source_idx_by_plugin_id(plugin->id(), added);
			auto source_idx_engine = m_state->engine->add_source(plugin->event_source(), filter_factory, formatter_factory);
			if (!added || source_idx != source_idx_engine)
			{
				return run_result::fatal("Could not add event source in the engine: " + plugin->event_source());
			}
		}
	}

	// Iterate over the plugins with extractor capability and add them to the
	// filtercheck list of their compatible sources
	std::vector<const filter_check_info*> filtercheck_info;
	for(const auto& p : m_state->inspector->get_plugin_manager()->plugins())
	{
		if (!(p->caps() & CAP_EXTRACTION))
		{
			continue;
		}

		bool used = false;
		for (auto &it : m_state->plugin_filter_checks)
		{
			// check if the event source is compatible with this plugin
			if (p->is_source_compatible(it.first))
			{
				// check if some fields are overlapping on this event sources
				filtercheck_info.clear();
				it.second.get_all_fields(filtercheck_info);
				for (auto &info : filtercheck_info)
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
								return run_result::fatal(
									"Plugin '" + p->name()
									+ "' supports extraction of field '" + fname
									+ "' that is overlapping for source '" + it.first + "'");
							}
						}
					}
				}

				// add plugin filterchecks to the event source
				it.second.add_filter_check(sinsp_plugin::new_filtercheck(p));
				used = true;
			}
		}
		if (!used)
		{
			return run_result::fatal("Plugin '" + p->name()
				+ "' has field extraction capability but is not compatible with any enabled event source");
		}
	}

	return run_result::ok();
}
