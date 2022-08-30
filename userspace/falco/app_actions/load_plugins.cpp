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
	auto empty_src_info = state::source_info{};

	// Initialize the set of loaded event sources. 
	// By default, the set includes the 'syscall' event source
	m_state->source_infos.clear();
	m_state->source_infos.insert(empty_src_info, falco_common::syscall_source);
	m_state->loaded_sources = { falco_common::syscall_source };

	// Initialize map of plugin configs
	m_state->plugin_configs.clear();

	// Initialize the offline inspector. This is used to load all the configured
	// plugins in order to have them available every time we need to access
	// their static info. If Falco is in capture mode, this inspector is also
	// used to open and read the trace file
	m_state->offline_inspector.reset(new sinsp());

	// Load all the configured plugins
	for(auto &p : m_state->config->m_plugins)
	{
		falco_logger::log(LOG_INFO, "Loading plugin '" + p.m_name + "' from file " + p.m_library_path + "\n");
		auto plugin = m_state->offline_inspector->register_plugin(p.m_library_path);
		m_state->plugin_configs.insert(p, plugin->name());
		if(plugin->caps() & CAP_SOURCING)
		{
			auto sname = plugin->event_source();
			m_state->source_infos.insert(empty_src_info, sname);
			m_state->loaded_sources.insert(sname);
		}
	}

	return run_result::ok();
}
