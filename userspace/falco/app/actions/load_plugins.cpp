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
#include <plugin_manager.h>

using namespace falco::app;
using namespace falco::app::actions;

falco::app::run_result falco::app::actions::load_plugins(falco::app::state& s)
{
#if !defined(MUSL_OPTIMIZED) and !defined(__EMSCRIPTEN__)
	if (!s.config->m_plugins.empty())
	{
		return run_result::fatal("Loading plugins dynamic libraries is not supported with this Falco build");
	}
#endif
	// Initialize the set of loaded event sources. 
	// By default, the set includes the 'syscall' event source
	state::source_info syscall_src_info;
	syscall_src_info.filterchecks.reset(new sinsp_filter_check_list());
	s.source_infos.clear();
	s.source_infos.insert(syscall_src_info, falco_common::syscall_source);
	s.loaded_sources = { falco_common::syscall_source };

	// Initialize map of plugin configs
	s.plugin_configs.clear();

	// Initialize the offline inspector. This is used to load all the configured
	// plugins in order to have them available every time we need to access
	// their static info. If Falco is in capture mode, this inspector is also
	// used to open and read the trace file
	s.offline_inspector.reset(new sinsp());

	// Load all the configured plugins
	for(auto &p : s.config->m_plugins)
	{
		falco_logger::log(LOG_INFO, "Loading plugin '" + p.m_name + "' from file " + p.m_library_path + "\n");
		auto plugin = s.offline_inspector->register_plugin(p.m_library_path);
		s.plugin_configs.insert(p, plugin->name());
		if(plugin->caps() & CAP_SOURCING && plugin->id() != 0)
		{
			state::source_info src_info;
			src_info.filterchecks.reset(new filter_check_list());
			auto sname = plugin->event_source();
			s.source_infos.insert(src_info, sname);
			// note: this avoids duplicate values
			if (std::find(s.loaded_sources.begin(), s.loaded_sources.end(), sname) == s.loaded_sources.end())
			{
				s.loaded_sources.push_back(sname);
			}
		}
	}

	return run_result::ok();
}
