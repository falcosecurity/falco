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

#include "load_plugins.h"

namespace falco {
namespace app {

act_load_plugins::act_load_plugins(application &app)
	: init_action(app), m_name("load plugins"),
	  m_prerequsites({"init falco engine", "load config"})
{
}

act_load_plugins::~act_load_plugins()
{
}

const std::string &act_load_plugins::name()
{
	return m_name;
}

const std::list<std::string> &act_load_plugins::prerequsites()
{
	return m_prerequsites;
}

runnable_action::run_result act_load_plugins::run()
{
	run_result ret = {true, "", true};

	// Factories that can create filters/formatters for
	// the (single) source supported by the (single) input plugin.
	// libs requires raw pointer, we should modify libs to use reference/shared_ptr
	std::shared_ptr<gen_event_filter_factory> plugin_filter_factory(new sinsp_filter_factory(state().inspector.get(), m_plugin_filter_checks));
	std::shared_ptr<gen_event_formatter_factory> plugin_formatter_factory(new sinsp_evt_formatter_factory(state().inspector.get(), m_plugin_filter_checks));

	if(state().config->m_json_output)
	{
		plugin_formatter_factory->set_output_format(gen_event_formatter::OF_JSON);
	}

	std::shared_ptr<sinsp_plugin> input_plugin;
	std::list<std::shared_ptr<sinsp_plugin>> extractor_plugins;
	for(auto &p : state().config->m_plugins)
	{
		std::shared_ptr<sinsp_plugin> plugin;
#ifdef MUSL_OPTIMIZED
		ret.success = ret.proceed = false;
		ret.errstr = "Can not load/use plugins with musl optimized build";
		return ret;
#else
		falco_logger::log(LOG_INFO, "Loading plugin (" + p.m_name + ") from file " + p.m_library_path + "\n");

		// libs requires raw pointer, we should modify libs to use reference/shared_ptr
		plugin = sinsp_plugin::register_plugin(state().inspector.get(),
						       p.m_library_path,
						       (p.m_init_config.empty() ? NULL : (char *)p.m_init_config.c_str()),
						       m_plugin_filter_checks);
#endif

		if(plugin->type() == TYPE_SOURCE_PLUGIN)
		{
			sinsp_source_plugin *splugin = static_cast<sinsp_source_plugin *>(plugin.get());

			if(input_plugin)
			{
				ret.success = false;
				ret.errstr = string("Can not load multiple source plugins. ") + input_plugin->name() + " already loaded";
				ret.proceed = false;
				return ret;
			}

			input_plugin = plugin;
			state().event_source = splugin->event_source();

			state().inspector->set_input_plugin(p.m_name);
			if(!p.m_open_params.empty())
			{
				state().inspector->set_input_plugin_open_params(p.m_open_params.c_str());
			}

			state().engine->add_source(state().event_source, plugin_filter_factory, plugin_formatter_factory);

		} else {
			extractor_plugins.push_back(plugin);
		}
	}

	// Ensure that extractor plugins are compatible with the event source.
	// Also, ensure that extractor plugins don't have overlapping compatible event sources.
	std::set<std::string> compat_sources_seen;
	for(auto plugin : extractor_plugins)
	{
		// If the extractor plugin names compatible sources,
		// ensure that the input plugin's source is in the list
		// of compatible sources.
		sinsp_extractor_plugin *eplugin = static_cast<sinsp_extractor_plugin *>(plugin.get());
		const std::set<std::string> &compat_sources = eplugin->extract_event_sources();
		if(input_plugin &&
		   !compat_sources.empty())
		{
			if (compat_sources.find(state().event_source) == compat_sources.end())
			{
				ret.success = ret.proceed = false;
				ret.errstr = string("Extractor plugin not compatible with event source ") + state().event_source;
				return ret;
			}

			for(const auto &compat_source : compat_sources)
			{
				if(compat_sources_seen.find(compat_source) != compat_sources_seen.end())
				{
					ret.success = ret.proceed = false;
					ret.errstr = string("Extractor plugins have overlapping compatible event source ") + compat_source;
					return ret;
				}
				compat_sources_seen.insert(compat_source);
			}
		}
	}

	state().plugin_infos = sinsp_plugin::plugin_infos(state().inspector.get());

	return ret;
}

}; // namespace application
}; // namespace falco

