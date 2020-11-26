/*
Copyright (C) 2020 The Falco Authors.

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

#include "lifecycle.h"
#include "exception.h"

#include <iostream>

std::map<std::string, hawk_plugin_definition> *libhawk::g_plugins;

void libhawk_register_plugin(const char *name, hawk_plugin_definition def)
{
	if(libhawk::g_plugins == nullptr)
	{
		libhawk::g_plugins = new std::map<std::string, hawk_plugin_definition>();
	}

	auto name_str = std::string(name);
	auto plugin = libhawk::g_plugins->find(name_str);
	if(plugin != libhawk::g_plugins->end())
	{
		throw libhawk::hawk_exception("cannot register an already registered plugin: " + name_str);
	}
	libhawk::g_plugins->insert(std::make_pair(name_str, def));
};

hawk_plugin_registry plugin_registry = {
	.register_plugin = &libhawk_register_plugin,
};

void libhawk::lifecycle::start()
{
	if(g_plugins == nullptr)
	{
		throw hawk_exception("no libhawk plugins registered");
	}

	for(const auto& plugin : *g_plugins)
	{
		if(plugin.second.hawk_init != nullptr)
		{
			plugin.second.hawk_init();
		}
	}
}

void libhawk::lifecycle::stop()
{
	for(const auto& plugin : *g_plugins)
	{
		if(plugin.second.hawk_destroy != nullptr)
		{
			plugin.second.hawk_destroy();
		}
	}
}

void libhawk::lifecycle::watch_rules(hawk_watch_rules_cb cb, const std::string &plugin_name)
{
	auto plugin = g_plugins->find(plugin_name);
	if(plugin == g_plugins->end())
	{
		throw hawk_plugin_exception(plugin_name, "cannot watch_rules on a non existing plugin");
	}
	if(plugin->second.hawk_watch_rules == nullptr)
	{
		throw hawk_plugin_exception(plugin_name, "plugin does not implement hawk_watch_rules");
	}
	plugin->second.hawk_watch_rules(cb);
}
