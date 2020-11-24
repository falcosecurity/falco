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

#pragma once

#include <map>
#include <string>
#include <vector>

extern "C"
{
#include "hawk.h"
}

namespace libhawk
{
extern std::map<std::string, hawk_plugin_definition>* g_plugins;

class lifecycle
{
public:
	lifecycle();

	void watch_rules(hawk_watch_rules_cb cb, hawk_engine* engine, const std::string& plugin_name);
	void stop();
};
} // namespace libhawk
