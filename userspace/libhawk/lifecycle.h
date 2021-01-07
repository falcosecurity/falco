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

#include "hawk.h"

namespace libhawk
{
extern std::map<std::string, hawk_plugin_definition>* g_plugins;

namespace lifecycle
{
void start();
void stop();
void watch_rules(hawk_rules_begin_cb begin_cb,
		 hawk_rules_insert_cb insert_cb,
		 hawk_rules_commit_cb commit_cb,
		 hawk_rules_rollback_cb rollback_cb,
		 const std::string& plugin_name);
} // namespace lifecycle
} // namespace libhawk
