/*
Copyright (C) 2016-2019 Draios Inc dba Sysdig.

This file is part of falco.

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

#include <string>

namespace utils
{
const std::string db("/proc/modules");
const std::string module(PROBE_NAME);
const std::string module_state_live("live");
// Module's taint state constants
// see: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/kernel/panic.c#n351
const std::string taint_die("D");
const std::string taint_forced_rmmod("R");
const std::string taint_warn("W");
bool has_module(bool verbose, bool strict);
bool ins_module();
bool module_predicate(bool has_module);
} // namespace utils
