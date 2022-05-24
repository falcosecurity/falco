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

#pragma once

#include <set>
#include <string>
#include "falco_common.h"

struct falco_rule
{
	size_t id;
	std::string source;
	std::string name;
	std::string description;
	std::string output;
	std::set<std::string> tags;
	std::set<std::string> exception_fields;
	falco_common::priority_type priority;
};
