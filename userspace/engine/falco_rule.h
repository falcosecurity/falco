// SPDX-License-Identifier: Apache-2.0
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

#pragma once

#include <set>
#include <string>
#include "falco_common.h"

/*!
	\brief Represents a rule in the Falco Engine.
	The rule ID must be unique across all the rules loaded in the engine.
*/
struct falco_rule
{
	falco_rule(): id(0), priority(falco_common::PRIORITY_DEBUG) {}
	falco_rule(falco_rule&&) = default;
	falco_rule& operator = (falco_rule&&) = default;
	falco_rule(const falco_rule&) = default;
	falco_rule& operator = (const falco_rule&) = default;

	std::size_t id;
	std::string source;
	std::string name;
	std::string description;
	std::string output;
	std::set<std::string> tags;
	std::set<std::string> exception_fields;
	falco_common::priority_type priority;
};
