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

#include <string>
#include "ruleset.h"

struct falco_source
{
	std::string name;
	uint16_t default_ruleset_id;
	std::shared_ptr<filter_ruleset> ruleset;
	std::shared_ptr<filter_ruleset_factory> ruleset_factory;
	std::shared_ptr<gen_event_filter_factory> filter_factory;
	std::shared_ptr<gen_event_formatter_factory> formatter_factory;		

	inline bool is_field_defined(std::string field) const
	{
		auto *chk = filter_factory->new_filtercheck(field.c_str());
		if (chk)
		{
			delete(chk);
			return true;
		}
		return false;
	}
};
