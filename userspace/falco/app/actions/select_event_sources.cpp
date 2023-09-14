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

#include "actions.h"
#include "helpers.h"

using namespace falco::app;
using namespace falco::app::actions;

falco::app::run_result falco::app::actions::select_event_sources(falco::app::state& s)
{
	s.enabled_sources = { s.loaded_sources.begin(), s.loaded_sources.end() };

	// event sources selection is meaningless when reading trace files
	if (s.is_capture_mode())
	{
		return run_result::ok();
	}

	if (!s.options.enable_sources.empty() && !s.options.disable_sources.empty())
	{
		return run_result::fatal("You can not mix --enable-source and --disable-source");
	}

	if (!s.options.enable_sources.empty())
	{
		s.enabled_sources.clear();
		for(const auto &src : s.options.enable_sources)
		{
			if (std::find(s.loaded_sources.begin(), s.loaded_sources.end(), src) == s.loaded_sources.end())
			{
				return run_result::fatal("Attempted enabling an unknown event source: " + src);
			}
			s.enabled_sources.insert(src);
		}
	}
	else if (!s.options.disable_sources.empty())
	{
		for(const auto &src : s.options.disable_sources)
		{
			if (std::find(s.loaded_sources.begin(), s.loaded_sources.end(), src) == s.loaded_sources.end())
			{
				return run_result::fatal("Attempted disabling an unknown event source: " + src);
			}
			s.enabled_sources.erase(src);
		}
	}

	if(s.enabled_sources.empty())
	{
		return run_result::fatal("Must enable at least one event source");
	}

	return run_result::ok();
}
