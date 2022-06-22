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

#include "application.h"

using namespace falco::app;

application::run_result application::select_event_sources()
{
	// event sources selection is meaningless when reading trace files
	if (!is_capture_mode())
	{
		for(const auto &src : m_options.disable_sources)
		{
			if (m_state->enabled_sources.find(src) == m_state->enabled_sources.end())
			{
				return run_result::fatal("Attempted disabling an unknown event source: " + src);
			}
			m_state->enabled_sources.erase(src);
		}

		if(m_state->enabled_sources.empty())
		{
			return run_result::fatal("Must enable at least one event source");
		}

		/* Print all enabled sources. */
		std::ostringstream os;
		std::copy(m_state->enabled_sources.begin(), m_state->enabled_sources.end(), std::ostream_iterator<std::string>(os, ","));
		std::string result = os.str();
		result.pop_back();
		falco_logger::log(LOG_INFO, "Enabled event sources: " + result + "\n");
	}

	return run_result::ok();
}