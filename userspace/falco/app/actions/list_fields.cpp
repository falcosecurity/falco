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

using namespace falco::app;
using namespace falco::app::actions;

falco::app::run_result falco::app::actions::list_fields(falco::app::state& s)
{
	if(s.options.list_fields)
	{
		if(s.options.list_source_fields != "" &&
		   !s.engine->is_source_valid(s.options.list_source_fields))
		{
			return run_result::fatal("Value for --list must be a valid source type");
		}
		s.engine->list_fields(s.options.list_source_fields, s.options.verbose, s.options.names_only, s.options.markdown);
		return run_result::exit();
	}

	return run_result::ok();
}
