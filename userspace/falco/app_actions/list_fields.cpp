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

#include "list_fields.h"

namespace falco {
namespace app {

act_list_fields::act_list_fields(application &app)
	: init_action(app), m_name("list fields"),
	  m_prerequsites({"load plugins"})
{
}

act_list_fields::~act_list_fields()
{
}

const std::string &act_list_fields::name()
{
	return m_name;
}

const std::list<std::string> &act_list_fields::prerequsites()
{
	return m_prerequsites;
}

runnable_action::run_result act_list_fields::run()
{
	run_result ret = {true, "", true};

	if(options().list_fields)
	{
		if(options().list_source_fields != "" &&
		   !state().engine->is_source_valid(options().list_source_fields))
		{
			ret.success = false;
			ret.errstr = "Value for --list must be a valid source type";
			ret.proceed = false;
			return ret;
		}
		state().engine->list_fields(options().list_source_fields, options().verbose, options().names_only);

		ret.proceed = false;
	}

	return ret;
}

}; // namespace application
}; // namespace falco

