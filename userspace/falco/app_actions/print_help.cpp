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

#include "print_help.h"

namespace falco {
namespace app {

act_print_help::act_print_help(application &app)
	: easyopts_action(app), m_name("print help")
{
}

act_print_help::~act_print_help()
{
}

const std::string &act_print_help::name()
{
	return m_name;
}

const std::list<std::string> &act_print_help::prerequsites()
{
	return m_prerequsites;
}

runnable_action::run_result act_print_help::run()
{
	run_result ret = {true, "", true};

	if(options().help)
	{
		printf("%s", options().usage().c_str());
		ret.proceed = false;
	}

	return ret;
}

}; // namespace application
}; // namespace falco

