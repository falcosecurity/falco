/*
Copyright (C) 2020 The Falco Authors

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

#include "falco_outputs_syslog.h"
#include <syslog.h>
#include "banned.h" // This raises a compilation error when certain functions are used

void falco::outputs::output_syslog::output_event(gen_event *evt, std::string &rule, std::string &source,
						 falco_common::priority_type priority, std::string &format, std::string &msg)
{
	output_msg(priority, msg);
}

void falco::outputs::output_syslog::output_msg(falco_common::priority_type priority, std::string &msg)
{
	::syslog(priority, "%s", msg.c_str());
}
