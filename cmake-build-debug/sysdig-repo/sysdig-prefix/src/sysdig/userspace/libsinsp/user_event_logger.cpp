/*
Copyright (C) 2019 Sysdig Inc.

This file is part of sysdig.

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
#include "sinsp.h"
#include "user_event_logger.h"
#include <memory>
#include <string>

namespace
{

/**
 * Do-nothing realization of the user_event_logger::callback interface.
 */
class null_callback : public user_event_logger::callback
{
public:
	void log(const sinsp_user_event& evt,
	         const user_event_logger::severity severity) override
	{ }

	bool is_null() const override { return true; }
};

/** The current callback handler. */
user_event_logger::callback::ptr_t s_callback = std::make_shared<null_callback>();

} // end namespace

void user_event_logger::log(const sinsp_user_event& evt,
                            const user_event_logger::severity severity)
{
	s_callback->log(evt, severity);
}

void user_event_logger::register_callback(callback::ptr_t callback)
{
	if(callback)
	{
		s_callback = callback;
	}
	else
	{
		s_callback = std::make_shared<null_callback>();
	}
}

const user_event_logger::callback& user_event_logger::get_callback()
{
	return *s_callback;
}
