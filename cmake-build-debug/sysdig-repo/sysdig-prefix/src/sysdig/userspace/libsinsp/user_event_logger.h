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
#pragma once

#include <memory>
#include "user_event.h"

/**
 * This namespace exposes an API for logging user events.
 */
namespace user_event_logger
{

/**
 * The severities at which user events may be logged.
 */
enum severity
{
	SEV_EVT_FATAL,
	SEV_EVT_CRITICAL,
	SEV_EVT_ERROR,
	SEV_EVT_WARNING,
	SEV_EVT_NOTICE,
	SEV_EVT_INFORMATION,
	SEV_EVT_DEBUG,
};

/**
 * Interface to an object that will receive callbacks whenever user event
 * logs are generated.
 */
class callback
{
public:
	using ptr_t = std::shared_ptr<callback>;

	virtual ~callback() = default;

	/**
	 * Write the given log str with the given severity.
	 */
	virtual void log(const sinsp_user_event& evt, user_event_logger::severity sev) = 0;

	/**
	 * We use the "Null Object Pattern" with this interface; this will
	 * return true for do-nothing implementations, false otherwise.
	 */
	virtual bool is_null() const { return false; }
};

/**
 * Write the given user event log message with the given severity to the
 * registered callback.
 */
void log(const sinsp_user_event& evt, user_event_logger::severity sev);

/**
 * Register the given callback.  If a callback is already registered, it will
 * be replaced with the given callback.  The given callback may be nullptr,
 * in which case the registered callback will be replaced with a null
 * callback handler.
 */
void register_callback(user_event_logger::callback::ptr_t callback);

/**
 * Returns a reference to the current callback handler.  Use the is_null()
 * method on the returned object to determine if the handler is expected to
 * perform useful logging.
 */
const callback& get_callback();

} // end namespace user_event_logger

