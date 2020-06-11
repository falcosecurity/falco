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

typedef struct wh_t wh_t;

/**
 * Interface to an object that can provide a Windows Management
 * Instrumentation (WHI) handle. This is needed for windows support.
 *
 * This class does nothing for non-windows to enable simpler
 * cross-compilation.
 *
 * Note that the intention here is to apply the Interface Segregation
 * Principle (ISP) to class sinsp.  Some clients of sinsp need only the
 * get_capture_stats() API, and this interface exposes only that API.  Do
 * not add additional APIs here.  If some client of sinsp needs a different
 * set of APIs, introduce a new interface.
 */
class SINSP_PUBLIC wmi_handle_source
{
public:
	virtual ~wmi_handle_source() = default;


#ifdef CYGWING_AGENT
	/**
	 * Return a wmi handle
	 */
	virtual wh_t* get_wmi_handle() = 0;
#endif
};
