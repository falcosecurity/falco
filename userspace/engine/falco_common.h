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
#include <exception>
#include <mutex>
#include <sinsp.h>

//
// Most falco_* classes can throw exceptions. Unless directly related
// to low-level failures like inability to open file, etc, they will
// be of this type.
//

struct falco_exception : std::exception
{
	falco_exception()
	{
	}

	virtual ~falco_exception() throw()
	{
	}

	falco_exception(std::string error_str)
	{
		m_error_str = error_str;
	}

	char const* what() const throw()
	{
		return m_error_str.c_str();
	}

	std::string m_error_str;
};

namespace falco_common
{
	const std::string syscall_source = "syscall";

	// Same as numbers/indices into the above vector
	enum priority_type
	{
		PRIORITY_EMERGENCY = 0,
		PRIORITY_ALERT = 1,
		PRIORITY_CRITICAL = 2,
		PRIORITY_ERROR = 3,
		PRIORITY_WARNING = 4,
		PRIORITY_NOTICE = 5,
		PRIORITY_INFORMATIONAL = 6,
		PRIORITY_DEBUG = 7
	};
	
	bool parse_priority(std::string v, priority_type& out);
	priority_type parse_priority(std::string v);
	bool format_priority(priority_type v, std::string& out, bool shortfmt=false);
	std::string format_priority(priority_type v, bool shortfmt=false);
};
