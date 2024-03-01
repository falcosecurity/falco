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

#pragma once

#include <string>
#include <exception>
#include <mutex>
#include <libsinsp/sinsp.h>

//
// equivalent to an "unbounded queue" in TBB terms or largest long value
// https://github.com/oneapi-src/oneTBB/blob/b2474bfc636937052d05daf8b3f4d6b76e20273a/include/oneapi/tbb/concurrent_queue.h#L554
//
#define DEFAULT_OUTPUTS_QUEUE_CAPACITY_UNBOUNDED_MAX_LONG_VALUE std::ptrdiff_t(~size_t(0) / 2)

#define DEFAULT_FALCO_LIBS_THREAD_TABLE_SIZE 262144

//
// Most falco_* classes can throw exceptions. Unless directly related
// to low-level failures like inability to open file, etc, they will
// be of this type.
//

struct falco_exception : std::runtime_error
{
	using std::runtime_error::runtime_error;
};

namespace falco_common
{

	const std::string syscall_source = sinsp_syscall_event_source_name;

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
	
	bool parse_priority(const std::string& v, priority_type& out);
	priority_type parse_priority(const std::string& v);
	bool format_priority(priority_type v, std::string& out, bool shortfmt=false);
	std::string format_priority(priority_type v, bool shortfmt=false);

	enum rule_matching
	{
		FIRST = 0,
		ALL = 1
	};

	bool parse_rule_matching(const std::string& v, rule_matching& out);
};
