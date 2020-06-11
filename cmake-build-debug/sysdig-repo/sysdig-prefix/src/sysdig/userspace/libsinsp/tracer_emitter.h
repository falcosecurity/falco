/*
Copyright (C) 2013-2018 Draios Inc dba Sysdig.

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
#include <string>

// This class allows the caller to output sysdig tracers
// to /dev/null.
class tracer_emitter
{
public:
	static const uint64_t no_timeout = ~0ULL;

	tracer_emitter(std::string tag, uint64_t timeout_ns=no_timeout);
	tracer_emitter(std::string tag, const tracer_emitter &parent, uint64_t timeout_ns=no_timeout);
	~tracer_emitter();

	tracer_emitter() = delete;
	tracer_emitter(const tracer_emitter&) = delete;
	tracer_emitter& operator=(const tracer_emitter&) = delete;

	// Stop is only needed if you want the exit
	// event before the instance gets destructed,
	// i.e. goes out of scope
	uint64_t stop();
	static void set_enabled(bool enabled) { m_enabled = enabled; }

private:
	void start();
	void write_tracer(const bool enter);
	const std::string& tag() const { return m_tag; }
	uint64_t elapsed_time() const;

	const std::string m_tag;
	const uint64_t m_start_ns = 0;
	const uint64_t m_timeout_ns = 0;
	bool m_exit_written = false;
	static bool m_enabled;
};
