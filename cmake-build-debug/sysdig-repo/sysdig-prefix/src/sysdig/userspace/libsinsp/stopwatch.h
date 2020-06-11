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
//
// stopwatch.h
//
// stopwatch utility
//

#pragma once

#include <chrono>

class sinsp_stopwatch
{
public:
	sinsp_stopwatch();

	void stop();
	void start();
	void reset();

	template<typename T>
	typename T::rep elapsed() const
	{
		return std::chrono::duration_cast<T>(m_stop - m_start).count();
	}

private:
	void record(std::chrono::high_resolution_clock::time_point& tp);

	std::chrono::high_resolution_clock::time_point m_start;
	std::chrono::high_resolution_clock::time_point m_stop;
};

inline void sinsp_stopwatch::sinsp_stopwatch::reset()
{
	m_start = std::chrono::high_resolution_clock::time_point::min();
	m_stop = m_start;
}

inline void sinsp_stopwatch::sinsp_stopwatch::start()
{
	record(m_start);
}

inline void sinsp_stopwatch::sinsp_stopwatch::stop()
{
	record(m_stop);
}

inline void sinsp_stopwatch::record(std::chrono::high_resolution_clock::time_point& tp)
{
	tp = std::chrono::high_resolution_clock::now();
}
