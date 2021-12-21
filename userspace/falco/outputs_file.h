/*
Copyright (C) 2020 The Falco Authors.

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

#include "outputs.h"
#include <iostream>
#include <fstream>
#include <ctime>

namespace falco
{
namespace outputs
{

class output_file : public abstract_output
{
	output_file();

	void output(const message *msg);

	void cleanup();

	void reopen();

	void logrotate();

private:
	void open_file();

	std::ofstream m_outfile;
	std::queue<string> m_rotating_queue;
	std::time_t m_lastlog;
	const unsigned int m_secs_day = 86400;
};

} // namespace outputs
} // namespace falco
