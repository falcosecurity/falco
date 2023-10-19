// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2023 The Falco Authors

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

#include "outputs_stdout.h"
#include <iostream>

void falco::outputs::output_stdout::output(const message *msg)
{
	//
	// By default, the stdout stream is fully buffered or line buffered
	// (if the stream can be determined to refer to an interactive device, e.g. in a TTY).
	// Just enable automatic flushing when unbuffered output is desired.
	// Note that it is set every time since other writings to the stdout can disable it.
	//
	if(!m_buffered)
	{
		std::cout << std::unitbuf;
	}
	std::cout << msg->msg + "\n";
}

void falco::outputs::output_stdout::cleanup()
{
	std::cout.flush();
}
