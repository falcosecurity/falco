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

#include "actions.h"

using namespace falco::app;
using namespace falco::app::actions;

/* These indexes could change over the Falco releases. */
#define MIN_INDEX 1
#define MAX_INDEX 10
#define DEFAULT_BYTE_SIZE 1 << 23

falco::app::run_result falco::app::actions::configure_syscall_buffer_size(falco::app::state& s)
{
#ifdef __linux__
	/* We don't need to compute the syscall buffer dimension if we are in capture mode or if the
	 * the syscall source is not enabled.
	 */
	if(s.is_capture_mode()
			|| !s.is_source_enabled(falco_common::syscall_source)
			|| s.is_gvisor_enabled()
			|| s.options.nodriver)
	{
		return run_result::ok();
	}

	uint16_t index = s.config->m_syscall_buf_size_preset;
	if(index < MIN_INDEX || index > MAX_INDEX)
	{
		return run_result::fatal("The 'syscall_buf_size_preset' value must be between '" + std::to_string(MIN_INDEX) + "' and '" + std::to_string(MAX_INDEX) + "'\n");
	}

	/* Sizes from `1 MB` to `512 MB`. The index `0` is reserved, users cannot use it! */
	std::vector<uint32_t> vect{0, 1 << 20, 1 << 21, 1 << 22, DEFAULT_BYTE_SIZE, 1 << 24, 1 << 25, 1 << 26, 1 << 27, 1 << 28, 1 << 29};

	uint64_t chosen_size = vect[index];

	/* If the page size is not valid we return here. */
	long page_size = getpagesize();
	if(page_size <= 0)
	{
		s.syscall_buffer_bytes_size = DEFAULT_BYTE_SIZE;
		falco_logger::log(LOG_WARNING, "Unable to get the system page size through 'getpagesize()'. Try to use the default syscall buffer dimension: " + std::to_string(DEFAULT_BYTE_SIZE) + " bytes\n");
		return run_result::ok();
	}

	/* Check if the chosen size is a multiple of the page size. */
	if(chosen_size % page_size != 0)
	{
		return run_result::fatal("The chosen syscall buffer size '" + std::to_string(chosen_size) + "' is not a multiple of your system page size '" + std::to_string(page_size) + "'. Please configure a greater 'syscall_buf_size_preset' value in the Falco configuration file\n");
	}

	/* Check if the chosen size is greater than `2 * page_size`. */
	if((chosen_size / page_size) <= 2)
	{
		return run_result::fatal("The chosen syscall buffer size '" + std::to_string(chosen_size) + "' is not greater than '2 * " + std::to_string(page_size) + "' where '" + std::to_string(page_size) + "' is your system page size. Please configure a greater 'syscall_buf_size_preset' value in the Falco configuration file\n");
	}

	s.syscall_buffer_bytes_size = chosen_size;
	falco_logger::log(LOG_INFO, "The chosen syscall buffer dimension is: " + std::to_string(chosen_size) + " bytes (" +  std::to_string(chosen_size / (uint64_t)(1024 * 1024)) + " MBs)\n");
	
#endif // __linux__
	return run_result::ok();
}
