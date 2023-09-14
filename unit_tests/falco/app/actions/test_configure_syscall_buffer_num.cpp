// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2023 The Falco Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless ASSERTd by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include "app_action_helpers.h"

TEST(ActionConfigureSyscallBufferNum, variable_number_of_CPUs)
{
	auto action = falco::app::actions::configure_syscall_buffer_num;

	ssize_t online_cpus = sysconf(_SC_NPROCESSORS_ONLN);
	if(online_cpus <= 0)
	{
		FAIL() << "cannot get the number of online CPUs from the system\n";
	}

	// not modern bpf engine, we do nothing
	{
		falco::app::state s;
		s.options.modern_bpf = false;
		EXPECT_ACTION_OK(action(s));
	}

	// modern bpf engine, with an invalid number of CPUs
	// default `m_cpus_for_each_syscall_buffer` to online CPU number
	{
		falco::app::state s;
		s.options.modern_bpf = true;
		s.config->m_cpus_for_each_syscall_buffer = online_cpus + 1;
		EXPECT_ACTION_OK(action(s));
		EXPECT_EQ(s.config->m_cpus_for_each_syscall_buffer, online_cpus);
	}

	// modern bpf engine, with an valid number of CPUs
	// we don't modify `m_cpus_for_each_syscall_buffer`
	{
		falco::app::state s;
		s.options.modern_bpf = true;
		s.config->m_cpus_for_each_syscall_buffer = online_cpus - 1;
		EXPECT_ACTION_OK(action(s));
		EXPECT_EQ(s.config->m_cpus_for_each_syscall_buffer, online_cpus - 1);
	}
}
