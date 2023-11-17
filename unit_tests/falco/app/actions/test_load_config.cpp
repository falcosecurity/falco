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
#include "falco_test_var.h"

TEST(ActionLoadConfig, check_depracated_falco_038_configs)
{
	auto action = falco::app::actions::load_config;

	// todo!: remove in 0.38.0 since we don't have anymore any precedence
	{
		falco::app::state s;
		s.options.conf_filename = ENGINE_SELECTION_TEST_CONFIG;
		EXPECT_ACTION_OK(action(s));
		EXPECT_EQ(s.config->m_modern_ebpf.m_buf_size_preset, 5);
		EXPECT_TRUE(s.config->m_modern_ebpf.m_drop_failed_exit);
		EXPECT_EQ(s.config->m_modern_ebpf.m_cpus_for_each_syscall_buffer, 3);
	}
}
