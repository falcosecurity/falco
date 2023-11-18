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

auto action = falco::app::actions::load_config;

TEST(ActionLoadConfig, check_engine_config_is_correctly_parsed)
{
	falco::app::state s = {};
	s.options.conf_filename = NEW_ENGINE_CONFIG_CHANGED;
	// TODO: understand why load_yaml is called more times
	EXPECT_ACTION_OK(action(s));

	// Check that the engine is the kmod
	EXPECT_TRUE(s.config->m_engine_mode == engine_kind_t::KMOD);

	// Check that kmod params are the ones specified in the config
	EXPECT_EQ(s.config->m_kmod.m_buf_size_preset, 2);
	EXPECT_FALSE(s.config->m_kmod.m_drop_failed_exit);

	// Check that all other engine params are empty
	EXPECT_TRUE(s.config->m_ebpf.m_probe_path.empty());
	EXPECT_EQ(s.config->m_ebpf.m_buf_size_preset, 0);
	EXPECT_FALSE(s.config->m_ebpf.m_drop_failed_exit);

	EXPECT_EQ(s.config->m_modern_ebpf.m_cpus_for_each_syscall_buffer, 0);
	EXPECT_EQ(s.config->m_modern_ebpf.m_buf_size_preset, 0);
	EXPECT_FALSE(s.config->m_modern_ebpf.m_drop_failed_exit);

	EXPECT_TRUE(s.config->m_replay.m_trace_file.empty());

	EXPECT_TRUE(s.config->m_gvisor.m_config.empty());
	EXPECT_TRUE(s.config->m_gvisor.m_root.empty());

	// Check that deprecated configs are not populated since we are using
	// the new config.
	EXPECT_EQ(s.config->m_syscall_buf_size_preset, 0);
	EXPECT_EQ(s.config->m_cpus_for_each_syscall_buffer, 0);
	EXPECT_FALSE(s.config->m_syscall_drop_failed_exit);
}

// Equal to the one above but checks that the command line options are not parsed
TEST(ActionLoadConfig, check_command_line_options_are_not_used)
{
	falco::app::state s;
	s.options.modern_bpf = true;
	s.options.conf_filename = NEW_ENGINE_CONFIG_CHANGED;
	EXPECT_ACTION_OK(action(s));

	// Check that the engine is the kmod
	EXPECT_TRUE(s.config->m_engine_mode == engine_kind_t::KMOD);

	// Check that kmod params are the ones specified in the config
	EXPECT_EQ(s.config->m_kmod.m_buf_size_preset, 2);
	EXPECT_FALSE(s.config->m_kmod.m_drop_failed_exit);

	// Check that all other engine params are empty
	EXPECT_TRUE(s.config->m_ebpf.m_probe_path.empty());
	EXPECT_EQ(s.config->m_ebpf.m_buf_size_preset, 0);
	EXPECT_FALSE(s.config->m_ebpf.m_drop_failed_exit);

	EXPECT_EQ(s.config->m_modern_ebpf.m_cpus_for_each_syscall_buffer, 0);
	EXPECT_EQ(s.config->m_modern_ebpf.m_buf_size_preset, 0);
	EXPECT_FALSE(s.config->m_modern_ebpf.m_drop_failed_exit);

	EXPECT_TRUE(s.config->m_replay.m_trace_file.empty());

	EXPECT_TRUE(s.config->m_gvisor.m_config.empty());
	EXPECT_TRUE(s.config->m_gvisor.m_root.empty());

	// Check that deprecated configs are not populated since we are using
	// the new config.
	EXPECT_EQ(s.config->m_syscall_buf_size_preset, 0);
	EXPECT_EQ(s.config->m_cpus_for_each_syscall_buffer, 0);
	EXPECT_FALSE(s.config->m_syscall_drop_failed_exit);
}

TEST(ActionLoadConfig, check_kmod_with_syscall_configs)
{
	falco::app::state s;
	s.options.conf_filename = NEW_ENGINE_CONFIG_UNCHANGED;
	EXPECT_ACTION_OK(action(s));

	// Check that the engine is the kmod
	EXPECT_TRUE(s.config->m_engine_mode == engine_kind_t::KMOD);

	// Kmod params should be populated with the syscall configs
	// since the `engine` block is untouched.
	EXPECT_EQ(s.config->m_kmod.m_buf_size_preset, 6);
	EXPECT_TRUE(s.config->m_kmod.m_drop_failed_exit);

	// Check that all other engine params are empty
	EXPECT_TRUE(s.config->m_ebpf.m_probe_path.empty());
	EXPECT_EQ(s.config->m_ebpf.m_buf_size_preset, 0);
	EXPECT_FALSE(s.config->m_ebpf.m_drop_failed_exit);

	EXPECT_EQ(s.config->m_modern_ebpf.m_cpus_for_each_syscall_buffer, 0);
	EXPECT_EQ(s.config->m_modern_ebpf.m_buf_size_preset, 0);
	EXPECT_FALSE(s.config->m_modern_ebpf.m_drop_failed_exit);

	EXPECT_TRUE(s.config->m_replay.m_trace_file.empty());

	EXPECT_TRUE(s.config->m_gvisor.m_config.empty());
	EXPECT_TRUE(s.config->m_gvisor.m_root.empty());

	// Check that deprecated configs are populated
	EXPECT_EQ(s.config->m_syscall_buf_size_preset, 6);
	EXPECT_EQ(s.config->m_cpus_for_each_syscall_buffer, 3);
	EXPECT_TRUE(s.config->m_syscall_drop_failed_exit);
}

TEST(ActionLoadConfig, check_override_command_line_modern)
{
	falco::app::state s;
	// The comman line options should be correctly applied since the
	// config is unchanged
	s.options.modern_bpf = true;
	s.options.conf_filename = NEW_ENGINE_CONFIG_UNCHANGED;
	EXPECT_ACTION_OK(action(s));

	// Check that the engine is the kmod
	EXPECT_TRUE(s.is_modern_ebpf());

	// Check that the modern ebpf engine uses the default syscall configs
	// and not the ones in the `engine` block
	EXPECT_EQ(s.config->m_modern_ebpf.m_cpus_for_each_syscall_buffer, 3);
	EXPECT_EQ(s.config->m_modern_ebpf.m_buf_size_preset, 6);
	EXPECT_TRUE(s.config->m_modern_ebpf.m_drop_failed_exit);

	// Kmod params should be always populated since the kmod is the default
	EXPECT_EQ(s.config->m_kmod.m_buf_size_preset, 6);
	EXPECT_TRUE(s.config->m_kmod.m_drop_failed_exit);

	// Check that all other engine params are empty
	EXPECT_TRUE(s.config->m_ebpf.m_probe_path.empty());
	EXPECT_EQ(s.config->m_ebpf.m_buf_size_preset, 0);
	EXPECT_FALSE(s.config->m_ebpf.m_drop_failed_exit);

	EXPECT_TRUE(s.config->m_replay.m_trace_file.empty());

	EXPECT_TRUE(s.config->m_gvisor.m_config.empty());
	EXPECT_TRUE(s.config->m_gvisor.m_root.empty());

	// Check that deprecated configs are populated
	EXPECT_EQ(s.config->m_syscall_buf_size_preset, 6);
	EXPECT_EQ(s.config->m_cpus_for_each_syscall_buffer, 3);
	EXPECT_TRUE(s.config->m_syscall_drop_failed_exit);
}

TEST(ActionLoadConfig, check_override_command_line_gvisor)
{
	falco::app::state s;
	// The comman line options should be correctly applied since the
	// config is unchanged
	s.options.gvisor_config = "config";
	s.options.conf_filename = NEW_ENGINE_CONFIG_UNCHANGED;
	EXPECT_ACTION_OK(action(s));

	// Check that the engine is the kmod
	EXPECT_TRUE(s.is_gvisor());
	EXPECT_EQ(s.config->m_gvisor.m_config, "config");
	EXPECT_TRUE(s.config->m_gvisor.m_root.empty());

	// Kmod params should be always populated since the kmod is the default
	EXPECT_EQ(s.config->m_kmod.m_buf_size_preset, 6);
	EXPECT_TRUE(s.config->m_kmod.m_drop_failed_exit);

	// Check that all other engine params are empty
	EXPECT_TRUE(s.config->m_ebpf.m_probe_path.empty());
	EXPECT_EQ(s.config->m_ebpf.m_buf_size_preset, 0);
	EXPECT_FALSE(s.config->m_ebpf.m_drop_failed_exit);

	EXPECT_EQ(s.config->m_modern_ebpf.m_cpus_for_each_syscall_buffer, 0);
	EXPECT_EQ(s.config->m_modern_ebpf.m_buf_size_preset, 0);
	EXPECT_FALSE(s.config->m_modern_ebpf.m_drop_failed_exit);

	EXPECT_TRUE(s.config->m_replay.m_trace_file.empty());

	// Check that deprecated configs are populated
	EXPECT_EQ(s.config->m_syscall_buf_size_preset, 6);
	EXPECT_EQ(s.config->m_cpus_for_each_syscall_buffer, 3);
	EXPECT_TRUE(s.config->m_syscall_drop_failed_exit);
}
