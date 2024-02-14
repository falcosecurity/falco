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

#ifndef __EMSCRIPTEN__
TEST(ActionLoadConfig, check_kmod_engine_config)
{
	falco::app::state s = {};
	s.options.conf_filename = TEST_ENGINE_KMOD_CONFIG;
	EXPECT_ACTION_OK(falco::app::actions::load_config(s));

	// Check that the engine is the kmod
	EXPECT_TRUE(s.config->m_engine_mode == engine_kind_t::KMOD);

	// Check that kmod params are the ones specified in the config
	EXPECT_EQ(s.config->m_kmod.m_buf_size_preset, 2);
	EXPECT_FALSE(s.config->m_kmod.m_drop_failed_exit);

	// Check that all other engine params are empty
	EXPECT_TRUE(s.config->m_ebpf.m_probe_path.empty());
	EXPECT_EQ(s.config->m_ebpf.m_buf_size_preset, 0);
	EXPECT_FALSE(s.config->m_ebpf.m_drop_failed_exit);

	EXPECT_EQ(s.config->m_modern_ebpf.m_cpus_for_each_buffer, 0);
	EXPECT_EQ(s.config->m_modern_ebpf.m_buf_size_preset, 0);
	EXPECT_FALSE(s.config->m_modern_ebpf.m_drop_failed_exit);

	EXPECT_TRUE(s.config->m_replay.m_capture_file.empty());

	EXPECT_TRUE(s.config->m_gvisor.m_config.empty());
	EXPECT_TRUE(s.config->m_gvisor.m_root.empty());
}

TEST(ActionLoadConfig, check_modern_engine_config)
{
	falco::app::state s = {};
	s.options.conf_filename = TEST_ENGINE_MODERN_CONFIG;
	EXPECT_ACTION_OK(falco::app::actions::load_config(s));

	// Check that the engine is the modern ebpf
	EXPECT_TRUE(s.config->m_engine_mode == engine_kind_t::MODERN_EBPF);

	// Check that modern ebpf params are the ones specified in the config
	EXPECT_EQ(s.config->m_modern_ebpf.m_cpus_for_each_buffer, 1);
	EXPECT_EQ(s.config->m_modern_ebpf.m_buf_size_preset, 4);
	EXPECT_TRUE(s.config->m_modern_ebpf.m_drop_failed_exit);

	// Check that all other engine params are empty
	EXPECT_EQ(s.config->m_kmod.m_buf_size_preset, 0);
	EXPECT_FALSE(s.config->m_kmod.m_drop_failed_exit);

	EXPECT_TRUE(s.config->m_ebpf.m_probe_path.empty());
	EXPECT_EQ(s.config->m_ebpf.m_buf_size_preset, 0);
	EXPECT_FALSE(s.config->m_ebpf.m_drop_failed_exit);

	EXPECT_TRUE(s.config->m_replay.m_capture_file.empty());

	EXPECT_TRUE(s.config->m_gvisor.m_config.empty());
	EXPECT_TRUE(s.config->m_gvisor.m_root.empty());
}

#endif
