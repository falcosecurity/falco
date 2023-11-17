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

TEST(ActionSelectEventSources, pre_post_conditions)
{
    auto action = falco::app::actions::select_event_sources;

    // requires sources to be already loaded
    {
        falco::app::state s;
        EXPECT_ACTION_FAIL(action(s));
    }

    // ignore source selection in capture mode
    {
        falco::app::state s;
        s.config->m_engine_mode = engine_kind_t::REPLAY;
        EXPECT_TRUE(s.is_capture_mode());
        EXPECT_ACTION_OK(action(s));
    }

    // enable all loaded sources by default, even with multiple calls
    {
        falco::app::state s;
        s.loaded_sources = {"syscall", "some_source"};
        EXPECT_ACTION_OK(action(s));
        EXPECT_EQ(s.loaded_sources.size(), s.enabled_sources.size());
        for (const auto& v : s.loaded_sources)
        {
            ASSERT_TRUE(s.enabled_sources.find(v) != s.enabled_sources.end());
        }
        s.loaded_sources.push_back("another_source");
        EXPECT_ACTION_OK(action(s));
        EXPECT_EQ(s.loaded_sources.size(), s.enabled_sources.size());
        for (const auto& v : s.loaded_sources)
        {
            ASSERT_TRUE(s.enabled_sources.find(v) != s.enabled_sources.end());
        }
    }

    // enable only selected sources
    {
        falco::app::state s;
        s.loaded_sources = {"syscall", "some_source"};
        s.options.enable_sources = {"syscall"};
        EXPECT_ACTION_OK(action(s));
        EXPECT_EQ(s.enabled_sources.size(), 1);
        EXPECT_EQ(*s.enabled_sources.begin(), "syscall");
    }

    // enable all loaded sources expect the disabled ones
    {
        falco::app::state s;
        s.loaded_sources = {"syscall", "some_source"};
        s.options.disable_sources = {"syscall"};
        EXPECT_ACTION_OK(action(s));
        EXPECT_EQ(s.enabled_sources.size(), 1);
        EXPECT_EQ(*s.enabled_sources.begin(), "some_source");
    }

    // enable unknown sources
    {
        falco::app::state s;
        s.loaded_sources = {"syscall", "some_source"};
        s.options.enable_sources = {"some_other_source"};
        EXPECT_ACTION_FAIL(action(s));
    }

    // disable unknown sources
    {
        falco::app::state s;
        s.loaded_sources = {"syscall", "some_source"};
        s.options.disable_sources = {"some_other_source"};
        EXPECT_ACTION_FAIL(action(s));
    }

    // mix enable and disable sources options
    {
        falco::app::state s;
        s.loaded_sources = {"syscall", "some_source"};
        s.options.disable_sources = {"syscall"};
        s.options.enable_sources = {"syscall"};
        EXPECT_ACTION_FAIL(action(s));
    }
}
