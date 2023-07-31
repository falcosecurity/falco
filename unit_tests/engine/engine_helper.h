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

#pragma once
#include <gtest/gtest.h>

// When updating unit_tests/falco_rules_test.yaml bump this
#define N_TEST_RULES_FALCO_RULES_TEST_YAML 3

#define ASSERT_CONTAINS(a, b)            \
    {                                    \
        auto a1 = a;                     \
        auto b1 = b;                     \
        uint32_t prev_size = a1.size();  \
        for(const auto& val : b1)        \
        {                                \
            a1.insert(val);              \
        }                                \
        ASSERT_EQ(prev_size, a1.size()); \
    }

#define ASSERT_STRING_EQUAL(a, b)        \
    {                                    \
        auto a1 = a;                     \
        auto b1 = b;                     \
        ASSERT_EQ(a1.compare(b1), 0);    \
    }
