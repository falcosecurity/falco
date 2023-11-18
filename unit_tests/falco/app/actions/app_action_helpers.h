// SPDX-License-Identifier: Apache-2.0
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
#include <falco/app/state.h>
#include <falco/app/actions/actions.h>

#define EXPECT_ACTION_OK(r)     { auto result = r; EXPECT_TRUE(result.success); EXPECT_TRUE(result.proceed); EXPECT_EQ(result.errstr, ""); }
#define EXPECT_ACTION_FAIL(r)   { auto result = r; EXPECT_FALSE(result.success); EXPECT_FALSE(result.proceed); EXPECT_NE(result.errstr, ""); }
