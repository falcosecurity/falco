#pragma once
#include <gtest/gtest.h>
#include <falco/app/state.h>
#include <falco/app/actions/actions.h>

#define EXPECT_ACTION_OK(r)     { EXPECT_TRUE(r.success); EXPECT_TRUE(r.proceed); EXPECT_EQ(r.errstr, ""); }
#define EXPECT_ACTION_FAIL(r)   { EXPECT_FALSE(r.success); EXPECT_FALSE(r.proceed); EXPECT_NE(r.errstr, ""); }
