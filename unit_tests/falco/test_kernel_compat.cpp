// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2025 The Falco Authors.
*/

#include <gtest/gtest.h>
#include "../../userspace/falco/kernel_compat.h"

using namespace falco::kernel_compat;

TEST(KernelCompatTest, ParseKernelVersion) {
    auto [major, minor, patch] = parse_kernel_version("6.18.7-0-lts");
    EXPECT_EQ(major, 6);
    EXPECT_EQ(minor, 18);
    EXPECT_EQ(patch, 7);
}

TEST(KernelCompatTest, ParseKernelVersionSimple) {
    auto [major, minor, patch] = parse_kernel_version("5.15.0");
    EXPECT_EQ(major, 5);
    EXPECT_EQ(minor, 15);
    EXPECT_EQ(patch, 0);
}

TEST(KernelCompatTest, ParseKernelVersionInvalid) {
    auto [major, minor, patch] = parse_kernel_version("invalid");
    EXPECT_EQ(major, 0);
    EXPECT_EQ(minor, 0);
    EXPECT_EQ(patch, 0);
}

TEST(KernelCompatTest, Kernel618Incompatible) {
    EXPECT_FALSE(is_modern_ebpf_compatible(6, 18, 7));
}

TEST(KernelCompatTest, Kernel619Incompatible) {
    EXPECT_FALSE(is_modern_ebpf_compatible(6, 19, 0));
}

TEST(KernelCompatTest, Kernel65Compatible) {
    EXPECT_TRUE(is_modern_ebpf_compatible(6, 5, 0));
}

TEST(KernelCompatTest, Kernel515Compatible) {
    EXPECT_TRUE(is_modern_ebpf_compatible(5, 15, 0));
}

TEST(KernelCompatTest, Kernel58Compatible) {
    EXPECT_TRUE(is_modern_ebpf_compatible(5, 8, 0));
}

TEST(KernelCompatTest, Kernel57Incompatible) {
    EXPECT_FALSE(is_modern_ebpf_compatible(5, 7, 0));
}

TEST(KernelCompatTest, Kernel4Incompatible) {
    EXPECT_FALSE(is_modern_ebpf_compatible(4, 19, 0));
}

TEST(KernelCompatTest, CompatibilityMessage618) {
    std::string msg = get_compatibility_message(6, 18, 7);
    EXPECT_NE(msg.find("6.18.7"), std::string::npos);
    EXPECT_NE(msg.find("compatibility issues"), std::string::npos);
}

TEST(KernelCompatTest, CompatibilityMessage515) {
    std::string msg = get_compatibility_message(5, 15, 0);
    EXPECT_NE(msg.find("compatible"), std::string::npos);
}
