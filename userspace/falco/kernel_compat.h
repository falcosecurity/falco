// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2025 The Falco Authors.

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

#include <string>
#include <tuple>

namespace falco {
namespace kernel_compat {

// Parse kernel version string (e.g., "6.18.7-0-lts") into major, minor, patch
std::tuple<int, int, int> parse_kernel_version(const std::string& version_str);

// Check if kernel version is compatible with modern eBPF
bool is_modern_ebpf_compatible(int major, int minor, int patch);

// Get detailed compatibility message for logging
std::string get_compatibility_message(int major, int minor, int patch);

}  // namespace kernel_compat
}  // namespace falco
