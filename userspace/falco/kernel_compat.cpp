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

#include "kernel_compat.h"
#include <sstream>
#include <regex>

namespace falco {
namespace kernel_compat {

std::tuple<int, int, int> parse_kernel_version(const std::string& version_str) {
	std::regex version_regex(R"((\d+)\.(\d+)\.(\d+))");
	std::smatch match;
	
	if (std::regex_search(version_str, match, version_regex) && match.size() > 3) {
		return std::make_tuple(
			std::stoi(match[1].str()),
			std::stoi(match[2].str()),
			std::stoi(match[3].str())
		);
	}
	return std::make_tuple(0, 0, 0);
}

bool is_modern_ebpf_compatible(int major, int minor, int patch) {
	// Kernel 6.18+ requires special handling due to syscall table and BPF changes
	// For now, we consider 6.18+ as potentially incompatible until libs are updated
	if (major == 6 && minor >= 18) {
		return false;
	}
	// Modern eBPF requires at least kernel 5.8
	if (major < 5 || (major == 5 && minor < 8)) {
		return false;
	}
	return true;
}

std::string get_compatibility_message(int major, int minor, int patch) {
	std::ostringstream msg;
	msg << "Kernel version " << major << "." << minor << "." << patch;
	
	if (major == 6 && minor >= 18) {
		msg << " detected. This kernel version has known compatibility issues with the current "
		    << "modern eBPF driver. Please use kernel module driver or wait for libs update. "
		    << "See: https://github.com/falcosecurity/falco/issues/3813";
	} else if (major < 5 || (major == 5 && minor < 8)) {
		msg << " is too old for modern eBPF (requires >= 5.8)";
	} else {
		msg << " is compatible with modern eBPF";
	}
	
	return msg.str();
}

}  
}  
