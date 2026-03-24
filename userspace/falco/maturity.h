// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2026 The Falco Authors.

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

#include <cstdint>
#include <string>

#include "logger.h"

// Feature maturity levels as defined by the adoption and deprecation policy.
// See: proposals/20231220-features-adoption-and-deprecation.md
enum class maturity_level : uint8_t { STABLE, INCUBATING, SANDBOX, DEPRECATED };

inline const char* maturity_level_str(maturity_level level) {
	switch(level) {
	case maturity_level::STABLE:
		return "Stable";
	case maturity_level::INCUBATING:
		return "Incubating";
	case maturity_level::SANDBOX:
		return "Sandbox";
	case maturity_level::DEPRECATED:
		return "Deprecated";
	}
	return "Unknown";
}

// Emit the appropriate log message for a feature's maturity level.
// SANDBOX  -> NOTICE
// DEPRECATED -> WARNING
// Others   -> no-op
inline void log_maturity_notice(const std::string& key, maturity_level level) {
	static const std::string proposal_url =
	        "https://github.com/falcosecurity/falco/blob/master/proposals/"
	        "20231220-features-adoption-and-deprecation.md";

	switch(level) {
	case maturity_level::SANDBOX:
		falco_logger::log(falco_logger::level::NOTICE,
		                  "'" + key +
		                          "' is a sandbox (experimental) feature and may "
		                          "change or be removed without notice. See: " +
		                          proposal_url);
		break;
	case maturity_level::DEPRECATED:
		falco_logger::log(falco_logger::level::WARNING,
		                  "'" + key +
		                          "' is deprecated and will be removed in a future "
		                          "release. See: " +
		                          proposal_url);
		break;
	default:
		break;
	}
}
