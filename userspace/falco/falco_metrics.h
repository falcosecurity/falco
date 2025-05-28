// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2024 The Falco Authors.

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

#include "configuration.h"

#include <libsinsp/sinsp.h>

namespace falco::app {
struct state;
}

class falco_metrics {
public:
	static const std::string content_type_prometheus;
	static std::string to_text_prometheus(const falco::app::state& state);

private:
	static std::string falco_to_text_prometheus(
	        const falco::app::state& state,
	        libs::metrics::prometheus_metrics_converter& prometheus_metrics_converter,
	        std::vector<metrics_v2>& additional_wrapper_metrics);
	static std::string sources_to_text_prometheus(
	        const falco::app::state& state,
	        libs::metrics::prometheus_metrics_converter& prometheus_metrics_converter,
	        std::vector<metrics_v2>& additional_wrapper_metrics);
};
