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

#include "actions.h"
#include "helpers.h"

using namespace falco::app;
using namespace falco::app::actions;

falco::app::run_result falco::app::actions::close_inspectors(falco::app::state& s) {
	falco_logger::log(falco_logger::level::DEBUG, "closing inspectors");

	if(s.offline_inspector != nullptr) {
		s.offline_inspector->close();
	}

	for(const auto& src : s.loaded_sources) {
		auto src_info = s.source_infos.at(src);

		if(src_info->inspector != nullptr) {
			src_info->inspector->close();
		}
	}

	return run_result::ok();
}
