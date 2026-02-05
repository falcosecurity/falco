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

#include "actions.h"
#include "falco_utils.h"
#include <sys/stat.h>
#include <filesystem>

using namespace falco::app;
using namespace falco::app::actions;

static int create_dir(const std::string &path);

falco::app::run_result falco::app::actions::create_requested_paths(falco::app::state &s) {
	if(s.config->m_grpc_enabled && !s.config->m_grpc_bind_address.empty()) {
		if(falco::utils::network::is_unix_scheme(s.config->m_grpc_bind_address)) {
			auto server_path = s.config->m_grpc_bind_address.substr(
			        falco::utils::network::UNIX_SCHEME.length());
			int ret = create_dir(server_path);
			if(ret != 0) {
				return run_result::fatal(server_path + ": " + strerror(errno));
			}
		}
	}

	// TODO: eventually other files written by Falco whose destination is
	// customizable by users, must be handled here.
	return run_result::ok();
}

// This function operates like `mkdir -p` excluding the last part of
// the path which we assume to be the filename.
static int create_dir(const std::string &path) {
	std::filesystem::path dirPath(path);

	try {
		std::filesystem::create_directories(dirPath.parent_path());
	} catch(const std::exception &ex) {
		return -1;
	}

	return 0;
}
