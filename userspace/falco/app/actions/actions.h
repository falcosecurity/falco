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

#include "../state.h"
#include "../run_result.h"

namespace falco {
namespace app {
namespace actions {

falco::app::run_result configure_interesting_sets(falco::app::state& s);
falco::app::run_result configure_syscall_buffer_size(falco::app::state& s);
falco::app::run_result configure_syscall_buffer_num(const falco::app::state& s);
falco::app::run_result create_requested_paths(falco::app::state& s);
falco::app::run_result create_signal_handlers(falco::app::state& s);
falco::app::run_result pidfile(const falco::app::state& s);
falco::app::run_result init_falco_engine(falco::app::state& s);
falco::app::run_result init_inspectors(falco::app::state& s);
falco::app::run_result init_outputs(falco::app::state& s);
falco::app::run_result list_fields(falco::app::state& s);
falco::app::run_result list_plugins(const falco::app::state& s);
falco::app::run_result load_config(const falco::app::state& s);
falco::app::run_result load_plugins(falco::app::state& s);
falco::app::run_result load_rules_files(falco::app::state& s);
falco::app::run_result print_config_schema(falco::app::state& s);
falco::app::run_result print_generated_gvisor_config(falco::app::state& s);
falco::app::run_result print_help(falco::app::state& s);
falco::app::run_result print_ignored_events(const falco::app::state& s);
falco::app::run_result print_kernel_version(const falco::app::state& s);
falco::app::run_result print_page_size(const falco::app::state& s);
falco::app::run_result print_plugin_info(const falco::app::state& s);
falco::app::run_result print_rule_schema(falco::app::state& s);
falco::app::run_result print_support(falco::app::state& s);
falco::app::run_result print_syscall_events(falco::app::state& s);
falco::app::run_result print_version(falco::app::state& s);
falco::app::run_result process_events(falco::app::state& s);
falco::app::run_result require_config_file(const falco::app::state& s);
falco::app::run_result select_event_sources(falco::app::state& s);
falco::app::run_result start_grpc_server(falco::app::state& s);
falco::app::run_result start_webserver(falco::app::state& s);
falco::app::run_result stop_grpc_server(falco::app::state& s);
falco::app::run_result stop_webserver(falco::app::state& s);
falco::app::run_result unregister_signal_handlers(falco::app::state& s);
falco::app::run_result validate_rules_files(falco::app::state& s);
falco::app::run_result close_inspectors(falco::app::state& s);

}; // namespace actions
}; // namespace app
}; // namespace falco
