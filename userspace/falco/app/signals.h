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

#include "../atomic_signal_handler.h"
#include <string>

namespace falco {
namespace app {

extern atomic_signal_handler g_terminate_signal;
extern atomic_signal_handler g_restart_signal;
extern atomic_signal_handler g_reopen_outputs_signal;

// Install once, at the first live run's signal setup, before starting its worker.
// SIGHUP reception and its descriptor survive every hot restart.
bool initialize_restart_signal_handler(std::string& err);
int restart_signal_fd();
// Record and wake a reload request without delivering an OS signal. Signal-safe
// after initialization; false means the notification could not be delivered.
bool request_reload() noexcept;

};  // namespace app
};  // namespace falco
