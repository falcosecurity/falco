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

#include <atomic>
#include <functional>

#define APP_SIGNAL_NOT_SET          0   // The signal flag is not set
#define APP_SIGNAL_SET              1   // The signal flag has been set
#define APP_SIGNAL_ACTION_TAKEN     2   // The signal flag has been set and the application took action

namespace falco {
namespace app {

// todo(jasondellaluce): hide this into a class
extern std::atomic<int> g_terminate;
extern std::atomic<int> g_restart;
extern std::atomic<int> g_reopen_outputs;

void terminate(bool verbose=true);

void restart(bool verbose=true);

void reopen_outputs(std::function<void()> on_reopen, bool verbose=true);

inline bool should_terminate()
{
    return g_terminate.load(std::memory_order_seq_cst) != APP_SIGNAL_NOT_SET;
}

inline bool should_restart()
{
    return g_restart.load(std::memory_order_seq_cst) != APP_SIGNAL_NOT_SET;
}

inline bool should_reopen_outputs()
{
    return g_reopen_outputs.load(std::memory_order_seq_cst) != APP_SIGNAL_NOT_SET;
}

}; // namespace app
}; // namespace falco
