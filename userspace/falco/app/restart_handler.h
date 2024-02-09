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

#include <thread>
#include <atomic>
#include <vector>
#include <string>
#include <functional>

namespace falco
{
namespace app
{

/**
 * @brief A thread-safe helper for handling hot-reload application restarts.
 */
class restart_handler
{
public:
    /**
     * @brief A function that performs safety checks before confirming
     * a triggered application restart. Returns true if the application
     * can safely be restarted.
     */
    using on_check_t = std::function<bool()>;

    /**
     * @brief A list of files or directories paths to watch.
     */
    using watch_list_t = std::vector<std::string>;

    explicit restart_handler(
        on_check_t on_check,
        const watch_list_t& watch_files = {},
        const watch_list_t& watch_dirs = {})
            : m_inotify_fd(-1),
              m_stop(false),
              m_forced(false),
              m_on_check(on_check),
              m_watched_dirs(watch_dirs),
              m_watched_files(watch_files) { }
    virtual ~restart_handler();

    bool start(std::string& err);
    void stop();
    void trigger();

private:
    void watcher_loop() noexcept;

    int m_inotify_fd;
    std::thread m_watcher;
    std::atomic<bool> m_stop;
    std::atomic<bool> m_forced;
    on_check_t m_on_check;
    watch_list_t m_watched_dirs;
    watch_list_t m_watched_files;
};

}; // namespace app
}; // namespace falco
