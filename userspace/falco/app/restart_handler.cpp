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

#include "restart_handler.h"
#include "signals.h"
#include "../logger.h"

#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/inotify.h>
#include <sys/select.h>

#if __GLIBC__ == 2 && __GLIBC_MINOR__ < 30
#include <sys/syscall.h>
#define gettid() syscall(SYS_gettid)
#endif

falco::app::restart_handler::~restart_handler()
{
    close(m_inotify_fd);
    stop();
}

void falco::app::restart_handler::trigger()
{
    m_forced.store(true, std::memory_order_release);
}

bool falco::app::restart_handler::start(std::string& err)
{
    m_inotify_fd = inotify_init();
    if (m_inotify_fd < 0)
    {
        err = "could not initialize inotify handler";
        return false;
    }

    for (const auto& f : m_watched_files)
    {
        auto wd = inotify_add_watch(m_inotify_fd, f.c_str(), IN_CLOSE_WRITE);
        if (wd < 0)
        {
            err = "could not watch file: " + f;
            return false;
        }
        falco_logger::log(LOG_DEBUG, "Watching file '" + f +"'\n");
    }

    for (const auto &f : m_watched_dirs)
    {
        auto wd = inotify_add_watch(m_inotify_fd, f.c_str(), IN_CREATE | IN_DELETE);
        if (wd < 0)
        {
            err = "could not watch directory: " + f;
            return false;
        }
        falco_logger::log(LOG_DEBUG, "Watching directory '" + f +"'\n");
    }

    // launch the watcher thread
    m_watcher = std::thread(&falco::app::restart_handler::watcher_loop, this);
    return true;
}

void falco::app::restart_handler::stop()
{
    m_stop.store(true, std::memory_order_release);
    if (m_watcher.joinable())
    {
        m_watcher.join();
    }
}

void falco::app::restart_handler::watcher_loop() noexcept
{
    if (fcntl(m_inotify_fd, F_SETOWN, gettid()) < 0)
    {
        falco_logger::log(LOG_ERR, "Failed setting owner on inotify handler");
        return;
    }

    fd_set set;
    bool forced = false;
    bool should_restart = false;
    struct timeval timeout;
    uint8_t buf[(10 * (sizeof(struct inotify_event) + NAME_MAX + 1))];
    while (!m_stop.load(std::memory_order_acquire))
    {
        // wait for inotify events with a certain timeout
        timeout.tv_sec = 0;
        timeout.tv_usec = 100000;
        FD_ZERO(&set);
        FD_SET(m_inotify_fd, &set);
        auto rv = select(m_inotify_fd + 1, &set, NULL, NULL, &timeout);
        if (rv < 0)
        {
            falco_logger::log(LOG_ERR, "Failed select in inotify watcher");
            return;
        }
        
        // check if there's been a forced restart request
        forced = m_forced.load(std::memory_order_acquire);
        m_forced.store(false, std::memory_order_release);

        if (rv > 0 || forced)
        {
            // if new inotify events have been received during the previous
            // dry run, even if the dry run was successful, we dismiss
            // the restart attempt and perform an additional dry-run for
            // safety purpose (the new inotify events may be related to
            // bad config/rules files changes).
            should_restart = false;

            // if there's date on the inotify fd, consume it
            if (rv > 0)
            {
                auto n = read(m_inotify_fd, buf, sizeof(buf));
                if (n == 0)
                {
                    continue;
                }
                if (n < 0)
                {
                    falco_logger::log(LOG_ERR, "Failed read in inotify watcher");
                    return;
                }
            }

            // perform a check run check and attempt restarting
            if (m_on_check())
            {
                should_restart = true;
            }
        }

        // if the previous dry run was successful, and no new
        // inotify events have been received during the dry run,
        // then we trigger the restarting signal and quit
        if (should_restart)
        {
            // todo(jasondellaluce): make this a callback too maybe?
            g_restart_signal.trigger();
            return;
        }
    }
}
