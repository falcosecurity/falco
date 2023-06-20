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
#ifdef __linux__
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
#endif
    return true;
}

void falco::app::restart_handler::stop()
{
#ifdef __linux__
    m_stop.store(true, std::memory_order_release);
    if (m_watcher.joinable())
    {
        m_watcher.join();
    }
#endif
}

void falco::app::restart_handler::watcher_loop() noexcept
{
    if (fcntl(m_inotify_fd, F_SETOWN, gettid()) < 0)
    {
        // an error occurred, we can't recover
        // todo(jasondellaluce): should we terminate the process?
        falco_logger::log(LOG_ERR, "Failed owning inotify handler, shutting down watcher...");
        return;
    }

    fd_set set;
    bool forced = false;
    bool should_check = false;
    bool should_restart = false;
    struct timeval timeout;
    uint8_t buf[(10 * (sizeof(struct inotify_event) + NAME_MAX + 1))];
    while (!m_stop.load(std::memory_order_acquire))
    {
        // wait for inotify events with a certain timeout.
        // Note, we'll run through select even before performing a dry-run,
        // so that we can dismiss in case we have to debounce rapid
        // subsequent events.
        timeout.tv_sec = 0;
        timeout.tv_usec = 100000;
        FD_ZERO(&set);
        FD_SET(m_inotify_fd, &set);
        auto rv = select(m_inotify_fd + 1, &set, NULL, NULL, &timeout);
        if (rv < 0)
        {
            // an error occurred, we can't recover
            // todo(jasondellaluce): should we terminate the process?
            falco_logger::log(LOG_ERR, "Failed select with inotify handler, shutting down watcher...");
            return;
        }
        
        // check if there's been a forced restart request
        forced = m_forced.load(std::memory_order_acquire);
        m_forced.store(false, std::memory_order_release);

        // no new watch event is received during the timeout
        if (rv == 0 && !forced)
        {
            // perform a dry run. In case no error occurs, we loop back
            // to the select in order to debounce new inotify events before
            // actually triggering a restart.
            if (should_check)
            {
                should_check = false;
                should_restart = m_on_check();
                continue;
            }

            // if the previous dry run was successful, and no new
            // inotify events have been received during the dry run,
            // then we trigger the restarting signal and quit.
            // note: quitting is a time optimization, the thread
            // will be forced to quit anyways later by the Falco app, but
            // at least we don't make users wait for the timeout.
            if (should_restart)
            {
                should_restart = false;
                // todo(jasondellaluce): make this a callback too maybe?
                g_restart_signal.trigger();
                return;
            }

            // let's go back to the select
            continue;
        }

        // at this point, we either received a new inotify event or a forced
        // restart. If this happened during a dry run (even if the dry run
        // was successful), or during a timeout wait since the last successful
        // dry run before a restart, we dismiss the restart attempt and
        // perform an additional dry-run for safety purposes (the new inotify
        // events may be related to bad config/rules files changes).
        should_restart = false;
        should_check = false;

        // if there's date on the inotify fd, consume it
        // (even if there is a forced request too)
        if (rv > 0)
        {
            // note: if available data is less than buffer size, this should
            // return n > 0 but not filling the buffer. If available data is
            // more than buffer size, we will loop back to select and behave
            // like we debounced an event.
            auto n = read(m_inotify_fd, buf, sizeof(buf));
            if (n < 0)
            {
                // an error occurred, we can't recover
                // todo(jasondellaluce): should we terminate the process?
                falco_logger::log(LOG_ERR, "Failed read with inotify handler, shutting down watcher...");
                return;
            }
            // this is an odd case, but if we got here with
            // no read data, and no forced request, we get back
            // looping in the select. This can likely happen if
            // there's data in the inotify fd but the first read
            // returned no bytes. Likely we'll get back here at the
            // next select call.
            else if (n == 0)
            {
                // we still proceed in case the request was forced
                if (!forced)
                {
                    continue;
                }
            }
        }

        // we consumed the new inotify events or we received a forced
        // restart request, so we'll perform a dry run after the
        // next timeout.
        should_check = true;
    }
}
