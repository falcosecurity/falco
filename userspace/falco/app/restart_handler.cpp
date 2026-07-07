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

#include "restart_handler.h"
#include "signals.h"
#include "logger.h"

#include <string.h>
#include <errno.h>
#include <fcntl.h>
#ifdef _WIN32
#include <io.h>
#else
#include <unistd.h>
#endif
#ifdef __linux__
#include <sys/inotify.h>
#include <sys/select.h>
#include <sys/eventfd.h>
#endif

#if __GLIBC__ == 2 && __GLIBC_MINOR__ < 30
#include <sys/syscall.h>
#define gettid() syscall(SYS_gettid)
#endif

falco::app::restart_handler::~restart_handler() {
	stop();
	close_fds();
}

void falco::app::restart_handler::close_fds() {
	if(m_inotify_fd != -1) {
		close(m_inotify_fd);
		m_inotify_fd = -1;
	}
	if(m_event_fd != -1) {
		close(m_event_fd);
		m_event_fd = -1;
	}
}

void falco::app::restart_handler::trigger() {
	m_forced.store(true, std::memory_order_release);
#ifdef __linux__
	// eventfd write is async-signal-safe, so this is safe from the SIGHUP handler
	if(m_event_fd != -1) {
		uint64_t v = 1;
		auto ret = write(m_event_fd, &v, sizeof(v));
		(void)ret;
	}
#endif
}

bool falco::app::restart_handler::start(std::string& err) {
#ifdef __linux__
	// Create the inotify handler only when there is something to watch, so we don't consume an
	// inotify instance; the watcher thread is always started, as it also serves forced restart
	// requests (e.g. SIGHUP).
	if(!m_watched_files.empty() || !m_watched_dirs.empty()) {
		m_inotify_fd = inotify_init();
		if(m_inotify_fd < 0) {
			err = "could not initialize inotify handler";
			close_fds();
			return false;
		}

		for(const auto& f : m_watched_files) {
			auto wd = inotify_add_watch(m_inotify_fd,
			                            f.c_str(),
			                            IN_CLOSE_WRITE | IN_MOVE_SELF | IN_DELETE_SELF);
			if(wd < 0) {
				err = "could not watch file: " + f;
				close_fds();
				return false;
			}
			falco_logger::log(falco_logger::level::DEBUG, "Watching file '" + f + "'\n");
		}

		for(const auto& f : m_watched_dirs) {
			auto wd = inotify_add_watch(m_inotify_fd, f.c_str(), IN_CREATE | IN_DELETE | IN_MOVE);
			if(wd < 0) {
				err = "could not watch directory: " + f;
				close_fds();
				return false;
			}
			falco_logger::log(falco_logger::level::DEBUG, "Watching directory '" + f + "'\n");
		}
	} else {
		falco_logger::log(
		        falco_logger::level::DEBUG,
		        "Nothing to watch, restart handler will only serve forced restart requests\n");
	}

	m_event_fd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
	if(m_event_fd < 0) {
		err = "could not initialize eventfd handler";
		close_fds();
		return false;
	}

	// launch the watcher thread
	m_watcher = std::thread(&falco::app::restart_handler::watcher_loop, this);
#endif
	return true;
}

void falco::app::restart_handler::stop() {
#ifdef __linux__
	m_stop.store(true, std::memory_order_release);
	// wake the watcher in case it is blocked in select() without a timeout
	if(m_event_fd != -1) {
		uint64_t v = 1;
		auto ret = write(m_event_fd, &v, sizeof(v));
		(void)ret;
	}
	if(m_watcher.joinable()) {
		m_watcher.join();
	}
#endif
}

void falco::app::restart_handler::watcher_loop() noexcept {
#ifdef __linux__
	if(m_inotify_fd >= 0 && fcntl(m_inotify_fd, F_SETOWN, gettid()) < 0) {
		// an error occurred, we can't recover
		// todo(jasondellaluce): should we terminate the process?
		falco_logger::log(falco_logger::level::ERR,
		                  "Failed owning inotify handler, shutting down watcher...");
		return;
	}

	fd_set set;
	bool should_check = false;
	bool should_restart = false;
	struct timeval timeout;
	uint8_t buf[(10 * (sizeof(struct inotify_event) + NAME_MAX + 1))];
	int nfds = (m_inotify_fd > m_event_fd ? m_inotify_fd : m_event_fd) + 1;
	while(!m_stop.load(std::memory_order_acquire)) {
		FD_ZERO(&set);
		if(m_inotify_fd >= 0) {
			FD_SET(m_inotify_fd, &set);
		}
		FD_SET(m_event_fd, &set);

		struct timeval* to = NULL;
		if(should_check || should_restart) {
			timeout.tv_sec = 0;
			timeout.tv_usec = 100000;
			to = &timeout;
		}
		auto rv = select(nfds, &set, NULL, NULL, to);
		if(rv < 0) {
			if(errno == EINTR) {
				continue;
			}
			// an error occurred, we can't recover
			// todo(jasondellaluce): should we terminate the process?
			falco_logger::log(falco_logger::level::ERR,
			                  "Failed select with inotify handler, shutting down watcher...");
			return;
		}

		if(rv > 0 && FD_ISSET(m_event_fd, &set)) {
			uint64_t v = 0;
			auto n = read(m_event_fd, &v, sizeof(v));
			(void)n;
		}

		bool forced = m_forced.exchange(false, std::memory_order_acq_rel);
		bool inotify_ready = m_inotify_fd >= 0 && rv > 0 && FD_ISSET(m_inotify_fd, &set);

		// no new watch event is received during the timeout
		if(rv == 0 && !forced) {
			// perform a dry run. In case no error occurs, we loop back
			// to the select in order to debounce new inotify events before
			// actually triggering a restart.
			if(should_check) {
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
			if(should_restart) {
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

		// if there's data on the inotify fd, consume it
		// (even if there is a forced request too)
		if(inotify_ready) {
			// note: if available data is less than buffer size, this should
			// return n > 0 but not filling the buffer. If available data is
			// more than buffer size, we will loop back to select and behave
			// like we debounced an event.
			auto n = read(m_inotify_fd, buf, sizeof(buf));
			if(n < 0) {
				// an error occurred, we can't recover
				// todo(jasondellaluce): should we terminate the process?
				falco_logger::log(falco_logger::level::ERR,
				                  "Failed read with inotify handler, shutting down watcher...");
				return;
			}
			// this is an odd case, but if we got here with
			// no read data, and no forced request, we get back
			// looping in the select. This can likely happen if
			// there's data in the inotify fd but the first read
			// returned no bytes. Likely we'll get back here at the
			// next select call.
			else if(n == 0 && !forced) {
				continue;
			}
		}

		// we consumed the new inotify events or we received a forced
		// restart request, so we'll perform a dry run after the
		// next timeout.
		should_check = true;
	}
#endif
}
