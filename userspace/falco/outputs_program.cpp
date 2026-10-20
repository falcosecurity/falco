// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2023 The Falco Authors

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

#include "outputs_program.h"
#include "compat.h"
#include "logger.h"
#include <stdio.h>
#include <fcntl.h>
#include <signal.h>
#include <spawn.h>
#include <sys/wait.h>
#include <unistd.h>
#include <cerrno>
#include <cstring>

extern char** environ;

static void sigpipe_handler(int) {}

// Start the program with "/bin/sh -c" and a pipe as its standard input, like
// popen(), but also return its pid, so that it can be reaped without waiting.
// Return 0, or an error number.
static int start_program(const std::string& program, FILE*& file, pid_t& pid) {
	// No program may inherit the pipe, apart from the program's own standard
	// input. Like popen() in glibc, create it close-on-exec at once where
	// possible, so that a program started by another thread in the meantime
	// cannot inherit it either.
	int fds[2];
#ifdef __linux__
	if(pipe2(fds, O_CLOEXEC) != 0) {
		return errno;
	}
#else
	if(pipe(fds) != 0) {
		return errno;
	}
	fcntl(fds[0], F_SETFD, FD_CLOEXEC);
	fcntl(fds[1], F_SETFD, FD_CLOEXEC);
#endif
	// The copy made by dup2() is not close-on-exec. When the read end already is
	// the standard input, i.e. when Falco runs without one, some posix_spawn()
	// implementations (e.g. on macOS) keep the flag instead, so clear it here.
	if(fds[0] == STDIN_FILENO) {
		fcntl(fds[0], F_SETFD, 0);
	}

	posix_spawn_file_actions_t actions;
	posix_spawn_file_actions_init(&actions);
	posix_spawn_file_actions_adddup2(&actions, fds[0], STDIN_FILENO);
	const char* argv[] = {"sh", "-c", program.c_str(), nullptr};
	int ret = posix_spawn(&pid,
	                      "/bin/sh",
	                      &actions,
	                      nullptr,
	                      const_cast<char* const*>(argv),
	                      environ);
	posix_spawn_file_actions_destroy(&actions);
	close(fds[0]);
	if(ret != 0) {
		close(fds[1]);
		pid = -1;
		return ret;
	}

	file = fdopen(fds[1], "w");
	if(file == nullptr) {
		ret = errno;
		close(fds[1]);
	}
	return ret;
}

bool falco::outputs::output_program::init(const config& oc,
                                          bool buffered,
                                          const std::string& hostname,
                                          bool json_output,
                                          std::string& err) {
	if(!falco::outputs::abstract_output::init(oc, buffered, hostname, json_output, err)) {
		return false;
	}

	// Writing to a program that has exited raises SIGPIPE, whose default action
	// terminates Falco. With a handler, the write fails with EPIPE instead.
	// Unlike SIG_IGN, a handler is reset to the default action on exec, so the
	// program keeps its own SIGPIPE behavior. Keep any non-default action.
	struct sigaction current {};
	if(sigaction(SIGPIPE, nullptr, &current) == 0 && current.sa_handler == SIG_DFL) {
		struct sigaction action {};
		action.sa_handler = sigpipe_handler;
		action.sa_flags = SA_RESTART;
		sigemptyset(&action.sa_mask);
		if(sigaction(SIGPIPE, &action, nullptr) != 0) {
			char errbuf[256];
			err = std::string("could not handle SIGPIPE for program output: ") +
			      falco_strerror_r(errno, errbuf, sizeof(errbuf));
			return false;
		}
	}
	return true;
}

void falco::outputs::output_program::open_pfile() {
	if(m_pfile == nullptr) {
		// Run one instance of the program at a time: one that closed its input
		// after a failed write must exit before the program is started again.
		if(!reap_closed_program()) {
			falco_logger::log(falco_logger::level::ERR,
			                  "Failed to open program output: " + m_oc.options["program"] +
			                          " (error: its previous instance closed its input but is "
			                          "still running)");
			return;
		}

		int err = start_program(m_oc.options["program"], m_pfile, m_pid);
		if(m_pfile == nullptr) {
			// The program may have started before its pipe could be opened.
			m_closed_pid = m_pid;
			m_pid = -1;
			char errbuf[256];
			const char* errstr = falco_strerror_r(err, errbuf, sizeof(errbuf));
			falco_logger::log(falco_logger::level::ERR,
			                  "Failed to open program output: " + m_oc.options["program"] +
			                          " (error: " + errstr + ")");
			return;
		}

		if(!m_buffered) {
			setvbuf(m_pfile, NULL, _IONBF, 0);
		}
	}
}

void falco::outputs::output_program::output(const message* msg) {
	open_pfile();

	if(m_pfile != nullptr) {
		fprintf(m_pfile, "%s\n", msg->msg.c_str());
		if(m_oc.options["keep_alive"] != "true") {
			// Flush before the pipe is closed, to detect a failed write.
			fflush(m_pfile);
		}

		if(ferror(m_pfile)) {
			// The program exited or closed its input (e.g. EPIPE). Close the pipe
			// without waiting for the program, which may still be running: that
			// would block all output channels. The next output starts the program
			// again once it has exited. Report the failure.
			close_pfile(false);
			throw falco_exception("failed to write to program output " + m_oc.options["program"]);
		}
	}

	if(m_oc.options["keep_alive"] != "true") {
		cleanup();
	}
}

void falco::outputs::output_program::cleanup() {
	close_pfile(true);
	reap_closed_program();
}

void falco::outputs::output_program::reopen() {
	cleanup();
	open_pfile();
}

void falco::outputs::output_program::close_pfile(bool wait) {
	if(m_pfile == nullptr) {
		return;
	}

	fclose(m_pfile);
	m_pfile = nullptr;
	if(wait) {
		while(waitpid(m_pid, nullptr, 0) < 0 && errno == EINTR) {
		}
	} else {
		m_closed_pid = m_pid;
		reap_closed_program();
	}
	m_pid = -1;
}

bool falco::outputs::output_program::reap_closed_program() {
	if(m_closed_pid > 0) {
		if(waitpid(m_closed_pid, nullptr, WNOHANG) == 0) {
			return false;
		}
		m_closed_pid = -1;
	}
	return true;
}
