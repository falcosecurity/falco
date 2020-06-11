/*
Copyright (C) 2013-2018 Draios Inc dba Sysdig.

This file is part of sysdig.

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
#include "tracer_emitter.h"
#include "sinsp.h"
#include "sinsp_int.h"
#include "analyzer_utils.h"
#include <unistd.h>
#include <fcntl.h>
#include <mutex>

thread_local int tls_fd = -1;

// Helper class to allow multiple tracer_emitter instances to
// share a single connection to /dev/null. Multiple threads can
// write safely and without locking by storing the /dev/null
// fd in thread local storage. Locking is only required when
// the fd is created or destroyed, and that should only happen
// at startup.
class tracer_writer
{
public:
	tracer_writer() {}
	~tracer_writer() { close_fd(); }

	void write(const std::string &trc);

private:
	int get_fd();
	void close_fd();

	int m_fd = -1;
	run_on_interval m_open_interval = 60 * ONE_SECOND_IN_NS;
	std::mutex m_fd_lock;
	constexpr static const char *m_file = "/dev/null";
};

void tracer_writer::write(const std::string &trc)
{
	if (tls_fd < 0)
	{
		tls_fd = get_fd();
		if (tls_fd < 0)
		{
			// Something is wrong with /dev/null,
			// so all writes are going to drop
			return;
		}
	}
	ASSERT(tls_fd >= 0);

	// Writes to /dev/null should always succeed.
	// Still, error check because if m_fd changes
	// for some reason, tls_fd needs to get
	// cleared so we pick up the new m_fd next time.
	auto ret = ::write(tls_fd, trc.c_str(), trc.length());
	if (ret < 0 && errno == EINTR)
	{
		// Try once more before giving up
		ret = ::write(tls_fd, trc.c_str(), trc.length());
	}

	if (ret < 0 && errno != EINTR)
	{
		g_logger.format(sinsp_logger::SEV_ERROR,
				"Unable to write tracer (%s) to %s: %s",
				trc.c_str(), m_file, strerror(errno));
		close_fd();
	}
	// We know ret >= 0 so size_t cast is safe
	else if ((size_t)ret != trc.length())
	{
		ASSERT(false);
		g_logger.format(sinsp_logger::SEV_ERROR,
				"Incomplete write of tracer (%s) to %s",
				trc.c_str(), m_file);
		close_fd();
	}
	return;
}

int tracer_writer::get_fd()
{
	std::lock_guard<std::mutex> lock(m_fd_lock);

	if (m_fd >= 0)
	{
		return m_fd;
	}

	m_open_interval.run(
		[this]()
		{
			g_logger.format(sinsp_logger::SEV_DEBUG,
					"Opening %s for writing tracers", m_file);
			m_fd = ::open(m_file, O_WRONLY|O_NONBLOCK|O_CLOEXEC);
			if (m_fd < 0)
			{
				g_logger.format(sinsp_logger::SEV_ERROR,
						"Unable to open %s for writing tracers: %s",
						m_file, strerror(errno));
			}
	}, sinsp_utils::get_current_time_ns());

	return m_fd;
}

void tracer_writer::close_fd()
{
	std::lock_guard<std::mutex> lock(m_fd_lock);

	if (m_fd > -1)
	{
		g_logger.format(sinsp_logger::SEV_DEBUG,
				"Closing %s (fd %d) for writing tracers",
				m_file, m_fd);
		::close(m_fd);
		m_fd = -1;
	}
}

tracer_emitter::tracer_emitter(std::string tag, uint64_t timeout_ns)
	: m_tag(std::move(tag))
	, m_start_ns(sinsp_utils::get_current_time_ns())
	, m_timeout_ns(timeout_ns)
{
	start();
}

bool tracer_emitter::m_enabled = false;

// XXX find/write a constexpr-compatible string class
// for compile time concatenation
tracer_emitter::tracer_emitter(std::string tag, const tracer_emitter &parent, uint64_t timeout_ns)
	: tracer_emitter::tracer_emitter(
		parent.tag() + '.' + std::move(tag),
		std::min(timeout_ns, parent.m_timeout_ns))
{
}

tracer_emitter::~tracer_emitter()
{
	if (!m_exit_written)
	{
		write_tracer(false);
		elapsed_time(); // just for the side effect of logging if needed
	}
}

void tracer_emitter::start()
{
	write_tracer(true);
}

uint64_t tracer_emitter::stop()
{
	ASSERT(!m_exit_written);
	if (!m_exit_written)
	{
		write_tracer(false);
	}
	return elapsed_time();
}

void tracer_emitter::write_tracer(const bool enter)
{
	if (!m_enabled)
	{
		return;
	}

	static tracer_writer trc_writer;

	// XXX can we constexpr this part too?
	std::string trc_str(enter ? ">" : "<");
	// 't' == use thread id
	trc_str.append(":t:");
	trc_str.append(m_tag);
	trc_str.append("::");

	trc_writer.write(trc_str);

	if (!enter)
	{
		m_exit_written = true;
	}
}

uint64_t tracer_emitter::elapsed_time() const
{
	auto elapsed = sinsp_utils::get_current_time_ns() - m_start_ns;
	if (elapsed > m_timeout_ns)
	{
		g_logger.format(sinsp_logger::SEV_INFO, "Tracer %s elapsed time %llu ns", m_tag.c_str(), elapsed);
	}
	return elapsed;
}
