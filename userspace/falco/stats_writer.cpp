/*
Copyright (C) 2022 The Falco Authors.

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

#include <sys/time.h>
#include <signal.h>
#include <nlohmann/json.hpp>
#include <atomic>

#include <nlohmann/json.hpp>

#include "falco_common.h"
#include "stats_writer.h"
#include "logger.h"
#include "banned.h" // This raises a compilation error when certain functions are used
#include "logger.h"

// note: ticker_t is an uint16_t, which is enough because we don't care about
// overflows here. Threads calling stats_writer::handle() will just
// check that this value changed since their last observation.
static std::atomic<stats_writer::ticker_t> s_timer((stats_writer::ticker_t) 0);

static void timer_handler(int signum)
{
	s_timer.fetch_add(1, std::memory_order_relaxed);
}

bool stats_writer::init_ticker(uint32_t interval_msec, std::string &err)
{
	struct itimerval timer;
	struct sigaction handler;

	memset (&handler, 0, sizeof (handler));
	handler.sa_handler = &timer_handler;
	if (sigaction(SIGALRM, &handler, NULL) == -1)
	{
		err = std::string("Could not set up signal handler for periodic timer: ") + strerror(errno);
		return false;
	}

	timer.it_value.tv_sec = interval_msec / 1000;
	timer.it_value.tv_usec = (interval_msec % 1000) * 1000;
	timer.it_interval = timer.it_value;
	if (setitimer(ITIMER_REAL, &timer, NULL) == -1)
	{
		err = std::string("Could not set up periodic timer: ") + strerror(errno);
		return false;
	}

	return true;
}

stats_writer::ticker_t stats_writer::get_ticker()
{
	return s_timer.load(std::memory_order_relaxed);
}

stats_writer::stats_writer()
	: m_initialized(false), m_total_samples(0)
{

}

stats_writer::stats_writer(const std::string &filename)
	: m_initialized(true), m_total_samples(0)
{
	m_output.exceptions(std::ofstream::failbit | std::ofstream::badbit);
	m_output.open(filename, std::ios_base::app);
	m_worker = std::thread(&stats_writer::worker, this);
}

stats_writer::~stats_writer()
{
	if (m_initialized)
	{
		stop_worker();
		m_output.close();
	}
}

bool stats_writer::has_output() const
{
	return m_initialized;
}

void stats_writer::stop_worker()
{
	stats_writer::msg msg;
	msg.stop = true;
	push(msg);
	if(m_worker.joinable())
	{
		m_worker.join();
	}
}

inline void stats_writer::push(const stats_writer::msg& m)
{
	if (!m_queue.try_push(m))
	{
		fprintf(stderr, "Fatal error: Stats queue reached maximum capacity. Exiting.\n");
		exit(EXIT_FAILURE);
	}
}

void stats_writer::worker() noexcept
{
	stats_writer::msg m;
	nlohmann::json jmsg;
	auto tick = stats_writer::get_ticker();
	auto last_tick = tick;

	while(true)
	{
		// blocks until a message becomes availables
		m_queue.pop(m);
		if (m.stop)
		{
			return;
		}

		// update records for this event source
		jmsg[m.source]["cur"]["events"] = m.stats.n_evts;
		jmsg[m.source]["delta"]["events"] = m.delta.n_evts;
		if (m.source == falco_common::syscall_source)
		{
			jmsg[m.source]["cur"]["drops"] = m.stats.n_drops;
			jmsg[m.source]["cur"]["preemptions"] = m.stats.n_preemptions;
			jmsg[m.source]["cur"]["drop_pct"] = (m.stats.n_evts == 0 ? 0.0 : (100.0*m.stats.n_drops/m.stats.n_evts));
			jmsg[m.source]["delta"]["drops"] = m.delta.n_drops;
			jmsg[m.source]["delta"]["preemptions"] = m.delta.n_preemptions;
			jmsg[m.source]["delta"]["drop_pct"] = (m.delta.n_evts == 0 ? 0.0 : (100.0*m.delta.n_drops/m.delta.n_evts));
		}
		
		tick = stats_writer::get_ticker();
		if (last_tick != tick)
		{
			m_total_samples++;
			try
			{
				jmsg["sample"] = m_total_samples;
				m_output << jmsg.dump() << std::endl;
			}
			catch(const std::exception &e)
			{
				falco_logger::log(LOG_ERR, "stats_writer (worker): " + std::string(e.what()) + "\n");
			}
		}
	}
}

stats_writer::collector::collector(std::shared_ptr<stats_writer> writer)
	: m_writer(writer), m_last_tick(0), m_samples(0)
{

}

void stats_writer::collector::collect(std::shared_ptr<sinsp> inspector, const std::string& src)
{
	// just skip if no output is configured
	if (m_writer->has_output())
	{
		// collect stats once per each ticker period
		auto tick = stats_writer::get_ticker();
		if (tick != m_last_tick)
		{
			stats_writer::msg msg;
			msg.stop = false;
			msg.source = src;
			inspector->get_capture_stats(&msg.stats);
			m_samples++;
			if(m_samples == 1)
			{
				msg.delta = msg.stats;
			}
			else
			{
				msg.delta.n_evts = msg.stats.n_evts - m_last_stats.n_evts;
				msg.delta.n_drops = msg.stats.n_drops - m_last_stats.n_drops;
				msg.delta.n_preemptions = msg.stats.n_preemptions - m_last_stats.n_preemptions;
			}

			m_last_tick = tick;
			m_last_stats = msg.stats;
			m_writer->push(msg);
		}
	}
}
