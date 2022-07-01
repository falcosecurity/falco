/*
Copyright (C) 2019 The Falco Authors.

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

#include "statsfilewriter.h"
#include "logger.h"
#include "banned.h" // This raises a compilation error when certain functions are used
#include "logger.h"

// note: uint16_t is enough because we don't care about
// overflows here. Threads calling stats_writer::handle() will just
// check that this value changed since their last observation.
static std::atomic<uint16_t> s_last_tick((uint16_t) 0);

static void timer_handler(int signum)
{
	s_last_tick.fetch_add(1, std::memory_order_relaxed);
}

bool stats_writer::set_timer(uint32_t interval_msec, string &err)
{
	struct itimerval timer;
	struct sigaction handler;

	memset (&handler, 0, sizeof (handler));
	handler.sa_handler = &timer_handler;
	if (sigaction(SIGALRM, &handler, NULL) == -1)
	{
		err = string("Could not set up signal handler for periodic timer: ") + strerror(errno);
		return false;
	}

	timer.it_value.tv_sec = interval_msec / 1000;
	timer.it_value.tv_usec = (interval_msec % 1000) * 1000;
	timer.it_interval = timer.it_value;
	if (setitimer(ITIMER_REAL, &timer, NULL) == -1)
	{
		err = string("Could not set up periodic timer: ") + strerror(errno);
		return false;
	}

	return true;
}

stats_writer::stats_writer()
	: m_initialized(false), m_total_samples(0)
{
	// the stats writter do nothing
}

stats_writer::stats_writer(const std::string &filename)
	: m_initialized(true), m_total_samples(0)
{
	m_output.exceptions(ofstream::failbit | ofstream::badbit);
	m_output.open(filename, ios_base::app);
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

void stats_writer::handle(const std::shared_ptr<sinsp>& inspector, stats_writer::state& s)
{
	if (m_initialized)
	{
		auto tick = s_last_tick.load(std::memory_order_relaxed);
		if (tick != s.last_tick)
		{
			// gather stats sample and fill-up message
			stats_writer::msg msg;
			msg.stop = false;
			inspector->get_capture_stats(&msg.stats);
			if(s.samples == 1)
			{
				msg.delta = msg.stats;
			}
			else
			{
				msg.delta.n_evts = msg.stats.n_evts - s.last_stats.n_evts;
				msg.delta.n_drops = msg.stats.n_drops - s.last_stats.n_drops;
				msg.delta.n_preemptions = msg.stats.n_preemptions - s.last_stats.n_preemptions;
			}

			// update state
			s.samples++;
			s.last_tick = tick;
			s.last_stats = msg.stats;

			// push message into the queue
			push(msg);
		}
	}
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
	while(true)
	{
		// Block until a message becomes available.
		m_queue.pop(m);
		if (m.stop)
		{
			return;
		}

		try
		{
			jmsg["sample"] = m_num_stats;
			jmsg["cur"]["events"] = cstats.n_evts;
			jmsg["cur"]["drops"] = cstats.n_drops;
			jmsg["cur"]["preemptions"] = cstats.n_preemptions;
			jmsg["cur"]["drop_pct"] = (cstats.n_evts == 0 ? 0 : (100.0*cstats.n_drops/cstats.n_evts));
			jmsg["delta"]["events"] = delta.n_evts;
			jmsg["delta"]["drops"] = delta.n_drops;
			jmsg["delta"]["preemptions"] = delta.n_preemptions;
			jmsg["delta"]["drop_pct"] = (delta.n_evts == 0 ? 0 : (100.0*delta.n_drops/delta.n_evts));
			m_output << jmsg.dump() << endl;
		}
		catch(const exception &e)
		{
			falco_logger::log(LOG_ERR, "stats_writer (worker): " + string(e.what()) + "\n");
		}
	}
}
