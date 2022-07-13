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

#include "statsfilewriter.h"
#include "banned.h" // This raises a compilation error when certain functions are used
#include "logger.h"

using namespace std;

static bool g_save_stats = false;
static void timer_handler (int signum)
{
	g_save_stats = true;
}

StatsFileWriter::StatsFileWriter()
	: m_num_stats(0)
{
}

StatsFileWriter::~StatsFileWriter()
{
	m_output.close();
}

bool StatsFileWriter::init(std::shared_ptr<sinsp> inspector, string &filename, uint32_t interval_msec, string &errstr)
{
	struct itimerval timer;
	struct sigaction handler;

	m_inspector = inspector;

	m_output.exceptions ( ofstream::failbit | ofstream::badbit );
	m_output.open(filename, ios_base::app);

	memset (&handler, 0, sizeof (handler));
	handler.sa_handler = &timer_handler;
	if (sigaction(SIGALRM, &handler, NULL) == -1)
	{
		errstr = string("Could not set up signal handler for periodic timer: ") + strerror(errno);
		return false;
	}

	timer.it_value.tv_sec = interval_msec / 1000;
	timer.it_value.tv_usec = (interval_msec % 1000) * 1000;
	timer.it_interval = timer.it_value;
	if (setitimer(ITIMER_REAL, &timer, NULL) == -1)
	{
		errstr = string("Could not set up periodic timer: ") + strerror(errno);
		return false;
	}

	return true;
}

void StatsFileWriter::handle()
{
	if (g_save_stats)
	{
		scap_stats cstats;
		scap_stats delta;
		nlohmann::json jmsg;

		g_save_stats = false;
		m_num_stats++;
		m_inspector->get_capture_stats(&cstats);

		if(m_num_stats == 1)
		{
			delta = cstats;
		}
		else
		{
			delta.n_evts = cstats.n_evts - m_last_stats.n_evts;
			delta.n_drops = cstats.n_drops - m_last_stats.n_drops;
			delta.n_preemptions = cstats.n_preemptions - m_last_stats.n_preemptions;
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
			falco_logger::log(LOG_ERR, "StatsFileWriter (handle): " + string(e.what()) + "\n");
		}

		m_last_stats = cstats;
	}
}
