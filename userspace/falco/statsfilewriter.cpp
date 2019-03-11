/*
Copyright (C) 2016-2018 Draios Inc dba Sysdig.

This file is part of falco.

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

#include "statsfilewriter.h"

using namespace std;

static bool g_save_stats = false;
static void timer_handler (int signum)
{
	g_save_stats = true;
}

extern char **environ;

StatsFileWriter::StatsFileWriter()
	: m_num_stats(0), m_inspector(NULL)
{
}

StatsFileWriter::~StatsFileWriter()
{
	m_output.close();
}

bool StatsFileWriter::init(sinsp *inspector, string &filename, uint32_t interval_msec, string &errstr)
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

	timer.it_value.tv_sec = 0;
	timer.it_value.tv_usec = interval_msec * 1000;
	timer.it_interval = timer.it_value;
	if (setitimer(ITIMER_REAL, &timer, NULL) == -1)
	{
		errstr = string("Could not set up periodic timer: ") + strerror(errno);
		return false;
	}

	// (Undocumented) feature. Take any environment keys prefixed
	// with FALCO_STATS_EXTRA_XXX and add them to the output. Used by
	// run_performance_tests.sh.
	for(uint32_t i=0; environ[i]; i++)
	{
		char *p = strstr(environ[i], "=");
		if(!p)
		{
			errstr = string("Could not find environment separator in ") + string(environ[i]);
			return false;
		}
		string key(environ[i], p-environ[i]);
		string val(p+1, strlen(environ[i])-(p-environ[i])-1);
		if(key.compare(0, 18, "FALCO_STATS_EXTRA_") == 0)
		{
			string sub = key.substr(18);
			if (m_extra != "")
			{
				m_extra += ", ";
			}
			m_extra += "\"" + sub + "\": " + "\"" + val + "\"";
		}
	}

	return true;
}

void StatsFileWriter::handle()
{
	if (g_save_stats)
	{
		scap_stats cstats;
		scap_stats delta;

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

		m_output << "{\"sample\": " << m_num_stats;
		if(m_extra != "")
		{
			m_output << ", " << m_extra;
		}
		m_output << ", \"cur\": {" <<
			"\"events\": " << cstats.n_evts <<
			", \"drops\": " << cstats.n_drops <<
			", \"preemptions\": " << cstats.n_preemptions <<
			"}, \"delta\": {" <<
			"\"events\": " << delta.n_evts <<
			", \"drops\": " << delta.n_drops <<
			", \"preemptions\": " << delta.n_preemptions <<
			"}, \"drop_pct\": " << (delta.n_evts == 0 ? 0 : (100.0*delta.n_drops/delta.n_evts)) <<
			"}," << endl;

		m_last_stats = cstats;
	}
}
