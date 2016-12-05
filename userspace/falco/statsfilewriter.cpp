#include <sys/time.h>
#include <signal.h>

#include "statsfilewriter.h"

using namespace std;

static bool g_save_stats = false;
static void timer_handler (int signum)
{
	g_save_stats = true;
}

StatsFileWriter::StatsFileWriter()
	: m_num_stats(0), m_inspector(NULL)
{
}

StatsFileWriter::~StatsFileWriter()
{
	m_output.close();
}

bool StatsFileWriter::init(sinsp *inspector, string &filename, uint32_t interval_sec, string &errstr)
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

	timer.it_value.tv_sec = interval_sec;
	timer.it_value.tv_usec = 0;
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

		m_output << "{\"sample\": " << m_num_stats <<
			", \"cur\": {" <<
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
