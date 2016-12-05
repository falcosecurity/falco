#pragma once

#include <fstream>

#include <sinsp.h>

// Periodically collects scap stats files and writes them to a file as
// json.

class StatsFileWriter {
public:
	StatsFileWriter();
	virtual ~StatsFileWriter();

	// Returns success as bool. On false fills in errstr.
	bool init(sinsp *inspector, std::string &filename,
		  uint32_t interval_sec,
		  string &errstr);

	// Should be called often (like for each event in a sinsp
	// loop).
	void handle();

protected:
	uint32_t m_num_stats;
	sinsp *m_inspector;
	std::ofstream m_output;

	scap_stats m_last_stats;
};
