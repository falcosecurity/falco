#pragma once

#include <stdexcept>
#include "logger.h"

namespace libsinsp
{

/**
 * Simple helper to read a comma-separated list that includes ranges and
 * determine the total count of the values within.
 * Examples: 1,4-5 = 3; 0-15 = 16; 3,7,11 = 3
 *
 * See the "List Format" section of
 * http://man7.org/linux/man-pages/man7/cpuset.7.html
 *
 * Returns -1 if string is invalid.
 */
class cgroup_list_counter
{
public:
	const int INVALID_CPU_COUNT = -1;

	/**
	 * Return the number of elements given by the buffer. If needed, log at the
	 * given log-level.
	 */
	int operator ()(const char *buffer)
	{
		reset();

		int cpu_count = 0;

		try
		{
			const char *position = buffer;
			for(; '\0' != *position; ++position)
			{
				if ('-' == *position)
				{
					if (nullptr == m_section_start)
					{
						throw std::runtime_error("duplicate range indicator before start");
					}
					if (nullptr != m_range_indicator)
					{
						throw std::runtime_error("duplicate range indicators");
					}

					m_range_indicator = position;
				}
				else if (',' == *position)
				{
					cpu_count += process_section(m_section_start, position, m_range_indicator);
					reset();
				}
				else if (nullptr == m_section_start)
				{
					m_section_start = position;
				}

			}

			// There is never a trailing comma so always process the
			// final section
			cpu_count += process_section(m_section_start, position, m_range_indicator);

		}
		catch (const std::exception& ex)
		{
			g_logger.format(sinsp_logger::SEV_ERROR,
					"Invalid List Format: %s. Detail: %s",
					buffer,
					ex.what());
			return INVALID_CPU_COUNT;
		}

		return cpu_count;
	}

private:

	static int process_number(const char *section_start, const char *section_end)
	{
		std::string section(section_start, section_end - section_start);
		return std::stoi(section.c_str());

	}

	static int process_section(const char *section_start, const char *section_end, const char *range_indicator)
	{
		if (nullptr == section_start)
		{
			throw std::runtime_error("invalid end of section before start of section");
		}

		if (nullptr == section_end)
		{
			throw std::runtime_error("invalid end of section");
		}

		if (section_end <= section_start)
		{
			throw std::runtime_error("invalid section");
		}

		if (range_indicator)
		{
			// Split into two sections
			int first = process_number(section_start, range_indicator);
			int second = process_number(range_indicator + 1, section_end);

			if (second <= first)
			{
				throw std::runtime_error("invalid range");
			}

			return second - first + 1;
		}

		// We don't care what the value is, we just want to know that it is a number
		(void)process_number(section_start, section_end);
		return 1;
	}

	void reset()
	{
		m_section_start = nullptr;
		m_range_indicator = nullptr;
	}

	const char *m_section_start = nullptr;
	const char *m_range_indicator = nullptr;
};

}
