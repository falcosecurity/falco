/*
Copyright (C) 2016-2019 Draios Inc dba Sysdig.

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

#include "config_falco.h"
#include "logger.h"

#include <fstream>
#include <functional>

namespace utils
{
std::string db("/proc/modules");
std::string module(PROBE_NAME);

static auto has_module(bool verbose, bool strict)
{
	// Comparing considering underscores (95) equal to dashes (45), and viceversa
	std::function<bool(const char &, const char &)> comparator = [](const char &a, const char &b) {
		return a == b || (a == 45 && b == 95) || (b == 95 && a == 45);
	};

	std::ifstream modules(db);
	std::string line;

	while(std::getline(modules, line))
	{
		bool shorter = module.length() <= line.length();
		if(shorter && std::equal(module.begin(), module.end(), line.begin(), comparator))
		{
			bool result = true;
			if(!strict)
			{
				falco_logger::log(LOG_INFO, "Kernel module found: true (not strict)\n");
				return result;
			}

			std::istringstream iss(line);
			std::vector<std::string> cols(std::istream_iterator<std::string>{iss}, std::istream_iterator<std::string>());

			// Check the module's number of instances - ie., whether it is loaded or not
			auto ninstances = cols.at(2);
			result = result && std::stoi(ninstances) > 0;

			// Check the module's load state
			auto state = cols.at(4);
			std::transform(state.begin(), state.end(), state.begin(), ::tolower);
			result = result && (state == "live");

			if(verbose)
			{
				falco_logger::log(LOG_INFO, "Kernel module instances: " + ninstances + "\n");
				falco_logger::log(LOG_INFO, "Kernel module load state: " + state + "\n");
			}

			// Check the module's taint state
			// See https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/kernel/panic.c#n351
			if(cols.size() > 6)
			{
				auto taint = cols.at(6);
				auto died = taint.find("D") != std::string::npos;
				auto warn = taint.find("W") != std::string::npos;
				auto unloaded = taint.find("R") != std::string::npos;
				result = result && !died && !warn && !unloaded;

				if(verbose)
				{
					taint.erase(0, taint.find_first_not_of('('));
					taint.erase(taint.find_last_not_of(')') + 1);
					falco_logger::log(LOG_INFO, "Kernel module taint state: " + taint + "\n");
					std::ostringstream message;
					message << std::boolalpha << "Kernel module presence: " << result << "\n";
					falco_logger::log(LOG_INFO, message.str());
				}
			}

			return result;
		}
	}

	modules.close();

	return false;
}

static auto ins_module()
{
	if(system("modprobe " PROBE_NAME " > /dev/null 2> /dev/null"))
	{
		// todo > fallback to a custom directory where to look for the module using `modprobe -d build/driver`
		falco_logger::log(LOG_ERR, "Unable to load the module.\n");
		return false;
	}
	return true;
}

static auto module_predicate(bool has_module)
{
	if(has_module)
	{
		return false;
	}
	// Retry only when we have been not able to insert the module
	return !ins_module();
}
} // namespace utils