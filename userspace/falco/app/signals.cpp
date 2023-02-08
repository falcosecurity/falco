/*
Copyright (C) 2023 The Falco Authors.

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

#include "signals.h"
#include "../logger.h"
#include "../falco_outputs.h"

std::atomic<int> falco::app::g_terminate(APP_SIGNAL_NOT_SET);
std::atomic<int> falco::app::g_restart(APP_SIGNAL_NOT_SET);
std::atomic<int> falco::app::g_reopen_outputs(APP_SIGNAL_NOT_SET);

static inline bool should_take_action_to_signal(std::atomic<int>& v)
{
	// we expected the signal to be received, and we try to set action-taken flag
	int value = APP_SIGNAL_SET;
	while (!v.compare_exchange_weak(
			value,
			APP_SIGNAL_ACTION_TAKEN,
			std::memory_order_seq_cst,
			std::memory_order_seq_cst))
	{
		// application already took action, there's no need to do it twice
		if (value == APP_SIGNAL_ACTION_TAKEN)
		{
			return false;
		}

		// signal did was not really received, so we "fake" receiving it
		if (value == APP_SIGNAL_NOT_SET)
		{
			v.store(APP_SIGNAL_SET, std::memory_order_seq_cst);
		}

		// reset "expected" CAS variable and keep looping until we succeed
		value = APP_SIGNAL_SET;
	}
	return true;
}

void falco::app::terminate(bool verbose)
{
	if (should_take_action_to_signal(falco::app::g_terminate))
	{
		if (verbose)
		{
			falco_logger::log(LOG_INFO, "SIGINT received, exiting...\n");
		}
	}
}

void falco::app::reopen_outputs(std::function<void()> on_reopen, bool verbose)
{
	if (should_take_action_to_signal(falco::app::g_reopen_outputs))
	{
		if (verbose)
		{
			falco_logger::log(LOG_INFO, "SIGUSR1 received, reopening outputs...\n");
		}
        on_reopen();
		falco::app::g_reopen_outputs.store(APP_SIGNAL_NOT_SET);
	}
}

void falco::app::restart(bool verbose)
{
	if (should_take_action_to_signal(falco::app::g_restart))
	{
		if (verbose)
		{
			falco_logger::log(LOG_INFO, "SIGHUP received, restarting...\n");
		}
	}
}
